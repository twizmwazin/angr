from __future__ import annotations

import logging
import os
from collections import namedtuple

from angr.errors import SimFileError, SimMergeError
from angr.storage.file import SimFile

from .plugin import SimStatePlugin

l = logging.getLogger(name=__name__)

Stat = namedtuple(
    "Stat",
    (
        "st_dev",
        "st_ino",
        "st_nlink",
        "st_mode",
        "st_uid",
        "st_gid",
        "st_rdev",
        "st_size",
        "st_blksize",
        "st_blocks",
        "st_atime",
        "st_atimensec",
        "st_mtime",
        "st_mtimensec",
        "st_ctime",
        "st_ctimensec",
    ),
)


class SimFilesystem(SimStatePlugin):  # pretends links don't exist
    """
    angr's emulated filesystem. Available as state.fs.
    When constructing, all parameters are optional.

    The filesystem is the sole owner of every file storage object (:class:`SimFileBase`) attached to the state: they
    all live in its *file store*, keyed by a unique string. Everything else that refers to a file - path mappings,
    file descriptors, ``posix.stdin`` and friends - holds a store key and resolves it through here at access time.
    This means each file is copied exactly once when the state forks, without any cross-plugin copy coordination.

    :param files:       A mapping from filepath to SimFile
    :param pathsep:     The character used to separate path elements, default forward slash.
    :param cwd:         The path of the current working directory to use
    :param mountpoints: A mapping from filepath to SimMountpoint

    :ivar pathsep:      The current pathsep
    :ivar cwd:          The current working directory
    :ivar unlinks:      A list of unlink operations, tuples of filename and simfile. This list is constructed on the
                        fly from the file store; mutating it will not affect the state.
    """

    def __init__(self, files=None, pathsep=None, cwd=None, mountpoints=None):
        super().__init__()

        if files is None:
            files = {}
        if pathsep is None:
            pathsep = b"/"
        if cwd is None:
            cwd = pathsep
        if mountpoints is None:
            mountpoints = {}

        self.pathsep = pathsep
        self.cwd = cwd
        self._unlinks = []  # list of (path, store key)
        self._store = {}  # store key -> SimFileBase. THE owner of all file storage reachable from the state.
        self._files = {}  # path -> store key
        self._mountpoints = {}

        for fname in mountpoints:
            self.mount(fname, mountpoints[fname])
        for fname in files:
            self.insert(fname, files[fname])

    def adopt(self, simfile):
        """
        Take ownership of a file storage object, adding it to the file store if it's not already present, and return
        its store key. Adopting the same object multiple times returns the same key, so references created from
        different places (a path, several file descriptors, stdin...) all resolve to one object.
        """
        for key, f in self._store.items():
            if f is simfile:
                return key

        ident = getattr(simfile, "ident", None) or type(simfile).__name__
        key = ident
        serial = 0
        while key in self._store:
            serial += 1
            key = f"{ident}#{serial}"
        self._store[key] = simfile
        if self.state is not None:
            simfile.set_state(self.state)
        return key

    def file_by_key(self, key):
        """
        Resolve a file store key to the file storage object it refers to.
        """
        try:
            return self._store[key]
        except KeyError:
            raise SimFileError(
                f"No file with key {key!r} in the filesystem's file store - "
                "was the fs plugin replaced without inheriting the store?"
            ) from None

    def key_of(self, simfile):
        """
        Return the store key of a file storage object, or None if it is not in the file store.
        """
        for key, f in self._store.items():
            if f is simfile:
                return key
        return None

    def inherit_store(self, old_fs):
        """
        Carry over the file store of a previous filesystem plugin. This keeps already-issued references (open file
        descriptors, stdin/stdout/stderr) valid when the fs plugin is replaced - analogous to POSIX open file
        descriptions surviving a change of the mount namespace.
        """
        for key, f in old_fs._store.items():
            self._store.setdefault(key, f)

    @SimStatePlugin.memo
    def copy(self, memo):
        o = super().copy(memo)

        o.pathsep = self.pathsep
        o.cwd = self.cwd
        o._unlinks = list(self._unlinks)
        # every file is stored here exactly once, so this is the only place file storage gets copied
        o._store = {k: f.copy(memo) for k, f in self._store.items()}
        o._files = dict(self._files)
        o._mountpoints = {k: v.copy(memo) for k, v in self._mountpoints.items()}

        return o

    @property
    def unlinks(self):
        return [(path, self.file_by_key(key)) for path, key in self._unlinks]

    def set_state(self, state):
        super().set_state(state)
        for f in self._store.values():
            f.set_state(state)
        for fname in self._mountpoints:
            self._mountpoints[fname].set_state(state)

    def merge(self, others, merge_conditions, common_ancestor=None):
        for o in others:
            if o.cwd != self.cwd:
                raise SimMergeError("Can't merge filesystems with disparate cwds")
            if len(o._mountpoints) != len(self._mountpoints):
                raise SimMergeError("Can't merge filesystems with disparate mountpoints")
            if o._unlinks != self._unlinks:
                raise SimMergeError("Can't merge filesystems with disparate unlinks")

        for fname in self._mountpoints:
            try:
                subdeck = [o._mountpoints[fname] for o in others]
            except KeyError as err:
                raise SimMergeError("Can't merge filesystems with disparate file sets") from err

            if common_ancestor is not None and fname in common_ancestor._mountpoints:
                common_mp = common_ancestor._mountpoints[fname]
            else:
                common_mp = None

            self._mountpoints[fname].merge(subdeck, merge_conditions, common_ancestor=common_mp)

        # As the owner of all file storage, the filesystem is responsible for merging file content, and does so
        # exactly once per file. Keys are shared lineage: states forked from a common ancestor agree on them.
        merging_occurred = False
        for key in self._store:
            if any(key not in o._store for o in others):
                l.warning("Not merging file %s: it does not exist in all states", key)
                continue

            common_simfile = None
            if common_ancestor is not None:
                common_simfile = common_ancestor._store.get(key)

            merging_occurred |= self._store[key].merge(
                [o._store[key] for o in others], merge_conditions, common_ancestor=common_simfile
            )

        for fname, key in self._files.items():
            if any(o._files.get(fname) != key for o in others):
                l.warning("Filesystems bind %s to different files; keeping the first state's version", fname)

        return merging_occurred

    def _normalize_path(self, path):
        """
        Takes a path and returns a simple absolute path as a list of directories from the root
        """
        if type(path) is str:
            path = path.encode()
        path = path.split(b"\0")[0]

        if path[0:1] != self.pathsep:
            path = self.cwd + self.pathsep + path
        keys = path.split(self.pathsep)
        i = 0
        while i < len(keys):
            if keys[i] == b"" or keys[i] == b".":
                keys.pop(i)
            elif keys[i] == b"..":
                keys.pop(i)
                if i != 0:
                    keys.pop(i - 1)
                    i -= 1
            else:
                i += 1
        return keys

    def _join_chunks(self, keys):
        """
        Takes a list of directories from the root and joins them into a string path
        """
        return self.pathsep + self.pathsep.join(keys)

    def chdir(self, path):
        """
        Changes the current directory to the given path
        """
        self.cwd = self._join_chunks(self._normalize_path(path))

    def get(self, path):
        """
        Get a file from the filesystem. Returns a SimFile or None.
        """
        mountpoint, chunks = self.get_mountpoint(path)

        if mountpoint is None:
            key = self._files.get(self._join_chunks(chunks))
            if key is None:
                return None
            return self.file_by_key(key)
        return mountpoint.get(chunks)

    def insert(self, path, simfile):
        """
        Insert a file into the filesystem. Returns whether the operation was successful.
        """
        mountpoint, chunks = self.get_mountpoint(path)

        if mountpoint is None:
            self._files[self._join_chunks(chunks)] = self.adopt(simfile)
            return True
        return mountpoint.insert(chunks, simfile)

    def delete(self, path):
        """
        Remove a file from the filesystem. Returns whether the operation was successful.

        This will add a ``fs_unlink`` event with the path of the file and also the index into the `unlinks` list.

        The file's storage stays in the file store, so open file descriptors (and the ``unlinks`` list) can still
        reach it - just like a POSIX unlink of an open file.
        """
        mountpoint, chunks = self.get_mountpoint(path)
        apath = self._join_chunks(chunks)

        if mountpoint is None:
            try:
                key = self._files.pop(apath)
            except KeyError:
                return False
            else:
                self.state.history.add_event("fs_unlink", path=apath, unlink_idx=len(self._unlinks))
                self._unlinks.append((apath, key))
                return True
        else:
            return mountpoint.delete(chunks)

    def mount(self, path, mount):
        """
        Add a mountpoint to the filesystem.
        """
        self._mountpoints[self._join_chunks(self._normalize_path(path))] = mount

    def unmount(self, path):
        """
        Remove a mountpoint from the filesystem.
        """
        del self._mountpoints[self._join_chunks(self._normalize_path(path))]

    def get_mountpoint(self, path):
        """
        Look up the mountpoint servicing the given path.

        :return: A tuple of the mount and a list of path elements traversing from the mountpoint to the specified file.
        """
        path_chunks = self._normalize_path(path)
        for i in range(len(path_chunks) - 1, -1, -1):
            partial_path = self._join_chunks(path_chunks[:-i])
            if partial_path in self._mountpoints:
                mountpoint = self._mountpoints[partial_path]
                if mountpoint is None:
                    break
                return mountpoint, path_chunks[-i:]

        return None, path_chunks


SimFilesystem.register_default("fs")


class SimMount(SimStatePlugin):
    """
    This is the base class for "mount points" in angr's simulated filesystem. Subclass this class and
    give it to the filesystem to intercept all file creations and opens below the mountpoint.
    Since this a SimStatePlugin you may also want to implement set_state, copy, merge, etc.
    """

    def get(self, path_elements):
        """
        Implement this function to instrument file lookups.

        :param path_elements:   A list of path elements traversing from the mountpoint to the file
        :return:                A SimFile, or None
        """
        raise NotImplementedError

    def insert(self, path_elements, simfile):
        """
        Implement this function to instrument file creation.

        :param path_elements:   A list of path elements traversing from the mountpoint to the file
        :param simfile:         The file to insert
        :return:                A bool indicating whether the insert occurred
        """
        raise NotImplementedError

    def delete(self, path_elements):
        """
        Implement this function to instrument file deletion.

        :param path_elements:   A list of path elements traversing from the mountpoint to the file
        :return:                A bool indicating whether the delete occurred
        """
        raise NotImplementedError

    def lookup(self, sim_file):
        """
        Look up the path of a SimFile in the mountpoint

        :param sim_file:        A SimFile object needs to be looked up
        :return:                A string representing the path of the file in the mountpoint
                                Or None if the SimFile does not exist in the mountpoint
        """
        raise NotImplementedError


class SimConcreteFilesystem(SimMount):
    """
    Abstract SimMount allowing the user to import files from some external source into the guest

    :param str pathsep:         The host path separator character, default os.path.sep
    """

    def __init__(self, pathsep=os.path.sep):
        super().__init__()
        self.pathsep = pathsep
        self.cache = {}  # path -> file store key
        self.deleted_list = set()

    def get(self, path_elements):
        path = self._join_chunks([x.decode() for x in path_elements])
        if path in self.deleted_list:
            return None
        if path not in self.cache:
            simfile = self._load_file(path)
            if simfile is None:
                return None
            self.insert(path_elements, simfile)

        return self.state.fs.file_by_key(self.cache[path])

    def _load_file(self, guest_path):
        raise NotImplementedError

    def _get_stat(self, guest_path, dereference=False):
        raise NotImplementedError

    def insert(self, path_elements, simfile):
        path = self._join_chunks([x.decode() for x in path_elements])
        self.cache[path] = self.state.fs.adopt(simfile)
        self.deleted_list.discard(path)
        return True

    def delete(self, path_elements):
        path = self._join_chunks([x.decode() for x in path_elements])
        self.deleted_list.add(path)
        return self.cache.pop(path, None) is not None

    def lookup(self, sim_file):
        for path, key in self.cache.items():
            if self.state.fs.file_by_key(key) is sim_file:
                return path
        return None

    @SimStatePlugin.memo
    def copy(self, memo):  # pylint: disable=unused-argument
        x = type(self)(pathsep=self.pathsep)
        x.cache = dict(self.cache)  # the cache holds file store keys; the fs plugin owns (and copies) the files
        x.deleted_list = set(self.deleted_list)
        return x

    def merge(self, others, merge_conditions, common_ancestor=None):
        # file content is merged by the fs plugin's file store; only sanity-check the mount metadata here
        for o in others:
            if o.pathsep != self.pathsep:
                raise SimMergeError("Can't merge concrete filesystems with disparate pathseps")
            if o.deleted_list != self.deleted_list:
                raise SimMergeError("Can't merge concrete filesystems with disparate deleted files")

        return False

    def _join_chunks(self, keys):
        """
        Takes a list of directories from the root and joins them into a string path
        """
        return self.pathsep + self.pathsep.join(keys)


class SimHostFilesystem(SimConcreteFilesystem):
    """
    Simulated mount that makes some piece from the host filesystem available to the guest.

    :param str host_path:       The path on the host to mount
    :param str pathsep:         The host path separator character, default os.path.sep
    """

    def __init__(self, host_path=None, **kwargs):
        super().__init__(**kwargs)
        self.host_path = host_path if host_path is not None else self.pathsep

    @SimStatePlugin.memo
    def copy(self, memo):
        o = super().copy(memo)
        o.host_path = self.host_path
        return o

    def _load_file(self, guest_path):
        guest_path = guest_path.lstrip(self.pathsep)
        path = os.path.join(self.host_path, guest_path)
        try:
            with open(path, "rb") as fp:
                content = fp.read()
        except OSError:
            return None
        else:
            return SimFile(name="file://" + os.path.realpath(path), content=content, size=len(content))

    def _get_stat(self, guest_path, dereference=False):
        guest_path = guest_path.lstrip(self.pathsep)
        path = os.path.join(self.host_path, guest_path)
        try:
            if dereference:
                path = os.path.realpath(path)
            s = os.stat(path)
            return Stat(
                s.st_dev,
                s.st_ino,
                s.st_nlink,
                s.st_mode,
                s.st_uid,
                s.st_gid,
                s.st_rdev,
                s.st_size,
                s.st_blksize,
                s.st_blocks,
                round(s.st_atime),
                s.st_atime_ns,
                round(s.st_mtime),
                s.st_mtime_ns,
                round(s.st_ctime),
                s.st_ctime_ns,
            )
        except OSError:
            return None
