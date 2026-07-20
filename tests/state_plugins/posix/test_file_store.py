#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
"""
Tests for the filesystem file store: the fs plugin is the single owner of all file storage, and every other
reference (file descriptors, posix.stdin and friends, socket pairs, path mappings) resolves through it. These
tests pin down the aliasing invariants that used to depend on the cross-plugin copy memo.
"""

from __future__ import annotations

import unittest

import claripy

from angr import SimFile, SimState
from angr.state_plugins import SimFilesystem, SimSystemPosix
from angr.storage.file import SimFileDescriptor, SimFileStream


class TestFileStoreCoherence(unittest.TestCase):
    def test_tty_aliasing_after_copy(self):
        state = SimState(arch="AMD64", mode="symbolic")
        assert state.posix.fd[0] is state.posix.fd[1]
        assert state.posix.stdin is state.posix.fd[0].read_storage
        assert state.posix.stdout is state.posix.fd[1].write_storage
        assert state.posix.stderr is state.posix.fd[2].file

        copied = state.copy()
        assert copied.posix.fd[0] is copied.posix.fd[1]
        assert copied.posix.stdin is copied.posix.fd[0].read_storage
        assert copied.posix.stdout is copied.posix.fd[1].write_storage
        assert copied.posix.stderr is copied.posix.fd[2].file
        # and the copy is actually a copy
        assert copied.posix.stdin is not state.posix.stdin

    def test_fd_and_fs_share_file_after_copy(self):
        state = SimState(arch="AMD64", mode="symbolic")
        fd = state.posix.open(b"/tmp/foo", 1)
        assert state.posix.fd[fd].file is state.fs.get(b"/tmp/foo")

        copied = state.copy()
        assert copied.posix.fd[fd].file is copied.fs.get(b"/tmp/foo")
        assert copied.posix.fd[fd].file is not state.posix.fd[fd].file

        # writes through the fd are visible through the fs, and don't leak into the parent state
        copied.posix.fd[fd].write_data(claripy.BVV(b"hello"))
        assert copied.fs.get(b"/tmp/foo").concretize() == b"hello"
        assert state.fs.get(b"/tmp/foo").concretize() == b""

    def test_multiple_opens_share_file(self):
        state = SimState(arch="AMD64", mode="symbolic")
        fd1 = state.posix.open(b"/tmp/foo", 1)
        fd2 = state.posix.open(b"/tmp/foo", 0)
        assert state.posix.fd[fd1].file is state.posix.fd[fd2].file

        copied = state.copy()
        assert copied.posix.fd[fd1].file is copied.posix.fd[fd2].file

    def test_dup_aliasing_after_copy(self):
        state = SimState(arch="AMD64", mode="symbolic")
        fd = state.posix.open(b"/tmp/foo", 1)
        # what the dup/dup2/dup3 procedures do
        state.posix.fd[100] = state.posix.fd[fd]

        copied = state.copy()
        assert copied.posix.fd[100] is copied.posix.fd[fd]
        assert copied.posix.fd[100] is not state.posix.fd[100]

    def test_socket_identity_after_copy(self):
        state = SimState(arch="AMD64", mode="symbolic")
        sockfd = state.posix.open_socket(3)
        # the identity checks the accept() procedure performs
        assert state.posix.sockets[3][0] is state.posix.fd[sockfd].read_storage
        assert state.posix.sockets[3][1] is state.posix.fd[sockfd].write_storage

        copied = state.copy()
        assert copied.posix.sockets[3][0] is copied.posix.fd[sockfd].read_storage
        assert copied.posix.sockets[3][1] is copied.posix.fd[sockfd].write_storage

    def test_unlinked_file_stays_reachable(self):
        state = SimState(arch="AMD64", mode="symbolic")
        fd = state.posix.open(b"/tmp/foo", 1)
        state.posix.fd[fd].write_data(claripy.BVV(b"data"))
        assert state.fs.delete(b"/tmp/foo")
        assert state.fs.get(b"/tmp/foo") is None
        # the open fd and the unlinks list can still reach the storage
        assert state.posix.fd[fd].file.concretize() == b"data"
        assert state.fs.unlinks[0][0] == b"/tmp/foo"
        assert state.fs.unlinks[0][1] is state.posix.fd[fd].file

        copied = state.copy()
        assert copied.posix.fd[fd].file.concretize() == b"data"
        assert copied.fs.unlinks[0][1] is copied.posix.fd[fd].file

    def test_shared_stdin_between_kwarg_and_fd(self):
        # the pattern used by the identifier analysis and some tests: hand-built fd table sharing storage
        # with the stdin= kwarg
        stdin_storage = SimFileStream(name="stdin", content=b"aaaa")
        stdin_fd = SimFileDescriptor(stdin_storage)
        state = SimState(arch="AMD64", mode="symbolic")
        state.register_plugin("posix", SimSystemPosix(stdin=stdin_storage, fd={0: stdin_fd}))
        assert state.posix.stdin is state.posix.fd[0].file

        copied = state.copy()
        assert copied.posix.stdin is copied.posix.fd[0].file

    def test_fs_replacement_keeps_references_valid(self):
        # replacing the fs plugin (as SimLinux.state_blank does) must not orphan open file descriptions
        state = SimState(arch="AMD64", mode="symbolic")
        stdin = state.posix.stdin
        state.register_plugin("fs", SimFilesystem(files={"/flag": SimFile("flag", content=b"FLAG{}")}))
        assert state.posix.stdin is stdin
        assert state.posix.stdin is state.posix.fd[0].read_storage
        fd = state.posix.open(b"/flag", 0)
        assert state.posix.fd[fd].file is state.fs.get(b"/flag")

    def test_copy_without_shared_memo(self):
        # the point of the file store: each plugin can be copied in isolation and the object graph stays coherent
        state = SimState(arch="AMD64", mode="symbolic")
        fd = state.posix.open(b"/tmp/foo", 1)

        fs_copy = state.fs.copy({})
        posix_copy = state.posix.copy({})  # separate memo: no cross-plugin sharing
        copied = SimState(
            arch="AMD64",
            mode="symbolic",
            plugins={"fs": fs_copy, "posix": posix_copy},
        )
        assert copied.posix.fd[fd].file is copied.fs.get(b"/tmp/foo")
        assert copied.posix.stdin is copied.posix.fd[0].read_storage

    def test_merge_stdout_content(self):
        state = SimState(arch="AMD64", mode="symbolic")
        ancestor = state.copy()
        a = ancestor.copy()
        b = ancestor.copy()
        a.posix.fd[1].write_data(claripy.BVV(b"AAAA"))
        b.posix.fd[1].write_data(claripy.BVV(b"BBBB"))
        merged, _, _ = a.merge(b, common_ancestor=ancestor)
        packet = merged.posix.stdout.content[0][0]
        vals = merged.solver.eval_upto(packet, 3, cast_to=bytes)
        assert set(vals) == {b"AAAA", b"BBBB"}


if __name__ == "__main__":
    unittest.main()
