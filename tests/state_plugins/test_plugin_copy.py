#!/usr/bin/env python3
from __future__ import annotations

import unittest

import angr
from angr.state_plugins.plugin import SimStatePlugin, copy_context
from angr.storage.file import SimFile


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class DictPlugin(SimStatePlugin):
    """A plugin with no declarations: the default copy discovers fields from the instance dict."""

    def __init__(self):
        super().__init__()
        self.number = 1
        self.items = [1, 2]
        self.mapping = {"k": "v"}


class ExplicitPlugin(SimStatePlugin):
    """A plugin that uses _COPY_FIELDS to declare exactly what the default copy should duplicate."""

    _COPY_FIELDS = ("x",)

    def __init__(self):
        super().__init__()
        self.x = [1]
        self.y = [2]


class ExplicitChildPlugin(ExplicitPlugin):
    _COPY_FIELDS = ("z",)

    def __init__(self):
        super().__init__()
        self.z = 9


class SlottedPlugin(SimStatePlugin):
    """A plugin whose fields are discovered from __slots__ declarations."""

    __slots__ = ("mapping", "scalar")

    def __init__(self):
        super().__init__()
        self.mapping = {"a": 1}
        self.scalar = 5


class HolderPlugin(SimStatePlugin):
    def __init__(self, inner):
        super().__init__()
        self.inner = inner


class TestPluginCopy(unittest.TestCase):
    def test_default_copy_from_instance_dict(self):
        p = DictPlugin()
        c = p.copy()
        assert c is not p
        assert c.state is None
        assert c.number == 1
        assert c.items == [1, 2]
        assert c.items is not p.items
        assert c.mapping == {"k": "v"}
        assert c.mapping is not p.mapping

    def test_copy_fields_declaration(self):
        p = ExplicitPlugin()
        c = p.copy()
        assert c.x == [1]
        assert c.x is not p.x
        assert not hasattr(c, "y")

    def test_copy_fields_union_with_parent(self):
        p = ExplicitChildPlugin()
        c = p.copy()
        assert c.x == [1]
        assert c.z == 9
        assert not hasattr(c, "y")

    def test_slots_discovery(self):
        p = SlottedPlugin()
        c = p.copy()
        assert c.mapping == {"a": 1}
        assert c.mapping is not p.mapping
        assert c.scalar == 5

    def test_plugin_fields_copied_recursively(self):
        inner = DictPlugin()
        p = HolderPlugin(inner)
        c = p.copy()
        assert c.inner is not inner
        assert c.inner.items == inner.items

    def test_shared_identity_within_copy_context(self):
        inner = DictPlugin()
        h1 = HolderPlugin(inner)
        h2 = HolderPlugin(inner)
        with copy_context():
            c1 = h1.copy()
            c2 = h2.copy()
        assert c1.inner is c2.inner
        assert c1.inner is not inner

        # separate copy operations must produce independent copies
        c1 = h1.copy()
        c2 = h2.copy()
        assert c1.inner is not c2.inner

    def test_state_copy_preserves_fd_identity(self):
        state = angr.SimState(arch="AMD64")
        assert state.posix.fd[0] is state.posix.fd[1]  # the tty duplex
        copied = state.copy()
        assert copied.posix.fd[0] is copied.posix.fd[1]
        assert copied.posix.fd[0] is not state.posix.fd[0]

    def test_state_copy_preserves_file_identity_across_plugins(self):
        state = angr.SimState(arch="AMD64")
        simfile = SimFile(name="foo", content=b"abcd")
        state.fs.insert(b"/foo", simfile)
        fd = state.posix.open(b"/foo", 0)
        copied = state.copy()
        assert copied.fs.get(b"/foo") is copied.posix.fd[fd].file
        assert copied.fs.get(b"/foo") is not simfile


if __name__ == "__main__":
    unittest.main()
