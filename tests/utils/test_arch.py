#!/usr/bin/env python3
from __future__ import annotations

import unittest

import archinfo

from angr.utils.arch import get_sp_offset


# pylint: disable=missing-class-docstring,disable=no-self-use
class TestGetSpOffset(unittest.TestCase):
    def test_all_arches(self):
        # every in-tree architecture except Soot defines a stack pointer under its canonical name "sp"
        for arch in archinfo.all_arches:
            if isinstance(arch, archinfo.ArchSoot):
                assert get_sp_offset(arch) is None
            else:
                assert get_sp_offset(arch) == arch.registers["sp"][0]

    def test_amd64(self):
        arch = archinfo.ArchAMD64()
        assert get_sp_offset(arch) == arch.registers["rsp"][0]

    def test_arch_without_sp(self):
        assert get_sp_offset(archinfo.ArchSoot()) is None


if __name__ == "__main__":
    unittest.main()
