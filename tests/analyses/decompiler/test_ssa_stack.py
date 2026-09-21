#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os.path
import unittest

from tests.common import bin_location, load_project_with_scoped_cfg, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


# pylint: disable=missing-class-docstring, no-self-use
class TestSSAStack(unittest.TestCase):
    def test_missing_stack_defs(self):
        bin_path = os.path.join(
            test_location,
            "i386",
            "windows",
            "22322afab6d7b2b21e715ff2568b02454ac39fb6a5fe305537bb529e106e407b",
        )
        proj, cfg = load_project_with_scoped_cfg(bin_path, 0x4720B2, run_ccc=False)

        func = cfg.functions[0x4720B2]
        dec = proj.analyses.Decompiler(func, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        # basic sanity check
        assert "WideCharToMultiByte(" in dec.codegen.text
        assert "CreateDCA(" in dec.codegen.text
        assert '"DISPLAY"' in dec.codegen.text

    def test_incorrect_narrowing_of_phi_vars(self):
        bin_path = os.path.join(
            test_location,
            "x86_64",
            "windows",
            "28ce9dfc983d8489242743635c792d3fc53a45c96316b5854301f6fa514df55e.sys",
        )
        # the call tree of 0x14001a314 is two levels deep (one internal callee, itself only calling two imports
        # through the IAT), so a whole-binary CFG of this 108 KB driver is not needed; auto_load_libs=False since
        # the imported kernel DLLs (ntoskrnl.exe etc.) are never found anyway.
        proj, cfg = load_project_with_scoped_cfg(
            bin_path, 0x14001A314, project_kwargs={"auto_load_libs": False}, run_ccc=False
        )

        func = cfg.functions[0x14001A314]
        dec = proj.analyses.Decompiler(func, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        # basic sanity check
        lines = dec.codegen.text.splitlines()
        assert len(lines) >= 100

    def test_removing_arm_stack_pointer_alignments(self):
        bin_path = os.path.join(
            test_location,
            "armel",
            "chall.bin",
        )
        # 0x35d and its callees are all reachable through direct 'bl' instructions, so seeding just the root (instead
        # of the whole-blob smart sweep in both ARM and Thumb modes) suffices.
        proj, cfg = load_project_with_scoped_cfg(
            bin_path,
            0x35D,
            window=0x400,
            project_kwargs={"main_opts": {"backend": "blob", "arch": "ARMEL", "base_addr": 0x0}},
            run_ccc=False,
        )

        func = cfg.functions[0x35D]
        dec = proj.analyses.Decompiler(func, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        assert "0xfffffffc" not in dec.codegen.text  # the stack pointer alignment mask should be simplified away


if __name__ == "__main__":
    unittest.main()
