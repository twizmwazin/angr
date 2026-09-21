#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import os.path
import unittest

import angr
import angr.flirt
from tests.common import bin_location


class TestFlirt(unittest.TestCase):
    def test_amd64_elf_static_libc_ubuntu_2004(self):
        binary_path = os.path.join(bin_location, "tests", "x86_64", "elf_with_static_libc_ubuntu_2004_stripped")
        proj = angr.Project(binary_path, auto_load_libs=False, load_debug_info=False)
        # FLIRT names 0x415cc0 from the fileops.o module whose base function is 0x4140a0 (0x415cc0 is at module
        # offset 0x1c20), and 0x436980 is itself a module base; neither module references other functions, so only
        # these three functions need to exist. A whole-binary CFG of this static glibc build takes over a minute.
        cfg = proj.analyses.CFGFast(
            show_progressbar=False,
            regions=[(0x4140A0, 0x416000), (0x436980, 0x436B80)],
            function_starts=[0x4140A0, 0x415CC0, 0x436980],
            start_at_entry=False,
        )
        flirt_path = os.path.join(bin_location, "tests", "x86_64", "libc_ubuntu_2004.sig")
        proj.analyses.Flirt(flirt_path)

        assert cfg.functions[0x415CC0].name == "_IO_file_open"
        assert cfg.functions[0x415CC0].is_default_name is False
        assert cfg.functions[0x415CC0].from_signature == "flirt"
        assert cfg.functions[0x436980].name == "__mempcpy_chk_avx512_no_vzeroupper"
        assert cfg.functions[0x436980].is_default_name is False
        assert cfg.functions[0x436980].from_signature == "flirt"

    def test_armhf_elf_static_using_armel_libc(self):
        binary_path = os.path.join(bin_location, "tests", "armhf", "amp_challenge_07.gcc")
        proj = angr.Project(binary_path, auto_load_libs=False, load_debug_info=False)
        proj.analyses.CFGFast(show_progressbar=False, regions=[(0x1004C9, 0x1007A9)])
        flirt_path = os.path.join(bin_location, "tests", "armhf", "debian_10.3_libc.sig")
        flirt = proj.analyses.Flirt(flirt_path)

        assert len(flirt.matched_suggestions) == 1

        assert proj.kb.functions[0x1004C9].name == "strstr"
        assert proj.kb.functions[0x1004C9].prototype is not None
        assert proj.kb.functions[0x1004C9].calling_convention is not None

    def test_flirt_sig_loading(self):
        flirt_path = os.path.join(bin_location, "tests", "armhf", "debian_10.3_libc.sig")
        r = angr.flirt.load_signature(flirt_path)
        assert r is not None
        _, sig = r
        assert sig.sig_name == "libc"

        # with meta file
        meta_path = os.path.join(bin_location, "tests", "armhf", "debian_10.3_libc.meta")
        r = angr.flirt.load_signature(flirt_path, meta_path=meta_path)
        assert r is not None
        _, sig = r
        assert sig.arch == "armel"
        assert sig.os_name == "debian"


if __name__ == "__main__":
    unittest.main()
