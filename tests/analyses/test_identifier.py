#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import logging
import os
import sys
import unittest
from types import SimpleNamespace

import angr
from angr.analyses.identifier.functions.memcpy import memcpy
from angr.analyses.identifier.runner import Runner
from tests.common import bin_location


@unittest.skipIf(sys.platform == "win32", "broken on windows")
class TestIdentifier(unittest.TestCase):
    def test_comparison_identification(self):
        true_symbols = {0x804A3D0: "strncmp", 0x804A0F0: "strcmp", 0x8048E60: "memcmp", 0x8049F40: "strcasecmp"}

        p = angr.Project(os.path.join(bin_location, "tests", "i386", "identifiable"))
        idfer = p.analyses.Identifier(require_predecessors=False)

        seen = {}
        for addr, symbol in idfer.run():
            seen[addr] = symbol

        for addr, symbol in true_symbols.items():
            assert symbol == seen[addr]

    def test_memcpy_memmove_safe(self):
        # push esi; push edi; mov edi, [esp+0xc]; mov esi, [esp+0x10]; mov ecx, [esp+0x14]
        prologue = bytes.fromhex("56578b7c240c8b7424108b4c2414")
        # cld; rep movsb; pop edi; pop esi; ret
        forward_copy = bytes.fromhex("fcf3a45f5ec3")
        # test ecx, ecx; jz done; cmp edi, esi; jbe forward
        # backward: dec ecx; mov al, [esi+ecx]; mov [edi+ecx], al; jnz backward; jmp done
        overlap_check = bytes.fromhex("85c9741239f7760b498a040e88040f75f7eb03")
        funcs = {
            "memcpy": (0x8000, prologue + forward_copy),
            "memmove": (0x9000, prologue + overlap_check + forward_copy),
        }

        p = angr.Project(os.path.join(bin_location, "tests", "i386", "identifiable"), auto_load_libs=False)
        runner = Runner(p, None)
        base_state = runner._get_recv_state()
        # the functions are short enough to not need unicorn
        base_state.options.discard(angr.options.UNICORN)
        for addr, code in funcs.values():
            base_state.memory.store(addr, code)
        runner.base_state = base_state

        for name, (addr, _) in funcs.items():
            func = SimpleNamespace(startpoint=SimpleNamespace(addr=addr))
            match = memcpy()
            assert match.pre_test(func, runner)
            assert match.get_name() == name


if __name__ == "__main__":
    logging.getLogger("identifier").setLevel("DEBUG")
    unittest.main()
