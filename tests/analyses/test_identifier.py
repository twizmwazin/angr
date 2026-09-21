#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import logging
import os
import sys
import unittest

import angr
from tests.common import bin_location


@unittest.skipIf(sys.platform == "win32", "broken on windows")
class TestIdentifier(unittest.TestCase):
    def test_comparison_identification(self):
        true_symbols = {0x804A3D0: "strncmp", 0x804A0F0: "strcmp", 0x8048E60: "memcmp", 0x8049F40: "strcasecmp"}

        p = angr.Project(os.path.join(bin_location, "tests", "i386", "identifiable"))
        # CGC has no symbols or eh_frame; the four functions are 0x90-0xf0 bytes, so scan just their neighbourhood
        # instead of the whole binary. Identifier iterates cfg.functions, so only these four get find_stack_vars/
        # identify_func, and only_find restricts run() to the matchers that can name them.
        cfg = p.analyses.CFGFast(
            resolve_indirect_jumps=True,
            regions=[(0x8048E60, 0x8048F00), (0x8049F40, 0x804A4C0)],
            start_at_entry=False,
            function_starts=sorted(true_symbols),
            force_smart_scan=False,
        )
        idfer = p.analyses.Identifier(cfg=cfg, require_predecessors=False, only_find=set(true_symbols.values()))

        seen = {}
        for addr, symbol in idfer.run():
            seen[addr] = symbol

        for addr, symbol in true_symbols.items():
            assert symbol == seen[addr]


if __name__ == "__main__":
    logging.getLogger("identifier").setLevel("DEBUG")
    unittest.main()
