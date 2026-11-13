#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.analyses import CFGFast, Decompiler
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestCFGModelLookup(unittest.TestCase):
    """
    Analyses must find the CFG model in the knowledge base regardless of the identifier that it is stored under.
    """

    def test_switch_recovery_when_cfg_is_not_named_cfgfast(self):
        p = angr.Project(os.path.join(test_location, "x86_64", "switch_0"), auto_load_libs=False)
        cfg = p.analyses[CFGFast].prep()(normalize=True, data_references=True)

        # store the model the way a second CFG recovery would
        p.kb.cfgs.cfgs["CFGFast_0"] = p.kb.cfgs.cfgs.pop("CFGFast")
        assert p.kb.cfgs.get_most_accurate() is cfg.model

        dec = p.analyses[Decompiler].prep(fail_fast=True)(cfg.functions["main"], cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None
        code = dec.codegen.text
        assert "switch" in code
        assert "case 1:" in code
        assert "case 2:" in code
        assert "case 3:" in code

        # looking the model up must not leave an empty "CFGFast" model behind
        assert sorted(p.kb.cfgs.cfgs) == ["CFGFast_0"]


if __name__ == "__main__":
    unittest.main()
