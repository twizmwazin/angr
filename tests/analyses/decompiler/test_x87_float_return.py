#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,no-member
"""Tests for analyzing x86 functions that return a float or a double.

The x86 cdecl ABI returns them in st0, a slot of the x87 register stack. st0 is addressed relative to the runtime value
of ftop, so it has no fixed offset in the register file and archinfo does not list it in arch.registers. Looking the
name up anyway crashed with ``KeyError: 'st0'`` (angr/angr#4455).
"""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import unittest

import angr
from angr.calling_conventions import SimCCCdecl
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeDouble, SimTypeFunction

FLD1_RET = b"\xd9\xe8\xc3"  # fld1 ; ret -- returns 1.0 in st0
CALL_FLD1_RET = b"\xe8\x01\x00\x00\x00\xc3" + FLD1_RET  # the same, preceded by a caller


class TestX87FloatReturn(unittest.TestCase):
    @staticmethod
    def _load(code, callee_addr):
        proj = angr.load_shellcode(code, "x86", load_address=0x400000)
        cfg = proj.analyses.CFGFast(normalize=True)

        callee = proj.kb.functions[callee_addr]
        callee.prototype = SimTypeFunction([], SimTypeDouble()).with_arch(proj.arch)
        callee.calling_convention = SimCCCdecl(proj.arch)
        callee.prototype_libname = None
        callee.prototype_source = PrototypeSource.USER
        return proj, cfg

    def test_decompiling_a_float_returning_function(self):
        proj, cfg = self._load(FLD1_RET, 0x400000)
        func = proj.kb.functions[0x400000]
        decomp = proj.analyses[angr.analyses.Decompiler].prep(fail_fast=True)(func, cfg=cfg.model)
        assert decomp.codegen is not None
        assert decomp.codegen.text.startswith("double sub_400000(void)")

    def test_variable_recovery_over_a_float_returning_callsite(self):
        proj, _ = self._load(CALL_FLD1_RET, 0x400006)
        proj.analyses.VariableRecoveryFast(proj.kb.functions[0x400000])

    def test_reaching_definitions_over_a_float_returning_callsite(self):
        proj, _ = self._load(CALL_FLD1_RET, 0x400006)
        caller = proj.kb.functions[0x400000]
        proj.analyses.ReachingDefinitions(subject=caller, func_graph=caller.graph)


if __name__ == "__main__":
    unittest.main()
