#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest import mock

import archinfo

from angr import claripy
from angr.ailment import Const
from angr.ailment.expression import Load
from angr.analyses.decompiler.optimization_passes import const_prop_reverter
from angr.analyses.decompiler.optimization_passes.const_prop_reverter import ConstPropOptReverter
from angr.knowledge_plugins.key_definitions.atoms import MemoryLocation
from angr.knowledge_plugins.key_definitions.live_definitions import LiveDefinitions
from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues

GLOBAL_ADDR = 0x601000


class _Call:
    def __init__(self, *args):
        self.args = args


class TestConstPropReverter(unittest.TestCase):
    @staticmethod
    def _reverts(*values: int) -> bool:
        """
        Whether f(75) becomes f(global) next to another f(global), when the global holds the given values, each from
        a definition of its own, at the call that passes 75.
        """
        arch = archinfo.ArchAMD64()
        atom = MemoryLocation(GLOBAL_ADDR, 4, "Iend_LE")
        live_defs = None
        for codeloc, value in enumerate(values):
            one = LiveDefinitions(arch)
            one.kill_and_add_definition(atom, codeloc, MultiValues(claripy.BVV(value, 32)))
            live_defs = one if live_defs is None else live_defs.merge(one)[0]
        rda = SimpleNamespace(get_reaching_definitions_by_node=lambda addr, kind: live_defs)

        const = Const(1, 75, 32)
        load = Load(2, Const(3, GLOBAL_ADDR, 64), 4, "Iend_LE")
        const_call, load_call = _Call(const), _Call(load)
        const_blk, load_blk = SimpleNamespace(addr=0x400000), SimpleNamespace(addr=0x400010)

        opt = object.__new__(ConstPropOptReverter)
        opt._func = SimpleNamespace(
            project=SimpleNamespace(analyses=SimpleNamespace(ReachingDefinitions=lambda **_: rda))
        )
        opt._graph = opt.manager = None
        opt._rewrite_call_in_block = lambda blk, call: None
        opt.resolution = False
        opt._call_pair_targets = [((const_call, const_blk, load_call, load_blk, {0: (const, load)}), [])]
        with mock.patch.object(const_prop_reverter, "variable_map_of", lambda manager: None):
            opt._analyze_call_pair_targets()
        return opt.resolution

    def test_constant_becomes_the_global_holding_it(self):
        assert self._reverts(75)

    def test_several_definitions_of_the_same_value_are_one_value(self):
        assert self._reverts(75, 75, 75)

    def test_constant_stays_when_the_global_holds_another_value(self):
        assert not self._reverts(80)

    def test_constant_stays_when_the_global_may_hold_another_value(self):
        # which of several values is looked at first depends on their hashes, so try a range of them
        assert not any(self._reverts(75, other) for other in range(76, 96))
        assert not self._reverts(75, 76, 77, 78)


if __name__ == "__main__":
    unittest.main()
