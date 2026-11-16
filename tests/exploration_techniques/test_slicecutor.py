#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.exploration_techniques"  # pylint:disable=redefined-builtin

import unittest

import angr


class _FakeAnnotatedCFG:
    """
    A minimal stand-in for AnnotatedCFG that only allows the given exits.
    """

    def __init__(self, targets: dict[int, list[int]]):
        self._targets = targets

    def get_whitelisted_statements(self, addr):  # pylint:disable=unused-argument
        return None

    def get_last_statement_index(self, addr):  # pylint:disable=unused-argument
        return None

    def get_targets(self, addr):
        return self._targets.get(addr)

    def should_take_exit(self, src, dst):
        return dst in self._targets.get(src, [])


class TestSlicecutor(unittest.TestCase):
    def test_force_sat_fastpath(self):
        # 0: xor eax, eax
        # 2: test eax, eax
        # 4: jnz 0x8  ; never taken
        # 6: nop
        # 7: ret
        # 8: ret
        proj = angr.load_shellcode(b"\x31\xc0\x85\xc0\x75\x02\x90\xc3\xc3", arch="amd64")
        state = proj.factory.blank_state(addr=0, mode="fastpath")
        simgr = proj.factory.simulation_manager(state, save_unsat=True)
        # the slice only contains the infeasible branch
        simgr.use_technique(angr.exploration_techniques.Slicecutor(_FakeAnnotatedCFG({0: [8]}), force_sat=True))
        simgr.step()

        assert not simgr.unsat
        assert [s.addr for s in simgr.active] == [8]
        forced = simgr.active[0]
        assert forced.satisfiable()
        assert not forced.solver.constraints


if __name__ == "__main__":
    unittest.main()
