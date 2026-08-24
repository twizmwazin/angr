#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.state_plugins"  # pylint:disable=redefined-builtin

import unittest

import claripy

import angr


class TestPreconstrainer(unittest.TestCase):
    """Regression tests for angr/angr#1338: a constraint asserted by both the program and the
    preconstrainer must survive remove_preconstraints()."""

    def _forced(self, state, var, value):
        return not state.solver.satisfiable(extra_constraints=[var != value])

    def test_program_constraint_added_before_preconstraint(self):
        state = angr.SimState(arch="AMD64", mode="symbolic")
        var = claripy.BVS("x", 64)
        value = claripy.BVV(0x1337, 64)

        state.add_constraints(var == value)
        state.preconstrainer.preconstrain(value, var)
        state.add_constraints(var == value)
        state.preconstrainer.remove_preconstraints()

        assert state.satisfiable()
        assert self._forced(state, var, value)

    def test_program_constraint_added_after_preconstraint(self):
        state = angr.SimState(arch="AMD64", mode="symbolic")
        var = claripy.BVS("x", 64)
        value = claripy.BVV(0x1337, 64)

        state.preconstrainer.preconstrain(value, var)
        state.add_constraints(var == value)
        state.preconstrainer.remove_preconstraints()

        assert state.satisfiable()
        assert self._forced(state, var, value)

    def test_preconstraint_without_program_constraint_is_removed(self):
        state = angr.SimState(arch="AMD64", mode="symbolic")
        var = claripy.BVS("x", 64)
        value = claripy.BVV(0x1337, 64)

        state.preconstrainer.preconstrain(value, var)
        assert self._forced(state, var, value)
        state.preconstrainer.remove_preconstraints()

        assert state.satisfiable()
        assert not self._forced(state, var, value)


if __name__ == "__main__":
    unittest.main()
