from __future__ import annotations

import unittest

from angr import claripy


class TestUnsatCore(unittest.TestCase):
    def assertCore(self, core, expected):
        self.assertEqual(sorted(hash(c) for c in core), sorted(hash(c) for c in expected), (core, expected))

    def test_unsat_core_simple(self):
        """Test basic unsat core functionality"""
        # Create a solver with unsat_core enabled
        s = claripy.Solver(track=True)

        x = claripy.BVS("x", 8)

        gt = x > 10
        lt = x < 5
        s.add(gt)
        s.add(lt)
        s.add(x > 0)

        self.assertFalse(s.satisfiable())
        self.assertCore(s.unsat_core(), [gt, lt])

    def test_unsat_core_bool(self):
        """Test unsat core with boolean constraints"""
        s = claripy.Solver(track=True)

        a = claripy.BoolS("a")
        b = claripy.BoolS("b")

        # Add contradictory constraints
        s.add(a == b)
        s.add(a)
        s.add(claripy.Not(b))

        # Should be unsat
        self.assertFalse(s.satisfiable())

        # Get unsat core - all three constraints are necessary
        core = s.unsat_core()
        self.assertEqual(len(core), 3)
        for c in core:
            self.assertIsInstance(c, claripy.ast.Bool)

    def test_unsat_core_not_enabled(self):
        """Test that unsat_core raises error when not enabled"""
        s = claripy.Solver()  # unsat_core not enabled

        x = claripy.BVS("x", 8)
        s.add(x > 10)
        s.add(x < 5)

        self.assertFalse(s.satisfiable())

        # Should raise an error
        with self.assertRaises(claripy.ClaripyError):
            s.unsat_core()

    def test_unsat_core_on_sat(self):
        """Test that unsat_core raises error on SAT result"""
        s = claripy.Solver(track=True)

        x = claripy.BVS("x", 8)
        s.add(x > 5)

        # Should be sat
        self.assertTrue(s.satisfiable())

        # Should raise an error because it's SAT
        with self.assertRaises(claripy.ClaripyError):
            s.unsat_core()

    def test_unsat_core_complex(self):
        """Test unsat core with more complex constraints"""
        s = claripy.Solver(track=True)

        x = claripy.BVS("x", 32)
        y = claripy.BVS("y", 32)

        # Add various constraints
        total = x + y == 100
        x_big = x > 60
        y_big = y > 50  # makes it unsat with the two above
        s.add(total)
        s.add(x_big)
        s.add(y_big)
        s.add(x < 200)  # not relevant
        s.add(y < 200)  # not relevant

        # Should be unsat (x > 60 and y > 50 means x + y > 110)
        self.assertFalse(s.satisfiable())

        # z3 does not promise a minimal core
        core = {hash(c) for c in s.unsat_core()}
        self.assertTrue({hash(total), hash(x_big), hash(y_big)} <= core)

    def test_unsat_core_with_extra_constraints(self):
        s = claripy.Solver(track=True)
        x = claripy.BVS("x", 8)
        gt = x > 10
        lt = x < 5
        s.add(gt)
        self.assertTrue(s.satisfiable())

        self.assertCore(s.unsat_core(extra_constraints=[x > 0, lt]), [gt, lt])
        self.assertEqual(len(s.constraints), 1)
        self.assertTrue(s.satisfiable())

    def test_unsat_core_with_extra_constraints_as_passed(self):
        """Extras are named as passed, even when the backend sees them simplified."""
        s = claripy.Solver(track=True)
        x = claripy.BVS("x", 8)
        gt = x > 10
        s.add(gt)
        wrapped = claripy.Not(claripy.Not(x < 5))
        self.assertCore(s.unsat_core(extra_constraints=[claripy.true(), wrapped]), [gt, wrapped])

    def test_unsat_core_hybrid(self):
        s = claripy.SolverHybrid(track=True)
        x = claripy.BVS("x", 8)
        gt = x > 10
        lt = x < 5
        s.add(gt)
        s.add(lt)
        self.assertFalse(s.satisfiable())
        self.assertCore(s.unsat_core(), [gt, lt])

    def test_unsat_core_composite(self):
        """SolverComposite returns the core of whichever independent child is unsat."""
        s = claripy.SolverComposite(track=True)

        x = claripy.BVS("x", 8)
        y = claripy.BVS("y", 8)

        gt = x > 10
        lt = x < 5
        s.add(y == 3)
        s.add(gt)
        s.add(lt)

        self.assertFalse(s.satisfiable())
        self.assertCore(s.unsat_core(), [gt, lt])

    def test_unsat_core_composite_on_sat(self):
        """A satisfiable composite solver has an empty unsat core."""
        s = claripy.SolverComposite(track=True)
        x = claripy.BVS("x", 8)
        y = claripy.BVS("y", 8)
        s.add(x > 1)
        s.add(y < 10)
        self.assertTrue(s.satisfiable())
        self.assertEqual(s.unsat_core(), [])

    def test_unsat_core_composite_with_extra_constraints(self):
        x = claripy.BVS("x", 32)
        y = claripy.BVS("y", 32)
        s = claripy.SolverComposite(track=True)
        gt = x > 10
        s.add([y == 3, gt])
        self.assertTrue(s.satisfiable())
        extra = claripy.And(x < 5, y == 3)  # spans both children
        self.assertCore(s.unsat_core(extra_constraints=[extra]), [gt, extra])
        self.assertEqual(len(s.constraints), 2)
        self.assertTrue(s.satisfiable())

    def test_unsat_core_unsupported_solver(self):
        s = claripy.SolverVSA()
        x = claripy.BVS("x", 8)
        s.add(x > 10)
        with self.assertRaises(claripy.ClaripyError):
            s.unsat_core()
