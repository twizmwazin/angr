from __future__ import annotations

import pickle
import unittest

from angr import claripy

# Solver flavours backed by Z3 whose constructor takes a timeout.
Z3_SOLVERS = (
    claripy.Solver,
    claripy.SolverCacheless,
    claripy.SolverHybrid,
    claripy.SolverComposite,
)

# Two primes just below 2**28. Factoring their product takes Z3 on the order of
# a hundred milliseconds: far longer than a 1 ms timeout, yet quick without one.
P = 268435367
Q = 268435399


def factoring_problem(name):
    """Constraints whose only solution is x == P, y == Q, and the variable x."""
    x = claripy.BVS(f"{name}_x", 28)
    y = claripy.BVS(f"{name}_y", 28)
    return x, [x.zero_extend(28) * y.zero_extend(28) == P * Q, x > 1, y > 1, x <= y]


class TestSolverTimeoutSetter(unittest.TestCase):
    """Assigning Solver.timeout reconfigures the live backend solver."""

    def test_setter_applies_to_fresh_solver(self):
        for cls in Z3_SOLVERS:
            with self.subTest(solver=cls.__name__):
                s = cls()
                self.assertIsNone(s.timeout)
                s.timeout = 1
                self.assertEqual(s.timeout, 1)
                _, constraints = factoring_problem(f"fresh_{cls.__name__}")
                s.add(constraints)
                with self.assertRaises(claripy.ClaripySolverInterruptError):
                    s.satisfiable()

    def test_setter_applies_to_solver_in_use(self):
        """The timeout reaches a backend solver that has already been built and queried."""
        for cls in Z3_SOLVERS:
            with self.subTest(solver=cls.__name__):
                x, constraints = factoring_problem(f"used_{cls.__name__}")
                s = cls()
                s.add(x != 0)
                self.assertTrue(s.satisfiable())
                s.timeout = 1
                s.add(constraints)
                with self.assertRaises(claripy.ClaripySolverInterruptError):
                    s.satisfiable()
                with self.assertRaises(claripy.ClaripySolverInterruptError):
                    s.satisfiable(extra_constraints=[x != 5])

    def test_setter_applies_to_min_max(self):
        for cls in Z3_SOLVERS:
            with self.subTest(solver=cls.__name__):
                x, constraints = factoring_problem(f"minmax_{cls.__name__}")
                s = cls()
                s.add(constraints)
                s.timeout = 1
                with self.assertRaises(claripy.ClaripySolverInterruptError):
                    s.min(x)
                with self.assertRaises(claripy.ClaripySolverInterruptError):
                    s.max(x, signed=True)

    def test_composite_children_created_later_inherit_timeout(self):
        a = claripy.BVS("composite_a", 8)
        s = claripy.SolverComposite()
        s.add(a == 3)
        self.assertTrue(s.satisfiable())
        s.timeout = 1
        # Independent of `a`, so these constraints go to a new child solver.
        x, constraints = factoring_problem("composite_late")
        s.add(constraints)
        with self.assertRaises(claripy.ClaripySolverInterruptError):
            s.eval(x, 1)

    def test_timeout_can_be_cleared_and_raised(self):
        for cls in Z3_SOLVERS:
            for relaxed in (None, 600_000):
                with self.subTest(solver=cls.__name__, timeout=relaxed):
                    _, constraints = factoring_problem(f"clear_{cls.__name__}_{relaxed}")
                    s = cls(timeout=1)
                    s.add(constraints)
                    with self.assertRaises(claripy.ClaripySolverInterruptError):
                        s.satisfiable()
                    s.timeout = relaxed
                    self.assertEqual(s.timeout, relaxed)
                    self.assertTrue(s.satisfiable())

    def test_derived_solvers_keep_timeout(self):
        for cls in Z3_SOLVERS:
            with self.subTest(solver=cls.__name__):
                _, constraints = factoring_problem(f"derived_{cls.__name__}")
                s = cls()
                s.add(constraints)
                s.timeout = 1
                derived = {
                    "branch": s.branch(),
                    "pickle": pickle.loads(pickle.dumps(s)),
                }
                blank = s.blank_copy()
                blank.add(constraints)
                derived["blank_copy"] = blank
                for how, d in derived.items():
                    with self.subTest(how=how):
                        self.assertEqual(d.timeout, 1)
                        with self.assertRaises(claripy.ClaripySolverInterruptError):
                            d.satisfiable()

    def test_solvers_without_z3_accept_timeout(self):
        for cls in (claripy.SolverConcrete, claripy.SolverVSA):
            with self.subTest(solver=cls.__name__):
                s = cls()
                s.timeout = 5
                self.assertEqual(s.timeout, 5)
                self.assertEqual(s.eval(claripy.BVV(7, 8), 1), [7])

    def test_replacement_solver_setter(self):
        s = claripy.SolverReplacement(auto_replace=False)
        s.timeout = 1
        self.assertEqual(s.timeout, 1)
        _, constraints = factoring_problem("replacement")
        s.add(constraints)
        with self.assertRaises(claripy.ClaripySolverInterruptError):
            s.satisfiable()


if __name__ == "__main__":
    unittest.main()
