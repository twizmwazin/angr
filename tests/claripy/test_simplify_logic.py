from __future__ import annotations

import itertools
import unittest

from angr import claripy


class TestSimplifyLogic(unittest.TestCase):
    def setUp(self):
        self.x, self.y, self.z = (claripy.BoolS(name, explicit_name=True) for name in "xyz")

    def assert_equivalent(self, a, b):
        s = claripy.Solver()
        s.add(a != b)
        self.assertFalse(s.satisfiable())

    def test_merges_minterms(self):
        x, y, z = self.x, self.y, self.z
        expr = claripy.Or(
            claripy.And(claripy.Not(x), claripy.Not(y), claripy.Not(z)),
            claripy.And(claripy.Not(x), claripy.Not(y), z),
        )
        self.assertIs(claripy.simplify_logic(expr), claripy.And(claripy.Not(x), claripy.Not(y)))

    def test_absorption(self):
        x, y, z = self.x, self.y, self.z
        self.assertIs(claripy.simplify_logic(claripy.Or(x, claripy.And(x, y, z))), x)
        self.assertIs(claripy.simplify_logic(claripy.And(claripy.Or(x, y), claripy.Or(x, claripy.Not(y)))), x)

    def test_constants(self):
        x, y = self.x, self.y
        self.assertTrue(
            claripy.is_true(claripy.simplify_logic(claripy.Or(x, claripy.And(claripy.Not(x), y), claripy.Not(y))))
        )
        self.assertTrue(
            claripy.is_false(claripy.simplify_logic(claripy.And(claripy.Or(x, y), claripy.Not(x), claripy.Not(y))))
        )
        self.assertIs(claripy.simplify_logic(x), x)

    def test_unifies_comparisons(self):
        a, b = claripy.BVS("a", 32), claripy.BVS("b", 32)
        self.assertTrue(claripy.is_true(claripy.simplify_logic(claripy.Or(a.UGT(b), a.ULE(b)))))
        self.assertTrue(claripy.is_true(claripy.simplify_logic(claripy.Or(a.SGE(b), a.SLT(b)))))
        expr = claripy.Or(claripy.And(a != b, a.UGT(b)), claripy.And(a == b, a.UGT(b)))
        self.assertIs(claripy.simplify_logic(expr), a.UGT(b))

    def test_predicate_limit(self):
        x, y, z = self.x, self.y, self.z
        expr = claripy.Or(x, claripy.And(x, y, z))
        self.assertIs(claripy.simplify_logic(expr, max_predicates=3), x)
        self.assertIs(claripy.simplify_logic(expr, max_predicates=2), expr)

    def test_preserves_meaning(self):
        x, y, z = self.x, self.y, self.z
        literals = [x, y, z, claripy.Not(x), claripy.Not(y), claripy.Not(z)]
        for a, b, c in itertools.combinations(literals, 3):
            for expr in (
                claripy.Or(claripy.And(a, b), claripy.And(b, c), claripy.And(a, c)),
                claripy.And(claripy.Or(a, b), claripy.Or(claripy.Not(b), c)),
            ):
                self.assert_equivalent(claripy.simplify_logic(expr), expr)

    def test_rejects_non_bool(self):
        with self.assertRaises(TypeError):
            claripy.simplify_logic(claripy.BVS("a", 32))


if __name__ == "__main__":
    unittest.main()
