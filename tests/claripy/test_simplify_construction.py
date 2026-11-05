from __future__ import annotations

import unittest

from angr import claripy


class TestSimplifyConstruction(unittest.TestCase):
    """AST-building entry points that bind their operation result before
    wrapping it (`chop`, `Concat`) simplify it, so a concrete result is folded
    and interned rather than returned as a raw `Extract`/`Concat`."""

    def test_concat_of_concrete_folds(self):
        c = claripy.Concat(claripy.BVV(0, 32), claripy.BVV(0x1337, 32))
        self.assertEqual(c.op, "BVV")
        self.assertEqual(c.concrete_value, 0x1337)
        # interned: equal to the directly-built constant
        self.assertIs(c, claripy.BVV(0x1337, 64))

    def test_chop_of_concrete_folds(self):
        bytes_ = claripy.BVV(0x41424344, 32).chop(8)
        self.assertEqual([b.op for b in bytes_], ["BVV"] * 4)
        self.assertEqual([b.concrete_value for b in bytes_], [0x41, 0x42, 0x43, 0x44])

    def test_chop_isolates_concrete_from_symbolic(self):
        # The concrete high half must come back concrete even when concatenated
        # with a symbolic low half (the chopped pieces are simplified).
        v = claripy.Concat(claripy.BVV(0xAABBCCDD, 32), claripy.BVS("s", 32))
        hi = v.chop(8)[0]
        self.assertFalse(hi.symbolic)
        self.assertEqual(hi.concrete_value, 0xAA)


class TestAddSubConstantFolding(unittest.TestCase):
    """Folding a constant into a (const - x) operand must keep x negated."""

    def test_const_plus_const_minus_sym(self):
        x = claripy.BVS("x", 32)
        for expr in (claripy.BVV(10, 32) + (claripy.BVV(3, 32) - x), (claripy.BVV(3, 32) - x) + claripy.BVV(10, 32)):
            self.assertEqual(expr.op, "__sub__")
            self.assertIs(expr.args[1], x)
            self.assertEqual(expr.args[0].concrete_value, 13)
            s = claripy.Solver()
            s.add(x == 4)
            self.assertEqual(list(s.eval(expr, 1)), [9])


class TestNarySub(unittest.TestCase):
    def test_sub_takes_many_operands(self):
        x = claripy.BVS("x", 32)
        y = claripy.BVS("y", 32)
        z = claripy.BVS("z", 32)
        expr = claripy.Sub(x, y, z)
        self.assertEqual(expr.op, "__sub__")
        self.assertEqual(expr.args, (x, y, z))
        self.assertEqual(repr(expr), f"<BV32 {x.args[0]} - {y.args[0]} - {z.args[0]}>")

        s = claripy.Solver()
        s.add(claripy.And(x == 10, y == 3, z == 4))
        self.assertEqual(list(s.eval(expr, 1)), [3])

    def test_nested_sub_flattens(self):
        x = claripy.BVS("x", 32)
        y = claripy.BVS("y", 32)
        z = claripy.BVS("z", 32)
        self.assertIs((x - y) - z, claripy.Sub(x, y, z))
        # x - (y + z) spreads over the sum
        self.assertIs(x - (y + z), claripy.Sub(x, y, z))
        # the right-hand side of a subtraction is not flattened: x - (y - z) == x - y + z
        expr = x - (y - z)
        self.assertEqual(expr.args, (x, y - z))

    def test_subtracted_constants_fold_into_one_trailing_term(self):
        x = claripy.BVS("x", 32)
        y = claripy.BVS("y", 32)
        expr = x - 3 - y - 4
        self.assertEqual(expr.op, "__sub__")
        self.assertEqual(expr.args[:2], (x, y))
        self.assertEqual(expr.args[2].concrete_value, 7)

        # a constant on the positive side absorbs the subtracted ones
        expr = (x + 10) - y - 4
        self.assertEqual(expr.op, "__sub__")
        self.assertEqual(len(expr.args), 2)
        self.assertEqual(expr.args[0].op, "__add__")
        self.assertEqual(expr.args[0].args[1].concrete_value, 6)
        self.assertIs(expr.args[1], y)

    def test_concrete_sub_folds(self):
        self.assertEqual(claripy.Sub(claripy.BVV(100, 32), 30, 20).concrete_value, 50)
        self.assertEqual(claripy.Sub(claripy.BVV(0, 32), 1, 1).concrete_value, 0xFFFFFFFE)

    def test_sub_round_trips_through_z3(self):
        x = claripy.BVS("x", 32)
        y = claripy.BVS("y", 32)
        z = claripy.BVS("z", 32)
        s = claripy.Solver()
        s.add(claripy.And(claripy.Sub(x, y, z) == 5, y == 1, z == 2))
        self.assertEqual(list(s.eval(x, 1)), [8])
