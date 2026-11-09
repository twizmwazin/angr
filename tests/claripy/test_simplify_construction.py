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


class TestSubAsAdd(unittest.TestCase):
    """Subtraction is simplified as addition of negated terms, so opposing terms of a sum
    cancel, and the result is expressed as a subtraction again."""

    def test_opposing_terms_cancel(self):
        x = claripy.BVS("x", 32)
        y = claripy.BVS("y", 32)
        self.assertIs((x + y) - x, y)
        self.assertIs((x - y) + y, x)
        self.assertIs(x - (x - y), y)
        self.assertEqual((x + -x).concrete_value, 0)
        self.assertEqual(((x + 5) - (x + 3)).concrete_value, 2)

    def test_result_is_a_subtraction(self):
        x = claripy.BVS("x", 32)
        y = claripy.BVS("y", 32)
        z = claripy.BVS("z", 32)
        self.assertIs(x + -y, x - y)
        self.assertIs(-y + x, x - y)
        self.assertIs(x + claripy.BVV(0xFFFFFFFB, 32), x - 5)
        self.assertIs(x - y - z, x - (y + z))
        self.assertEqual((x - y).op, "__sub__")
        self.assertEqual((x - 5).args[1].concrete_value, 5)
