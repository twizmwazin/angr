"""
Tests for the MultiValue operation: a set of alternative values.
"""

from __future__ import annotations

import pickle
import unittest

from angr import claripy


class TagAnnotation(claripy.Annotation):
    """
    A relocatable annotation, like the definition annotations reaching definitions attaches to values.
    """

    relocatable = True
    eliminatable = False

    def __init__(self, tag):
        super().__init__()
        self.tag = tag

    def __hash__(self):
        return hash((TagAnnotation, self.tag))

    def __eq__(self, other):
        return type(other) is TagAnnotation and other.tag == self.tag


class TestMultiValue(unittest.TestCase):
    def test_members_are_canonical(self):
        a, b, x = claripy.BVV(1, 32), claripy.BVV(2, 32), claripy.BVS("x", 32)
        mv = claripy.MultiValue(a, b, x)
        assert mv.op == "MultiValue"
        assert isinstance(mv, claripy.ast.BV)
        assert mv.size() == 32
        assert mv.symbolic
        assert mv is claripy.MultiValue(x, b, a, b)
        assert set(mv.args) == {a, b, x}

    def test_nested_sets_are_flattened(self):
        a, b, c = (claripy.BVV(v, 32) for v in (1, 2, 3))
        assert claripy.MultiValue(claripy.MultiValue(a, b), c) is claripy.MultiValue(a, b, c)

    def test_single_member(self):
        a = claripy.BVV(1, 32)
        assert claripy.MultiValue(a) is a
        assert claripy.MultiValue(a, claripy.BVV(1, 32)) is a
        # members that simplify to the same value collapse too
        assert claripy.MultiValue(a, claripy.BVV(0, 32) + 1) is a

    def test_invalid_members(self):
        with self.assertRaises(claripy.ClaripyError):
            claripy.MultiValue()
        with self.assertRaises(claripy.ClaripyError):
            claripy.MultiValue(claripy.BVV(1, 32), claripy.BVV(1, 8))
        with self.assertRaises(claripy.ClaripyError):
            claripy.MultiValue(claripy.BVV(1, 32), claripy.FPV(1.0, claripy.FSORT_FLOAT))
        with self.assertRaises(claripy.ClaripyError):
            claripy.MultiValue(claripy.true(), claripy.false())

    def test_float_members(self):
        mv = claripy.MultiValue(claripy.FPV(1.0, claripy.FSORT_DOUBLE), claripy.FPV(2.0, claripy.FSORT_DOUBLE))
        assert isinstance(mv, claripy.ast.FP)
        assert mv.op == "MultiValue"

    def test_member_annotations_stay_on_members(self):
        tag = TagAnnotation("a")
        a = claripy.BVS("a", 32).annotate(tag)
        mv = claripy.MultiValue(a, claripy.BVS("b", 32))
        assert not mv.annotations
        assert not (mv + 1).annotations

    def test_excavate(self):
        x = claripy.BVS("x", 32)
        mv = claripy.MultiValue(claripy.BVV(1, 32), x)
        values = claripy.excavate_multi_value(mv + 2)
        assert set(values) == {claripy.BVV(3, 32), x + 2}

        # every occurrence of one set takes the same choice
        assert claripy.excavate_multi_value(mv - mv) == [claripy.BVV(0, 32)]

        # distinct sets are independent
        other = claripy.MultiValue(claripy.BVV(10, 32), claripy.BVV(20, 32))
        assert len(claripy.excavate_multi_value(mv + other)) == 4
        assert claripy.excavate_multi_value(mv + other, limit=3) is None

        # an expression without a set expands to itself
        assert claripy.excavate_multi_value(x + 1) == [x + 1]

    def test_excavate_keeps_member_annotations(self):
        tag = TagAnnotation("a")
        a = claripy.BVS("a", 32).annotate(tag)
        mv = claripy.MultiValue(a, claripy.BVS("b", 32))
        values = claripy.excavate_multi_value(mv + 1)
        assert sorted(tag in v.annotations for v in values) == [False, True]

    def test_vsa(self):
        mv = claripy.MultiValue(claripy.BVV(2, 32), claripy.BVV(4, 32), claripy.BVV(6, 32))
        assert claripy.vsa.min(mv) == 2
        assert claripy.vsa.max(mv + 1) == 7
        assert sorted(claripy.vsa.eval(mv, 10)) == [2, 4, 6]

    def test_z3_rejects(self):
        mv = claripy.MultiValue(claripy.BVV(1, 32), claripy.BVV(2, 32))
        with self.assertRaises(claripy.ClaripyError):
            claripy.Solver().eval(mv, 2)

    def test_pickle(self):
        tag = TagAnnotation("a")
        mv = claripy.MultiValue(claripy.BVS("a", 32).annotate(tag), claripy.BVV(1, 32))
        assert pickle.loads(pickle.dumps(mv)) is mv


if __name__ == "__main__":
    unittest.main()
