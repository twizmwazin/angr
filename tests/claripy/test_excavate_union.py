"""
Tests for excavate_union: expanding the Unions in an expression into the values it can take.
"""

from __future__ import annotations

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


class TestExcavateUnion(unittest.TestCase):
    def test_excavate(self):
        x = claripy.BVS("x", 32)
        mv = claripy.union(claripy.BVV(1, 32), x)
        values = claripy.excavate_union(mv + 2)
        assert set(values) == {claripy.BVV(3, 32), x + 2}

        # every occurrence of one set takes the same choice
        assert claripy.excavate_union(mv - mv) == [claripy.BVV(0, 32)]

        # distinct sets are independent
        other = claripy.union(claripy.BVV(10, 32), claripy.BVV(20, 32))
        assert len(claripy.excavate_union(mv + other)) == 4
        assert claripy.excavate_union(mv + other, limit=3) is None

        # an expression without a set expands to itself
        assert claripy.excavate_union(x + 1) == [x + 1]

    def test_excavate_keeps_member_annotations(self):
        tag = TagAnnotation("a")
        a = claripy.BVS("a", 32).annotate(tag)
        mv = claripy.union(a, claripy.BVS("b", 32))
        values = claripy.excavate_union(mv + 1)
        (from_a,) = (v for v in values if "a" in {name.split("_")[0] for name in v.variables})
        assert tag in from_a.annotations


if __name__ == "__main__":
    unittest.main()
