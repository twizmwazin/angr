#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

from unittest import TestCase, main

from angr import claripy
from angr.claripy.vsa import mv_eval, mv_eval_one, mv_segments


def bvv(value: int, bits: int) -> claripy.ast.BV:
    return claripy.BVV(value, bits)


class TestMultiValue(TestCase):
    def test_single_value(self):
        v = bvv(0x1338133813371337, 64)
        assert mv_eval_one(v) is v
        assert mv_eval(v) == (v,)
        assert mv_segments(v) == [(0, (v,))]

    def test_symbolic_single_value(self):
        x = claripy.BVS("x", 32)
        assert mv_eval_one(x + 4) is not None
        assert mv_eval(claripy.Concat(x, x)) is not None
        assert mv_eval_one(claripy.Concat(claripy.union(bvv(1, 32), x), x)) is None

    def test_union_under_operation(self):
        x = claripy.BVS("x", 32)
        mv = claripy.union(bvv(1, 32), x)
        assert mv_eval_one(mv + 2) is None
        assert set(mv_eval(mv + 2)) == {bvv(3, 32), x + 2}
        assert mv_eval_one(mv - mv).concrete_value == 0

    def test_alternatives(self):
        a, b = bvv(1, 32), bvv(2, 32)
        mv = claripy.union(a, b)
        assert mv_eval_one(mv) is None
        assert set(mv_eval(mv)) == {a, b}
        assert len(mv) == 32
        assert claripy.union(a, a) is a

    def test_segments_round_trip(self):
        x = claripy.BVS("x", 32)
        mv = claripy.Concat(claripy.union(bvv(0, 32), x), bvv(1, 32), bvv(2, 32))
        assert len(mv) == 96
        assert mv_eval(mv) is None
        # adjacent single-valued pieces are joined
        segments = mv_segments(mv)
        assert [off for off, _ in segments] == [0, 4]
        assert set(segments[0][1]) == {bvv(0, 32), x}
        assert segments[1][1] == (bvv(0x100000002, 64),)

    def test_segments_with_a_leading_zero_piece(self):
        # Concat(0, MultiValue(..)) simplifies to ZeroExt(MultiValue(..))
        mv = claripy.Concat(bvv(0, 32), claripy.union(bvv(1, 32), bvv(2, 32)))
        segments = mv_segments(mv)
        assert [off for off, _ in segments] == [0, 4]
        assert set(segments[1][1]) == {bvv(1, 32), bvv(2, 32)}

    def test_merge(self):
        a, b, c = bvv(1, 32), bvv(2, 32), bvv(3, 32)
        assert set(mv_eval(claripy.union(claripy.union(a, b), c))) == {a, b, c}

        # merging values made of pieces keeps the bytes of each value together
        lhs = claripy.Concat(claripy.union(bvv(0x11, 8), bvv(0x12, 8)), bvv(0x22, 8))
        rhs = bvv(0x3344, 16)
        merged = claripy.union(lhs, rhs)
        assert {v.concrete_value for v in mv_eval(merged)} == {0x1122, 0x1222, 0x3344}

    def test_extract(self):
        x = claripy.BVS("x", 16)
        mv = claripy.Concat(claripy.union(bvv(0x1122, 16), x), bvv(0x3344, 16))
        # claripy.Extract keeps the alternatives of the piece it slices
        middle = claripy.Extract(23, 8, mv)
        assert len(middle) == 16
        segments = mv_segments(middle)
        assert [off for off, _ in segments] == [0, 1]
        assert set(segments[0][1]) == {bvv(0x22, 8), x[7:0]}
        assert segments[1][1] == (bvv(0x33, 8),)
        assert claripy.Extract(15, 0, mv) is bvv(0x3344, 16)


if __name__ == "__main__":
    main()
