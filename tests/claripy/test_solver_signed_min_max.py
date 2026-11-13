from __future__ import annotations

import unittest

from angr import claripy


class TestSolverSignedMinMax(unittest.TestCase):
    def test_negative_range(self):
        x = claripy.BVS("x", 8)
        s = claripy.Solver()
        s.add(x.SLT(0))
        self.assertEqual(s.min(x, signed=True), -128)
        self.assertEqual(s.max(x, signed=True), -1)
        self.assertEqual(s.min(x), 128)
        self.assertEqual(s.max(x), 255)

    def test_mixed_sign_range_wider_than_64_bits(self):
        x = claripy.BVS("x", 128)
        s = claripy.Solver()
        s.add(x.SGE(-(2**100)))
        s.add(x.SLE(7))
        self.assertEqual(s.min(x, signed=True), -(2**100))
        self.assertEqual(s.max(x, signed=True), 7)


if __name__ == "__main__":
    unittest.main()
