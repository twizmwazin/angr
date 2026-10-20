from __future__ import annotations

import pickle
import unittest

from angr import claripy


class TestSIOp(unittest.TestCase):
    def test_si_is_an_op_not_an_annotation(self):
        si = claripy.SI(bits=32, stride=4, lower_bound=8, upper_bound=24)

        self.assertEqual(si.op, "SI")
        self.assertEqual(si.args, ("SI32_4_8_24", 32, 4, 8, 24))
        self.assertEqual(len(si.annotations), 0)
        self.assertTrue(si.symbolic)
        self.assertEqual(si.variables, frozenset({"SI32_4_8_24"}))

    def test_unnamed_si_is_named_after_its_bounds(self):
        a = claripy.SI(bits=32, stride=1, lower_bound=0, upper_bound=10)
        b = claripy.SI(bits=32, stride=1, lower_bound=0, upper_bound=10)
        self.assertIs(a, b)

    def test_named_si(self):
        a = claripy.SI(32, 1, 0, 10, name="bound")
        b = claripy.SI(32, 1, 0, 10, name="bound")
        self.assertIsNot(a, b)
        self.assertTrue(a.args[0].startswith("bound_"))

        explicit = claripy.SI(32, 1, 0, 10, name="bound", explicit_name=True)
        self.assertEqual(explicit.args[0], "bound")

    def test_negative_bounds_wrap(self):
        si = claripy.SI(bits=8, stride=1, lower_bound=-2, upper_bound=-1)
        self.assertEqual(si.args[3:], (0xFE, 0xFF))

    def test_esi(self):
        esi = claripy.ESI(32)
        self.assertEqual(esi.op, "SI")
        self.assertEqual(esi.args, ("ESI32", 32, None, None, None))
        self.assertEqual(claripy.vsa.cardinality(esi), 0)

    def test_vsa_reads_the_bounds(self):
        si = claripy.SI(32, 2, 10, 20, name="x")
        self.assertEqual(claripy.vsa.min(si), 10)
        self.assertEqual(claripy.vsa.max(si), 20)
        self.assertEqual(claripy.vsa.cardinality(si), 6)

        reduced = claripy.vsa.simplify(si + 1)
        self.assertEqual(reduced.op, "SI")
        self.assertEqual(reduced.args[1:], (32, 2, 11, 21))

    def test_reconstruct_from_op_and_args(self):
        for si in (claripy.SI(32, 2, 10, 20, name="x"), claripy.ESI(16)):
            with self.subTest(si=si):
                self.assertIs(claripy.ast.BV(si.op, si.args), si)
                self.assertIs(pickle.loads(pickle.dumps(si)), si)

    def test_annotations_stack_on_si(self):
        si = claripy.SI(32, 1, 0, 10, name="x").annotate(claripy.UninitializedAnnotation())
        self.assertEqual(si.op, "SI")
        self.assertTrue(si.has_annotation_type(claripy.UninitializedAnnotation))
        self.assertEqual(claripy.vsa.max(si), 10)


if __name__ == "__main__":
    unittest.main()
