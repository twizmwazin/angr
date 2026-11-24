#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,no-member
from __future__ import annotations

import pickle
import unittest

from angr import ailment, claripy
from angr.rustylib import FPRM  # pylint:disable=import-error,no-name-in-module
from angr.rustylib.ailment import RoundingMode  # pylint:disable=import-error,no-name-in-module

MODES = {
    "RM_NearestTiesEven": 0,
    "RM_TowardsNegativeInf": 1,
    "RM_TowardsPositiveInf": 2,
    "RM_TowardsZero": 3,
    "RM_NearestTiesAwayFromZero": 4,
}


class TestFPRM(unittest.TestCase):
    def test_claripy_and_ailment_share_one_type(self):
        assert claripy.fp.RM is FPRM
        assert RoundingMode is FPRM

    def test_values_follow_vex(self):
        for name, value in MODES.items():
            rm = getattr(FPRM, name)
            assert rm.name == name
            assert rm.value == value
            assert int(rm) == value
            assert rm == value
            assert hash(rm) == hash(value)
            assert FPRM._from_int_py(value) == rm  # pylint:disable=protected-access
        with self.assertRaises(ValueError):
            FPRM._from_int_py(5)  # pylint:disable=protected-access

    def test_default(self):
        assert FPRM.default() == FPRM.RM_NearestTiesEven

    def test_pickle(self):
        for name in MODES:
            rm = getattr(FPRM, name)
            assert pickle.loads(pickle.dumps(rm)) == rm

    def test_one_value_in_both_asts(self):
        for name in MODES:
            rm = getattr(FPRM, name)
            x = claripy.FPS("x", claripy.FSORT_DOUBLE)
            assert claripy.fpAdd(rm, x, x).args[-1] == rm

            operand = ailment.Expr.Const(None, 0, 64)
            conv = ailment.Expr.Convert(
                None,
                64,
                32,
                True,
                operand,
                from_type=ailment.Expr.Convert.TYPE_FP,
                to_type=ailment.Expr.Convert.TYPE_INT,
                rounding_mode=rm,
            )
            assert conv.rounding_mode == rm
            assert pickle.loads(pickle.dumps(conv)).rounding_mode == rm


if __name__ == "__main__":
    unittest.main()
