from __future__ import annotations

from angr.ailment.expression import BinaryOp, Const

from .base import PeepholeOptimizationExprBase


class CmpSubZero(PeepholeOptimizationExprBase):
    """
    Rewrite an equality test of a difference against zero into a direct comparison::

        (A - B) == 0    ==>  A == B
        (A - B) != 0    ==>  A != B

    Over the modular integers ``Z/2^n``, ``A - B == 0`` iff ``A == B``, so this holds for any width,
    independent of signedness, and regardless of whether the subtraction wraps around. Ordered
    comparisons are not folded across the subtraction because it can overflow, and floating-point
    subtraction is excluded because ``inf - inf`` is NaN. Subtractions against a constant are left to
    :class:`CmpSubConst`, which folds the constant into the compared value instead.
    """

    __slots__ = ()

    NAME = "(A - B) == 0 => A == B"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, **kwargs):
        if expr.op not in ("CmpEQ", "CmpNE"):
            return None

        op0, op1 = expr.operands
        if isinstance(op0, BinaryOp) and isinstance(op1, Const) and op1.is_int and op1.value_int == 0:
            sub = op0
        elif isinstance(op1, BinaryOp) and isinstance(op0, Const) and op0.is_int and op0.value_int == 0:
            sub = op1
        else:
            return None

        if sub.op != "Sub" or sub.floating_point or sub.vector_count is not None:
            return None

        a, b = sub.operands
        if isinstance(a, Const) or isinstance(b, Const):
            return None
        # a narrowing Sub would only tell us that the low sub.bits of A and B agree
        if a.bits != b.bits or a.bits != sub.bits:
            return None

        return BinaryOp(
            expr.idx,
            expr.op,
            (a, b),
            expr.signed,
            bits=expr.bits,
            floating_point=expr.floating_point,
            rounding_mode=expr.rounding_mode,
            **expr.tags,
        )
