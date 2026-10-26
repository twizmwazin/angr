from __future__ import annotations

from typing import cast

from archinfo import Endness

import angr
from angr import ailment, claripy
from angr.analyses.reaching_definitions.engine_ail import SimEngineRDAIL
from angr.analyses.reaching_definitions.function_handler import FunctionHandler
from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState


class _ConstantState:
    class _CodeLocation:
        context = None

    codeloc = _CodeLocation()

    @staticmethod
    def mark_const(_value: int, _size: int) -> None:
        pass

    @staticmethod
    def top(bits: int) -> claripy.ast.BV:
        return claripy.BVS("TOP", bits)

    @staticmethod
    def annotate_with_def(value: claripy.ast.BV, _definition) -> claripy.ast.BV:
        return value

    @staticmethod
    def add_memory_use_by_def(_definition, *, expr) -> None:
        pass


def _engine() -> SimEngineRDAIL:
    project = angr.load_shellcode(b"\xc3", arch="amd64")
    engine = SimEngineRDAIL(project, FunctionHandler())
    engine.state = cast(ReachingDefinitionsState, _ConstantState())
    return engine


def test_convert_handles_operand_width_mismatches():
    engine = _engine()
    base = ailment.Expr.Const(0, 0x0123456789ABCDEF, 64)

    # the operand is 64 bits wide, but the conversion claims to widen a 32-bit value
    widened = ailment.Expr.Convert(1, 32, 64, False, base)
    widened_result = engine._expr(widened)  # pylint: disable=protected-access
    assert len(widened_result) == widened.bits
    widened_value = widened_result.one_value()
    assert widened_value is not None and widened_value.symbolic

    # the operand is 32 bits wide, but the conversion claims to narrow a 64-bit value
    narrowed = ailment.Expr.Convert(2, 64, 32, False, ailment.Expr.Const(3, 1, 32))
    narrowed_result = engine._expr(narrowed)  # pylint: disable=protected-access
    assert len(narrowed_result) == narrowed.bits
    narrowed_value = narrowed_result.one_value()
    assert narrowed_value is not None and narrowed_value.symbolic


def test_extract_and_insert_offsets_follow_the_endness():
    engine = _engine()
    base = ailment.Expr.Const(0, 0x0123456789ABCDEF, 64)

    def evaluate(expr) -> int | None:
        mv = engine._expr(expr)  # pylint: disable=protected-access
        assert len(mv) == expr.bits
        pieces = []
        for _, values in sorted(mv.items()):
            if len(values) != 1:
                return None
            pieces.append(next(iter(values)))
        value = claripy.Concat(*pieces)
        return value.concrete_value if value.concrete else None

    # Iend_LE counts bytes from the least significant end
    assert evaluate(ailment.Expr.Extract(1, 32, base, ailment.Expr.Const(2, 0, 64), Endness.LE)) == 0x89ABCDEF
    assert evaluate(ailment.Expr.Extract(3, 16, base, ailment.Expr.Const(4, 1, 64), Endness.LE)) == 0xABCD
    # Iend_BE counts bytes from the most significant end
    assert evaluate(ailment.Expr.Extract(5, 16, base, ailment.Expr.Const(6, 1, 64), Endness.BE)) == 0x2345

    assert (
        evaluate(ailment.Expr.Insert(7, base, ailment.Expr.Const(8, 0, 64), ailment.Expr.Const(9, 0x11, 8), Endness.LE))
        == 0x0123456789ABCD11
    )
    assert (
        evaluate(
            ailment.Expr.Insert(10, base, ailment.Expr.Const(11, 1, 64), ailment.Expr.Const(12, 0xAA, 8), Endness.BE)
        )
        == 0x01AA456789ABCDEF
    )

    # a slice running past the end of the base is unknown
    assert evaluate(ailment.Expr.Extract(13, 32, base, ailment.Expr.Const(14, 6, 64), Endness.LE)) is None
    assert (
        evaluate(
            ailment.Expr.Insert(15, base, ailment.Expr.Const(16, 7, 64), ailment.Expr.Const(17, 0, 16), Endness.LE)
        )
        is None
    )
