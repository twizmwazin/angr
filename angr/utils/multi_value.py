"""
Helpers for values that may stand for several alternatives.

Static analyses (reaching definitions, variable recovery, ...) track every value a register, temporary or memory location
may hold as a single claripy bitvector. A value with several alternatives is a ``Union`` (``claripy.union``); a value
whose bytes have independently tracked alternatives is a ``Concat`` of such pieces, the most significant piece first:

* ``x``: a single value (no ``Union`` anywhere in it);
* ``Union(a, b)``: either ``a`` or ``b``, which are single values of the same size;
* ``Concat(Union(a, b), c)``: the high bytes are ``a`` or ``b``, the low bytes are ``c``.

The functions here read and build values of these shapes. Values are always bitvectors: floating-point values are
stored as their IEEE bit patterns. Byte offsets count from the most significant byte, and a byte is always 8 bits wide.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping

from angr import claripy

# How many values to expand a piece holding Unions into, before treating it as opaque.
EXCAVATE_LIMIT = 256


def mv_one_value(value: claripy.ast.BV, strip_annotations: bool = False) -> claripy.ast.BV | None:
    """
    The single value a value stands for, or None.

    :param strip_annotations:   Also accept alternatives that only differ in their annotations, returning the
                                alternative without annotations.
    """
    values = mv_values(value)
    if values is None:
        return None
    if len(values) == 1:
        return values[0]
    if strip_annotations:
        stripped = {v.clear_annotations() if v.annotations else v for v in values}
        if len(stripped) == 1:
            return next(iter(stripped))
    return None


def mv_values(value: claripy.ast.BV) -> tuple[claripy.ast.BV, ...] | None:
    """
    The alternatives of a value that is a single piece, or None for a value made of several independently tracked
    pieces.
    """
    segments = mv_segments(value)
    return segments[0][1] if len(segments) == 1 else None


def mv_segments(value: claripy.ast.BV, join: bool = True) -> list[tuple[int, tuple[claripy.ast.BV, ...]]]:
    """
    The pieces of a value as ``(byte offset, alternatives)`` pairs, ordered by offset.

    :param join:    Join adjacent single-valued pieces into one.
    """
    if not value.symbolic:
        return [(0, (value,))]
    segments: list[tuple[int, tuple[claripy.ast.BV, ...]]] = []
    offset = 0
    pending: list[claripy.ast.BV] = []  # adjacent single-valued pieces not yet added
    pending_offset = 0

    def flush():
        if pending:
            segments.append((pending_offset, (pending[0] if len(pending) == 1 else claripy.Concat(*pending),)))
            pending.clear()

    # split the value into the pieces its alternatives are tracked in, most significant first
    stack = [value]
    while stack:
        piece = stack.pop()
        if piece.op == "Concat":
            stack.extend(reversed(piece.args))
            continue
        if piece.op == "ZeroExt" and piece.args[0] % 8 == 0:
            # the simplifier turns Concat(0, x) into ZeroExt(x)
            amount, inner = piece.args
            stack.extend((inner, claripy.BVV(0, amount)))
            continue
        # a Union is always symbolic, so a concrete piece is a single value; a symbolic one is expanded into the values
        # it can take, or kept as is when there are too many of them
        expanded = claripy.excavate_union(piece, limit=EXCAVATE_LIMIT) if piece.symbolic else None
        alternatives = tuple(expanded) if expanded is not None else (piece,)
        if join and len(alternatives) == 1:
            if not pending:
                pending_offset = offset
            pending.append(alternatives[0])
        else:
            flush()
            segments.append((offset, alternatives))
        offset += piece.size() // 8
    flush()
    return segments


def mv_from_segments(
    segments: Mapping[int, Iterable[claripy.ast.BV]] | Iterable[tuple[int, Iterable[claripy.ast.BV]]],
) -> claripy.ast.BV:
    """
    Build a value from ``(byte offset, alternatives)`` pairs. The pieces must be contiguous and start at offset 0.
    """
    items = sorted(segments.items() if isinstance(segments, Mapping) else segments, key=lambda kv: kv[0])
    if not items:
        raise ValueError("A value needs at least one piece")
    pieces: list[claripy.ast.BV] = []
    expected = 0
    for offset, values in items:
        if offset != expected:
            raise ValueError(f"Pieces are not contiguous: expected offset {expected}, got {offset}")
        piece = claripy.union(*values)
        pieces.append(piece)
        expected = offset + piece.size() // 8
    return claripy.Concat(*pieces)


def mv_leaves(value: claripy.ast.BV) -> Iterator[claripy.ast.BV]:
    """
    Every alternative of every piece of a value.
    """
    if not value.symbolic:
        yield value
        return
    for _, alternatives in mv_segments(value):
        yield from alternatives
