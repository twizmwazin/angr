"""AIL Statement classes.

Mirror of ``angr.ailment.expression`` for the Statement side.
"""

# pylint:disable=import-error,no-name-in-module
from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from angr.rustylib.ailment import (
        CAS,
        Assignment,
        ConditionalJump,
        DirtyStatement,
        IncompleteSwitchCaseHeadStatement,
        Jump,
        Label,
        NoOp,
        Return,
        SideEffectStatement,
        Statement,
        Store,
        WeakAssignment,
    )
else:
    from angr.rustylib.ailment import Statement as _Statement
    from angr.rustylib.ailment import StatementKind as SK

    class _AilStmtMarkerMeta(type):
        """Metaclass for the Statement marker classes. ``_kind`` (class attr) is the variant tag this marker matches."""

        _kind: SK
        _kind_int: int

        def __init__(cls, name, bases, namespace, **kwargs):
            super().__init__(name, bases, namespace, **kwargs)
            # a plain int: comparing ``pykind`` against it skips the Rust-side enum conversion
            cls._kind_int = int(namespace["_kind"])

        def __instancecheck__(cls, instance: Any) -> bool:
            return type(instance) is _Statement and instance.pykind == cls._kind_int

        def __subclasscheck__(cls, subclass: type) -> bool:
            return subclass is cls

        def __call__(cls, *args, **kwargs):
            # Normalize idx=None to 0.
            if args and args[0] is None:
                args = (0, *args[1:])
            return type.__call__(cls, *args, **kwargs)

    class Assignment(metaclass=_AilStmtMarkerMeta):
        """Marker for ``Statement`` instances whose variant is ``Assignment``."""

        _kind = SK.Assignment

        def __new__(cls, idx, dst, src, **tags) -> _Statement:  # type: ignore[misc]
            return _Statement._new_assignment(idx, dst, src, **tags)

    class WeakAssignment(metaclass=_AilStmtMarkerMeta):
        """Marker for ``Statement`` instances whose variant is ``WeakAssignment``."""

        _kind = SK.WeakAssignment

        def __new__(cls, idx, dst, src, **tags) -> _Statement:  # type: ignore[misc]
            return _Statement._new_weak_assignment(idx, dst, src, **tags)

    class Label(metaclass=_AilStmtMarkerMeta):
        """Marker for ``Statement`` instances whose variant is ``Label``."""

        _kind = SK.Label

        def __new__(cls, idx, name, **tags) -> _Statement:  # type: ignore[misc]
            return _Statement._new_label(idx, name, **tags)

    class Store(metaclass=_AilStmtMarkerMeta):
        """Marker for ``Statement`` instances whose variant is ``Store``."""

        _kind = SK.Store

        def __new__(  # type: ignore[misc]
            cls,
            idx,
            addr,
            data,
            size,
            endness,
            guard=None,
            **tags,
        ) -> _Statement:
            return _Statement._new_store(idx, addr, data, size, endness, guard=guard, **tags)

    class Jump(metaclass=_AilStmtMarkerMeta):
        """Marker for ``Statement`` instances whose variant is ``Jump``."""

        _kind = SK.Jump

        def __new__(cls, idx, target, target_idx=0, **tags) -> _Statement:  # type: ignore[misc]
            return _Statement._new_jump(idx, target, target_idx=target_idx, **tags)

    class ConditionalJump(metaclass=_AilStmtMarkerMeta):
        """Marker for ``Statement`` instances whose variant is ``ConditionalJump``."""

        _kind = SK.ConditionalJump

        def __new__(  # type: ignore[misc]
            cls,
            idx,
            condition,
            true_target,
            false_target,
            *,
            true_target_idx=0,
            false_target_idx=0,
            **tags,
        ) -> _Statement:
            return _Statement._new_conditional_jump(
                idx,
                condition,
                true_target,
                false_target,
                true_target_idx=true_target_idx,
                false_target_idx=false_target_idx,
                **tags,
            )

    class SideEffectStatement(metaclass=_AilStmtMarkerMeta):
        """Marker for ``Statement`` instances whose variant is ``SideEffectStatement``."""

        _kind = SK.SideEffectStatement

        def __new__(  # type: ignore[misc]
            cls,
            idx,
            expr,
            ret_expr=None,
            fp_ret_expr=None,
            **tags,
        ) -> _Statement:
            return _Statement._new_side_effect_statement(idx, expr, ret_expr=ret_expr, fp_ret_expr=fp_ret_expr, **tags)

    class Return(metaclass=_AilStmtMarkerMeta):
        """Marker for ``Statement`` instances whose variant is ``Return``."""

        _kind = SK.Return

        def __new__(cls, idx, ret_exprs, **tags) -> _Statement:  # type: ignore[misc]
            return _Statement._new_return(idx, ret_exprs, **tags)

    class CAS(metaclass=_AilStmtMarkerMeta):
        """Marker for ``Statement`` instances whose variant is ``CAS``."""

        _kind = SK.CAS

        def __new__(  # type: ignore[misc]
            cls,
            idx,
            addr,
            data_lo,
            data_hi,
            expd_lo,
            expd_hi,
            old_lo,
            old_hi,
            endness,
            **tags,
        ) -> _Statement:
            return _Statement._new_cas(idx, addr, data_lo, data_hi, expd_lo, expd_hi, old_lo, old_hi, endness, **tags)

    class DirtyStatement(metaclass=_AilStmtMarkerMeta):
        """Marker for ``Statement`` instances whose variant is ``DirtyStatement``."""

        _kind = SK.DirtyStatement

        def __new__(cls, idx, dirty, **tags) -> _Statement:  # type: ignore[misc]
            return _Statement._new_dirty_statement(idx, dirty, **tags)

    class NoOp(metaclass=_AilStmtMarkerMeta):
        """Marker for ``Statement`` instances whose variant is ``NoOp``.

        Placeholder for a removed statement; defines and uses no atoms.
        Primarily used by the AIL simplifier's dead-assignment removal
        so the indices of surrounding statements stay stable until the
        block is compacted.
        """

        _kind = SK.NoOp

        def __new__(cls, idx, **tags) -> _Statement:  # type: ignore[misc]
            return _Statement._new_no_op(idx, **tags)

    class IncompleteSwitchCaseHeadStatement(metaclass=_AilStmtMarkerMeta):
        """Describes a switch-case head. This is only created by LoweredSwitchSimplifier."""

        _kind = SK.IncompleteSwitchCaseHeadStatement

        def __new__(cls, idx, switch_variable, case_addrs, **tags) -> _Statement:  # type: ignore[misc]
            return _Statement._new_incomplete_switch_case_head_statement(idx, switch_variable, case_addrs, **tags)

    # every AIL statement is an instance of the one Rust class
    Statement = _Statement


__all__ = [
    "CAS",
    "Assignment",
    "ConditionalJump",
    "DirtyStatement",
    "IncompleteSwitchCaseHeadStatement",
    "Jump",
    "Label",
    "NoOp",
    "Return",
    "SideEffectStatement",
    "Statement",
    "Store",
    "WeakAssignment",
]
