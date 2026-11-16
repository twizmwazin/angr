# pylint:disable=arguments-differ
from __future__ import annotations

from angr.ailment.expression import Call, Const
from angr.ailment.statement import SideEffectStatement

from .base import PeepholeOptimizationStmtBase


class RemoveCxxDestructorCalls(PeepholeOptimizationStmtBase):
    """
    Rewrite C++ operator function calls into operations.
    """

    __slots__ = ()

    NAME = "Remove C++ destructor function calls"
    stmt_classes = (SideEffectStatement,)

    def optimize(self, stmt: SideEffectStatement, **kwargs) -> tuple | None:  # type: ignore
        # are we calling a function that we deem as a C++ destructor?
        assert self.project is not None

        if not isinstance(stmt.expr, Call):
            return None

        if isinstance(stmt.expr.target, Const):
            func_addr = stmt.expr.target.value
            func = self.project.kb.functions.function(addr=func_addr)
            if func is None:
                return None
            if "::~" in func.demangled_name and stmt.expr.args is not None:
                # yes it is!
                return ()
        return None
