from __future__ import annotations

from typing import TYPE_CHECKING

import angr

if TYPE_CHECKING:
    import claripy


class Caller(angr.SimProcedure):
    """
    Caller stub. Creates a Ijk_Call exit to the specified function
    """

    def run(self, target_addr: int | claripy.ast.BV | None = None, target_cc: angr.SimCC | None = None):
        self.call(target_addr, [], "after_call", cc=target_cc, prototype="void x()")

    def after_call(self, target_addr: int | claripy.ast.BV | None = None, target_cc: angr.SimCC | None = None):
        pass
