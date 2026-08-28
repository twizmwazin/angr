from __future__ import annotations

from typing import TYPE_CHECKING

from angr.state_plugins.sim_action_object import _raw_ast
from angr.storage.memory_mixins.memory_mixin import MemoryMixin

if TYPE_CHECKING:
    import claripy

    from angr.state_plugins.sim_action_object import SimActionObject


class UnwrapperMixin(MemoryMixin):
    """
    This mixin processes SimActionObjects by passing on their .ast field.
    """

    def store(
        self,
        addr,
        data,
        size=None,
        *,
        condition: SimActionObject | claripy.ast.Bool | bool | None = None,
        **kwargs,
    ):
        return super().store(
            _raw_ast(addr), _raw_ast(data), size=_raw_ast(size), condition=_raw_ast(condition), **kwargs
        )

    def load(
        self,
        addr,
        size=None,
        *,
        condition: SimActionObject | claripy.ast.Bool | bool | None = None,
        fallback: SimActionObject | claripy.ast.Bits | float | bytes | bytearray | memoryview | str | None = None,
        **kwargs,
    ):
        return super().load(
            _raw_ast(addr), size=_raw_ast(size), condition=_raw_ast(condition), fallback=_raw_ast(fallback), **kwargs
        )

    def find(self, addr, data, max_search, *, default: SimActionObject | claripy.ast.BV | int | None = None, **kwargs):
        return super().find(_raw_ast(addr), _raw_ast(data), max_search, default=_raw_ast(default), **kwargs)

    def copy_contents(
        self, dst, src, size, condition: SimActionObject | claripy.ast.Bool | bool | None = None, **kwargs
    ):
        return super().copy_contents(_raw_ast(dst), _raw_ast(src), _raw_ast(size), _raw_ast(condition), **kwargs)
