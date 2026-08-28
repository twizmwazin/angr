from __future__ import annotations

from typing import TYPE_CHECKING

from .base import SimConcretizationStrategy

if TYPE_CHECKING:
    from collections.abc import Sequence

    import claripy


class SimConcretizationStrategyNonzeroRange(SimConcretizationStrategy):
    """
    Concretization strategy that resolves a range in a non-zero location.
    """

    def __init__(self, limit, **kwargs):
        super().__init__(**kwargs)
        self._limit = limit

    def _concretize(self, memory, addr, extra_constraints: Sequence[claripy.ast.Bool] | None = None, **kwargs):
        mn, mx = self._range(memory, addr, extra_constraints=extra_constraints, **kwargs)
        if mx - mn <= self._limit:
            child_constraints = (addr != 0,)
            if extra_constraints is not None:
                child_constraints += tuple(extra_constraints)
            return self._eval(memory, addr, self._limit, extra_constraints=child_constraints, **kwargs)
        return None
