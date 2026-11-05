from __future__ import annotations

from collections.abc import Iterable

from angr import claripy

from .base import SimConcretizationStrategy


class SimConcretizationStrategySignedAdd(SimConcretizationStrategy):
    """
    Concretization strategy that changes additions of big offsets to subtractions of small offsets.

    An address like ``x + 0xfffffff0`` is really ``x - 0x10`` wrapped around the bit width. Approximate
    (VSA) resolution handles the subtraction far more tightly than the addition, so this strategy rewrites the
    address and then concretizes the rewritten form with the strategies it wraps. Addresses that are not of the
    form ``symbolic + negative immediate`` are left to the strategies that follow this one.
    """

    def __init__(self, strategies: Iterable[SimConcretizationStrategy], subtraction_limit=0x10000, **kwargs):
        """
        :param strategies:          The strategies to concretize the rewritten address with, in order.
        :param subtraction_limit:   Only rewrite when the resulting subtracted offset is below this limit.
        """
        super().__init__(**kwargs)
        self._strategies = list(strategies)
        self._subtraction_limit = subtraction_limit

    def _rewrite(self, memory, addr: claripy.ast.BV) -> claripy.ast.BV | None:
        if addr.depth != 2 or addr.op != "__add__" or len(addr.args) != 2:
            return None
        variable, immediate = addr.args
        if variable.singlevalued and immediate.symbolic:
            variable, immediate = immediate, variable
        if not (variable.symbolic and immediate.singlevalued):
            return None

        bits = immediate.size()
        # only rewrite a negative immediate
        if not memory.state.solver.is_true(immediate >= 1 << (bits - 1)):
            return None
        new_arg = (1 << bits) - memory.state.solver.eval(immediate)
        if new_arg >= self._subtraction_limit:
            return None
        return variable - claripy.BVV(new_arg, bits)

    def _concretize(self, memory, addr, **kwargs):
        rewritten = self._rewrite(memory, addr)
        if rewritten is None:
            return None
        for strategy in self._strategies:
            result = strategy.concretize(memory, rewritten, **kwargs)
            if result is not None:
                return result
        return None

    def copy(self):
        return SimConcretizationStrategySignedAdd(
            [s.copy() for s in self._strategies],
            subtraction_limit=self._subtraction_limit,
            filter=self._filter,
            exact=self._exact,
        )

    def merge(self, others):
        for strategy, other_strategies in zip(self._strategies, zip(*(o._strategies for o in others))):
            strategy.merge(other_strategies)
