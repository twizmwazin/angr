from __future__ import annotations

from typing import TYPE_CHECKING

from .base import ExplorationTechnique

if TYPE_CHECKING:
    from angr.sim_manager import SimulationManager
    from angr.sim_state import SimState


class LengthLimiter(ExplorationTechnique):
    """
    Length limiter on paths.
    """

    def __init__(self, max_length: int, drop: bool = False):
        super().__init__()
        self._max_length = max_length
        self._drop = drop

    def _filter(self, s: SimState) -> bool:
        return s.history.block_count > self._max_length

    def step(self, simgr: SimulationManager, stash: str = "active", **kwargs) -> SimulationManager:
        simgr = simgr.step(stash=stash, **kwargs)
        simgr.move("active", "_DROP" if self._drop else "cut", self._filter)
        return simgr
