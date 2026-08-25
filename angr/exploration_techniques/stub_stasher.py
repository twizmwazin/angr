from __future__ import annotations

from typing import TYPE_CHECKING

from .base import ExplorationTechnique

if TYPE_CHECKING:
    from angr.sim_manager import SimulationManager
    from angr.sim_state import SimState


class StubStasher(ExplorationTechnique):
    """
    Stash states that reach a stub SimProcedure.
    """

    @staticmethod
    def post_filter(state: SimState) -> bool:
        if state.project is None:
            return False
        hook = state.project.hooked_by(state.addr)
        return hook is not None and hook.is_stub

    def step(self, simgr: SimulationManager, stash: str = "active", **kwargs) -> SimulationManager:
        simgr.step(stash=stash, **kwargs)
        simgr.move(stash, "stub", filter_func=self.post_filter)
        return simgr
