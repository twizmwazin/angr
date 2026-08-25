from __future__ import annotations

from typing import TYPE_CHECKING

from angr.sim_options import EFFICIENT_STATE_MERGING

from .base import ExplorationTechnique

if TYPE_CHECKING:
    from angr.sim_manager import SimulationManager
    from angr.sim_state import SimState


class Veritesting(ExplorationTechnique):
    """
    Enable veritesting. This technique, described in a paper[1] from CMU, attempts to address the problem of state
    explosions in loops by performing smart merging.

    [1] https://users.ece.cmu.edu/~aavgerin/papers/veritesting-icse-2014.pdf
    """

    def __init__(self, **options):
        super().__init__()
        self.options = options

    def step_state(
        self, simgr: SimulationManager, state: SimState, successor_func=None, **kwargs
    ) -> dict[str | None, list[SimState]]:
        if EFFICIENT_STATE_MERGING not in state.options:
            state.options.add(EFFICIENT_STATE_MERGING)

        vt = self.project.analyses.Veritesting(state, **self.options)
        if vt.result and vt.final_manager:
            simgr2 = vt.final_manager
            simgr2.stash(from_stash="deviated", to_stash="active")
            simgr2.stash(from_stash="successful", to_stash="active")

            return {
                "active": simgr2.active,
                "unconstrained": simgr2.stashes.get("unconstrained", []),
                "unsat": simgr2.stashes.get("unsat", []),
                "pruned": simgr2.stashes.get("pruned", []),
                # the ErrorRecords are intentionally stored into the "errored" stash as-is
                "errored": simgr2.errored,  # pyright: ignore[reportReturnType]
            }

        return simgr.step_state(state, successor_func=successor_func, **kwargs)
