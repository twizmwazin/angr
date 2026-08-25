from __future__ import annotations

import concurrent.futures
import logging
from typing import TYPE_CHECKING

from .base import ExplorationTechnique

if TYPE_CHECKING:
    from angr.sim_manager import ErrorRecord, SimulationManager
    from angr.sim_state import SimState

l = logging.getLogger(__name__)


class Threading(ExplorationTechnique):
    """
    Enable multithreading.

    This is only useful in paths where a lot of time is taken inside z3, doing constraint solving.
    This is because of python's GIL, which says that only one thread at a time may be executing python code.
    """

    def __init__(self, threads: int = 8, local_stash: str = "thread_local"):
        super().__init__()
        self.threads = threads
        self.queued = set()
        self.tasks = set()
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=threads)
        self.local_stash = local_stash

    def step(
        self,
        simgr: SimulationManager,
        stash: str = "active",
        error_list: list[ErrorRecord] | None = None,
        target_stash: str | None = None,
        **kwargs,
    ) -> SimulationManager:
        target_stash = target_stash or stash
        if error_list is not None:
            raise ValueError("Can't pass error_list to step with threading enabled. Did you install threading twice?")

        l.info("Thread-stepping %s of %s", stash, simgr)

        for state in simgr.stashes[stash]:
            if state in self.queued:
                continue

            # construct new simgr with new lists
            # this means that threads won't trample each other's hook stacks
            # but can still negotiate over shared resources
            tsimgr = simgr.copy()
            tsimgr._stashes = {self.local_stash: [state]}
            tsimgr._errored = []
            self.tasks.add(self.executor.submit(self.inner_step, state, tsimgr, target_stash=target_stash, **kwargs))
            self.queued.add(state)

        timeout = None
        while True:
            done, self.tasks = concurrent.futures.wait(
                self.tasks, timeout=timeout, return_when=concurrent.futures.FIRST_COMPLETED
            )
            if not done:
                break

            for done_future in done:
                done_future: concurrent.futures.Future
                state, thread_errors, tsimgr = done_future.result()
                simgr.absorb(tsimgr)
                simgr.errored.extend(thread_errors)
                simgr.stashes[stash].remove(state)
                self.queued.remove(state)
            timeout = 0

        return simgr

    def inner_step(
        self, state: SimState, simgr: SimulationManager, **kwargs
    ) -> tuple[SimState, list[ErrorRecord], SimulationManager]:
        error_list = []
        simgr.step(stash=self.local_stash, error_list=error_list, **kwargs)
        return state, error_list, simgr
