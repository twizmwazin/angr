from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

from .base import ExplorationTechnique

if TYPE_CHECKING:
    from angr.sim_manager import SimulationManager

l = logging.getLogger(name=__name__)


class Timeout(ExplorationTechnique):
    """
    Timeout exploration technique that stops an active exploration if the run time exceeds
    a predefined timeout
    """

    def __init__(self, timeout: float | None = None):
        super().__init__()
        self.start_time: float | None = None
        self.timeout = timeout

    def setup(self, simgr: SimulationManager) -> None:
        simgr.stashes["timeout"] = []

    def step(self, simgr: SimulationManager, stash: str = "active", **kwargs) -> SimulationManager:
        if self.start_time is None:
            self.start_time = time.time()
        if self.timeout is not None and time.time() - self.start_time > self.timeout:
            self.start_time = None
            simgr.move(stash, "timeout")
            l.warning("exploration timeout in %s seconds!", self.timeout)
        else:
            simgr = simgr.step(stash=stash, **kwargs)
        return simgr
