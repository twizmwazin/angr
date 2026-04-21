"""Pending exception queue for asynchronous execution preemption.

This plugin stores a priority-ordered queue of pending exceptions that an
engine should inject into execution at appropriate boundaries. It is
arch-agnostic: the concrete entry/exit semantics (stack frame format,
exception return detection) live in arch-specific ``SimException`` models.

Event sources (timer models, signal injectors, peripheral IRQ models, etc.)
call :meth:`SimStateExceptions.pend` to queue an exception. The engine
integration (typically an ``ExceptionMixin``) consults the queue between
execution batches.
"""

from __future__ import annotations

import heapq
import logging
from dataclasses import dataclass, field
from typing import Any
from typing_extensions import Self

from angr.sim_state import SimState

from .plugin import SimStatePlugin

log = logging.getLogger(__name__)


# Counter used to break priority ties so ``PendingException`` stays totally
# ordered without requiring the payload to be comparable.
_tiebreaker: int = 0


def _next_tiebreaker() -> int:
    global _tiebreaker
    _tiebreaker += 1
    return _tiebreaker


@dataclass(order=True)
class PendingException:
    """A pending exception waiting to be dispatched.

    Lower ``priority`` values run first (matching the Cortex-M convention
    where priority 0 is the highest priority). The ``payload`` holds any
    arch/source-specific data that the ``SimException`` model needs to
    construct the exception frame (handler address, vector number,
    signal info, etc.).
    """

    #: Priority — lower values dispatch first.
    priority: int
    #: Tiebreaker (insertion order) so equal-priority events preserve FIFO order.
    sequence: int = field(default_factory=_next_tiebreaker, compare=True)
    #: Arch/source-specific data passed to ``SimException.enter()``.
    payload: Any = field(default=None, compare=False)


class SimStateExceptions(SimStatePlugin):
    """Priority queue of pending exceptions plus the next-fire deadline.

    :ivar pending: heap of :class:`PendingException` ordered by (priority, sequence).
    :ivar next_deadline: absolute instruction-count deadline of the next scheduled
        exception, or ``None`` if nothing is scheduled. Used by the engine mixin
        to cap execution batch sizes so scheduled exceptions don't fire late.
    """

    def __init__(
        self,
        pending: list[PendingException] | None = None,
        next_deadline: int | None = None,
        icount: int = 0,
    ):
        super().__init__()
        self.pending: list[PendingException] = list(pending) if pending else []
        heapq.heapify(self.pending)
        self.next_deadline: int | None = next_deadline
        #: Running instruction count maintained by the engine mixin. Event
        #: sources use this to register deadlines (``schedule(icount + N)``)
        #: and the mixin reads it to cap execution batch sizes.
        self.icount: int = icount

    def set_state(self, state: SimState) -> None:
        pass  # no weak ref needed

    @SimStatePlugin.memo
    def copy(self, _memo: dict) -> Self:
        return type(self)(
            pending=list(self.pending),
            next_deadline=self.next_deadline,
            icount=self.icount,
        )

    def merge(self, others, merge_conditions, common_ancestor=None) -> bool:
        # Merging exception queues across branches is not meaningful in
        # general — concrete execution is the intended use case. If any
        # state has pending exceptions, keep them but flag as a merge.
        all_pending: list[PendingException] = list(self.pending)
        for other in others:
            all_pending.extend(other.pending)
        self.pending = all_pending
        heapq.heapify(self.pending)
        return True

    def widen(self, others) -> bool:
        return False

    # ── Queue operations ──

    def pend(self, exc: PendingException) -> None:
        """Add an exception to the pending queue."""
        heapq.heappush(self.pending, exc)

    def pop_highest(self) -> PendingException | None:
        """Remove and return the highest-priority pending exception, or None."""
        if not self.pending:
            return None
        return heapq.heappop(self.pending)

    def peek_highest(self) -> PendingException | None:
        """Return the highest-priority pending exception without removing it."""
        return self.pending[0] if self.pending else None

    def has_pending(self) -> bool:
        return bool(self.pending)

    def schedule(self, deadline_icount: int) -> None:
        """Register an instruction-count deadline for the next scheduled fire.

        Used by event sources that fire on a cadence (timers) to hint the
        engine about when to sample the queue. The engine may cap its next
        execution batch to avoid overshooting this deadline.

        Repeated calls take the earliest deadline.
        """
        if self.next_deadline is None or deadline_icount < self.next_deadline:
            self.next_deadline = deadline_icount

    def clear_deadline(self) -> None:
        """Clear the next-deadline hint. Called when the deadline has been met."""
        self.next_deadline = None

    def clear(self) -> None:
        """Remove all pending exceptions."""
        self.pending.clear()
        self.next_deadline = None

    def advance_icount(self, n: int) -> None:
        """Bump the running instruction counter by ``n``.

        Called by the engine mixin after each execution step. Event sources
        can read :attr:`icount` to compute absolute deadlines relative to a
        known reference point.
        """
        self.icount += n


SimState.register_default("exceptions", SimStateExceptions)
