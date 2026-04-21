"""Engine mixin that injects pending exceptions and handles exception returns.

This mixin sits above any execution engine in the MRO. It consults the
generic :class:`angr.state_plugins.SimStateExceptions` queue and delegates
the arch-specific frame manipulation to a :class:`angr.sim_exceptions.SimException`
subclass.

Before delegating to the underlying engine, it:

1. Checks the pending-exception queue. If something is pending, calls the
   arch's ``SimException.enter()`` and produces a state that begins executing
   the handler — no underlying engine step is performed.

2. Caps the underlying engine's ``num_inst`` at the next deadline registered
   on the queue (via :meth:`SimStateExceptions.schedule`), so scheduled
   exceptions don't fire late.

After the underlying engine produces successors, it:

3. Inspects each successor for an exception-return point (e.g., Cortex-M
   ``EXC_RETURN`` in PC) and replaces it with the state that results from
   calling ``SimException.exit()``.
"""

from __future__ import annotations

import logging
from typing import Any

import claripy

from angr.sim_exceptions import SimException, default_exception_model

from .successors import SuccessorsEngine

log = logging.getLogger(__name__)


class ExceptionMixin(SuccessorsEngine):
    """Route pending exceptions through the arch's exception model.

    The mixin is engine-agnostic: it works equally well above ``IcicleEngine``,
    ``HeavyVEXMixin``, or any other ``SuccessorsEngine`` subclass. Integration
    requires:

    - A :class:`SimStateExceptions` plugin on the state (registered as a
      default, so this is automatic).
    - A :class:`SimException` model registered for the state's architecture.
      If no model is registered, the mixin is a no-op.

    To disable the mixin for a particular run, clear the queue and remove
    pending deadlines before stepping.
    """

    def _get_exception_model(self, state) -> SimException | None:
        """Look up the arch/platform exception model for ``state``.

        The platform is drawn from the project's SimOS name if available;
        otherwise defaults to Linux (the same convention as ``SimCC``).
        """
        arch_name = state.arch.name
        platform: str | None = None
        if state.project is not None and state.project.simos is not None:
            platform = getattr(state.project.simos, "name", None)

        cls = default_exception_model(arch_name, platform=platform)
        if cls is None:
            return None
        return cls(state.arch)

    def process_successors(
        self,
        successors,
        *,
        num_inst: int | None = None,
        **kwargs: Any,
    ) -> None:
        state = self.state
        model = self._get_exception_model(state)

        # No exception model → pass through to the underlying engine.
        if model is None:
            super().process_successors(successors, num_inst=num_inst, **kwargs)
            return

        queue = state.exceptions if hasattr(state, "exceptions") else None
        if queue is None:
            super().process_successors(successors, num_inst=num_inst, **kwargs)
            return

        # (1) Inject a pending exception if any — this produces an immediate
        # successor and skips the underlying engine for this step.
        pending = queue.pop_highest()
        if pending is not None:
            new_state = model.enter(state, pending)
            successors.add_successor(
                new_state,
                new_state.regs.pc,
                claripy.true(),
                "Ijk_Boring",
                add_guard=False,
            )
            successors.processed = True
            return

        # (2) Cap num_inst at the next deadline so we resample the queue in
        # time. Deadlines are absolute instruction counts against the queue's
        # internal counter (bumped via advance_icount after each step).
        if queue.next_deadline is not None:
            remaining = queue.next_deadline - queue.icount
            if remaining <= 0:
                # Deadline already reached — let the source fire before we
                # step the engine. Do nothing here; on the next call, the
                # source's pre-step hook will have pended an exception.
                queue.clear_deadline()
            else:
                num_inst = min(num_inst, remaining) if num_inst is not None else remaining

        # (3) Run the underlying engine.
        super().process_successors(successors, num_inst=num_inst, **kwargs)

        # (4) Bump the icount by the number of instructions executed in this
        # step so event sources can register future deadlines relative to now.
        flat = getattr(successors, "flat_successors", None)
        if flat is None:
            return
        for s in flat:
            new_queue = s.exceptions if hasattr(s, "exceptions") else None
            if new_queue is not None:
                recent = getattr(s.history, "recent_instruction_count", 0) or 0
                if recent > 0:
                    new_queue.advance_icount(recent)

        # (5) Detect exception returns in the produced successors and replace
        # them with the state produced by SimException.exit(). We update both
        # ``flat_successors`` and ``successors`` because angr.Emulator reads
        # from the latter and running engines need a consistent view.
        all_lists = [flat, getattr(successors, "successors", None)]
        for i, s in enumerate(list(flat)):
            if model.is_return_point(s):
                exited = model.exit(s)
                # Break the chain from ``exited`` back to ``s`` (and via
                # ``s`` back to the pre-exception state) so concrete
                # execution doesn't accumulate history nodes and the
                # memory/solver plugins they pin.
                hist = getattr(exited, "history", None)
                if hist is not None:
                    hist.parent = None
                    hist.recent_bbl_addrs = []
                    hist.recent_events = []
                for lst in all_lists:
                    if lst is None:
                        continue
                    for j, entry in enumerate(lst):
                        if entry is s:
                            lst[j] = exited
