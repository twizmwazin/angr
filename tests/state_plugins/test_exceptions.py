#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
"""Tests for the SimStateExceptions plugin."""

from __future__ import annotations

import unittest

import angr
from angr.state_plugins.exceptions import PendingException, SimStateExceptions


class TestSimStateExceptions(unittest.TestCase):
    def _state(self) -> angr.SimState:
        return angr.SimState(arch="ARMCortexM")

    def test_plugin_is_default(self):
        state = self._state()
        plugin = state.get_plugin("exceptions")
        assert isinstance(plugin, SimStateExceptions)

    def test_initially_empty(self):
        q = self._state().get_plugin("exceptions")
        assert not q.has_pending()
        assert q.pop_highest() is None
        assert q.peek_highest() is None
        assert q.next_deadline is None

    def test_priority_ordering(self):
        q = self._state().get_plugin("exceptions")
        q.pend(PendingException(priority=5, payload="low"))
        q.pend(PendingException(priority=1, payload="high"))
        q.pend(PendingException(priority=3, payload="mid"))

        assert q.pop_highest().payload == "high"
        assert q.pop_highest().payload == "mid"
        assert q.pop_highest().payload == "low"
        assert q.pop_highest() is None

    def test_fifo_within_priority(self):
        q = self._state().get_plugin("exceptions")
        q.pend(PendingException(priority=2, payload="first"))
        q.pend(PendingException(priority=2, payload="second"))
        q.pend(PendingException(priority=2, payload="third"))

        assert q.pop_highest().payload == "first"
        assert q.pop_highest().payload == "second"
        assert q.pop_highest().payload == "third"

    def test_peek_does_not_remove(self):
        q = self._state().get_plugin("exceptions")
        q.pend(PendingException(priority=1, payload="a"))
        assert q.peek_highest().payload == "a"
        assert q.has_pending()
        assert q.pop_highest().payload == "a"
        assert not q.has_pending()

    def test_schedule_takes_earliest_deadline(self):
        q = self._state().get_plugin("exceptions")
        q.schedule(1000)
        assert q.next_deadline == 1000
        q.schedule(500)  # earlier wins
        assert q.next_deadline == 500
        q.schedule(2000)  # later is ignored
        assert q.next_deadline == 500

    def test_clear_deadline(self):
        q = self._state().get_plugin("exceptions")
        q.schedule(1000)
        q.clear_deadline()
        assert q.next_deadline is None

    def test_clear_removes_everything(self):
        q = self._state().get_plugin("exceptions")
        q.pend(PendingException(priority=1))
        q.schedule(1000)
        q.clear()
        assert not q.has_pending()
        assert q.next_deadline is None

    def test_copy_preserves_queue(self):
        state = self._state()
        q = state.get_plugin("exceptions")
        q.pend(PendingException(priority=3, payload="x"))
        q.schedule(500)

        state2 = state.copy()
        q2 = state2.get_plugin("exceptions")

        # Independent — popping from copy doesn't affect original
        assert q2.pop_highest().payload == "x"
        assert q2.next_deadline == 500
        assert q.peek_highest().payload == "x"

    def test_payload_is_opaque(self):
        """Payload can be any object; plugin doesn't inspect it."""

        class CustomPayload:
            def __init__(self, x):
                self.x = x

        q = self._state().get_plugin("exceptions")
        payload = CustomPayload(42)
        q.pend(PendingException(priority=0, payload=payload))
        popped = q.pop_highest()
        assert popped.payload is payload
        assert popped.payload.x == 42


if __name__ == "__main__":
    unittest.main()
