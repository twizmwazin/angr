#!/usr/bin/env python3
"""
Tests for the SimStatePluginProtocol: SimState must accept any object satisfying the protocol,
whether or not it inherits from SimStatePlugin.
"""

from __future__ import annotations

import unittest

import angr
from angr.state_plugins import SimStatePlugin, SimStatePluginProtocol

# pylint: disable=missing-class-docstring,no-self-use


class DuckPlugin:
    """A state plugin that does not inherit from SimStatePlugin."""

    def __init__(self, counter=0):
        self.counter = counter

    def set_state(self, state):
        pass

    def init_state(self):
        pass

    def copy(self, memo=None):  # pylint: disable=unused-argument
        return DuckPlugin(self.counter)

    def merge(self, others, merge_conditions, common_ancestor=None):  # pylint: disable=unused-argument
        self.counter += sum(o.counter for o in others)
        return True


class TestPluginProtocol(unittest.TestCase):
    def test_simstateplugin_satisfies_protocol(self):
        assert isinstance(SimStatePlugin(), SimStatePluginProtocol)

    def test_default_plugins_satisfy_protocol(self):
        state = angr.SimState(arch="AMD64", mode="symbolic")
        state.get_plugin("globals")  # trigger instantiation of the globals plugin
        for name, plugin in state.plugins.items():
            assert isinstance(plugin, SimStatePluginProtocol), f"plugin {name} does not satisfy the protocol"

    def test_duck_typed_plugin(self):
        plugin = DuckPlugin(5)
        assert not isinstance(plugin, SimStatePlugin)
        assert isinstance(plugin, SimStatePluginProtocol)

        def duck_of(state) -> DuckPlugin:
            duck = state.get_plugin("duck")
            assert isinstance(duck, DuckPlugin)
            return duck

        state = angr.SimState(arch="AMD64", mode="symbolic")
        state.register_plugin("duck", plugin)
        assert duck_of(state).counter == 5

        # copying the state copies the plugin
        state2 = state.copy()
        duck_of(state2).counter = 7
        assert duck_of(state).counter == 5

        # merging the states merges the plugin
        merged, _, _ = state.merge(state2)
        assert duck_of(merged).counter == 12


if __name__ == "__main__":
    unittest.main()
