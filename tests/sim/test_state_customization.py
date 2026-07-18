#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

__package__ = __package__ or "tests.sim"  # pylint:disable=redefined-builtin

import glob
import os
import unittest

import angr
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestStateCustomization(unittest.TestCase):
    def test_stack_end(self):
        for fn in glob.glob(os.path.join(test_location, "*", "fauxware")):
            p = angr.Project(fn, auto_load_libs=False)

            # normal state
            s = p.factory.full_init_state()
            offset = s.solver.eval(p.arch.initial_sp - s.regs.sp)

            # different stack ends
            for n in [0x1337000, 0xBAAAAA00, 0x100, 0xFFFFFF00, 0x13371337000, 0xBAAAAAAA0000, 0xFFFFFFFFFFFFFF00]:
                if n.bit_length() > p.arch.bits:
                    continue
                s = p.factory.full_init_state(stack_end=n)
                assert s.solver.eval_one(s.regs.sp + offset == n)

    def test_execstack(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        proj = angr.Project(bin_path, auto_load_libs=False)
        # manually mark the stack as executable
        proj.loader.main_object.execstack = True
        s = proj.factory.blank_state()
        assert s.memory._stack_perms == 7

    def test_brk(self):
        for fn in glob.glob(os.path.join(test_location, "*", "fauxware")):
            p = angr.Project(fn, auto_load_libs=False)

            # different stack ends
            for n in [0x1337000, 0xBAAAAA00, 0x100, 0xFFFFFF00, 0x13371337000, 0xBAAAAAAA0000, 0xFFFFFFFFFFFFFF00]:
                if n.bit_length() > p.arch.bits:
                    continue
                s = p.factory.full_init_state(brk=n)
                assert s.solver.eval_one(s.posix.brk == n)


class CustomPlugin(angr.SimStatePlugin):
    @angr.SimStatePlugin.memo
    def copy(self, memo):  # pylint: disable=unused-argument
        return CustomPlugin()


class TestPluginPresetPreservation(unittest.TestCase):
    def test_copy_preserves_custom_preset(self):
        preset = angr.sim_state.default_state_plugin_preset.copy()
        preset.add_default_plugin("custom_plugin", CustomPlugin)
        angr.SimState.register_preset("custom_preset_copy_test", preset)

        state = angr.SimState(arch="AMD64", mode="symbolic", plugin_preset="custom_preset_copy_test")
        assert state.plugin_preset is preset

        # copying must not emit the "Overriding active preset" warning
        with self.assertNoLogs("angr.misc.plugins", level="WARNING"):
            copied = state.copy()

        assert copied.plugin_preset is preset
        # lazily requesting the custom plugin on the copy must resolve through the custom preset
        assert type(copied.get_plugin("custom_plugin")) is CustomPlugin

    def test_copy_preserves_absent_preset(self):
        # build a fully-populated plugin dict so __init__'s "default" fallback doesn't kick in
        base = angr.SimState(arch="AMD64", mode="symbolic")
        plugins = base._copy_plugins()  # pylint: disable=protected-access

        state = angr.SimState(arch="AMD64", mode="symbolic", plugins=plugins, plugin_preset=None)
        assert state.plugin_preset is None

        copied = state.copy()
        assert copied.plugin_preset is None


if __name__ == "__main__":
    unittest.main()
