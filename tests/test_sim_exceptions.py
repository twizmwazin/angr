#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
"""Tests for :mod:`angr.sim_exceptions`."""

from __future__ import annotations

import unittest

import angr
from angr.state_plugins.exceptions import PendingException
from angr.sim_exceptions import (
    CortexMPendingException,
    EXC_RETURN_THREAD_MSP,
    SimExceptionCortexM,
    default_exception_model,
    register_default_exception_model,
)


class TestRegistry(unittest.TestCase):
    def test_cortex_m_registered_by_default(self):
        assert default_exception_model("ARMCortexM") is SimExceptionCortexM

    def test_unknown_arch_returns_none(self):
        assert default_exception_model("MIPS32") is None

    def test_unknown_arch_with_default(self):
        fallback = SimExceptionCortexM
        assert default_exception_model("MIPS32", default=fallback) is fallback

    def test_platform_fallback(self):
        assert default_exception_model("ARMCortexM", platform="Win32") is SimExceptionCortexM

    def test_register_new_model(self):
        class FakeModel(SimExceptionCortexM):
            pass

        register_default_exception_model("FakeArch", FakeModel, platform="Bare")
        assert default_exception_model("FakeArch", platform="Bare") is FakeModel


class TestSimExceptionCortexM(unittest.TestCase):
    def _state(self) -> angr.SimState:
        state = angr.SimState(arch="ARMCortexM")
        state.memory.map_region(0x2000_0000, 0x1000, 7)
        state.regs.sp = 0x2000_0800
        return state

    def _model(self, state: angr.SimState) -> SimExceptionCortexM:
        return SimExceptionCortexM(state.arch)

    def _ev(self, state: angr.SimState, reg: str) -> int:
        return state.solver.eval(getattr(state.regs, reg))

    def test_enter_pushes_frame_and_redirects_pc(self):
        state = self._state()
        state.regs.r0 = 0xA0A0A0A0
        state.regs.lr = 0x0800_1234
        state.regs.pc = 0x0800_5000

        model = self._model(state)
        exc = PendingException(priority=15, payload=CortexMPendingException(handler=0x0800_A800))
        after = model.enter(state, exc)

        assert self._ev(after, "pc") == 0x0800_A801  # handler with thumb bit
        assert self._ev(after, "sp") == 0x2000_0800 - 32
        assert self._ev(after, "lr") == EXC_RETURN_THREAD_MSP

    def test_enter_requires_cortex_m_payload(self):
        state = self._state()
        model = self._model(state)
        exc = PendingException(priority=0, payload="wrong")
        with self.assertRaises(TypeError):
            model.enter(state, exc)

    def test_is_return_point(self):
        state = self._state()
        model = self._model(state)
        state.regs.pc = 0x0800_5000
        assert not model.is_return_point(state)

        # Standard ARMv7-M EXC_RETURN values.
        for magic in (0xFFFFFFF1, 0xFFFFFFF9, 0xFFFFFFFD):
            state.regs.pc = magic
            assert model.is_return_point(state)

        # FP-frame EXC_RETURN variants (FPU pushed).
        for magic in (0xFFFFFFE1, 0xFFFFFFE9, 0xFFFFFFED):
            state.regs.pc = magic
            assert model.is_return_point(state)

    def test_is_return_point_rejects_near_misses(self):
        """0xFFFFFFFx with low bits other than 1/9/D is not EXC_RETURN —
        loose ``(pc & 0xF0) == 0xF0`` matching would mishandle a corrupted
        ``bx lr`` whose target happens to land here, popping random stack
        bytes as a fake exception frame."""
        state = self._state()
        model = self._model(state)
        for pc in (0xFFFFFFF0, 0xFFFFFFF2, 0xFFFFFFF3, 0xFFFFFFF4,
                   0xFFFFFFF5, 0xFFFFFFF6, 0xFFFFFFF7, 0xFFFFFFF8,
                   0xFFFFFFFA, 0xFFFFFFFB, 0xFFFFFFFC, 0xFFFFFFFE,
                   0xFFFFFFFF, 0xFFFFFFE0):
            state.regs.pc = pc
            assert not model.is_return_point(state), f"PC {pc:#x} should not match"

    def test_roundtrip_preserves_registers(self):
        state = self._state()
        state.regs.r0 = 0xA0A0A0A0
        state.regs.r1 = 0xA1A1A1A1
        state.regs.r2 = 0xA2A2A2A2
        state.regs.r3 = 0xA3A3A3A3
        state.regs.r12 = 0xACACACAC
        state.regs.lr = 0x0800_1234
        state.regs.pc = 0x0800_5000

        model = self._model(state)
        exc = PendingException(priority=15, payload=CortexMPendingException(handler=0x0800_A800))
        in_handler = model.enter(state, exc)

        # Simulate handler clobbering R0-R3 then returning
        in_handler.regs.r0 = 0xDEAD0000
        in_handler.regs.r1 = 0xDEAD0001
        in_handler.regs.r2 = 0xDEAD0002
        in_handler.regs.r3 = 0xDEAD0003
        in_handler.regs.pc = EXC_RETURN_THREAD_MSP
        restored = model.exit(in_handler)

        # Original context recovered from the stack frame
        assert self._ev(restored, "pc") == 0x0800_5001  # return addr with thumb bit
        assert self._ev(restored, "sp") == 0x2000_0800
        assert self._ev(restored, "r0") == 0xA0A0A0A0
        assert self._ev(restored, "r1") == 0xA1A1A1A1
        assert self._ev(restored, "r2") == 0xA2A2A2A2
        assert self._ev(restored, "r3") == 0xA3A3A3A3
        assert self._ev(restored, "r12") == 0xACACACAC
        assert self._ev(restored, "lr") == 0x0800_1234

    def test_exit_resets_jumpkind_to_boring(self):
        """``exit()`` must clear ``Ijk_SigSEGV`` on the returning state.

        Concrete engines (icicle) fetch at the EXC_RETURN magic PC and
        fault, so the state about to be passed to ``exit()`` carries
        ``Ijk_SigSEGV`` in its history. Without the reset, downstream
        engines (SimEngineFailure) refuse to continue execution from
        what should be a normal sequential resume."""
        state = self._state()
        state.regs.lr = 0x0800_1234
        state.regs.pc = 0x0800_5000
        model = self._model(state)
        exc = PendingException(priority=15, payload=CortexMPendingException(handler=0x0800_A800))
        in_handler = model.enter(state, exc)

        # Simulate concrete fetch-at-EXC_RETURN faulting before exit() runs.
        in_handler.regs.pc = EXC_RETURN_THREAD_MSP
        in_handler.history.jumpkind = "Ijk_SigSEGV"
        restored = model.exit(in_handler)
        assert restored.history.jumpkind == "Ijk_Boring"

    def test_nested_exception_entries(self):
        """A handler that pre-empts and re-enters another exception."""
        state = self._state()
        state.regs.r0 = 0xAAAA0000
        state.regs.lr = 0x0800_1000
        state.regs.pc = 0x0800_2000

        model = self._model(state)
        # First exception — SysTick-like, priority 15
        exc1 = PendingException(priority=15, payload=CortexMPendingException(handler=0x0800_A000, vector=15))
        s1 = model.enter(state, exc1)
        assert self._ev(s1, "sp") == 0x2000_0800 - 32
        assert self._ev(s1, "pc") == 0x0800_A001

        # Second exception arrives while handling first
        s1.regs.r0 = 0xBBBB0000  # handler modified r0
        exc2 = PendingException(priority=5, payload=CortexMPendingException(handler=0x0800_B000, vector=16))
        s2 = model.enter(s1, exc2)
        assert self._ev(s2, "sp") == 0x2000_0800 - 64  # two frames
        assert self._ev(s2, "pc") == 0x0800_B001

        # Return from second exception
        s2.regs.pc = EXC_RETURN_THREAD_MSP
        s3 = model.exit(s2)
        assert self._ev(s3, "sp") == 0x2000_0800 - 32  # back to first frame
        # Return to first handler's saved PC (which was the handler1 entry point)
        assert self._ev(s3, "pc") == 0x0800_A001
        assert self._ev(s3, "r0") == 0xBBBB0000

        # Return from first exception
        s3.regs.pc = EXC_RETURN_THREAD_MSP
        s4 = model.exit(s3)
        assert self._ev(s4, "sp") == 0x2000_0800
        assert self._ev(s4, "pc") == 0x0800_2001  # original pc with thumb bit
        assert self._ev(s4, "r0") == 0xAAAA0000  # original r0 restored


if __name__ == "__main__":
    unittest.main()
