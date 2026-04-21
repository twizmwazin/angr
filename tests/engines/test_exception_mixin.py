#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
"""End-to-end tests for the ExceptionMixin.

These tests construct a minimal Cortex-M program and verify that a pending
exception is dispatched to the handler, the handler's ``BX LR`` with an
``EXC_RETURN`` value triggers the exit path, and the interrupted code
resumes from the correct PC.
"""

from __future__ import annotations

import struct
import unittest

import angr
from angr.engines.icicle import UberIcicleEngine
from angr.sim_exceptions import CortexMPendingException
from angr.state_plugins.exceptions import PendingException


def _build_tiny_cortex_m() -> angr.Project:
    """A minimal Cortex-M 'program' used purely for wiring tests.

    Flash layout:
      0x08000000-0x08001000: code region
      0x08000000            : initial SP (part of vector table)
      0x08000004            : reset vector (unused here)
      0x08000100            : main code: infinite loop (b .)
      0x08000200            : SysTick handler: increment r4, bx lr
    """
    # Vector table + main code + handler.
    data = bytearray(0x1000)
    # Initial SP
    struct.pack_into("<I", data, 0, 0x20001000)
    # Reset vector
    struct.pack_into("<I", data, 4, 0x08000101)  # thumb-bit set
    # SysTick vector (entry 15, offset 0x3C)
    struct.pack_into("<I", data, 0x3C, 0x08000201)  # thumb-bit set

    # Main code at 0x08000100: "b ." (infinite loop)
    # Thumb: b . = 0xE7FE
    struct.pack_into("<H", data, 0x100, 0xE7FE)

    # Handler at 0x08000200: adds r4, r4, #1; bx lr
    struct.pack_into("<H", data, 0x200, 0x3401)  # adds r4, #1
    struct.pack_into("<H", data, 0x202, 0x4770)  # bx lr

    # Write to a temp file so angr can load it.
    import tempfile, os
    fd, path = tempfile.mkstemp(suffix=".bin")
    os.write(fd, bytes(data))
    os.close(fd)

    proj = angr.Project(
        path,
        main_opts={
            "backend": "blob",
            "arch": "ARMCortexM",
            "base_addr": 0x08000000,
            "entry_point": 0x08000100,
        },
        load_options={"auto_load_libs": False},
    )
    return proj


class TestExceptionMixinEndToEnd(unittest.TestCase):
    def test_pending_exception_dispatches_to_handler(self):
        proj = _build_tiny_cortex_m()
        engine = UberIcicleEngine(proj)

        state = proj.factory.blank_state(
            addr=0x08000101,
            add_options={
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            },
        )
        state.memory.map_region(0x20000000, 0x1000, 7)
        state.regs.sp = 0x20001000
        state.regs.r4 = 0  # handler will increment this

        emu = angr.Emulator(engine, state)

        # Pend a SysTick exception.
        emu.state.exceptions.pend(PendingException(
            priority=15,
            payload=CortexMPendingException(handler=0x08000200, vector=15),
        ))

        # Run enough to let the mixin dispatch the exception, execute the
        # two-instruction handler (adds r4, #1; bx lr), and return.
        emu.run(num_inst=20)

        # Key invariant: the handler ran. If it ran once we see r4 == 1.
        r4 = emu.state.solver.eval(emu.state.regs.r4)
        assert r4 >= 1, f"handler should have incremented r4 at least once, got {r4}"

    def test_exception_return_resumes_at_original_pc(self):
        """After the handler's ``bx lr``, execution must resume at the
        pre-exception PC with SP restored. This exercises the full path:
        ``is_return_point`` → ``exit()`` → ``process_successors``
        replaces the entry in ``successors.successors`` (which
        ``angr.Emulator`` reads). Updating only ``flat_successors`` would
        silently leave the EXC_RETURN-PC state in ``successors``,
        producing an Ijk_SigSEGV (icicle fault on the magic PC)."""
        proj = _build_tiny_cortex_m()
        engine = UberIcicleEngine(proj)
        state = proj.factory.blank_state(
            addr=0x08000101,
            add_options={
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            },
        )
        state.memory.map_region(0x20000000, 0x1000, 7)
        state.regs.sp = 0x20001000

        emu = angr.Emulator(engine, state)
        emu.state.exceptions.pend(PendingException(
            priority=15,
            payload=CortexMPendingException(handler=0x08000200, vector=15),
        ))
        emu.run(num_inst=20)

        # After return, SP is restored and PC is back in the infinite
        # loop at 0x08000100 (or the immediately-following insn).
        sp = emu.state.solver.eval(emu.state.regs.sp)
        pc = emu.state.solver.eval(emu.state.regs.pc) & ~1
        assert sp == 0x20001000, f"SP should be restored to 0x20001000, got {sp:#x}"
        assert pc == 0x08000100, f"PC should be back at the loop, got {pc:#x}"
        # And the jumpkind must be Ijk_Boring, not the SigSEGV that icicle
        # produced when trying to fetch at the EXC_RETURN magic PC.
        assert emu.state.history.jumpkind == "Ijk_Boring", (
            f"jumpkind should be Ijk_Boring after exception return, "
            f"got {emu.state.history.jumpkind}"
        )


if __name__ == "__main__":
    unittest.main()
