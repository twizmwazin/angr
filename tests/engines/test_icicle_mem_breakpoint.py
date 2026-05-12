#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
"""Tests for icicle memory breakpoints.

Covers the Rust ``Icicle.add_memory_breakpoint`` binding and the
``IcicleEngine`` machinery that fires ``mem_read`` / ``mem_write``
inspect breakpoints on accesses to ranges added to
``state.icicle.mem_breakpoints``.
"""

from __future__ import annotations

import os
import struct
import unittest

import angr
import claripy
from angr.engines.icicle import UberIcicleEngine
from angr.rustylib.icicle import ExceptionCode, Icicle, VmExit


def _processors_dir() -> str:
    import pypcode
    return os.path.join(os.path.dirname(pypcode.__file__), "processors")


class TestRustBinding(unittest.TestCase):
    """Exercise the raw pyo3 binding: arm a memory breakpoint over an
    address range via ``add_memory_breakpoint`` and observe icicle traps."""

    def test_load_traps_after_add_memory_breakpoint(self):
        """A page armed with ``add_memory_breakpoint`` + a load into it
        halts icicle with ``ExceptionCode.ReadWatch`` at the faulting PC."""
        emu = Icicle("armv7m", _processors_dir(), True, True)
        emu.mem_map(0x08000000, 0x1000, 5)  # RX code
        emu.mem_map(0x40000000, 0x1000, 3)  # RW data
        # ldr r0, [r1, #0] ; bkpt
        emu.mem_write(0x08000000, list(b"\x08\x68\xff\xbe"))
        emu.add_memory_breakpoint(0x40000000, 0x1000)
        emu.reg_write("r1", 0x40000010)
        emu.pc = 0x08000000
        emu.isa_mode = 1
        status = emu.run()
        assert status == VmExit.UnhandledException, status
        assert emu.exception_code == ExceptionCode.ReadWatch, emu.exception_code
        assert emu.pc == 0x08000000, hex(emu.pc)

    def test_store_traps_after_add_memory_breakpoint(self):
        """A page armed with ``add_memory_breakpoint`` + a store into it
        halts icicle with ``ExceptionCode.WriteWatch``."""
        emu = Icicle("armv7m", _processors_dir(), True, True)
        emu.mem_map(0x08000000, 0x1000, 5)
        emu.mem_map(0x40000000, 0x1000, 3)
        # str r0, [r1, #0] ; bkpt
        emu.mem_write(0x08000000, list(b"\x08\x60\xff\xbe"))
        emu.add_memory_breakpoint(0x40000000, 0x1000)
        emu.reg_write("r0", 0xDEADBEEF)
        emu.reg_write("r1", 0x40000020)
        emu.pc = 0x08000000
        emu.isa_mode = 1
        status = emu.run()
        assert status == VmExit.UnhandledException, status
        assert emu.exception_code == ExceptionCode.WriteWatch, emu.exception_code

    def test_unarmed_page_does_not_trap(self):
        """Loading from a regular (unarmed) RW page proceeds without a
        trap, returning whatever was in icicle physical memory."""
        emu = Icicle("armv7m", _processors_dir(), True, True)
        emu.mem_map(0x08000000, 0x1000, 5)
        emu.mem_map(0x20000000, 0x1000, 3)
        emu.mem_write(0x20000000, list(struct.pack("<I", 0x12345678)))
        emu.mem_write(0x08000000, list(b"\x08\x68\xff\xbe"))
        emu.reg_write("r1", 0x20000000)
        emu.pc = 0x08000000
        emu.isa_mode = 1
        emu.run()
        assert emu.reg_read("r0") == 0x12345678

    def test_add_memory_breakpoint_size_zero_errors(self):
        """``add_memory_breakpoint`` rejects size=0 explicitly so a
        zero-length range doesn't silently become a no-op."""
        emu = Icicle("armv7m", _processors_dir(), True, True)
        with self.assertRaises(RuntimeError):
            emu.add_memory_breakpoint(0x40000000, 0)

    def test_add_memory_breakpoint_unmapped_pages_silent(self):
        """A range spanning unmapped pages does not error; unmapped
        pages are silently skipped (the user may register before mapping
        is settled)."""
        emu = Icicle("armv7m", _processors_dir(), True, True)
        # Nothing mapped at 0x40000000.
        emu.add_memory_breakpoint(0x40000000, 0x1000)  # should not raise


_LOAD_BASE = 0x08000000

# ldr r0, [r1, #0] ; bkpt #0xff
_LDR_SHELLCODE = b"\x08\x68\xff\xbe"

# str r2, [r3, #0] ; bkpt #0xff
_STR_SHELLCODE = b"\x1a\x60\xff\xbe"


def _shellcode_state(code: bytes) -> tuple[angr.Project, angr.SimState]:
    """Build a tiny ARMCortexM project + blank state ready to execute
    ``code`` (Thumb). Two extra RW regions are mapped on the state at
    fixed addresses for tests to drive loads/stores against.
    """
    proj = angr.load_shellcode(
        code,
        "ARMCortexM",
        load_address=_LOAD_BASE,
        thumb=True,
    )
    state = proj.factory.blank_state(
        addr=_LOAD_BASE | 1,
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        },
    )
    state.memory.map_region(0x20000000, 0x1000, 7)
    state.memory.map_region(0x40000000, 0x1000, 3)
    state.regs.sp = 0x20001000
    return proj, state


class TestEngineDispatch(unittest.TestCase):
    """End-to-end: add a range to ``state.icicle.mem_breakpoints``, run
    a Thumb load/store that accesses it, verify ``mem_read`` /
    ``mem_write`` inspect breakpoints fire with the live PC and operand
    register context.
    """

    def test_load_fires_mem_read_inspect_with_handler_supplied_value(self):
        proj, state = _shellcode_state(_LDR_SHELLCODE)
        state.regs.r1 = 0x40000010

        observed = []
        def on_read(s):
            addr = s.solver.eval(s.inspect.attrs.mem_read_address)
            length = s.inspect.attrs.mem_read_length
            if length is not None and not s.solver.symbolic(length):
                length = s.solver.eval(length)
            else:
                length = 4
            if addr == 0x40000010:
                observed.append((addr, length))
                s.inspect.attrs.mem_read_expr = claripy.BVV(0xCAFEBABE, length * 8)
        state.inspect.b("mem_read", when=angr.BP_AFTER, action=on_read)

        state.icicle.mem_breakpoints.add((0x40000000, 0x40001000))
        emu = angr.Emulator(UberIcicleEngine(proj), state)
        emu.run(num_inst=4)

        assert (0x40000010, 4) in observed, f"inspect did not fire, observed={observed}"
        assert emu.state.solver.eval(emu.state.regs.r0) == 0xCAFEBABE

    def test_store_fires_mem_write_inspect(self):
        proj, state = _shellcode_state(_STR_SHELLCODE)
        state.regs.r2 = 0xDEADBEEF
        state.regs.r3 = 0x40000020

        captured = []
        def on_write(s):
            addr = s.solver.eval(s.inspect.attrs.mem_write_address)
            expr = s.inspect.attrs.mem_write_expr
            if expr is None or s.solver.symbolic(expr):
                return
            captured.append((addr, s.solver.eval(expr)))
        state.inspect.b("mem_write", when=angr.BP_BEFORE, action=on_write)

        state.icicle.mem_breakpoints.add((0x40000000, 0x40001000))
        emu = angr.Emulator(UberIcicleEngine(proj), state)
        emu.run(num_inst=4)

        assert (0x40000020, 0xDEADBEEF) in captured, f"observed writes: {captured}"

    def test_no_range_means_no_dispatch(self):
        """Without an entry in ``state.icicle.mem_breakpoints`` the load
        reads icicle physical memory directly (no trap, no inspect)."""
        proj, state = _shellcode_state(_LDR_SHELLCODE)
        state.regs.r1 = 0x40000010
        # state.icicle.mem_breakpoints stays empty.
        emu = angr.Emulator(UberIcicleEngine(proj), state)
        emu.run(num_inst=4)
        # The page is mapped RW with zero-init, so the load returns 0.
        assert emu.state.solver.eval(emu.state.regs.r0) == 0


if __name__ == "__main__":
    unittest.main()
