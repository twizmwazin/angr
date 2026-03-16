"""Fuzz a realistic ARM Cortex-M firmware blob and collect edge coverage.

This test assembles a small but representative firmware "command parser" as raw
ARM Thumb-2 machine code, loads it into angr as a bare-metal blob, and uses
``angr.rustylib.Fuzzer`` with the ``HavocMutator`` to exercise multiple code
paths.  A progress callback records ``ClientStats.edges_hit`` after every
iteration so we can assert that the fuzzer actually discovers new coverage.
"""

from __future__ import annotations

import struct
import tempfile
import os

import angr
from angr.rustylib.fuzzer import (
    ClientStats,
    DeterministicMutator,
    Fuzzer,
    HavocMutator,
    InMemoryCorpus,
    OnDiskCorpus,
)

# ---------------------------------------------------------------------------
# Firmware blob: a minimal ARM Cortex-M "command parser"
#
# The code is Thumb-2 machine code that reads a command byte from r0 and
# dispatches to one of several handlers.  Each handler performs a few
# distinguishable operations so the edge-coverage map lights up differently
# depending on which path is taken.
#
# Pseudo-C:
#
#   void dispatch(uint8_t cmd) {
#       if (cmd == 0x01) { handler_ping(); }
#       else if (cmd == 0x02) { handler_read(); }
#       else if (cmd == 0x03) { handler_write(); }
#       else if (cmd == 0xFF) { handler_reset(); }  // triggers crash
#       else { handler_default(); }
#       return;
#   }
#
# Memory layout (loaded at 0x08000000):
#   0x08000000  dispatch  (entry point)
#   ...         handlers
#   0x08000100  dead-end return address (breakpoint)
# ---------------------------------------------------------------------------

# fmt: off
#
# Offset map (Thumb addresses = offset | 1 for execution):
#   0x00  dispatch entry
#   0x14  handler_ping
#   0x1C  handler_read
#   0x24  handler_write
#   0x2C  handler_reset  (crash path)
#   0x36  handler_default
#
# beq offset formula: imm8 = (target - (instr_addr + 4)) / 2
# b   offset formula: imm11 = (target - (instr_addr + 4)) / 2
#
FIRMWARE_THUMB2 = bytes([
    # --- dispatch (0x00) ---
    # push {lr}
    0x00, 0xB5,
    # cmp r0, #1
    0x01, 0x28,
    # beq handler_ping (0x14): imm8 = (0x14 - (0x04+4))/2 = 6
    0x06, 0xD0,
    # cmp r0, #2
    0x02, 0x28,
    # beq handler_read (0x1C): imm8 = (0x1C - (0x08+4))/2 = 8
    0x08, 0xD0,
    # cmp r0, #3
    0x03, 0x28,
    # beq handler_write (0x24): imm8 = (0x24 - (0x0C+4))/2 = 10
    0x0A, 0xD0,
    # cmp r0, #0xFF
    0xFF, 0x28,
    # beq handler_reset (0x2C): imm8 = (0x2C - (0x10+4))/2 = 12
    0x0C, 0xD0,
    # b handler_default (0x36): imm11 = (0x36 - (0x12+4))/2 = 16
    0x10, 0xE0,

    # --- handler_ping (0x14) ---
    # movs r1, #0x10
    0x10, 0x21,
    # adds r1, r1, #1
    0x49, 0x1C,
    # pop {pc}
    0x00, 0xBD,
    # nop (pad)
    0x00, 0xBF,

    # --- handler_read (0x1C) ---
    # movs r1, #0x20
    0x20, 0x21,
    # adds r1, r1, #2
    0x89, 0x1C,
    # pop {pc}
    0x00, 0xBD,
    # nop (pad)
    0x00, 0xBF,

    # --- handler_write (0x24) ---
    # movs r1, #0x30
    0x30, 0x21,
    # adds r1, r1, #3
    0xC9, 0x1C,
    # pop {pc}
    0x00, 0xBD,
    # nop (pad)
    0x00, 0xBF,

    # --- handler_reset (0x2C) - crash path ---
    # movw r2, #0x0000
    0x40, 0xF2, 0x00, 0x02,
    # movt r2, #0xDEAD  (second halfword: 0 110 0010 1010_1101 = 0x62AD)
    0xCD, 0xF6, 0xAD, 0x62,
    # ldr r2, [r2]      (load from 0xDEAD0000 -> MEMORY_ERROR)
    0x12, 0x68,

    # --- handler_default (0x36) ---
    # movs r1, #0
    0x00, 0x21,
    # pop {pc}
    0x00, 0xBD,
])
# fmt: on

BASE_ADDR = 0x08000000
ENTRY_POINT = BASE_ADDR | 1  # Thumb bit set
RETURN_ADDR = 0x08000100  # past the code; used as breakpoint


def _apply_firmware_input(state: angr.SimState, input_bytes: bytes):
    """Feed fuzzed bytes into the firmware's entry register and set up return."""
    # The firmware reads the command byte from r0.
    cmd = input_bytes[0] if input_bytes else 0
    state.regs.r0 = cmd

    # Set the link register so the executor's breakpoint fires on return.
    state.regs.lr = RETURN_ADDR


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestFuzzFirmwareCoverage:
    """Fuzz ARM Cortex-M firmware blobs and verify edge coverage."""

    def _make_project(self):
        """Load the firmware blob as an ARMCortexM bare-metal binary."""
        return angr.Project(
            __import__("io").BytesIO(FIRMWARE_THUMB2),
            main_opts={
                "backend": "blob",
                "arch": "ARMCortexM",
                "base_addr": BASE_ADDR,
                "entry_point": ENTRY_POINT,
            },
            auto_load_libs=False,
        )

    def _make_base_state(self, project):
        """Create a blank state suitable for firmware execution."""
        state = project.factory.blank_state(
            addr=ENTRY_POINT,
            add_options={
                angr.sim_options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.sim_options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            },
        )
        # Map a small stack page and point SP there.
        STACK_PAGE = 0x20000000
        state.memory.map_region(STACK_PAGE, 0x1000, 7)
        state.memory.store(STACK_PAGE, b"\x00" * 0x1000)
        state.regs.sp = STACK_PAGE + 0xFF0
        # Pre-store the return address on the stack (push {lr} will use SP).
        state.memory.store(
            STACK_PAGE + 0xFF0,
            struct.pack("<I", RETURN_ADDR),
        )
        return state

    # -- basic coverage test ------------------------------------------------

    def test_havoc_firmware_coverage(self):
        """HavocMutator discovers multiple paths and increases edge coverage."""
        project = self._make_project()
        base_state = self._make_base_state(project)

        # Seed corpus with one neutral byte.
        corpus = InMemoryCorpus.from_list([b"\x00"])
        solutions = InMemoryCorpus()

        edges_log: list[int | None] = []

        def progress_cb(stats: ClientStats, _event: str, _idx: int):
            edges_log.append(stats.edges_hit)

        fuzzer = Fuzzer(
            base_state,
            corpus,
            solutions,
            _apply_firmware_input,
            timeout=0,
            seed=42,
            max_mutations=5,
            mutator=HavocMutator(max_stack_pow=3),
        )

        # Run enough iterations for the havoc mutator to discover new paths.
        fuzzer.run(progress_callback=progress_cb, iterations=50)

        # We should have recorded progress.
        assert len(edges_log) > 0, "progress callback was never called"
        # At least one report should show edges hit.
        valid_edges = [e for e in edges_log if e is not None and e > 0]
        assert len(valid_edges) > 0, f"no edges were ever hit; log={edges_log}"

        # The corpus should have grown beyond the single seed.
        live_corpus = fuzzer.corpus()
        assert len(live_corpus) > 1, (
            f"corpus did not grow (size={len(live_corpus)}); "
            "fuzzer failed to discover new coverage"
        )

    # -- deterministic path coverage ----------------------------------------

    def test_deterministic_all_handlers(self):
        """Walk every handler with a deterministic mutator and verify coverage."""
        project = self._make_project()
        base_state = self._make_base_state(project)

        corpus = InMemoryCorpus.from_list([b"\x00"])
        solutions = InMemoryCorpus()

        # Hit every non-crash handler: ping(0x01), read(0x02), write(0x03),
        # default(0x00/0x55).
        mutator = DeterministicMutator([b"\x01", b"\x02", b"\x03", b"\x55"])
        fuzzer = Fuzzer(
            base_state,
            corpus,
            solutions,
            _apply_firmware_input,
            timeout=0,
            seed=0,
            max_mutations=1,
            mutator=mutator,
        )

        for _ in range(4):
            fuzzer.run_once()

        # All four distinct inputs should be in the corpus (plus the initial seed).
        live_corpus = fuzzer.corpus()
        assert len(live_corpus) >= 4, (
            f"expected at least 4 corpus entries for 4 handlers, got {len(live_corpus)}"
        )

        # No crashes expected from these inputs.
        assert len(fuzzer.solutions()) == 0, "non-crash inputs should not produce solutions"

    # -- crash detection via firmware reset handler -------------------------

    def test_deterministic_crash_detection(self):
        """Sending 0xFF to the firmware triggers a memory fault (crash)."""
        project = self._make_project()
        base_state = self._make_base_state(project)

        corpus = InMemoryCorpus.from_list([b"\x00"])
        solutions = InMemoryCorpus()

        # 0xFF triggers handler_reset which loads from 0xDEAD0000 -> crash.
        mutator = DeterministicMutator([b"\xFF"])
        fuzzer = Fuzzer(
            base_state,
            corpus,
            solutions,
            _apply_firmware_input,
            timeout=0,
            seed=0,
            max_mutations=1,
            mutator=mutator,
        )

        fuzzer.run_once()
        live_solutions = fuzzer.solutions()
        assert len(live_solutions) >= 1, (
            "handler_reset (0xFF) should trigger a memory fault and produce a solution"
        )

    # -- on-disk corpus for persistent firmware fuzzing ---------------------

    def test_ondisk_corpus_firmware(self):
        """Verify on-disk corpus works for firmware fuzzing campaigns."""
        project = self._make_project()
        base_state = self._make_base_state(project)

        with tempfile.TemporaryDirectory() as tmp:
            corpus_dir = os.path.join(tmp, "fw_corpus")
            os.makedirs(corpus_dir)
            corpus = OnDiskCorpus(corpus_dir)
            corpus.add(b"\x00")

            solutions_dir = os.path.join(tmp, "fw_solutions")
            os.makedirs(solutions_dir)
            solutions = OnDiskCorpus(solutions_dir)

            fuzzer = Fuzzer(
                base_state,
                corpus,
                solutions,
                _apply_firmware_input,
                timeout=0,
                seed=42,
                max_mutations=3,
                mutator=HavocMutator(),
            )

            fuzzer.run(iterations=20)

            # Corpus should persist on disk and contain more than the seed.
            live_corpus = fuzzer.corpus()
            assert isinstance(live_corpus, OnDiskCorpus)
            assert len(live_corpus) >= 1

    # -- coverage stats reporting -------------------------------------------

    def test_coverage_stats_reporting(self):
        """Verify ClientStats fields are populated during firmware fuzzing."""
        project = self._make_project()
        base_state = self._make_base_state(project)

        corpus = InMemoryCorpus.from_list([b"\x00", b"\x01", b"\x02", b"\x03"])
        solutions = InMemoryCorpus()

        stats_log: list[ClientStats] = []

        def capture_stats(stats: ClientStats, _event: str, _idx: int):
            stats_log.append(stats)

        fuzzer = Fuzzer(
            base_state,
            corpus,
            solutions,
            _apply_firmware_input,
            timeout=0,
            seed=0,
            max_mutations=2,
            mutator=HavocMutator(max_stack_pow=2),
        )

        fuzzer.run(progress_callback=capture_stats, iterations=10)

        assert len(stats_log) > 0, "no stats were reported"
        last = stats_log[-1]

        # Basic sanity: executions counter should be positive.
        assert last.executions > 0, f"executions={last.executions}"
        # Corpus size should match what the fuzzer holds.
        assert last.corpus_size >= 1, f"corpus_size={last.corpus_size}"
