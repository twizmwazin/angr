"""
Performance benchmark for angr.rustylib.Fuzzer

Measures fuzzer throughput across different scenarios:
1. Simple shellcode with branching (small input, fast execution)
2. Shellcode with crash path (exercises crash feedback)
3. Real binary (vuln_stacksmash) with larger inputs
4. Scaling: increasing corpus sizes
5. Scaling: increasing input sizes

Also profiles where time is spent in the fuzzing loop by breaking down:
- Fuzzer initialization time
- Per-iteration execution time
- State copy overhead (via apply_fn instrumentation)
"""
from __future__ import annotations

import cProfile
import logging
import os
import pstats
import struct
import sys
import time

# Suppress noisy warnings that dominate output during benchmarks
logging.disable(logging.WARNING)

import angr
from angr.rustylib.fuzzer import (
    DeterministicMutator,
    Fuzzer,
    HavocMutator,
    InMemoryCorpus,
)

bin_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../../binaries")

# ---------------------------------------------------------------------------
# Shellcode targets
# ---------------------------------------------------------------------------

SHELLCODE_SIMPLE = """
cmp al, 0x41
je path_a
cmp al, 0x42
je path_b
cmp al, 0x43
je path_c
cmp al, 0x44
je path_d
ret
path_a:
nop
ret
path_b:
nop
nop
ret
path_c:
nop
nop
nop
ret
path_d:
nop
nop
nop
nop
ret
"""

SHELLCODE_WITH_CRASH = """
cmp al, 0x43
je crash_path
cmp al, 0x41
je path_a
ret
path_a:
nop
ret
crash_path:
mov rdi, 0xdeadbeef
mov byte ptr [rdi], 0
ret
"""

RETURN_ADDR = 0x100


# ---------------------------------------------------------------------------
# Apply functions
# ---------------------------------------------------------------------------

def _apply_fn_simple(state: angr.SimState, input_bytes: bytes):
    """Apply function for simple shellcode: feed first byte into rax."""
    state.regs.rax = input_bytes[0] if input_bytes else 0
    cc = state.project.factory.cc()
    cc.return_addr.set_value(state, RETURN_ADDR)


def _make_stacksmash_apply_fn(rbp: int, stack_ret: int):
    """Factory for the stack-smash apply function."""
    def apply_fn(state: angr.SimState, input_bytes: bytes):
        state.memory.store(rbp, struct.pack("<Q", 0))
        state.memory.store(rbp + 8, struct.pack("<Q", stack_ret))
        state.memory.store(rbp - 0x70, input_bytes)
        cc = state.project.factory.cc()
        cc.return_addr.set_value(state, stack_ret)
    return apply_fn


# ---------------------------------------------------------------------------
# Benchmark helpers
# ---------------------------------------------------------------------------

def _time_it(fn, *args, **kwargs):
    """Run fn and return (result, elapsed_seconds)."""
    start = time.perf_counter()
    result = fn(*args, **kwargs)
    elapsed = time.perf_counter() - start
    return result, elapsed


def _run_benchmark(name, fuzzer, iterations, warmup=2):
    """Run a fuzzer benchmark and print results."""
    # Warmup
    for _ in range(warmup):
        fuzzer.run_once()

    # Timed run
    start = time.perf_counter()
    for _ in range(iterations):
        fuzzer.run_once()
    elapsed = time.perf_counter() - start

    execs_per_sec = iterations / elapsed if elapsed > 0 else float("inf")
    ms_per_exec = (elapsed / iterations) * 1000 if iterations > 0 else 0

    print(f"  {name}:")
    print(f"    Iterations:    {iterations}")
    print(f"    Total time:    {elapsed:.3f}s")
    print(f"    Per iteration: {ms_per_exec:.3f}ms")
    print(f"    Throughput:    {execs_per_sec:.1f} exec/s")
    return elapsed, execs_per_sec


# ---------------------------------------------------------------------------
# Benchmark scenarios
# ---------------------------------------------------------------------------

def bench_simple_shellcode(iterations=100):
    """Benchmark: simple shellcode with havoc mutator."""
    print("\n=== Benchmark: Simple Shellcode (Havoc Mutator) ===")

    project = angr.load_shellcode(SHELLCODE_SIMPLE, "amd64")
    base_state = project.factory.entry_state()
    corpus = InMemoryCorpus.from_list([b"\x00", b"A", b"B", b"C", b"D"])
    solutions = InMemoryCorpus()

    _, init_time = _time_it(
        Fuzzer, base_state, corpus, solutions, _apply_fn_simple, 0, 0, max_mutations=2
    )
    print(f"  Init time: {init_time * 1000:.1f}ms")

    # Re-create for benchmark (init is part of setup, not measured)
    corpus = InMemoryCorpus.from_list([b"\x00", b"A", b"B", b"C", b"D"])
    solutions = InMemoryCorpus()
    fuzzer = Fuzzer(base_state, corpus, solutions, _apply_fn_simple, 0, 0, max_mutations=2)

    return _run_benchmark("simple_shellcode_havoc", fuzzer, iterations)


def bench_simple_shellcode_deterministic(iterations=100):
    """Benchmark: simple shellcode with deterministic mutator."""
    print("\n=== Benchmark: Simple Shellcode (Deterministic Mutator) ===")

    project = angr.load_shellcode(SHELLCODE_SIMPLE, "amd64")
    base_state = project.factory.entry_state()
    corpus = InMemoryCorpus.from_list([b"\x00"])
    solutions = InMemoryCorpus()

    values = [bytes([i]) for i in range(256)]
    mutator = DeterministicMutator(values)
    fuzzer = Fuzzer(
        base_state, corpus, solutions, _apply_fn_simple, 0, 0,
        max_mutations=1, mutator=mutator,
    )

    return _run_benchmark("simple_shellcode_deterministic", fuzzer, iterations)


def bench_crash_detection(iterations=50):
    """Benchmark: shellcode with crash path (exercises CrashFeedback)."""
    print("\n=== Benchmark: Crash Detection Shellcode ===")

    project = angr.load_shellcode(SHELLCODE_WITH_CRASH, "amd64")
    base_state = project.factory.entry_state()
    corpus = InMemoryCorpus.from_list([b"\x00"])
    solutions = InMemoryCorpus()

    mutator = DeterministicMutator([b"\x41", b"\x43", b"\x00", b"\x42"])
    fuzzer = Fuzzer(
        base_state, corpus, solutions, _apply_fn_simple, 0, 0,
        max_mutations=1, mutator=mutator,
    )

    elapsed, execs_per_sec = _run_benchmark("crash_detection", fuzzer, iterations)
    num_solutions = len(fuzzer.solutions())
    print(f"    Solutions found: {num_solutions}")
    return elapsed, execs_per_sec


def bench_real_binary(iterations=50):
    """Benchmark: real binary (vuln_stacksmash)."""
    print("\n=== Benchmark: Real Binary (vuln_stacksmash) ===")

    bin_path = os.path.join(bin_location, "tests", "x86_64", "vuln_stacksmash")
    if not os.path.exists(bin_path):
        print("  SKIPPED: binary not found at", bin_path)
        return None, None

    project = angr.Project(bin_path, auto_load_libs=False)

    AFTER_READ = 0x400505
    STACK_RET = 0x400100
    STACK_PAGE = 0x651000

    base_state = project.factory.blank_state(
        addr=AFTER_READ,
        add_options={
            angr.sim_options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.sim_options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
        },
    )
    base_state.memory.map_region(STACK_PAGE, 0x1000, 7)
    base_state.memory.store(STACK_PAGE, b"\x00" * 0x1000)

    RBP = STACK_PAGE + 0xFF0
    base_state.regs.rbp = RBP
    base_state.regs.rsp = RBP - 0x70

    apply_fn = _make_stacksmash_apply_fn(RBP, STACK_RET)

    # Mix of safe and crash inputs
    seeds = [b"\x00" * 64, b"A" * 64, b"A" * 128]
    mutator = DeterministicMutator(seeds)
    corpus = InMemoryCorpus.from_list([b"\x00" * 16])
    solutions = InMemoryCorpus()

    fuzzer = Fuzzer(
        base_state, corpus, solutions, apply_fn, 0, 0,
        max_mutations=1, mutator=mutator,
    )

    elapsed, execs_per_sec = _run_benchmark("vuln_stacksmash", fuzzer, iterations)
    num_solutions = len(fuzzer.solutions())
    print(f"    Solutions found: {num_solutions}")
    return elapsed, execs_per_sec


def bench_corpus_scaling():
    """Benchmark: measure impact of corpus size on iteration time."""
    print("\n=== Benchmark: Corpus Size Scaling ===")

    project = angr.load_shellcode(SHELLCODE_SIMPLE, "amd64")
    base_state = project.factory.entry_state()

    iterations = 10
    for corpus_size in [1, 10, 50, 100]:
        seeds = [bytes([i % 256]) for i in range(corpus_size)]
        corpus = InMemoryCorpus.from_list(seeds)
        solutions = InMemoryCorpus()
        fuzzer = Fuzzer(
            base_state, corpus, solutions, _apply_fn_simple, 0, 0, max_mutations=2
        )
        _run_benchmark(f"corpus_size={corpus_size}", fuzzer, iterations, warmup=1)


def bench_input_size_scaling():
    """Benchmark: measure impact of input size on iteration time."""
    print("\n=== Benchmark: Input Size Scaling ===")

    project = angr.load_shellcode(SHELLCODE_SIMPLE, "amd64")
    base_state = project.factory.entry_state()

    iterations = 10
    for input_size in [1, 16, 64, 256, 1024, 4096]:
        seed = b"\x41" * input_size
        corpus = InMemoryCorpus.from_list([seed])
        solutions = InMemoryCorpus()

        mutator = DeterministicMutator([b"\x42" * input_size])
        fuzzer = Fuzzer(
            base_state, corpus, solutions, _apply_fn_simple, 0, 0,
            max_mutations=1, mutator=mutator,
        )
        _run_benchmark(f"input_size={input_size}B", fuzzer, iterations, warmup=1)


def bench_mutation_count_scaling():
    """Benchmark: measure impact of max_mutations on iteration time."""
    print("\n=== Benchmark: Mutation Count Scaling ===")

    project = angr.load_shellcode(SHELLCODE_SIMPLE, "amd64")
    base_state = project.factory.entry_state()

    iterations = 10
    for max_mutations in [1, 2, 5, 10, 25]:
        corpus = InMemoryCorpus.from_list([b"\x00", b"A", b"B", b"C"])
        solutions = InMemoryCorpus()
        fuzzer = Fuzzer(
            base_state, corpus, solutions, _apply_fn_simple, 0, 0,
            max_mutations=max_mutations,
        )
        _run_benchmark(f"max_mutations={max_mutations}", fuzzer, iterations, warmup=1)


# ---------------------------------------------------------------------------
# Profiling
# ---------------------------------------------------------------------------

def profile_fuzzer(iterations=200):
    """Profile the fuzzer with cProfile to identify hotspots."""
    print("\n=== cProfile: Fuzzer Hot Path ===")

    project = angr.load_shellcode(SHELLCODE_SIMPLE, "amd64")
    base_state = project.factory.entry_state()
    corpus = InMemoryCorpus.from_list([b"\x00", b"A", b"B", b"C", b"D"])
    solutions = InMemoryCorpus()
    fuzzer = Fuzzer(
        base_state, corpus, solutions, _apply_fn_simple, 0, 0, max_mutations=2
    )

    # Warmup
    for _ in range(5):
        fuzzer.run_once()

    profiler = cProfile.Profile()
    profiler.enable()
    for _ in range(iterations):
        fuzzer.run_once()
    profiler.disable()

    stats = pstats.Stats(profiler)
    stats.strip_dirs()

    print("\n  --- Top 30 by cumulative time ---")
    stats.sort_stats("cumulative")
    stats.print_stats(30)

    print("\n  --- Top 30 by total (self) time ---")
    stats.sort_stats("tottime")
    stats.print_stats(30)

    return stats


def profile_apply_fn_overhead(iterations=200):
    """Measure how much time is spent in the Python apply_fn callback."""
    print("\n=== Profile: apply_fn Overhead ===")

    project = angr.load_shellcode(SHELLCODE_SIMPLE, "amd64")
    base_state = project.factory.entry_state()

    apply_fn_total = 0.0
    apply_fn_calls = 0

    def instrumented_apply_fn(state: angr.SimState, input_bytes: bytes):
        nonlocal apply_fn_total, apply_fn_calls
        t0 = time.perf_counter()
        _apply_fn_simple(state, input_bytes)
        apply_fn_total += time.perf_counter() - t0
        apply_fn_calls += 1

    corpus = InMemoryCorpus.from_list([b"\x00", b"A", b"B", b"C", b"D"])
    solutions = InMemoryCorpus()
    fuzzer = Fuzzer(
        base_state, corpus, solutions, instrumented_apply_fn, 0, 0, max_mutations=2
    )

    # Warmup
    for _ in range(5):
        fuzzer.run_once()

    apply_fn_total = 0.0
    apply_fn_calls = 0

    start = time.perf_counter()
    for _ in range(iterations):
        fuzzer.run_once()
    total_elapsed = time.perf_counter() - start

    print(f"  Total time:      {total_elapsed:.3f}s")
    print(f"  apply_fn calls:  {apply_fn_calls}")
    print(f"  apply_fn time:   {apply_fn_total:.3f}s ({apply_fn_total / total_elapsed * 100:.1f}%)")
    print(f"  Non-apply time:  {total_elapsed - apply_fn_total:.3f}s ({(total_elapsed - apply_fn_total) / total_elapsed * 100:.1f}%)")
    if apply_fn_calls > 0:
        print(f"  Per apply_fn:    {apply_fn_total / apply_fn_calls * 1000:.3f}ms")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 70)
    print("angr Fuzzer Performance Benchmark")
    print("=" * 70)

    results = {}

    # Core benchmarks
    elapsed, eps = bench_simple_shellcode(iterations=20)
    results["simple_havoc"] = eps

    elapsed, eps = bench_simple_shellcode_deterministic(iterations=20)
    results["simple_deterministic"] = eps

    elapsed, eps = bench_crash_detection(iterations=20)
    results["crash_detection"] = eps

    elapsed, eps = bench_real_binary(iterations=20)
    if eps is not None:
        results["real_binary"] = eps

    # Scaling benchmarks
    bench_corpus_scaling()
    bench_input_size_scaling()
    bench_mutation_count_scaling()

    # Profiling
    profile_apply_fn_overhead(iterations=30)
    profile_fuzzer(iterations=30)

    # Summary
    print("\n" + "=" * 70)
    print("Summary")
    print("=" * 70)
    for name, eps in results.items():
        print(f"  {name:30s}: {eps:8.1f} exec/s")


if __name__ == "__main__":
    main()
