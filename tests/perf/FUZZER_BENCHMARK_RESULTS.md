# angr Fuzzer Performance Benchmark Results

## Environment
- Target: `angr.rustylib.Fuzzer` (LibAFL + Icicle-based fuzzer)
- Architecture: x86_64 shellcode targets
- Build: Release mode (Rust `--release`)

## Benchmark Results

### Core Throughput

| Scenario                    | Throughput   | Per Iteration |
|-----------------------------|-------------|---------------|
| Simple shellcode (Havoc)    | **2.0 exec/s** | 502ms         |
| Simple shellcode (Deterministic) | **2.2 exec/s** | 456ms    |
| Crash detection shellcode   | **2.2 exec/s** | 464ms         |

For context, traditional fuzzers like AFL++ achieve 1,000-100,000+ exec/s on
similar trivial targets. The current throughput is **~500x slower** than typical
native fuzzing, which is expected given the Python/angr overhead, but there are
clear paths to improvement.

### Scaling Results

**Corpus size** has negligible impact (1.5-1.6 exec/s across 1-100 entries),
confirming the bottleneck is per-execution overhead, not corpus management.

**Input size** has negligible impact (2.2 exec/s for 1B to 4096B), confirming
the bottleneck is not in mutation or input handling.

**Mutation count** scales linearly as expected:
| max_mutations | exec/s | Per iteration |
|--------------|--------|---------------|
| 1            | 2.2    | 454ms         |
| 2            | 1.7    | 602ms         |
| 5            | 0.8    | 1,291ms       |
| 10           | 0.5    | 2,071ms       |
| 25           | 0.2    | 6,001ms       |

Each additional mutation adds ~240ms of overhead (another full execution cycle).

### apply_fn Overhead

The Python `apply_fn` callback itself accounts for only **0.1%** of total time
(0.35ms per call). The bottleneck is entirely in the execution pipeline.

## Profiling Analysis (cProfile)

### Top Bottlenecks by Self Time

| Rank | Function | Self Time | % of Total | Description |
|------|----------|-----------|------------|-------------|
| 1 | `Z3_solver_check_assumptions` | 7.77s | **43.4%** | Z3 SAT solving for register concretization |
| 2 | `Z3_solver_get_param_descrs` | 5.31s | **29.7%** | Z3 solver parameter descriptor overhead |
| 3 | `paged_memory_mixin <genexpr>` | 1.23s | 6.9% | Memory page iteration during concrete_load |
| 4 | `Z3_solver_dec_ref` | 1.09s | 6.1% | Z3 solver reference counting/cleanup |
| 5 | `Icicle.mem_write` | 0.25s | 1.4% | Writing memory pages to Icicle VM |

### Call Path Analysis

The hot path for each fuzzer iteration is:

```
run_once (Rust/LibAFL)
 -> Emulator.run (Python)
    -> engine.process (SimSuccessors)
       -> IcicleEngine.__sync_angr_state_to_icicle  [~95% of time]
          -> solver.eval (for each register)         [~78% of time]
             -> Z3_solver_check_assumptions           [43%]
             -> Z3_solver_get_param_descrs            [30%]
          -> concrete_load (for writable pages)       [~7%]
          -> Icicle.mem_write                         [~1.4%]
```

**78% of total execution time is spent in Z3** just to concretize register values
during state-to-icicle synchronization. This is by far the dominant bottleneck.

## Suggested Performance Improvements

### 1. **Avoid Z3 for concrete register values** (Expected: ~5-10x speedup)

**The #1 bottleneck.** Every iteration calls `state.solver.eval(state.registers.load(reg))`
for each register, which goes through the full Z3 pipeline even when values are
already concrete BVVs. In `executor.rs:60`, the base state is copied via Python's
`state.copy()`, which preserves concrete values.

**Fix:** In `__sync_angr_state_to_icicle`, check if the register value is already
concrete before invoking the solver:

```python
for register in base_translation_data.registers:
    with suppress(KeyError):
        val = state.registers.load(register)
        if val.concrete:
            emu.reg_write(register, val.concrete_value)
        else:
            emu.reg_write(register, state.solver.eval(val, cast_to=int))
```

This should eliminate nearly all Z3 calls since fuzzer states use concrete values.

### 2. **Cache the calling convention and return address extraction** (Expected: ~5% speedup)

In `executor.rs:86-102`, every iteration re-creates the calling convention object
and extracts the return address from the **base state** (not the copied state).
Since the base state never changes, cache the return address once:

```rust
// Cache in PyExecutorInner::new or on first use
let return_addr: u64 = /* extract once */;
// Reuse in run_target without Python calls
```

### 3. **Avoid re-creating Emulator object each iteration** (Expected: ~3% speedup)

In `executor.rs:80-83`, a new `Emulator` Python object is created every iteration.
The Icicle engine is cached (good), but the Emulator wrapper and breakpoints are
re-established each time. Consider caching the Emulator and just resetting its
state.

### 4. **Reduce register set for synchronization** (Expected: ~2-3x speedup)

`__sync_angr_state_to_icicle` syncs **all** registers (770 solver.eval calls for
35 iterations = 22 registers per iteration). For the fuzzer use case, only
registers modified by `apply_fn` need syncing. Add a mechanism to specify which
registers are "dirty" and only sync those.

### 5. **Move state copy + apply_fn into Rust** (Expected: ~20% speedup)

Currently each iteration crosses the Python/Rust boundary multiple times:
- Rust calls Python for `state.copy()`
- Rust calls Python for `apply_fn()`
- Rust calls Python for `Emulator()` creation
- Rust calls Python for `emulator.run()`
- Rust calls Python for hitmap extraction

Consider a "fast path" that does the entire execution cycle in Rust/Icicle
directly, only crossing to Python for the apply_fn callback.

### 6. **Use ZERO_FILL options to avoid symbolic register creation** (Expected: ~5% speedup)

The benchmark shows many "Filling register X with unconstrained bytes" warnings.
Using `ZERO_FILL_UNCONSTRAINED_REGISTERS` on the base state would avoid creating
symbolic values that then need Z3 to concretize:

```python
base_state = project.factory.entry_state(
    add_options={angr.sim_options.ZERO_FILL_UNCONSTRAINED_REGISTERS}
)
```

This should be documented as a best practice for fuzzer usage.

### 7. **Batch memory writes** (Expected: ~1-2% speedup)

Instead of calling `emu.mem_write()` per page (4550 calls), batch contiguous
writable pages into larger writes to reduce FFI overhead.

### 8. **Skip Z3 solver creation overhead** (Expected: ~30% speedup)

`Z3_solver_get_param_descrs` takes 30% of time — this appears to be Z3 solver
initialization overhead. If the solver instance could be reused across iterations
(or if a lightweight concrete-only solver path existed), this would be eliminated.

## Priority Ranking

| Priority | Improvement | Estimated Speedup | Effort |
|----------|-------------|-------------------|--------|
| P0 | Concrete register fast-path (avoid Z3) | 5-10x | Low |
| P0 | Skip Z3 solver creation overhead | ~2x | Medium |
| P1 | Reduce synced register set | 2-3x | Medium |
| P1 | ZERO_FILL best practice docs | 1.2x | Low |
| P2 | Cache return addr / calling convention | 1.05x | Low |
| P2 | Cache Emulator object | 1.03x | Low |
| P3 | Move execution loop to Rust | 1.2x | High |
| P3 | Batch memory writes | 1.02x | Low |

**Combined P0+P1 improvements could yield 10-30x throughput increase** (from ~2
exec/s to 20-60 exec/s), bringing the fuzzer much closer to practical usability.
