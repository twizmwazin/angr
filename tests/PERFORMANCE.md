# Test Suite Performance — Measurements and Recommendations

This document records a measurement of angr's Python test suite (`tests/`), an attribution of where
the time actually goes, and a ranked set of recommendations for reducing wall-clock time.

Everything below is measured, not estimated, unless explicitly labelled as an estimate.

---

## 1. How it was measured

| | |
|---|---|
| Machine | 4 cores, 15 GB RAM, Linux |
| angr | `9.3.3.dev0` at `d23a28a`, `uv sync -p 3.12` (dev + extras groups) |
| Binaries | `angr/binaries` @ `d35ea74` cloned as a sibling of the repo |
| Baseline command | `pytest tests -q -n 4 --dist loadfile --timeout=1800 --store-durations` |

Three separate runs were used:

1. **Baseline** — full suite, per-test durations via `pytest-split --store-durations`, plus a JUnit XML.
2. **Instrumented** — the full suite again with a plugin that wraps `AnalysisFactory.prep`,
   `Project.__init__` and `SimulationManager.run/explore/step`, recording every call's duration, its
   nesting depth (so nested analyses are not double-counted) and the binary it ran on.
3. **Sampling profiles** — the 15 slowest tests, each run alone under `py-spy record --rate 100`
   (sampling, so effectively zero overhead).

Caveats that matter when reading the numbers:

- Durations come from a `-n 4` run on a 4-core box, so every test is inflated by roughly the same
  contention factor. Rankings and shares are reliable; absolute seconds are not directly comparable
  to a serial run.
- Solver-bound tests are genuinely noisy run-to-run. `test_strtol` measured 58.7 s in the parallel
  run and 131 s standalone; `test_unique` measured 45.3 s in the parallel run and 6 s standalone.
  Treat any individual solver-heavy number as an order of magnitude, not a constant.
- The instrumented run lost one of four xdist workers to an OOM caused by the instrumentation itself
  (it accumulates every record in memory). Attribution percentages are computed over the 3 surviving
  workers (3678 s of attributed time) and are shares, not totals.
- `tracer` is not installed in this environment, so the CGC tracer tests skip. Java/pysoot,
  unicorn and keystone are installed and did run.

---

## 2. Baseline

```
2531 tests, 20m01s wall (-n 4), 73m38s CPU
sum of per-test durations: 4700 s  (78 min)
8 failed, 2478 passed, 46 skipped, 2 xfailed
```

The 8 failures are environmental, not performance-related: `angr/rust/utils/rust_sigs.py`
downloads a FLIRT signature tarball from GitHub at test time, the sandbox cannot reach it,
`get_default_sig_dir()` returns `None`, and every Rust-signature assertion fails. Worth noting
independently: **the test suite performs a network download on a cold cache**, once per fresh
runner and with no locking between concurrent workers.

### The distribution is extremely top-heavy

| band | tests | total | share |
|---|---:|---:|---:|
| ≥ 60 s | 12 | 1071 s | 22.8% |
| 30–60 s | 17 | 759 s | 16.1% |
| 10–30 s | 73 | 1277 s | 27.2% |
| 1–10 s | 384 | 1324 s | 28.2% |
| 0.1–1 s | 702 | 259 s | 5.5% |
| < 0.1 s | 1343 | 10 s | 0.2% |

Median test: **40 ms**. Slowest test: **175.6 s**. 1129 tests (44.6%) run in under 10 ms.

- The slowest **25 tests (1%)** are **36%** of the runtime.
- The slowest **100 tests (4%)** are **66%**.
- The **384 tests in the 1–10 s band** are **28%**, and **476 s of that band (36%) is one file**,
  `tests/analyses/decompiler/test_decompiler.py`.

So the "long tail" that matters is not the 1343 sub-100 ms tests — those are free. It is the
**486 tests that take ≥ 1 s and account for 94% of the runtime**, and within that, one file.

### By directory

| directory | time | share | tests |
|---|---:|---:|---:|
| `tests/analyses/decompiler` | 2122 s | 45.1% | 698 |
| `tests/analyses` (top level) | 726 s | 15.4% | 283 |
| `tests/analyses/cfg` | 639 s | 13.6% | 166 |
| `tests/factory` | 192 s | 4.1% | 57 |
| `tests` (top level) | 181 s | 3.9% | 55 |
| `tests/exploration_techniques` | 170 s | 3.6% | 48 |
| `tests/procedures/libc` | 161 s | 3.4% | 38 |
| everything else | 509 s | 10.8% | 1186 |

`tests/analyses/**` is **74%** of the suite.

### 25 slowest tests

| # | s | test |
|---|---:|---|
| 1 | 175.6 | `tests/analyses/decompiler/test_rust_decompiler.py::TestFmtNightly20230522O3::test_parse_arguments_2023052203` |
| 2 | 126.0 | `tests/test_cli.py::TestCommandLineInterface::test_decompile_rust` |
| 3 | 108.5 | `tests/factory/test_callable.py::TestCallable::test_manyfloatsum_symbolic_x86_64` |
| 4 | 85.8 | `tests/analyses/decompiler/test_rust_cfg_transformation.py::TestRustCFGTransformation::test_bbbq_rust_flavor_graph_has_no_dangling_terminators` |
| 5 | 84.9 | `tests/analyses/decompiler/test_phoenix_last_resort_isolation.py::TestPhoenixLastResortIsolation::test_bbbq_rust_root_region_structures_completely` |
| 6 | 84.8 | `tests/angrdb/test_angrdb_jumptables.py::TestAngrDBJumpTables::test_jump_tables_roundtrip` |
| 7 | 69.8 | `tests/analyses/test_flirt.py::TestFlirt::test_amd64_elf_static_libc_ubuntu_2004` |
| 8 | 69.1 | `tests/analyses/decompiler/test_rust_decompiler.py::TestFmtNightly20250522O3::test_uumain_2025052203` |
| 9 | 67.9 | `tests/factory/test_callable.py::TestCallable::test_manyfloatsum_symbolic_i386` |
| 10 | 67.3 | `tests/analyses/cfg/test_memload_resolver.py::TestMemloadResolver::test_indirect_jump_should_start_new_functions` |
| 11 | 66.2 | `tests/analyses/cfg/test_jumptables.py::TestJumpTableResolver::test_vtable_amd64_libc_ubuntu_2004` |
| 12 | 65.2 | `tests/analyses/test_identifier.py::TestIdentifier::test_comparison_identification` |
| 13 | 58.7 | `tests/procedures/libc/test_strtol.py::TestStrtol::test_strtol` |
| 14 | 58.4 | `tests/analyses/decompiler/test_rust_decompiler.py::TestFmtNightly20250522O0::test_uumain_2025052200` |
| 15 | 57.4 | `tests/analyses/decompiler/test_stack_arg_slices.py::TestStackArgSlices::test_2ac79168_stack_arg_accessed_as_two_slices` |
| 16 | 56.1 | `tests/analyses/test_string_obf_finder.py::TestStringObfFinder::test_find_obfuscated_strings_543991` |
| 17 | 55.5 | `tests/engines/test_unicorn.py::TestUnicorn::test_symbolic_flags_preserved_on_stop` |
| 18 | 53.1 | `tests/analyses/cfg/test_cfgfast.py::TestCfgfast::test_cfg_function_stubs_with_single_jumpouts` |
| 19 | 45.3 | `tests/exploration_techniques/test_unique.py::TestRunUnique::test_unique` |
| 20 | 44.5 | `tests/analyses/test_calling_convention_analysis.py::TestCallingConventionAnalysis::test_cdecl_nonconsecutive_stack_args_2` |
| 21 | 43.7 | `tests/analyses/test_calling_convention_analysis.py::TestCallingConventionAnalysis::test_cdecl_nonconsecutive_stack_args_3` |
| 22 | 41.5 | `tests/analyses/cfg/test_cfg_pe_msvc_eh.py::TestCFGFastPEMsvcEH::test_cfg_pe_msvc_eh` |
| 23 | 40.6 | `tests/analyses/test_calling_convention_analysis.py::TestCallingConventionAnalysis::test_x8664_dir_gcc_O0` |
| 24 | 40.3 | `tests/analyses/cfg/test_cfgfast_datarefs.py::TestCfgfastDataReferences::test_pe_32bit_pointer_array_detection` |
| 25 | 34.2 | `tests/analyses/test_api_obf_finder.py::TestAPIObfFinder::test_smoketest` |

---

## 3. Where the time goes

### 3.1 By angr operation (instrumented run, top-level calls only)

| operation | share | calls | mean |
|---|---:|---:|---:|
| `CFGFast` | 43.1% | 830 | 1.91 s |
| `Decompiler` | 21.0% | 717 | 1.08 s |
| `CompleteCallingConventions` | 8.6% | 212 | 1.50 s |
| `CFG` (alias of `CFGFast`) | 7.3% | 144 | 1.85 s |
| `SimulationManager.explore` | 4.6% | 148 | 1.14 s |
| `SimulationManager.run` | 4.6% | 371 | 0.45 s |
| `StringObfuscationFinder` | 2.1% | 5 | 15.6 s |
| `SimulationManager.step` | 2.0% | 2931 | 0.03 s |
| `Project(...)` load | 2.7% | 1670 | 0.06 s |
| everything else | ~4% | | |

**CFG recovery alone is half the suite** (`CFGFast` + `CFG` = 50.4%). Decompilation is another 21%.
Symbolic execution is ~11%. Loading binaries is almost free (2.7%) — `auto_load_libs` is worth fixing
for hygiene, not for speed.

### 3.2 Redundancy

Summing, for every `(analysis, exact binary path)` pair that occurs more than once, the time of all
but the longest occurrence, split by whether the repeat is inside one test or across tests:

| | time | share of attributed |
|---|---:|---:|
| **inside a single test** (loop decorators, the scoping helper's discovery rounds) | 358 s | 9.7% |
| **across different tests, same file** (shareable in-process under `--dist loadfile`) | 230 s | 6.3% |
| **across different tests, different files** (needs merging or an on-disk cache) | 541 s | 14.7% |
| **total** | **1130 s** | **30.7%** |

These numbers remain **upper bounds**: the key is the analysis class and the binary, not the options
passed, so a `CFGFast(regions=…)` and a whole-binary `CFGFast()` on the same file are counted as
interchangeable when they are not. The intra-test figure in particular includes the scoping helper's
discovery rounds, which write into throwaway `KnowledgeBase` objects and are not reusable by anyone —
they are waste, but of the kind §3.3 addresses, not the kind a shared fixture fixes.

> **Do not key this kind of metric on the binary's basename.** An earlier pass of this analysis did,
> and reported 45%. Four distinct binaries in `angr/binaries` are named `fmt` — the 224 KB C coreutils
> one used by `test_decompiler.py`, and three Rust builds of 1.2 MB, 1.6 MB and 2.8 MB used by
> `test_rust_decompiler.py`. Merging them inflated "`CFGFast @ fmt`" to 23 calls / 175 s with a 7.6 s
> mean; keyed on the full path, the C `fmt` accounts for **11.8 s** of cross-test redundancy across
> 8 tests, and a whole-binary CFG of it takes 1.4 s.

The largest cross-test candidates, keyed on full paths (the top two were checked against their call
sites and are genuinely identical; the rest are candidates, not confirmed):

| pair | tests | files | recoverable |
|---|---:|---:|---:|
| `Decompiler @ x86_64/bbbq` | 5 | 5 | 116 s |
| `CFGFast @ x86_64/elf_with_static_libc_ubuntu_2004_stripped` | 2 | 2 | 64 s |
| `Decompiler @ x86_64/windows/03fb29da…` | 5 | 5 | 63 s |
| `CFGFast @ x86_64/1cbbf108…` | 3 | 2 | 41 s |
| `CompleteCallingConventions @ i386/windows/48460c96…` | 4 | 2 | 36 s |
| `CFGFast @ x86_64/decompiler/vcruntime_test.exe` | 3 | 1 | 32 s |
| `CFGFast @ x86_64/fauxware` | 73 | 19 | 12 s |

Note the shape: the money is in a handful of *large* binaries analysed by a handful of tests, not in
the 73 tests that rebuild a fauxware CFG. Rebuilding fauxware 73 times costs 12 seconds in total.

### 3.3 `load_project_with_scoped_cfg` re-scans what it already scanned

`tests/common.py:257-277` discovers the call tree by running `CFGFast` up to `call_tree_depth`
(default 8) times, and each round passes `regions=_merged_regions(known, window)` — i.e. **every
region discovered so far**, including all regions already scanned in previous rounds.

Its sibling `recover_call_tree_cfg` in the same file already does this correctly: it tracks
`scanned`, computes `pending -= scanned`, and scans only `regions=_regions(pending)`.

Measured cost of the redundant rounds, across the 18 files that use the helper:

**140.5 s across 21 `(test, binary)` pairs** where `CFGFast` ran ≥ 3 times on one binary inside one
test. Observed rounds per test: 3 (×4), 4 (×7), 5 (×2), 6 (×2), 7 (×3), 8 (×2), 10 (×1).

Worst offenders: `test_win_security_cookie_removal_with_fp_relative_reload` (23.6 s of redundant
rounds), `test_stack_arg_slices` (18.9 s), `test_ssa_stack::test_missing_stack_defs` (15.4 s).

### 3.4 Sampling profiles: two distinct families

Profiling the 15 slowest tests individually splits them cleanly.

**Family A — Z3-bound.** Nothing angr does is hot; the time is inside the solver.

| test | z3 self time |
|---|---:|
| `test_manyfloatsum_symbolic_x86_64` | **97.2%** |
| `test_unicorn::test_symbolic_flags_preserved_on_stop` | 85.8% |
| `test_sscanf` | 85.4% |
| `test_unique` | 28.4% |
| `test_identifier` | 9.5% (+ 31.4% in `angr/storage/memory_mixins`) |

`test_manyfloatsum_symbolic_*` asks Z3 for an exact floating-point model in which **19 symbolic
doubles** sum to exactly `27.7` with every argument `> 1.0` (`tests/factory/test_callable.py:114`).
The test's own comment says "z3 is magic, if kinda slow!!!!!". The two architecture variants together
are **176 s = 3.7% of the entire suite**, spent almost entirely as a Z3 FP benchmark.

**Family B — CFG/knowledge-base-bound.** In every one of these, *bookkeeping costs more than the
analysis*:

| test | `knowledge_plugins/*` | `analyses/cfg` |
|---|---:|---:|
| `test_memload_resolver` | 34.5% | 10.5% |
| `test_angrdb_jumptables` | 33.1% | 9.1% |
| `test_cfgfast::…single_jumpouts` | 28.3% | 10.1% |
| `test_flirt` | 25.2% | 7.7% |
| `test_jumptables::test_vtable_amd64_libc` | 22.1% | 8.2% |

The hot frames are `spilling_cfg._load_from_lmdb_core`, `spilling_digraph._load_from_lmdb_core`,
`function_parser.parse_from_cmsg` and `cfg_node.parse_from_cmessage` — protobuf deserialization of
entries that were spilled to LMDB and read back.

### 3.5 Measured: angr's spilling caches cost 23–30% on big-binary tests

`angr/project.py:943` caps in-memory `Function` / `CFGNode` / edge caches for any binary ≥ 256 KB
(at most 5000 entries) and spills the rest to LMDB. A/B, each configuration in a fresh process:

| binary | size | funcs / nodes | spilling on | spilling off | delta |
|---|---:|---|---:|---:|---:|
| `elf_with_static_libc_ubuntu_2004_stripped` | 780 K | 5677 / 38607 | 57.1 s | 40.2 s | **−30%** |
| `bbbq` | 363 K | 1194 / 16236 | 17.7 s | 13.7 s | **−23%** |
| `decompiler/fmt` | 219 K | 454 / 1700 | 1.4 s | 1.4 s | 0% (under the threshold) |

"Spilling off" is `Project(..., cache_limits={"functions": None, "cfg_nodes": None, "cfg_edges": None})`.

Exactly one test in the suite already does this — `tests/analyses/decompiler/test_decompiler.py:5661`,
with the comment "turning off cache for better speed".

---

## 4. CI: the shard split is not duration-aware, and one test is the floor

`angr/ci-settings`'s `ga-test.sh` → `test.py:21` runs, per shard:

```
pytest -v -nauto --forked --splits 10 --group N --rootdir=./src/angr/tests ./src/angr/tests
```

with no `--durations-path`. pytest-split's default path is `$CWD/.test_durations`, which does not
exist in the CI build directory. Reading the installed plugin (`pytest_split/algorithms.py:161-168`):
when the durations map is empty **every test is assigned a weight of 1.0**, so the default
`duration_based_chunks` algorithm degenerates to contiguous equal-*count* chunks. Replaying the real
collection order gives shard serial totals of
`851 / 762 / 747 / 601 / 504 / 406 / 242 / 222 / 208 / 159 s` against an ideal of 470 s.

**That 81% imbalance is not an 81% wall-clock loss, because each shard is itself parallel.** `-n auto`
runs W xdist workers inside the shard and rebalances dynamically, so a shard's wall time is
approximately `max(serial_total / W, slowest_single_test)`. Simulating 10 shards, each dispatching its
group in collection order to W workers (xdist's `--dist load`):

| scenario | W=1 | W=2 | W=4 |
|---|---:|---:|---:|
| A. equal-count split, all tests (**today**) | 851 s | 426 s | 261 s |
| B. duration-aware split, all tests | 470 s | 296 s | 219 s |
| C. duration-aware + mark ≥ 60 s `slow` | 363 s | 189 s | 123 s |
| D. duration-aware + mark ≥ 30 s `slow` | 287 s | 149 s | 88 s |
| E. equal-count + mark ≥ 30 s `slow` | 785 s | 393 s | 206 s |

Saving versus today: **B is 16% (W=4) to 31% (W=2)**; **D is ~65% at every W**; **E alone is only
8–21%**.

The reason B saturates is that the slowest single test, at **175.6 s**, is a hard floor on any shard
at W ≥ 3 — at W=4 the optimal split lands at 219 s of which 176 s is one test. So:

- **Duration-aware splitting and a `slow` marker are complementary, and neither is worth much alone.**
- The binding constraint is not the split, it is **the slowest individual test**. Adding shards past
  10 buys nothing; at W=8 duration-aware splitting is actually 2% *worse* than equal-count because
  everything is floor-bound.

W is unmeasured here and matters: `-n auto` resolves via `psutil.cpu_count(logical=False)` (xdist
`plugin.py:32`) — *physical* cores — and psutil is a hard angr dependency, so a 4-vCPU GitHub runner
with 2 threads/core gives W=2, not 4.

**One blocker to fix first:** the only durations file angr produces comes from `coverage.yml`, which
runs `pytest … tests` from the repo root, while `test.py` passes `--rootdir=./src/angr/tests
./src/angr/tests`. The node IDs differ (`tests/analyses/…` vs `analyses/…`), and pytest-split's
`_remove_irrelevant_durations` drops every non-matching key and falls back to the 1.0 weight — so
wiring the file in without normalizing the keys silently reproduces today's split at 0% benefit.

Three more configuration facts, all verified:

1. **`-m "not slow"` deselects exactly zero tests.** `test.py:26` appends it for non-nightly runs,
   but no test in this repository carries a `slow` marker and the marker is not registered in
   `pyproject.toml`.
2. **`SKIP_SLOW_TESTS: 1` in `.github/workflows/coverage.yml:15` is read by nothing** in this
   repository or its dependencies.
3. **`--forked` re-runs `setUpClass` once per test method.** Verified directly on this machine: a
   4-test class produced 1 `setUpClass` invocation without `--forked` and 4 invocations, in 4
   distinct pids, with it. `pytest_forked` forks inside `pytest_runtest_protocol`, before setup runs.
   The 14 test files that use `setUpClass` to cache an expensive `Project`/CFG get **no benefit in
   CI**.

   The corollary is the useful half: **module-level state is built once in the parent and inherited
   by every forked child**, verified the same way (module-level init ran once for 4 forked tests, and
   each test observed a different pid than the one that built the object). Copy-on-write makes it
   free. Any shared-fixture work should be built at module import, not in a fixture.

---

## 5. Recommendations

Ordered by measured payoff per unit of effort. "Saving" is against the 4700 s serial total unless
stated otherwise.

### Tier 0 — CI configuration, no test changes

**R1 and R2 are one change. Do them together.** Separately they are worth 16–31% and 8–21%
respectively; together they are worth ~65% at any worker count (§4, scenarios B/D/E).

**R1. Make the 10-way shard split duration-aware.** *(saving: 16% at W=4, 31% at W=2, of the angr
portion of a shard; effort: small; risk: none)*

In `angr/ci-settings`'s `test.py`, add `--splitting-algorithm=least_duration` and an explicit
`--durations-path` pointing at a durations file shipped into the CI build.

**Do the key normalization first or this change does nothing.** The only durations file angr produces
comes from `.github/workflows/coverage.yml`, which runs `pytest … tests` from the repo root, while
`test.py` runs `--rootdir=./src/angr/tests ./src/angr/tests`. The node IDs differ, pytest-split's
`_remove_irrelevant_durations` discards every non-matching key, and the run falls back to uniform 1.0
weights — i.e. exactly today's split, silently. Either produce the durations with the same invocation
the consumer uses, or rewrite the keys when writing the file.

Two more caveats worth knowing: the durations from `coverage.yml` are measured under Python, Rust and
C coverage instrumentation, which inflates Python-heavy tests relative to native-heavy ones; and a PR
branch can read the base branch's `cov-test-durations-` cache but cannot write it, so the data is
only as fresh as the last master coverage run. Neither breaks the split — unknown tests get the
average — but both mean it will be good, not optimal.

**R2. Register a `slow` marker and actually apply it.** *(saving: takes R1 from 16–31% to ~65%;
effort: small; risk: regressions in marked tests surface up to 24 h later)*

`-m "not slow"` is already wired up in CI and is currently a no-op. Marking the long tail is what
lifts the floor that caps R1:

| threshold | deferred to nightly | serial total | slowest remaining test | crit path (W=4, with R1) |
|---|---:|---:|---:|---:|
| none | 0 | 4700 s | 175.6 s | 219 s |
| ≥ 60 s | 12 | 3629 s | 58.7 s | 123 s |
| ≥ 30 s | 29 | 2871 s | 28.8 s | 88 s |

Add `markers = ["slow: excluded from PR CI, run nightly"]` to `[tool.pytest.ini_options]` so the
marker is registered and typos fail loudly rather than silently selecting everything.

**R3. Remove `SKIP_SLOW_TESTS` from `coverage.yml`,** or implement it. As written it is dead and
misleads anyone reasoning about what the coverage job runs. *(effort: trivial)*

**R4. Add `fail-fast: false` to the `test` matrix in `coverage.yml`.** One bad shard currently
cancels the other nine, which throws away the durations artifact that R1 depends on. *(effort: trivial)*

**R5. Set a default `--timeout`.** `pytest-timeout` is already a dev dependency and is not used
anywhere. Pick a value from the measured durations (the slowest test is 175 s, so 600 s is
comfortable) so a hung test fails a shard in minutes instead of consuming the 6 h job limit.

### Tier 1 — targeted test edits with measured payoff

**R6. Fix the re-scanning in `load_project_with_scoped_cfg`.** *(saving: ~140 s, 3% of the suite;
effort: small; risk: low — mirrors an existing implementation)*

`tests/common.py:257-277` passes all previously-scanned regions to every discovery round. Track
`scanned` and pass only the newly-pending regions, exactly as `recover_call_tree_cfg`
(`tests/common.py` further down) already does. This benefits all 37 call sites across 18 files at once.

**R7. Disable the LMDB spilling caches in tests that build whole-binary CFGs of binaries ≥ 256 KB.**
*(saving: 23–30% of those tests, measured; effort: small; risk: low, costs memory)*

Add `cache_limits={"functions": None, "cfg_nodes": None, "cfg_edges": None}` to the `Project(...)`
call — the pattern already used and commented at `test_decompiler.py:5661`. The natural place is
inside `load_project_with_scoped_cfg` (which would then cover 37 tests), plus the standalone
whole-binary tests: `test_flirt.py:18`, `test_jumptables.py:2785`, `test_memload_resolver.py`,
`test_angrdb_jumptables.py:21`, `test_cfg_pe_msvc_eh.py`.

A cleaner variant worth considering on the angr side: size these caches from available memory rather
than from a fixed 256 KB / 5000-entry rule. A CI runner with 16 GB has no reason to spill a
38 000-node CFG to disk.

**R8. Merge the two byte-identical `bbbq` tests.** *(saving: ~85 s; effort: trivial; risk: none. The
wider `bbbq` cluster — 5 tests in 5 files decompiling `sub_410920` — carries 116 s of cross-test
`Decompiler` redundancy, the largest single entry in §3.2, but only these two are trivially mergeable.)*

`tests/analyses/decompiler/test_phoenix_last_resort_isolation.py:119` and
`tests/analyses/decompiler/test_rust_cfg_transformation.py:114` run character-for-character identical
setup — same `Project(bbbq, auto_load_libs=False)`, same `CFGFast(normalize=True,
data_references=True)`, same `CompleteCallingConventions()`, `RustSymbolRecovery()`, `TypeDBLoader()`,
same `Decompiler(0x410920, flavor="rust", fail_fast=True)`. Only the assertions differ, and both
docstrings state the whole-binary CFG is required. Measured 84.9 s + 85.8 s. Make it one test with
both assertion sets, or one module-level fixture shared by two tests in one file.

**R9. Share the `fmt` pipeline in `test_decompiler.py`.** *(saving: ~19 s; effort: medium;
risk: medium — see §6)*

Eight test methods use `x86_64/decompiler/fmt`; seven of them build the identical
`Project(auto_load_libs=False)` + `CFGFast(normalize=True, data_references=True)`. It is the cleanest
*example* of the duplicate-setup pattern, but the payoff is modest: the C `fmt` is 224 KB and its
whole-binary CFG takes 1.4 s, so the measured cross-test redundancy is **11.8 s of `CFGFast` plus
6.7 s of `Decompiler`**. Worth doing when touching the file; not worth a dedicated change.

(The same pattern on a *large* binary is where the money is — see R8 and R10.)

**R10. Share the static-libc CFG between `test_flirt` and `test_jumptables`.** *(saving: ~67 s;
effort: small)*

`test_flirt.py:19` (`CFGFast(show_progressbar=False)`) and `test_jumptables.py:2788` (`CFGFast()`)
build the same whole-binary CFG of `elf_with_static_libc_ubuntu_2004_stripped`, 67 s each. They are
in different files, so this needs either a shared module or a session-scoped cache built at import
time (§4). R7 alone already takes each from 57 s to 40 s.

**R11. Hoist the invariant setup out of `@for_all_structuring_algos`.** *(saving: a large share of the
362 s of intra-test repetition; effort: medium; risk: low)*

`tests/analyses/decompiler/test_decompiler.py:94-116` loops over the structurers and calls the whole
test body once per structurer. `STRUCTURER_CLASSES` minus Phoenix is `{sailr, dream}`, so **105 test
methods run their entire body twice** — including the `Project` load, `CFGFast` and, in ~24 of them,
`CompleteCallingConventions`. Only the final `Decompiler(...)` call depends on the structurer.

Restructure so the decorator parameterises only the decompilation: have decorated tests obtain
`(proj, cfg)` from a cached factory, and wrap each structurer iteration in `self.subTest(...)` so a
dream-only failure is attributable. This also fixes a secondary problem — each of those 105 tests is
a single pytest item doing two full pipelines, which is bad for shard granularity.

**R12. Cut the cost of `test_manyfloatsum_symbolic_*`.** *(saving: up to ~176 s, 3.7%; effort: small;
risk: low, mild coverage reduction)*

97% of the runtime is a single Z3 FP `check`. The angr-side behaviour under test — a `callable` with
symbolic float arguments returning a symbolic result — is fully exercised with far fewer arguments.
Reducing the symbolic arity, or relaxing the exact `== 27.7` equality, keeps the coverage. If the
19-argument case is considered valuable as a solver regression test, mark it `slow` (R2) rather than
running it on every PR.

**R13. Pass `auto_load_libs=False` in `tests/common.py:252`.** *(saving: small, ~0.5 s × 37 tests;
effort: trivial)*

`load_project_with_scoped_cfg` builds `Project(bin_path, **(project_kwargs or {}))` and no caller
passes `auto_load_libs`, so all 37 scoped tests load the host libc even though CFG recovery is scoped
to regions inside the main object. Use `{"auto_load_libs": False, **(project_kwargs or {})}` so
callers can still override. 114 other `Project()` call sites across the suite also default to
`auto_load_libs=True`; the measured payoff is small (loading is 2.7% of attributed time overall) but
it is free and removes a host dependency.

### Tier 2 — structural

**R14. Decide deliberately about `--forked`.** *(saving: unblocks R9/R10/R11 in CI; effort: medium;
risk: medium)*

Today `--forked` silently negates class-scoped caching (§4). Two coherent positions:

- **Keep `--forked`** (it presumably contains native segfaults from unicorn/pyvex; without it a crash
  takes down a whole xdist worker rather than one test) and build every shared object **at module
  import time**, where fork's copy-on-write shares it for free.
- **Drop `--forked`** and use `setUpClass`/session fixtures normally, accepting that a native crash
  loses a worker.

The first is strictly better if the crash-containment property is worth keeping, and it is what the
measurements support. Either way, the current state — paying for `--forked` *and* writing
`setUpClass` caches that never fire — is the worst of both.

**R15. Use `--dist loadfile` (or `loadscope`) instead of the default.** `-n auto` defaults to
`--dist load`, which scatters same-file tests across workers, so file-level sharing is diluted by up
to the worker count. `loadfile` also makes the durations-based split and module-level caching compose
sensibly. *(effort: trivial)*

**R16. Extend the scoping pattern beyond `tests/analyses/decompiler/`.** The scoped-CFG helpers in
`tests/common.py` are used by 19 files, every one of them under `tests/analyses/decompiler/`. The same pattern
applies directly to whole-binary CFG tests elsewhere — `tests/analyses/test_typehoon.py`,
`tests/analyses/test_calling_convention_analysis.py` (198 s), `tests/analyses/cfg/test_cfgfast.py`
(179 s), `tests/analyses/cfg/test_jumptables.py` (163 s) — wherever the assertion is about one
function rather than about whole-binary recovery. Note that some tests genuinely require the
whole-binary CFG and say so in their docstrings; those must not be scoped.

**R17. Split the monolithic tests.** `test_dogbolt_regressions.py:31` decompiles every function of a
binary (26 `Decompiler` calls) inside one test; `test_decompiling_all_x86_64` does the same and is
doubled by the structuring decorator. As single pytest items they cannot be spread across shards, and
a single 175 s test is a hard floor on any shard's wall time. Parameterising them per function makes
them shardable and makes failures point at one function.

**R18. If a `tests/conftest.py` is introduced, document the sharing hazards.** They are real:

- Every analysis writes into `project.kb` by default (`angr/analyses/analysis.py:243-246`), so a
  shared `Project` is a shared mutable knowledge base. `Clinic`, `CompleteCallingConventions` and
  `VariableRecovery` rewrite prototypes and calling conventions of *callees*, so one test can change
  what a later test sees.
- `Decompiler.__init__` takes **`use_cache: bool = True`** and keys `kb.decompilations` on
  `(func.addr, flavor)` (`angr/analyses/decompiler/decompiler.py:320-322`). Two tests sharing a kb and
  decompiling the same function with the same options will silently reuse the cached result — a
  regression test that cannot fail. Any shared fixture must pass `update_cache=False`, or hand each
  test a fresh `KnowledgeBase`.
- `project.hook`/`unhook` are process-global per `Project`.

The safe division is: share `Project` + CFG *model* freely for read-only assertions; give any test
that runs a mutating analysis its own `KnowledgeBase` via `proj.analyses[X].prep(kb=...)`, which
`tests/common.py` already does internally.

**R19. Make the FLIRT signature download a build step, not a test-time side effect.**
`angr/rust/utils/rust_sigs.py:58` downloads a tarball from GitHub into the user cache directory on
first use, with no lock — so N concurrent workers can each start the same download on a cold cache.
Pre-fetching it in the CI image (or in a setup step) removes a network dependency from the test path
and the 8 failures seen here.

---

## 6. What *not* to do

- **Do not chase the 1343 sub-100 ms tests.** They are 53% of the test count and 0.2% of the runtime.
- **Do not micro-optimise the decompiler from these profiles.** The `bbbq` profile is 21%
  `analyses/decompiler`, 12.6% `ailment/block_walker`, 6.3% `utils/ssa`, 5.6%
  `s_reaching_definitions` — genuine work, spread thin, with no hotspot. The win there is not running
  it five times.
- **Do not naively share knowledge bases across tests** to chase the redundancy number. 30.7% is an
  upper bound, the hazards in R18 are real, and angr has no `KnowledgeBase.copy()` — only
  `__getstate__`/`__setstate__` — so isolating a shared CFG from a consumer's mutations costs a pickle
  round-trip per consumer, which is not in any of the estimates above. The safe subset — identical
  tests merged, identical setups hoisted within a file, the scoping helper fixed, spilling disabled —
  captures much of it with none of the risk.
- **Do not trust redundancy metrics keyed on a binary's basename.** See the box in §3.2: four
  different binaries in the corpus are called `fmt`, and merging them inflated one line item from
  12 s to 175 s.
- **Do not micro-optimise the decompiler from these profiles.** The `bbbq` profile is 21%
  `analyses/decompiler`, 12.6% `ailment/block_walker`, 6.3% `utils/ssa`, 5.6%
  `s_reaching_definitions` — genuine work, spread thin, with no hotspot. The win there is not running
  it five times.
- **Do not expect CPU savings to become wall-clock savings one-for-one.** The measured run packed
  4700 s of test time into 1201 s of wall on 4 workers — already ~98% packed — so a serial-time saving
  only helps if it lands on whatever is currently the critical path. This is why the Tier 0 scheduling
  changes dominate the Tier 1 code changes.
- **`gc.collect()` per test is not a problem.** `_pytest/unraisableexception.py` shows up in the
  profiles, but its `gc_collect_harder` calls are only in `cleanup()` and `pytest_unconfigure`, both
  session-scoped; the per-test hooks only drain a queue.

---

## 7. Summary of expected impact

**Scheduling (Tier 0) — changes no test code, dominates everything else.** Critical path of the
angr portion of a PR-CI shard, simulated at 10 shards × W xdist workers:

| change | W=2 | W=4 |
|---|---:|---:|
| today | 426 s | 261 s |
| R1 duration-aware split | 296 s (−31%) | 219 s (−16%) |
| **R1 + R2 (mark ≥ 30 s `slow`)** | **149 s (−65%)** | **88 s (−66%)** |
| R2 alone | 393 s (−8%) | 206 s (−21%) |

**Test code (Tier 1) — off the 4700 s serial total.**

| change | effect | confidence |
|---|---|---|
| R7 disable spilling on big binaries | −23–30% on the CFG-bound tests | measured A/B |
| R6 scoping-helper re-scan fix | −140 s (−3%) | measured, 21 test/binary pairs |
| R12 reduce the Z3 FP benchmark | up to −176 s (−3.7%) | measured, 97% of those tests is one `check` |
| R8 merge duplicate `bbbq` tests | −85 s | measured, byte-identical setup |
| R10 share static-libc CFG | −67 s (−64 s after R7) | measured, same options |
| R11 hoist setup out of the structuring decorator | share of 358 s intra-test repetition | measured upper bound |
| R9 share the `fmt` pipeline | −19 s | measured |

Tier 1 together is roughly **500–700 s (11–15%)** of serial time. Note that serial savings translate
to wall clock only where they land on the critical path — which is why R1+R2 is the change to make
first.
