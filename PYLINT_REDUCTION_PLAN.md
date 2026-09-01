# Pylint message reduction plan

This document analyzes the current pylint status of the `angr` package and lays
out a phased plan to reduce the total number of messages, with special focus on
the error (E) and fatal (F) categories.

## Snapshot

- **Tool**: pylint 4.0.8 / astroid 4.0.4, Python 3.12.3, run with the repo's
  `[tool.pylint]` configuration from `pyproject.toml`.
- **Invocation**: `pylint angr` from the repository root, all dependencies
  installed via `uv sync` (so imports resolve and inference is accurate).
- **Scope**: the `angr` package — 1,211 Python files, ~269K lines.
- **Result**: **4,672 messages + 1 fatal**, score **0.00/10**.

| Category | Count |
| --- | ---: |
| Warning (W) | 2,408 |
| Convention (C) | 777 |
| Refactor (R) | 705 + 543 duplicate-code¹ |
| Error (E) | 238 |
| Fatal (F) | 1 |

¹ `duplicate-code` (R0801) messages are multi-line blocks; they are counted
separately from the single-line parse in some tallies below.

### Finding 0: parallel pylint runs crash outright

`pylint -j <N> angr` **aborts** with an unhandled `AstroidError` and produces a
truncated report. The trigger is `angr/rust/sim_type.py:386`:

```python
fget = SimStruct.size.fget
size = fget(self) if fget else 0
```

pylint's `_check_using_constant_test` asks astroid to infer the truthiness of a
`property.fget` object and astroid's `PropertyModel.infer_call_result` raises.
In serial mode this degrades to a per-module `F0002 astroid-error` and the run
continues; in parallel mode the worker exception kills the whole run. Until
fixed, any CI or local full run must be serial (~3 min) instead of parallel
(~45 s).

### Where the messages come from

| Bucket | Count | Share | Nature |
| --- | ---: | ---: | --- |
| `angr/rustylib/*.pyi` stubs | 712 | 15% | False positives — stub semantics |
| `angr/protos/*_pb2.py` generated protobuf | 640 | 14% | Generated code (620 are `protected-access`) |
| `cyclic-import` (R0401, whole-program) | 580 | 12% | Architectural; all reported on one arbitrary file |
| `duplicate-code` (R0801, whole-program) | 543 | 12% | Mostly known twin files (see below) |
| Real per-file messages in hand-written code | 2,197 | 47% | Mixed |

The `.pyi` bucket is pure noise: stub files legally use forward references
(→ 173 `undefined-variable` "errors") and declare signatures whose arguments
are never used (→ 428 `unused-argument`), plus 38 `super-init-not-called`,
39 `missing-class-docstring`, etc. `ruff` already excludes `*_pb2.py`;
pylint's config excludes nothing.

### Real per-file messages (2,197), top messages

| Count | Message | Notes |
| ---: | --- | --- |
| 1,059 | `protected-access` (W0212) | Endemic to angr's architecture; **already disabled in the angr/ci-settings container pylintrc** that gates CI, but not in this repo's config |
| 623 | `missing-class-docstring` (C0115) | 360 of them are `SimProcedure` classes in `angr/procedures/**` where the class name is the API name |
| 94 | `unused-argument` (W0613) | Mostly interface-conformance callbacks |
| 63 | `consider-using-f-string` (C0209) | Mechanical |
| 49 | `no-self-use` (R6301) | Mechanical-ish |
| 33 | `broad-exception-raised` (W0719) | Needs specific exception types |
| 31 | `logging-fstring-interpolation` (W1203) | Mechanical |
| 30 | `no-member` (E1101) | Mixed: real rot + mixin/protobuf false positives |
| 24 | `bad-builtin` (W0141) | `map`/`filter` uses |
| ~290 | long tail (40+ message types) | Mostly mechanical |

`duplicate-code` concentrates heavily in a few places:
`analyses/decompiler/structured_codegen/c.py` ↔ `.../rust.py` (127 + 125 hits —
the Rust code generator is a fork of the C one), `engines/light/engine.py` (34),
`knowledge_plugins/key_definitions/{unknown_size,undefined}.py` (21–23), and the
VEX/pcode lifters.

### The 62 error-category messages in hand-written code

Roughly **half are true positives**, including at least one guaranteed crash:

- `angr/analyses/vsa_ddg.py:417` — `nodes = []` then `nodes.add(n)`:
  **`AttributeError` whenever a node matches** (`.add` is a set method).
- `angr/state_plugins/trace_additions.py` — 6 uses of `SimCCCdecl.arg(...)`,
  an API that no longer exists; the module has rotted.
- `angr/procedures/stubs/Redirect.py:19` — calls nonexistent
  `self.add_successor`.
- `angr/analyses/datagraph_meta.py` — 10 `no-member`s: the mixin references
  members (`_vfg`, `graph`, `_imarks`, `_simproc_map`) it never declares.
- 9 × `possibly-used-before-assignment` (E0606) in `state_plugins/history.py`,
  `engines/vex/claripy/ccall.py`, `storage/file.py`, `analyses/ddg.py`,
  `analyses/congruency_check.py` — genuine uncovered branches; initialize the
  variables or raise explicitly.
- 3 × `used-before-assignment` (E0601) — `analyses/analysis.py:145`
  (`CFBlanket` referenced in the `KnownAnalysesPlugin` protocol before its
  deferred import), `soot_class_hierarchy.py:280`, `utils/formatting.py:23`
  (platform-gated `colorama`; safe at runtime but fragile).
- Singletons worth fixing: `reassembler.py:1067` (`__str__` returns non-str),
  `region_identifier.py:32` (invalid sequence index),
  `ret_deduplicator.py:102` (too many ctor args), `simos/userland.py:74`
  (assigning a `None`-returning call), `llm_client.py:94` (kwarg `vertexai`
  should be verified against the pinned pydantic-ai API).

The rest are **structural false positives** to be silenced precisely:

- 12 × `assignment-from-no-return` (E1111) — the cooperative
  `MemoryMixin.load/store` chain: base methods have no return statement, so
  every `r = super().load(...)` in a mixin trips it. Fix by giving the base
  methods in `angr/storage/memory_mixins/__init__.py` explicit return type
  annotations / `raise NotImplementedError` stubs (also improves typing), not
  by scattering disables.
- 6 × `no-member` on `angr.protos.*_pb2` module attributes — protobuf classes
  are created at runtime; add `ignored-modules = ["angr.protos.*"]`.
- 2 × cffi `unexpected-keyword-arg` in `state_plugins/unicorn_engine.py`,
  2 × `SimStatePlugin` mixin `no-member`, 1 × `Ellipsis.concat`
  (`pages/cooperation.py` — a `...`-typed class attribute), 1 ×
  `import-error` for optional `IPython` — targeted inline disables.

---

## The plan

Phases are ordered by leverage (messages removed per unit of effort and risk).
Projected counts assume the phases land in order.

### Phase 0 — Unbreak pylint itself (no message-count change)

1. Rewrite `angr/rust/sim_type.py:385-386` to avoid the astroid crash, e.g.
   `size = SimStruct.size.fget(self)` (a property's `fget` is never `None`;
   the conditional is vacuous) — and report the crash upstream to astroid
   (crash template is auto-generated in `~/.cache/pylint/`).
   This removes the F0002 and makes `pylint -j` usable (~45 s full runs).
2. Delete the stale `W0232` from the module-level disable in
   `angr/storage/file.py:21` (`useless-option-value`, R0022).

*Effort: minutes. Risk: none.*

### Phase 1 — Stop linting generated and stub files (−1,352 → ~3,320)

Add to `[tool.pylint.main]` in `pyproject.toml`:

```toml
ignore-patterns = [
    ".*_pb2\\.py$",  # generated protobuf modules (mirrors the ruff exclude)
    ".*\\.pyi$",     # stubs: forward refs and unused args are stub-legal
]
ignored-modules = ["angr.protos.*"]  # runtime-generated protobuf members
```

This removes 712 stub + 640 protobuf messages — including **176 of the 238
E-category messages** (173 stub `undefined-variable` + 3 stub
`used-before-assignment`) and the 6 `no-member`s on `_pb2` modules — all false
positives. `pyright` (already in the dev group) is the right tool for the
`.pyi` stubs instead.

*Effort: one small PR. Risk: none — these messages carry no signal.*

### Phase 2 — Decide policy on the two whole-program checks (−~980 → ~2,340)

Both checks are currently useless in practice: every occurrence is attributed
to whichever module pylint checked last (all 1,123 land on
`exploration_techniques/manual_mergepoint.py:1`), and the per-changed-file CI
gate can never act on them.

1. **`cyclic-import` (580)**: angr's core packages are deeply and deliberately
   interdependent (deferred imports everywhere). Recommendation: **disable
   R0401** in the config and, if decoupling is ever wanted, track it as an
   architectural project — a linter message per cycle-edge is not an actionable
   backlog. (−580)
2. **`duplicate-code` (543)**: raise `min-similarity-lines` from the default 4
   to ~15 so only egregious duplication surfaces (estimated −~400), and file
   issues for the two real hotspots: the C↔Rust structured-codegen twins and
   the `key_definitions` singleton pair. Full deduplication of the codegen
   backends is a worthwhile refactor but must not block lint hygiene.

*Effort: config PR + 2 tracking issues. Risk: none.*

### Phase 3 — Burn down the real E category (−62 → ~2,280, and real bugs fixed)

Fix the ~30 true positives listed above (the `vsa_ddg` crash, the rotted
`trace_additions`/`Redirect` APIs, `datagraph_meta` member declarations, the
E0606/E0601 initialization gaps, and the singletons). Silence the ~20
structural false positives at the source (mixin base-method annotations) or
with targeted inline disables. Suggested batching:

- one PR for `storage/memory_mixins` (annotations kill all 12 E1111 + 2 E1101),
- one PR for dead/rotted code (`trace_additions`, `Redirect`, `datagraph_meta`,
  `vsa_ddg` — decide fix vs. delete; some of this code may be scheduled for
  removal anyway),
- one PR for the initialization gaps and singletons.

After this phase **`pylint --fail-on=E,F angr` passes**, which is the
gate that matters most: E/F messages are the ones that flag probable runtime
breakage.

*Effort: 2–4 focused PRs. Risk: low; each fix is small and testable.*

### Phase 4 — Bulk warning policy + mechanical cleanup (−~1,600 → ~600–700)

1. **`protected-access` (1,059, 48% of real messages)**: the CI container's
   pylintrc already disables it — the repo config just hasn't caught up, so
   full-tree runs drown in a message CI never enforces. Cross-object access to
   `_`-members is a load-bearing angr idiom (45 inline disables already exist
   for it). Recommendation: **disable W0212 in `pyproject.toml`** to match the
   de facto CI standard. (−1,059) If maintainers instead want to keep it, it
   must be a per-subpackage burn-down (start: `analyses` 320, `storage` 164,
   `knowledge_plugins` 118) — months of churn for little defect yield.
2. **`missing-class-docstring` (623)**: script one-line docstrings for the 360
   `SimProcedure` classes in `angr/procedures/**` (the class name is the libc/
   API function being modeled — a docstring like `"""SimProcedure modeling
   memcpy."""` is genuinely useful in `help()`/docs), then write real
   docstrings for the remaining ~263 opportunistically (good first issues).
3. **Mechanical fixes, largely scriptable** (~250):
   `consider-using-f-string` (63), `logging-fstring-interpolation` +
   `logging-not-lazy` (35), `consider-using-in` (17), `no-else-return/raise`
   (21), `consider-using-dict-items` (10), `use-implicit-booleaness-not-len`
   (6), `useless-return` (3), import-order family (9), etc. Several have
   ruff autofixes (`UP032`, `SIM`, `G` families) — prefer enabling the
   matching ruff rule + `ruff --fix` over hand-editing, so the fix is
   enforced going forward.
4. **Judgment-call warnings** (~200): `unused-argument` (94 — rename to `_x`
   or disable per line where the signature is interface-bound),
   `no-self-use` (49 — make free functions or add the disable where the
   API shape is deliberate), `broad-exception-raised` (33 — introduce/use
   specific `AngrError` subclasses), `bad-builtin` (24),
   `useless-parent-delegation` (16), `arguments-renamed` (15),
   `attribute-defined-outside-init` (9), `super-init-not-called` (3).

*Effort: one config PR + a handful of mechanical PRs (scriptable) + slow-burn
for the judgment calls. Risk: low-medium (mechanical rewrites need test runs).*

### Phase 5 — Ratchet so counts only go down

1. The existing CI gate (angr/ci-settings `lint.py`) only lints changed files
   and compares scores, so whole-tree regressions in untouched files are
   invisible. After Phases 0–2 make full runs fast (parallel works) and clean
   of known noise, add a **full-package job**: `pylint -j 0 --fail-on=E,F angr`
   (fails only on error/fatal) to `nightly-ci.yml` or the main CI.
2. Once Phase 4 lands, tighten to a message-count budget (e.g.
   `--fail-under` on the score, or a counted-baseline diff) and lower the
   budget as cleanups land.
3. Align `pyproject.toml`'s disable list with the CI container pylintrc (they
   currently diverge: e.g. the container disables `protected-access`,
   `too-few-public-methods`, `no-else-return`, `consider-using-f-string`;
   the repo doesn't) so local runs, editor integration, and CI agree on what
   a violation is. The repo's `pyproject.toml` should be the single source of
   truth, and `ci-settings` should eventually defer to it.

## Projected trajectory

| Milestone | Total messages | E/F messages |
| --- | ---: | ---: |
| Today | 4,672 (+1 fatal, parallel runs broken) | 239 |
| After Phase 0–1 (config + crash fix) | ~3,320 | 56 |
| After Phase 2 (whole-program checks) | ~2,340 | 56 |
| After Phase 3 (error burn-down) | ~2,280 | **0** |
| After Phase 4 (policy + mechanical) | ~600–700 | 0 |
| Phase 5 | ratcheted downward | enforced 0 |

Phases 0–2 are pure configuration/one-liner work and remove ~50% of all
messages and ~77% of E/F messages — all of it noise with zero suppression of
real signal. Phase 3 is where actual bugs get fixed. Phase 4 is where the
long tail gets addressed at a sustainable pace, and Phase 5 keeps it from
regressing.
