# Typing in angr: state of play, and a plan to fix it

*Measured with pyright 1.1.411, Python 3.12, all dependencies installed (`uv sync -p 3.12`), against
`691b8e2`. Every number is reproducible with `python scripts/typecheck.py --stats` once the
`typing-baseline-ratchet` branch is in place.*

---

## 1. Where we are

**4,753 errors and 1 warning**, spread over 519 of 1,210 Python files.

There was no `pyrightconfig.json` and no `[tool.pyright]` block, so pyright ran at its CLI default
(`standard`). CI (`angr/ci-settings`, `ga-typecheck.sh`) type-checks only the files a PR touches and
compares a per-file "badness score" — `(errors * 10 + warnings) / lines` — against master. That gate
is real, but it is a *local* ratchet: it has never required the absolute count to fall, and it cannot
see a file a PR does not touch.

Supporting numbers:

| Metric | Value |
|---|---|
| Functions with a return annotation | 2,796 / 10,950 (25.5%) |
| Parameters annotated | 6,378 / 17,541 (36.4%) |
| Files with zero errors | 691 / 1,210 (57.1%) |
| `# type: ignore` comments | 351 (232 of them bare, with no rule) |
| `# pyright: ignore[...]` comments | 58 |
| `cast(...)` calls | 175 |
| `assert isinstance(...)` | 240 |

The errors are extremely concentrated — the top 10 files hold 23% of them, the top 50 hold 53%, the
top 100 hold 69%. **"Fix the majority" means fixing about a hundred files, not twelve hundred.**

angr ships a `py.typed` marker, so all of this is part of the public API contract that
angr-management, angrop and patcherex type-check against.

### Error distribution at HEAD

| Rule | Count | | Rule | Count |
|---|---:|---|---|---:|
| reportAttributeAccessIssue | 1334 | | reportOptionalIterable | 54 |
| reportArgumentType | 1023 | | reportPossiblyUnboundVariable | 50 |
| reportOptionalMemberAccess | 938 | | reportGeneralTypeIssues | 33 |
| reportIncompatibleMethodOverride | 267 | | reportIncompatibleVariableOverride | 23 |
| reportOperatorIssue | 205 | | reportOptionalCall | 19 |
| reportCallIssue | 179 | | reportFunctionMemberAccess | 11 |
| reportOptionalSubscript | 170 | | reportRedeclaration | 9 |
| reportReturnType | 99 | | reportPrivateImportUsage | 8 |
| reportAssignmentType | 93 | | reportOverlappingOverload | 8 |
| reportOptionalOperand | 74 | | reportInconsistentOverload | 6 |
| reportIndexIssue | 74 | | reportUndefinedVariable | 6 |
| reportInvalidTypeArguments | 62 | | *(7 rules with ≤2)* | 9 |

---

## 2. What is actually wrong

The rule histogram describes symptoms. Nearly all of these errors trace back to a **small number of
declarations**. The clusters below are ordered by the number of errors each single root cause emits.

### C1 — `SimState` does not declare most of its plugins (187 errors)

`SimState` is a `PluginHub[SimStatePlugin]`, so `PluginHub.__getattr__` types every undeclared
plugin as the bare base class. `SimState` declares 12 of the 29 names registered against it, which
makes this the largest single class bucket in the report.

Declaring all 29 removes 181 of those errors and is the wrong answer. Most plugins are
**situational**: `cgc` is meaningful only for a DECREE binary, `javavm_classloader` only for a Java
project, `unicorn` only when that engine is in use, `preconstrainer` only under the tracer.
Declaring them on `SimState` asserts that every state has them — and today `state.cgc` on a Linux
binary does not merely type-check, it *succeeds*, because `get_plugin()` lazily builds anything in
the preset.

Four designs were prototyped against pyright and judged on correctness, ergonomics and blast
radius. Two of them — a class-keyed accessor pair (`state.require_plugin(Unicorn)`) and a typed
plugin descriptor — were verified **not** to express the requirement at all: a function "requiring
Unicorn" handed a plain state draws no diagnostic, because the declaration lives on `SimState` and
therefore holds for every `SimState`. Per-plugin `Protocol`s do work, resting on the verified fact
that pyright consults `__getattr__` for attribute access but *not* for protocol matching. They lose
on one measurement: a protocol-typed value is not assignable back to a `SimState`-typed parameter,
so converting one signature drags every callee with it, and downstream code cannot wrap a converted
angr API at all.

**Adopted: marker subclasses.** The plugins meaningful on any state are declared on `SimState`; the
situational ones get a marker in `angr/state_plugins/markers.py`:

```python
class StateWithUnicorn[IPTypeConc, IPTypeSym](SimState[IPTypeConc, IPTypeSym], metaclass=StateMarkerMeta):
    _plugin_name = "unicorn"
    _plugin_cls = Unicorn
    unicorn: Unicorn
```

An API then says what it needs, and gets the whole `SimState` API alongside it:

```python
def resume_unicorn(state: StateWithUnicorn) -> None:
    state.unicorn.stop(STOP.STOP_NORMAL)
    state.solver.eval(state.regs.pc)
```

Passing a plain `SimState` is a type error; a caller crosses the boundary with `isinstance`, which
narrows. Because a marker is a *subclass* rather than a `Protocol`, a marked state still satisfies
every `SimState`-typed function in angr and downstream — the relationship only fails in the
direction that should fail, so this is adoptable one signature at a time.

The split is backed by usage: the mandatory set is referenced 862 (`solver`), 502 (`memory`), 437
(`regs`) … 13 (`fs`) times across 30–208 files each, while the situational set runs from 65
(`jni_references`) down to 1 (`icicle`, `dvars`), each confined to the subsystem that owns it.

Two details are load-bearing:

* **Markers are real runtime classes, not `TYPE_CHECKING`-only names.** The `TYPE_CHECKING`-only
  formulation type-checks perfectly and is a runtime trap: `isinstance` raises `NameError`,
  `typing.get_type_hints` fails on any annotated function, and angr's docs build resolves
  annotations at runtime. pyright reports none of it.
* **The check must not vivify.** `isinstance` bottoms out in a new
  `PluginHub.active_plugin(name)`, a lookup that does not fall back to the preset. Built on
  `getattr`/`hasattr` instead, the predicate would answer "yes" for every plugin and install one as
  a side effect of the question.

Measured: **−97 errors**, versus −181 for declaring everything. The difference is the point —
`state.cgc` on an ordinary state stays an error.

The known residual is that `active_plugin()` reports the state's *history*, not its
*configuration*: a plugin enters `_active_plugins` on first access, so anything that reads
`state.unicorn` — a debugger, a `__dir__` walk — flips the predicate to true. Making the static
story fully honest needs optional plugins to stop auto-vivifying, which is a runtime change to
`PluginHub.get_plugin` and is deliberately not in this workstream.

### C2 — `platform=None` in the VEX ccall tables (195 errors in one file)

`angr/engines/vex/claripy/ccall.py` was the worst file in the repo. 134 of its errors were a single
message: `Argument of type "Unknown | None" cannot be assigned to parameter "key" of type "str"`.

Two independent declaration bugs:

1. Twenty-five helper functions declared `platform=None`, then immediately indexed `data[platform]`.
   Every public entry point passes `platform="AMD64"` or `platform="X86"` explicitly — the `None`
   default was *already* a latent `KeyError`, not a supported call.
2. `data: dict[str, dict[str, dict[str, int | None]]]` did not describe the table. The second level is
   heterogeneous: `size` is an `int`, the other four keys are sub-dictionaries, and only `OpTypes`
   legitimately holds `None` (meaning "this op does not exist on this architecture").

Replacing the annotation with a `TypedDict` and a `Literal["AMD64", "X86"]` platform took the file
from 195 errors to 13. The tables are provably byte-identical at runtime before and after.

### C3 — protobuf messages are invisible to the type checker (~92 errors)

`setup.py`'s `build_protos()` passed `--python_out=.` but not `--pyi_out=.`. protobuf builds message
classes dynamically from the descriptor at import time, so without the generated stubs every
`pb2.MemoryData()` reads as an unknown module attribute.

This is what forced the file-level `# pyright: reportAttributeAccessIssue=false` in
`knowledge_plugins/functions/function_parser.py` and six `# pyright: ignore` comments in
`sim_variable.py`. Adding one flag to the build removed the errors *and* those seven suppressions.

### C4 — the Optional epidemic (1,255 errors, 26% of the total)

`reportOptionalMemberAccess` (938) + `OptionalSubscript` (170) + `OptionalOperand` (74) +
`OptionalIterable` (54) + `OptionalCall` (19). This is the largest remaining cluster and splits into
four structurally different problems that need different remedies:

* **P1 — `project: Project | None` on base classes that require a project.** The top attribute names
  are `.arch` (38), `.loader` (34), `.simos` (29), `.factory` (15), `.kb` (14).
  `PeepholeOptimizationStmtBase` and its siblings declare `project: Project | None`, and subclasses
  like `rewrite_mips_gp_loads` open with `self.project.arch.name not in {"MIPS32", "MIPS64"}`. If
  `project` were ever `None` these would raise `AttributeError`, so the declaration is simply wrong
  for the optimizers that need it. Remedy: split the base — optimizers that need a project declare
  `project: Project` and the registry only instantiates them when one exists.
* **P2 — lazy-init attributes.** `self.x = None` in `__init__`, populated by `_analyze()`, then read
  unguarded. Endemic to `Analysis` subclasses. Remedy: set the real value in `__init__` where
  possible; otherwise a raising `@property` that encodes "you must call `_analyze()` first".
* **P3 — optional-dependency import guards (~107 errors).** `try: import unicorn / except ImportError:
  unicorn = None` in 10 modules. `state_plugins/unicorn_engine.py` is still the worst file in the tree
  (171 errors) almost entirely because of `_UC_NATIVE = None` and `unicorn = None`. See W4.
* **P4 — optional returns used without a check** (`kb.functions.get`, `cfg.get_any_node`,
  `loader.find_symbol`). This is the subset most likely to be **real latent bugs** and should be
  triaged by hand, not mechanically narrowed.

### C5 — AIL expressions are declared too wide (~200 errors)

`Cannot access attribute "X" for class "Expression"` is 142 occurrences; `Statement` adds 23. The
attribute names are `args` (73), `target` (28), `operands` (14), `varid` (13), `op` (5).

The `angr/rustylib/ailment.pyi` stub already declares the variant hierarchy correctly
(`class Const(Atom)`, `class BinaryOp(Op)`, `class Call(Expression)`, …), and the runtime metaclass
makes `isinstance` narrowing work. The errors come from **container and parameter declarations that
say `Expression` where only one variant is ever stored** — e.g. `SideEffectStatement.expr` is typed
`Expression` but always holds a `Call`, so `stmt.expr.args` fails. The fix is tightening those
declarations in the stub and in `ailment/statement.py`, not casting at 200 call sites.

Because the consumers are `angr/analyses/decompiler` (669 errors, the largest directory), this is the
highest-leverage remaining cluster.

### C6 — LSP violations in the visitor and mixin hierarchies (298 errors)

`reportIncompatibleMethodOverride` (267) + `reportIncompatibleVariableOverride` (23) + 8 overlapping
overloads. Concentrated in `variable_recovery/engine_ail.py` (41), `engines/__init__.py` (24),
`engines/vex/heavy/heavy.py` (13), and the `_handle_*` visitor methods of `AILBlockWalker` /
`SimEngineLight`. A separate group is `angr/analyses/identifier/functions/*`, where 33 errors come
from `pre_test` / `can_call_other_funcs` / `var_args` overriding `Func` with narrowed parameters —
classic contravariance violations. The memory mixin stack (`angr/storage/memory_mixins`, 283 errors)
is the same story: `MemoryMixin.merge`/`store`/`changed_bytes` are declared with signatures the
concrete mixins cannot honour.

### C7 — claripy AST precision (~250 errors)

`Cannot access attribute … for class "Base"` (46), `for class "Backend"` (29), and
`No overloads for "eval" match the provided arguments` (the bulk of 179 `reportCallIssue`). angr
functions that always return a `BV` are declared or inferred as the `Base` supertype, so `.chop()`,
`__getitem__` and `solver.eval` overload matching all fail. Some of this is angr's to fix by
tightening its own return types; some needs `claripy`'s stubs to gain overloads and must be filed
upstream.

### C8 — genuine bugs pyright already found

Not typing debt — actual defects:

| Site | Defect |
|---|---|
| `storage/file.py:923` | `SimFileDescriptor.seek()` leaves `new_pos` unbound for any `whence` other than `"start"`/`"current"`/`"end"` → `NameError` instead of a proper error |
| `analyses/variable_recovery/engine_vex.py:24,29,30` | `"VariableRecoveryFastState"` is not defined — a forward reference with no matching import |
| `misc/bug_report.py:31–33,55,62,69,70` | `angr`, `pyvex`, `unicorn`, `Repo`, `InvalidGitRepositoryError`, `python_filename` all possibly-unbound; the bug-report helper can itself crash |
| `analyses/reaching_definitions/__init__.py:61`, `memory_mixins/…/cooperation.py:192` | `set` entries typed `X | set[X]` — a `set` is being added to a `set` |
| `analyses/propagator/engine_base.py:54` | abstract `process()` called on a class that never implements it |
| `procedures/cgc/receive.py:89–92` | `read_length` possibly unbound |
| `analyses/cfg/cfg_fast.py:4784` | `func_addr` possibly unbound |

`reportPossiblyUnboundVariable` has 50 sites; every one deserves a look, because the failure mode is
a `NameError` on an uncommon path.

---

## 3. The branches

The work is split so that each branch is based on `master` and can be reviewed, merged or dropped
independently. Each row below was measured by merging the branch onto `typing-baseline-ratchet` and
running `scripts/typecheck.py`, so the CI outcome is known before the PR is opened. "Regressed
pairs" counts `(file, rule)` pairs whose error count went up.

| Branch | What it does | Errors | Regressed pairs |
|---|---|---:|---:|
| `typing-baseline-ratchet` | config, `scripts/typecheck.py`, the baseline, `docs/getting-started/typing.rst` | sets 4,753 | — |
| `typing-ccall-tables` | `TypedDict` + `Literal` platform for the VEX ccall tables | −183 | 0 |
| `typing-simstate-plugin-markers` | mandatory plugin declarations + the marker types (C1) | −97 | 4 |
| `typing-protobuf-stubs` | `--pyi_out` for protobuf; drops 7 suppressions | −92 | 10 |
| `typing-dead-suppressions` | deletes 102 suppression comments that suppress nothing | 0 | 0 |
| `typing-latent-bugs` | fixes three latent `NameError`s pyright found | −13 | 0 |
| `typing-plan` | this document | — | — |

Ordering is free except that the baseline branch should land first, so the others are measured
against it. Only `typing-protobuf-stubs` and `typing-latent-bugs` touch a common file
(`pyproject.toml`), in different sections; the merge is clean.

**"Newly visible" is not "regressed."** Two branches make previously-hidden errors appear, which is
the mechanism working:

* The protobuf stubs expose 10 `(file, rule)` pairs of **real serialization bugs** — protobuf
  scalar fields are strictly typed at runtime too, so `edge.src_ea = <SootAddressDescriptor>`,
  `obj.value = <float>` and `var_ident = None` all raise `TypeError` when they are reached. These
  are worth their own pass over `Serializable`.
* The marker branch exposes 12, all the "attribute declared Optional but used unguarded" pattern,
  in `procedures/posix/accept.py` (5), `state_plugins/heap/heap_ptmalloc.py` (3), and one each in
  `glibc/__libc_start_main.py`, `posix/socket.py` and `win32/heap.py`.

Whichever of those merges after the baseline needs one `python scripts/typecheck.py --update`, with
the newly-visible list in the PR body — which is exactly the workflow `typing.rst` documents.

Tests run per branch: 569 passing across `engines/vex`, `state_plugins`, `sim`, `storage`,
`serialization`, `knowledge_plugins`, `procedures`, `simos`, `exploration_techniques`, `angrdb` and
the ccall rewriters.

Two things were deliberately *not* turned into branches:

* **The optional-dependency imports (W4).** Measuring the ceiling by making the imports
  unconditional gives −107, but `SimEngineUnicorn` is imported unconditionally by
  `angr.engines.__init__` and degrades gracefully via `if uc_module is None or _UC_NATIVE is None`.
  So the guard cannot simply move to the module without deciding what happens to that engine. It
  needs the design in W4 below, not a patch.
* **`Definition`'s generic arity.** See W14 — it looked mechanical and is not.

## 4. The plan

Ordered by errors-removed per unit of effort×risk, respecting dependencies.

### Phase 1 — mechanical, high-yield (done: −479; remaining: ~−200)

A tick means the change is on one of the branches in §3, with the error figure measured rather
than estimated.

| # | Workstream | Root cause | Errors | Effort | Risk |
|---|---|---|---:|---|---|
| W1 | `SimState` declarations + plugin markers | C1 | −97 ✅ | M | low |
| W2 | ccall typed tables | C2 | −183 ✅ | S | low |
| W3 | protobuf `--pyi_out` | C3 | −92 ✅ | S | low |
| W4 | Optional-dependency imports | C4/P3 | ~−107 | M | **medium** |
| W5 | Delete the 102 dead suppressions | — | 0 ✅ | S | low |
| W6 | Fix the C8 bugs | C8 | −13 ✅ (part) | M | low |

**W4 needs design, not a patch.** Measuring the ceiling by making the imports unconditional gives
−107, but that would make `unicorn`, `pypcode`, `sqlalchemy`, `xbe` and `pysoot` hard requirements —
unacceptable. The honest fix moves the guard from the *symbol* to the *module*: `unicorn_engine.py`
does a plain `import unicorn`, and `state_plugins/__init__.py` wraps *its* import in the
`try`/`except ImportError`. The module is then either fully importable and fully typed, or not
imported at all, and no name is ever secretly `None`. Applies to all 10 sites.
*Explicitly not acceptable:* `if TYPE_CHECKING: import unicorn / else: try: … except: unicorn = None`.
That silences the checker by lying about runtime and is exactly the kind of hack this plan avoids.

† W6 is partly landed: three of the C8 bugs are fixed on `typing-latent-bugs`. The remainder are
the other 47 `reportPossiblyUnbound` sites plus the `reportUnhashable` and `reportAbstractUsage`
ones; several need a behavioural decision rather than an annotation. One was deliberately deferred:
adding the missing `TYPE_CHECKING` import to `variable_recovery/engine_vex.py` fixes three
`reportUndefinedVariable` but makes the file checkable for the first time and surfaces 20 errors
underneath, almost all `RichR[BV]` not being assignable to `RichR[BV | FP]` — `RichR`'s invariance,
which belongs with W11.

**W5** is free and directly on-policy: `reportUnnecessaryTypeIgnoreComment` reports **102 dead
suppressions across 52 files** — a quarter of the ignore comments in the tree suppress nothing.
Deleting them is provably comment-and-whitespace-only (identical AST across all 52 files), and one
of the 102 turned out to be load-bearing: it listed two rules, one of which had gone stale, and
removing it exposed `RustSimTypeFunction._init_str` calling `_init_str()` on a `returnty` that may
be `None` — a regression from the base class, which already renders a void return as `"void"`.
Once landed, turn the rule on so they cannot come back.

### Phase 2 — the Optional epidemic (~−600 of the 1,255)

| # | Workstream | Errors | Effort | Risk |
|---|---|---:|---|---|
| W7 | `project: Project \| None` → `Project` on the peephole/optimization bases (C4/P1) | ~−150 | M | low |
| W8 | Lazy-init attributes in `Analysis` subclasses (C4/P2) | ~−250 | L | medium |
| W9 | Hand-triage optional lookups (C4/P4) | ~−200 | L | low |

W9 is deliberately last and deliberately manual: these are the sites where the `None` is *real* and
the code is missing a check. Mechanically narrowing them with `assert` would convert a wrong answer
into a crash and hide the defect — the point is to find the bugs.

### Phase 3 — the two big hierarchies (~−450)

| # | Workstream | Errors | Effort | Risk |
|---|---|---:|---|---|
| W10 | Tighten AIL container/parameter declarations to variant types (C5) | ~−200 | L | low |
| W11 | LSP-correct visitor and `Func` signatures (C6) | ~−150 | L | medium |
| W12 | Generic `MemoryMixin` over page/value type (C6) | ~−100 | XL | **high** |

W10 first: it is declaration-only, it unblocks the decompiler tree (669 errors, the largest
directory), and it needs no runtime change. W12 last: re-architecting the memory mixin stack is the
riskiest change in this document and should not gate anything else.

### Phase 4 — precision and the long tail (~−400)

W13 claripy return-type tightening (C7, ~−150, plus an upstream issue for `claripy`'s `eval`
overloads). W14 the generic arity of `Definition` and `CodeLocation` — 58 of the 62
`reportInvalidTypeArguments` are `Definition[Atom]` written against
`Definition[A: Atom, CodeLoc: CodeLocation | AILCodeLocation]`. Giving `CodeLoc` a PEP 696 default
fixes the arity (verified) but immediately surfaces 29 further errors, because `CodeLocation` is
*itself* generic in three parameters and is written bare almost everywhere. The two have to be
settled together; this is a design task, not the mechanical fix it looks like. W15 the `SimType`
hierarchy and `angr/rust/sim_type.py`, where making `SimTypeFunction` generic over its
argument/return types removes the three `reportIncompatibleVariableOverride` suppressions honestly.

### Phase 5 — raise the floor

Only once the count is low enough to see: promote rules in cost order. Measured cost of each today:

| Rule | Cost today | | Rule | Cost today |
|---|---:|---|---|---:|
| reportInconsistentConstructor | 1 | | reportUnnecessaryContains | 13 |
| reportPropertyTypeMismatch | 2 | | reportMissingTypeStubs | 27 |
| reportDeprecated | 3 | | reportConstantRedefinition | 73 |
| reportUnnecessaryCast | 5 | | reportUnnecessaryTypeIgnoreComment | 108 |
| reportUntypedNamedTuple | 5 | | reportUninitializedInstanceVariable | 116 |
| reportCallInDefaultInitializer | 12 | | reportImplicitStringConcatenation | 147 |
| | | | reportUnnecessaryIsInstance | 175 |
| | | | reportUnnecessaryComparison | 388 |

The two big ones are deliberately left for last: **`reportMissingParameterType` costs 13,393** and
**`reportImplicitOverride` costs 3,984**. Neither should be attempted globally. Instead use
`executionEnvironments` to hold already-clean subtrees to a higher standard while the rest catches
up. Ten directories with ≥4 files are already at zero errors today and can be pinned immediately:
`angr/mcp`, `angr/analyses/flirt`, `angr/protos`, `angr/rust/knowledge_plugins`, `angr/rust/utils`,
`angr/analyses/decompiler/presets`, `angr/analyses/cfg_slice_to_sink`, `angr/procedures/libstdcpp`,
`angr/procedures/win32_kernel`, `angr/engines/soot/statements`.

---

## 5. Process

1. **Replace the score ratchet with the baseline ledger.** The current per-file badness score only
   looks at changed files and only compares a ratio, so a file can gain errors while its score falls
   (add 200 clean lines, add 2 errors — score improves). `scripts/typecheck.py` checks the whole
   repo, keys on `(file, rule)`, and refuses to grow. Keep the existing per-file gate during the
   transition; it gives a better error message on the diff.
2. **The baseline can only shrink.** `--update` refuses to write a larger total. Because a
   suppression and a fix both reduce the count identically, the ledger must be paired with (3).
3. **Make every remaining suppression accountable.** Enable ruff's `PGH003` to ban bare
   `# type: ignore` (232 of the 351 today), require the rule code and a reason, and turn on
   `reportUnnecessaryTypeIgnoreComment` after W5 so dead ones cannot accumulate again.
4. **Document the policy** — `docs/getting-started/typing.rst` (added), linked from `developing.rst`.
5. **Add stub packages as dev dependencies** where they exist and are used: the 27
   `reportMissingTypeStubs` are `capstone` (12), `pysoot` (5), `sympy` (3), `pycparser` (3),
   `pydemumble` (3), `mulpyplexer` (1). `types-networkx` is worth evaluating separately: networkx is
   imported by 86 files and, having no `py.typed`, is inferred from source, so its graph types leak
   `Unknown` through every analysis that holds one.

---

## 6. Expected outcome

| | Errors | Note |
|---|---:|---|
| HEAD | 4,753 | |
| The six code branches in §3 | ~4,370 | −385 measured, with W4 and the rest of W6 still to come |
| After Phase 1 | ~4,050 | |
| After Phase 2 | ~3,450 | |
| After Phase 3 | ~3,000 | |
| After Phase 4 | ~2,600 | |

The Phase-1 total is lower than the sum of the branches because the two largest overlap: the marker
branch and the protobuf branch each surface errors the other would otherwise have hidden.

Roughly **half** the errors fall out of six declaration-level clusters. The residual after Phase 4
is dominated by three things: `angr/engines/soot` and `angr/procedures/java*` (~120 errors in a
subsystem whose maintenance status should be decided before anyone types it), the deep
`memory_mixins` stack (W12), and the long tail of one- and two-error files (247 files hold exactly
one, two or three errors each).

Getting to zero is not the goal and should not be. The goal is that the number only goes down, that
every remaining error is attributable, and that no error is hidden behind a comment.
