# Can PyO3 complex enums simplify the ailment Rust port?

Investigation notes. Conclusion: **no for the main `Expression` / `Statement`
types, but the boilerplate they were meant to remove can be removed a
different way** — by exposing a real PyO3 class hierarchy over the existing
fat enum. All claims below were verified empirically against PyO3 0.29
(the pinned version) under `abi3`.

## What a complex enum would give us

Declaring `AilExpression` as `#[pyclass] enum` would generate, for free:

* a Python class per variant (`Expression.Const`, `Expression.BinaryOp`, ...)
  that is a genuine subclass of `Expression`;
* a getter per variant field — replacing the ~1200 lines of hand-written
  per-variant `match`-and-`AttributeError` accessors in `ail_expr.rs`
  (73 getters) and `ail_stmt.rs` (35 getters);
* `__match_args__`, and `AttributeError` on wrong-variant field access;
* native `isinstance`, which would retire the `_AilMarkerMeta` metaclass,
  the `pykind` cached-`Py<int>` field, and most of the 984 lines of marker
  classes in `angr/ailment/{expression,statement}.py`.

`#[pymethods]` on the enum works and the methods are inherited by every
variant class, so the existing method surface (`likes`, `matches`, `replace`,
`__repr__`, `to_bytes`, ...) would carry over unchanged.

## Why it does not work here

Four blockers, each confirmed by compiling against PyO3 0.29:

1. **`Arc<T>` fields are rejected.** Every variant field must implement both
   `IntoPyObject` and `FromPyObject`; `Arc<AilExpression>` implements
   neither, and the macro errors with ``Arc<Shape> cannot be converted to a
   Python object`` / ``cannot be used as a Python function argument``.
   `ail_expr.rs` + `ail_stmt.rs` have 74 `Arc<AilExpression>` operand fields.
   The only accepted alternative is `Py<AilExpression>`, i.e. one Python heap
   object per AIL node — abandoning the whole point of the current model.

   Measured cost of that swap (perfect binary tree, 4095 nodes, release build):

   | | `Arc<T>` | `Py<T>` |
   |---|---|---|
   | Rust-side tree walk | 1.65 ns/node | 8.63 ns/node |
   | Rust-side tree build | 33.6 ns/node | 57.8 ns/node |

   A ~5x regression on traversal, which is the hot path for `cmp_ail`,
   `Hash`, `replace_ail`, repr and serialization.

2. **Variant fields are read-only, permanently.** Assigning raises
   ``AttributeError: attribute 'radius' of '...' objects is not writable``,
   and there is no opt-in: `#[pyo3(set)]` inside a variant is not even
   recognized as an attribute by the macro. There is no per-field control of
   any kind. angr mutates AIL nodes in place in many places
   (`call.args = ...`, `call.bits = ...`, `new_stmt.src = ...`,
   `assignment.dst = ...`, `expr.value = ...`, `last_stmt.ret_exprs = []`),
   and the port currently provides 37 setters to support that.

3. **`**kwargs` constructors are unsupported.** Every AIL constructor takes
   `**tags`. `#[pyo3(constructor = (radius, **tags))]` fails to compile with
   ``kwargs must be Option<_>`` for every field type tried
   (`Option<HashMap<String, i64>>`, `Option<Py<PyDict>>`, ...).

4. **The shared header has nowhere to live.** `idx` / `tags` / `bits` /
   `depth` / `cached_hash` are one `ExprHeader` struct today. In a complex
   enum they would have to be duplicated into all 27 expression and 10
   statement variants, and `CachedHash` is not `IntoPyObject` so it could not
   be a field at all. The universal accessors would each become a 27-arm
   match — *adding* boilerplate where the design currently has none.

The smaller payload enums (`OIdent`, `ParameterOIdent`, `CFGTarget`,
`RoundingModeOrExpr`, `ConstValue`) are also a poor fit, for a different
reason: they deliberately map onto *native* Python types (`None` / `int` /
`tuple`, `Expression`-or-`str`, `int`/`float`). A complex enum would replace
those with wrapper classes and break every consumer.

## What does work: a native class hierarchy over the fat enum

The valuable half of the complex-enum offer — native `isinstance` — is
available without touching the data model. Keep `AilExpression`/`ExprInner`
and the `Arc` operands exactly as they are, mark the base
`#[pyclass(subclass)]`, and add one empty PyO3 subclass per variant:

```rust
#[pyclass(module = "...", subclass, skip_from_py_object, name = "Expression")]
pub struct Expression { pub expr: AilExpression }   // pykind field no longer needed

#[pyclass(extends = Expression, subclass, name = "Atom")] pub struct Atom;
#[pyclass(extends = Atom, name = "Const")] pub struct Const;

#[pymethods]
impl Const {
    #[new]
    #[pyo3(signature = (idx, value, bits, **tags))]
    fn new(idx: i64, value: ConstValue, bits: u32, tags: Option<Tags>)
        -> PyClassInitializer<Self>
    {
        PyClassInitializer::from(Expression { expr: /* ... */ })
            .add_subclass(Atom)
            .add_subclass(Const)
    }
}
```

Verified working under `abi3`: multi-level chains (`FnMacro` -> `Macro` ->
`Call` -> `Expression`), `**kwargs` in `#[new]`, setters on the base,
base-class methods inherited by every subclass, `Bound<Expression>` borrows
through a subclass instance, and `Arc` operands untouched. The abstract
groupings are expressible because they are tree-shaped and disjoint:
`Atom` = {Const, Tmp, Register, ComboRegister, VirtualVariable, Phi},
`Op` = {UnaryOp, BinaryOp, Convert, Reinterpret, Let},
`Call` ⊃ `Macro` ⊃ `FunctionLikeMacro`.

Measured (min of 5 x 200k, release):

| check | current metaclass | native subclass |
|---|---|---|
| `isinstance` hit | ~164 ns | 23 ns |
| `isinstance` miss | ~165 ns | 38 ns |
| `isinstance(x, Atom)` | ~1 us (6 marker checks) | 26 ns |

Construction is slightly *cheaper* than today (no `pykind` `Py<int>` to
materialize, 48 vs 56 bytes/instance). The codebase has 1645 static
`isinstance` sites against AIL markers, and `expression.py` records ~1.1M
dynamic marker checks per `Decompiler(doit)`.

What this costs: `Expression::wrap` (57 call sites), `Statement::wrap` (4),
the ~33 `#[pymethods]` returning `PyResult<Self>`, and the three
`IntoPyObject` impls must route through one variant-aware constructor so a
node is never handed to Python as a bare base instance. Mechanical, but it
must be exhaustive — a missed site produces an object that silently fails
every `isinstance` check.
