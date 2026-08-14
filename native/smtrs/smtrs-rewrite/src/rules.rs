//! The rewrite rules. Every rule must be locally sound: the produced term is
//! logically equivalent to `(op args)` for all variable assignments. Rules
//! also normalize the operator set so later stages see fewer ops:
//!
//!   Implies -> Or          BvNand/Nor/Xnor -> BvNot(BvAnd/Or/Xor)
//!   BvUgt/Uge -> Ult/Ule   BvComp -> Ite(Eq)
//!   BvSgt/Sge -> Slt/Sle   ZeroExtend/SignExtend/RotateL/R/Repeat -> Concat/Extract
//!
//! After rewriting, only these BV ops remain for the bit-blaster:
//! Neg Add Sub Mul Udiv Urem Sdiv Srem Smod Not And Or Xor Shl Lshr Ashr
//! Concat Extract Ult Ule Slt Sle (+ Bool ops, Eq, Distinct, Ite).

use rustc_hash::FxHashMap;
use smtrs_core::{apply_op, BvConst as Bv, Op, PollTick, TermId, TermPool, Value};

const MAX_LOCAL_ITERS: usize = 16;

type Stats = FxHashMap<&'static str, u64>;

fn hit(stats: &mut Stats, rule: &'static str) {
    *stats.entry(rule).or_insert(0) += 1;
}

thread_local! {
    static RULE_DEPTH: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    /// Reference counts of pre-existing terms (parents across the assertion
    /// set), installed by `Rewriter::rewrite`. Flattening decisions consult
    /// this: re-associating a *shared* bvadd/bvmul destroys circuit reuse at
    /// the blaster (a shared inner product would be re-blasted per new
    /// association), so shared arithmetic children are left nested.
    pub static REFCOUNTS: std::cell::RefCell<FxHashMap<TermId, u32>> =
        RefCell::new(FxHashMap::default());
    /// Memo for the *recursive* rule applications (extract pushdown, concat
    /// splitting) within a single top-level `rewrite_node` call. See
    /// `NODE_MEMO` notes on `rewrite_node`.
    static NODE_MEMO: std::cell::RefCell<FxHashMap<(Op, Vec<TermId>), TermId>> =
        RefCell::new(FxHashMap::default());
    /// Cooperative interrupt, installed by `Rewriter::rewrite` for the
    /// duration of the call. Polled every `POLL_PERIOD` node rewrites.
    static TERMINATE: RefCell<Option<Arc<AtomicBool>>> = const { RefCell::new(None) };
    /// Sticky: set once the flag has been observed, so later polls are free
    /// and the whole in-flight recursion degrades consistently.
    static TERM_HIT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static POLL_TICK: std::cell::Cell<PollTick> = const { std::cell::Cell::new(PollTick::new()) };
    /// Ceiling on `pool.num_terms()`; 0 means unbounded.
    static SIZE_LIMIT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// Sticky: the ceiling was crossed during this rewrite.
    static SIZE_HIT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Conservative mode: the pushdown rules that can multiply the DAG are
    /// switched off. Used for the retry after a size blow-up.
    static CONSERVATIVE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Install (or clear) the interrupt for this thread; returns the previous one
/// so callers can restore it. Also resets the sticky bit and the throttle, so
/// the first node of the next rewrite polls.
pub fn swap_terminate(flag: Option<Arc<AtomicBool>>) -> Option<Arc<AtomicBool>> {
    TERM_HIT.with(|c| c.set(false));
    POLL_TICK.with(|c| c.set(PollTick::new()));
    TERMINATE.with(|t| std::mem::replace(&mut *t.borrow_mut(), flag))
}

/// Did the current (or most recent) rewrite observe the interrupt? A `true`
/// here means the produced terms are only *partially* normalized: they are
/// still logically equivalent to the input, but ops the bit-blaster expects
/// to have been eliminated may survive, so the caller must abandon the
/// result rather than blast it.
pub fn interrupted() -> bool {
    TERM_HIT.with(|c| c.get())
}

/// Why a rewrite is running degraded.
#[derive(Clone, Copy)]
enum Degraded {
    Interrupted,
    OverSize,
}

/// Poll the interrupt and the term-pool ceiling. Both are sticky, so once
/// either has fired the whole in-flight recursion degrades consistently, and
/// both share one throttle: the expensive parts (an atomic load and a pool
/// size read) happen once per 1024 node rewrites.
#[inline]
fn check_stop(pool: &TermPool) -> Option<Degraded> {
    if TERM_HIT.with(|c| c.get()) {
        return Some(Degraded::Interrupted);
    }
    if SIZE_HIT.with(|c| c.get()) {
        return Some(Degraded::OverSize);
    }
    // The counter is reset per top-level rewrite and `PollTick` fires on its
    // first step, so a flag already set when the call began is seen at the
    // first node rather than a whole period later.
    let due = POLL_TICK.with(|c| {
        let mut v = c.get();
        let due = v.due();
        c.set(v);
        due
    });
    if !due {
        return None;
    }
    let stop = TERMINATE.with(|t| {
        t.borrow()
            .as_ref()
            .is_some_and(|f| f.load(Ordering::Relaxed))
    });
    if stop {
        TERM_HIT.with(|c| c.set(true));
        return Some(Degraded::Interrupted);
    }
    let limit = SIZE_LIMIT.with(|c| c.get());
    if limit != 0 && pool.num_terms() > limit {
        SIZE_HIT.with(|c| c.set(true));
        return Some(Degraded::OverSize);
    }
    None
}

/// Install (or clear, with 0) the term-pool ceiling for this thread; returns
/// the previous one. Also resets the sticky bit.
pub fn swap_size_limit(limit: usize) -> usize {
    SIZE_HIT.with(|c| c.set(false));
    SIZE_LIMIT.with(|c| c.replace(limit))
}

/// Did the current (or most recent) rewrite cross the term-pool ceiling?
pub fn size_limit_hit() -> bool {
    SIZE_HIT.with(|c| c.get())
}

/// Switch the DAG-multiplying pushdown rules on or off; returns the previous
/// setting.
pub fn swap_conservative(on: bool) -> bool {
    CONSERVATIVE.with(|c| c.replace(on))
}

fn conservative() -> bool {
    CONSERVATIVE.with(|c| c.get())
}

/// True when this rewrite is running degraded — interrupted or out of size
/// budget. Results are still equivalent to their inputs but only partially
/// normalized, so they must not be memoized as if fully rewritten.
fn degraded() -> bool {
    interrupted() || SIZE_HIT.with(|c| c.get())
}

/// Is `t` referenced by more than one parent across the assertion set?
///
/// `SMTRS_SHARE_MIN=n` raises the threshold to `> n` for bisection: `n = 0`
/// treats everything as shared, a large `n` restores the behaviour the counts
/// had while they were stale (nothing shared).
fn term_shared(t: TermId) -> bool {
    thread_local! {
        static MIN: u32 = std::env::var("SMTRS_SHARE_MIN")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1);
    }
    let min = MIN.with(|m| *m);
    let shared = REFCOUNTS.with(|r| r.borrow().get(&t).copied().unwrap_or(1) > min);
    if shared {
        SHARE_DECLINES.with(|c| c.set(c.get() + 1));
    }
    shared
}

thread_local! {
    /// How many times the sharing guard has answered "shared", i.e. blocked a
    /// flattening that would otherwise have happened. Zero means the guarded
    /// and unguarded encodings are identical, which is what lets the solver
    /// skip building the second one.
    static SHARE_DECLINES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Number of flattenings the sharing guard has blocked on this thread.
pub fn share_declines() -> u64 {
    SHARE_DECLINES.with(|c| c.get())
}

/// Debug bisection: SMTRS_DISABLE_RULES=extract-push,eq-split,... disables
/// rule groups at runtime.
fn group_disabled(group: &str) -> bool {
    thread_local! {
        static DISABLED: Vec<String> = std::env::var("SMTRS_DISABLE_RULES")
            .map(|v| v.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_default();
    }
    DISABLED.with(|d| d.iter().any(|g| g == group))
}

/// Rules recurse through `rewrite_node` (extract pushdown, concat splitting);
/// on pathologically deep terms that recursion tracks term depth. Past this
/// limit we build nodes without further rule application — always sound,
/// merely less simplified.
const MAX_RULE_DEPTH: u32 = 2_000;

/// Above this many entries the per-call memo is rebuilt from scratch rather
/// than `clear()`ed, so a single pathological node cannot leave a
/// multi-million-bucket table to be walked on every subsequent `clear()`.
const MEMO_KEEP: usize = 4096;

/// Rewrite a single node whose children are already fully rewritten.
///
/// The recursive rules (extract pushdown through bitwise/arith operands,
/// concat splitting) re-enter here per child. On a shared DAG that is
/// exponential without a memo: a node reachable by k paths is rewritten k
/// times, and the effect compounds with depth. The memo below is keyed on the
/// application `(op, args)` and is **scoped to one top-level call**, which is
/// what makes it sound: the rules consult `REFCOUNTS`, and `Rewriter::rewrite`
/// mutates that between nodes of its outer loop — but never *during* a single
/// top-level `rewrite_node`. Within one call the rules are a pure function of
/// `(op, args)`, so replaying a cached result is exactly what recomputation
/// would have produced.
pub fn rewrite_node(pool: &mut TermPool, op: Op, args: &[TermId], stats: &mut Stats) -> TermId {
    let depth = RULE_DEPTH.with(|d| {
        let v = d.get();
        d.set(v + 1);
        v
    });
    if depth == 0 {
        NODE_MEMO.with(|m| {
            let mut m = m.borrow_mut();
            if m.len() > MEMO_KEEP {
                *m = FxHashMap::default();
            } else {
                m.clear();
            }
        });
    }
    let result = if depth >= MAX_RULE_DEPTH {
        hit(stats, "depth-limit");
        mk(pool, op, args)
    } else if let Some(why) = check_stop(pool) {
        // Degraded: build without applying rules. Sound (the term is
        // unchanged) and it unwinds the in-flight recursion promptly, since
        // every remaining frame now returns without recursing. On the
        // interrupt the caller must check `interrupted()` and discard the
        // result -- normalizations the blaster depends on may not have run.
        // On the size ceiling it recovers instead, by rewriting again in
        // conservative mode; see `Rewriter::set_size_budget`.
        hit(
            stats,
            match why {
                Degraded::Interrupted => "interrupted",
                Degraded::OverSize => "size-limit",
            },
        );
        mk(pool, op, args)
    } else if depth == 0 {
        rewrite_node_inner(pool, op, args, stats)
    } else {
        let key = (op, args.to_vec());
        if let Some(t) = NODE_MEMO.with(|m| m.borrow().get(&key).copied()) {
            hit(stats, "memo");
            RULE_DEPTH.with(|d| d.set(d.get() - 1));
            return t;
        }
        let t = rewrite_node_inner(pool, op, args, stats);
        // Not cached when degraded: those results are unnormalized.
        if !degraded() {
            NODE_MEMO.with(|m| m.borrow_mut().insert(key, t));
        }
        t
    };
    RULE_DEPTH.with(|d| d.set(d.get() - 1));
    result
}

fn rewrite_node_inner(pool: &mut TermPool, op: Op, args: &[TermId], stats: &mut Stats) -> TermId {
    let mut op = op;
    let mut args: Vec<TermId> = args.to_vec();
    for _ in 0..MAX_LOCAL_ITERS {
        // 1. Constant folding (total, via the shared semantics in smtrs-core).
        if !args.is_empty() && args.iter().all(|&a| is_const(pool, a)) {
            if let Some(v) = fold(pool, op, &args) {
                hit(stats, "fold");
                return value_term(pool, v);
            }
        }
        // 2. Structural rules.
        match step(pool, op, &args, stats) {
            Step::Done(t) => return t,
            Step::Again(new_op, new_args) => {
                op = new_op;
                args = new_args;
            }
            Step::NoChange => break,
        }
    }
    mk(pool, op, &args)
}

enum Step {
    /// Fully rewritten result.
    Done(TermId),
    /// Rule fired producing a new top-level application; loop again.
    Again(Op, Vec<TermId>),
    NoChange,
}

fn is_const(pool: &TermPool, t: TermId) -> bool {
    matches!(pool.op(t), Op::True | Op::False | Op::BvConst(_))
}

fn const_value(pool: &TermPool, t: TermId) -> Option<Value> {
    match pool.op(t) {
        Op::True => Some(Value::Bool(true)),
        Op::False => Some(Value::Bool(false)),
        Op::BvConst(id) => Some(Value::Bv(pool.bv_const(id).clone())),
        _ => None,
    }
}

fn fold(pool: &TermPool, op: Op, args: &[TermId]) -> Option<Value> {
    let vals: Vec<Value> = args
        .iter()
        .map(|&a| const_value(pool, a))
        .collect::<Option<_>>()?;
    apply_op(op, &vals)
}

fn value_term(pool: &mut TermPool, v: Value) -> TermId {
    match v {
        Value::Bool(b) => pool.bool_const(b),
        Value::Bv(c) => pool.bv(c),
    }
}

/// Build without further rewriting (children are already normal forms and no
/// rule matched the top).
fn mk(pool: &mut TermPool, op: Op, args: &[TermId]) -> TermId {
    pool.mk(op, args)
        .expect("rewriter produced ill-sorted term")
}

fn bv_zero(pool: &mut TermPool, width: u32) -> TermId {
    pool.bv(Bv::zero(width))
}

fn is_not_of(pool: &TermPool, a: TermId, b: TermId) -> bool {
    if (pool.op(a) == Op::Not && pool.args(a)[0] == b)
        || (pool.op(b) == Op::Not && pool.args(b)[0] == a)
        || (pool.op(a) == Op::BvNot && pool.args(a)[0] == b)
        || (pool.op(b) == Op::BvNot && pool.args(b)[0] == a)
    {
        return true;
    }
    // Comparisons are normalized not-free (not (bvult x y) -> bvule y x), so
    // complements appear as (bvult x y) vs (bvule y x).
    let flipped = |x: Op, y: Op| -> bool {
        matches!((x, y), (Op::BvUlt, Op::BvUle) | (Op::BvSlt, Op::BvSle))
    };
    let (oa, ob) = (pool.op(a), pool.op(b));
    if flipped(oa, ob) || flipped(ob, oa) {
        let (aa, ab) = (pool.args(a), pool.args(b));
        return aa[0] == ab[1] && aa[1] == ab[0];
    }
    false
}

/// Above this arity, look complements up in a hash index instead of comparing
/// every pair. Small conjunctions are the overwhelmingly common case and the
/// pairwise scan beats building a table for them; wide ones are where the
/// quadratic blows up.
const COMPLEMENT_INDEX_ARITY: usize = 12;

/// Does `args` contain a term and its complement?
///
/// The pairwise version of this scan is `O(n^2)` calls to [`is_not_of`], which
/// is invisible on hand-written formulas and catastrophic on machine-generated
/// ones: the regex and string encodings AC-flatten into `or` nodes with tens of
/// thousands of arguments, and a single such node cost tens of seconds. The
/// indexed path answers the same question in one pass by looking each argument's
/// *possible* complement up, which is exactly what [`is_not_of`] enumerates:
/// `Not`/`BvNot` of an argument, or the swapped-operand `bvule`/`bvsle` partner
/// of a `bvult`/`bvslt`.
fn has_complementary_pair(pool: &TermPool, args: &[TermId]) -> bool {
    if args.len() <= COMPLEMENT_INDEX_ARITY {
        return (0..args.len())
            .any(|i| (i + 1..args.len()).any(|j| is_not_of(pool, args[i], args[j])));
    }
    let present: rustc_hash::FxHashSet<TermId> = args.iter().copied().collect();
    // Non-strict comparisons, keyed by operand pair and signedness, so a strict
    // one can find the partner that negates it.
    let mut non_strict: rustc_hash::FxHashSet<(TermId, TermId, bool)> = Default::default();
    for &a in args {
        match pool.op(a) {
            Op::Not | Op::BvNot if present.contains(&pool.args(a)[0]) => return true,
            o @ (Op::BvUle | Op::BvSle) => {
                let ar = pool.args(a);
                non_strict.insert((ar[0], ar[1], o == Op::BvSle));
            }
            _ => {}
        }
    }
    args.iter().any(|&a| match pool.op(a) {
        o @ (Op::BvUlt | Op::BvSlt) => {
            let ar = pool.args(a);
            non_strict.contains(&(ar[1], ar[0], o == Op::BvSlt))
        }
        _ => false,
    })
}

fn step(pool: &mut TermPool, op: Op, args: &[TermId], stats: &mut Stats) -> Step {
    use Op::*;
    match op {
        // ---- normalizations that eliminate operators entirely ----
        Implies => {
            // (=> a b c) == (or (not a) (not b) c)
            hit(stats, "implies-to-or");
            let mut new_args = Vec::with_capacity(args.len());
            for &a in &args[..args.len() - 1] {
                new_args.push(rewrite_node(pool, Not, &[a], stats));
            }
            new_args.push(args[args.len() - 1]);
            Step::Again(Or, new_args)
        }
        BvNand | BvNor | BvXnor => {
            hit(stats, "nand-elim");
            let inner = match op {
                BvNand => BvAnd,
                BvNor => BvOr,
                _ => BvXor,
            };
            let t = rewrite_node(pool, inner, args, stats);
            Step::Again(BvNot, vec![t])
        }
        BvUgt => Step::Again(BvUlt, vec![args[1], args[0]]),
        BvUge => Step::Again(BvUle, vec![args[1], args[0]]),
        BvSgt => Step::Again(BvSlt, vec![args[1], args[0]]),
        BvSge => Step::Again(BvSle, vec![args[1], args[0]]),
        BvComp => {
            hit(stats, "bvcomp-elim");
            let eq = rewrite_node(pool, Eq, args, stats);
            let one = pool.bv_u64(1, 1);
            let zero = pool.bv_u64(1, 0);
            Step::Again(Ite, vec![eq, one, zero])
        }
        ZeroExtend(n) => {
            hit(stats, "zext-to-concat");
            let zeros = bv_zero(pool, n);
            Step::Again(Concat, vec![zeros, args[0]])
        }
        SignExtend(n) => {
            hit(stats, "sext-to-concat");
            let w = pool.width(args[0]);
            let msb = rewrite_node(
                pool,
                Extract {
                    hi: w - 1,
                    lo: w - 1,
                },
                &[args[0]],
                stats,
            );
            let mut parts = vec![msb; n as usize];
            parts.push(args[0]);
            Step::Again(Concat, parts)
        }
        RotateLeft(n) => {
            let w = pool.width(args[0]);
            let n = n % w;
            if n == 0 {
                return Step::Done(args[0]);
            }
            hit(stats, "rotl-to-concat");
            let lo = rewrite_node(
                pool,
                Extract {
                    hi: w - n - 1,
                    lo: 0,
                },
                &[args[0]],
                stats,
            );
            let hi = rewrite_node(
                pool,
                Extract {
                    hi: w - 1,
                    lo: w - n,
                },
                &[args[0]],
                stats,
            );
            Step::Again(Concat, vec![lo, hi])
        }
        RotateRight(n) => {
            let w = pool.width(args[0]);
            let n = n % w;
            Step::Again(RotateLeft((w - n) % w), vec![args[0]])
        }
        Repeat(n) => {
            if n == 1 {
                return Step::Done(args[0]);
            }
            hit(stats, "repeat-to-concat");
            Step::Again(Concat, vec![args[0]; n as usize])
        }

        // ---- Bool ----
        Not => {
            let a = args[0];
            match pool.op(a) {
                True => Step::Done(pool.false_term),
                False => Step::Done(pool.true_term),
                Not => {
                    hit(stats, "not-not");
                    Step::Done(pool.args(a)[0])
                }
                // not (bvult a b) -> bvule b a ; not (bvule a b) -> bvult b a
                BvUlt => {
                    hit(stats, "not-ult");
                    let [x, y] = [pool.args(a)[0], pool.args(a)[1]];
                    Step::Again(BvUle, vec![y, x])
                }
                BvUle => {
                    hit(stats, "not-ule");
                    let [x, y] = [pool.args(a)[0], pool.args(a)[1]];
                    Step::Again(BvUlt, vec![y, x])
                }
                BvSlt => {
                    hit(stats, "not-slt");
                    let [x, y] = [pool.args(a)[0], pool.args(a)[1]];
                    Step::Again(BvSle, vec![y, x])
                }
                BvSle => {
                    hit(stats, "not-sle");
                    let [x, y] = [pool.args(a)[0], pool.args(a)[1]];
                    Step::Again(BvSlt, vec![y, x])
                }
                _ => Step::NoChange,
            }
        }
        And | Or => {
            let (unit, absorb) = if op == And {
                (pool.true_term, pool.false_term)
            } else {
                (pool.false_term, pool.true_term)
            };
            // AC-flatten nested applications of the same op first.
            if args.iter().any(|&a| pool.op(a) == op) {
                hit(stats, "ac-flatten");
                let mut flat: Vec<TermId> = Vec::with_capacity(args.len() * 2);
                let mut stack: Vec<TermId> = args.iter().rev().copied().collect();
                while let Some(a) = stack.pop() {
                    if pool.op(a) == op {
                        stack.extend(pool.args(a).iter().rev().copied());
                    } else {
                        flat.push(a);
                    }
                }
                return Step::Again(op, flat);
            }
            let mut new_args: Vec<TermId> = Vec::with_capacity(args.len());
            let mut changed = false;
            for &a in args {
                if a == absorb {
                    hit(stats, "and-or-absorb");
                    return Step::Done(absorb);
                }
                if a == unit {
                    changed = true;
                    continue;
                }
                if new_args.last() == Some(&a) {
                    // Args are sorted (commutative): duplicates are adjacent.
                    changed = true;
                    continue;
                }
                new_args.push(a);
            }
            // x and (not x) -> contradiction / tautology.
            if has_complementary_pair(pool, &new_args) {
                hit(stats, "and-or-complement");
                return Step::Done(absorb);
            }
            match new_args.len() {
                0 => Step::Done(unit),
                1 => Step::Done(new_args[0]),
                _ if changed => {
                    hit(stats, "and-or-shrink");
                    Step::Done(mk(pool, op, &new_args))
                }
                _ => Step::NoChange,
            }
        }
        Xor => {
            if args.iter().any(|&a| pool.op(a) == Xor) {
                hit(stats, "ac-flatten");
                let mut flat: Vec<TermId> = Vec::with_capacity(args.len() * 2);
                for &a in args {
                    if pool.op(a) == Xor {
                        flat.extend_from_slice(pool.args(a));
                    } else {
                        flat.push(a);
                    }
                }
                return Step::Again(Xor, flat);
            }
            // Sorted args: identical pairs cancel; fold constants into parity.
            let mut parity = false;
            let mut rest: Vec<TermId> = Vec::with_capacity(args.len());
            let mut i = 0;
            while i < args.len() {
                let a = args[i];
                if i + 1 < args.len() && args[i + 1] == a {
                    i += 2; // x xor x = false
                    continue;
                }
                if a == pool.true_term {
                    parity = !parity;
                } else if a != pool.false_term {
                    rest.push(a);
                }
                i += 1;
            }
            if rest.len() == args.len() && !parity {
                return Step::NoChange;
            }
            hit(stats, "xor-shrink");
            let base = match rest.len() {
                0 => pool.bool_const(parity),
                1 => {
                    if parity {
                        return Step::Again(Not, vec![rest[0]]);
                    }
                    rest[0]
                }
                _ => {
                    let x = mk(pool, Xor, &rest);
                    if parity {
                        return Step::Again(Not, vec![x]);
                    }
                    x
                }
            };
            Step::Done(base)
        }
        Eq => {
            // Dedup (sorted); 2-ary special cases.
            let mut new_args: Vec<TermId> = args.to_vec();
            new_args.dedup();
            if new_args.len() == 1 {
                hit(stats, "eq-refl");
                return Step::Done(pool.true_term);
            }
            // Two distinct constants anywhere -> false.
            let consts: Vec<TermId> = new_args
                .iter()
                .copied()
                .filter(|&a| is_const(pool, a))
                .collect();
            if consts.windows(2).any(|w| w[0] != w[1]) {
                hit(stats, "eq-const-conflict");
                return Step::Done(pool.false_term);
            }
            if new_args.len() == 2 {
                let [a, b] = [new_args[0], new_args[1]];
                if is_not_of(pool, a, b) {
                    hit(stats, "eq-complement");
                    return Step::Done(pool.false_term);
                }
                if b == pool.true_term {
                    hit(stats, "eq-true");
                    return Step::Done(a);
                }
                if a == pool.true_term {
                    hit(stats, "eq-true");
                    return Step::Done(b);
                }
                if b == pool.false_term {
                    hit(stats, "eq-false");
                    return Step::Again(Not, vec![a]);
                }
                if a == pool.false_term {
                    hit(stats, "eq-false");
                    return Step::Again(Not, vec![b]);
                }
            }
            if new_args.len() < args.len() {
                hit(stats, "eq-dedup");
                return Step::Done(mk(pool, Eq, &new_args));
            }
            if new_args.len() == 2 && pool.sort(new_args[0]).is_bv() {
                let [a, b] = [new_args[0], new_args[1]];
                // Split equality over concat into per-slice equalities.
                for (cc, other) in [(a, b), (b, a)] {
                    if pool.op(cc) != Concat || group_disabled("eq-split") {
                        continue;
                    }
                    let parts: Vec<TermId> = pool.args(cc).to_vec();
                    let w = pool.width(cc);
                    // The split pays off when the other side slices for free —
                    // it is a constant, or a concat with the same boundaries.
                    // When it does not, each part equality drags in a fresh
                    // extract of an opaque term and the assertion count grows
                    // without the term graph shrinking. Term ids are dense
                    // indices, so anything at or past this mark was invented.
                    let mark = TermId(pool.num_terms() as u32);
                    let mut slices: Vec<TermId> = Vec::with_capacity(parts.len());
                    let mut bit_hi = w;
                    for &part in &parts {
                        let pw = pool.width(part);
                        slices.push(rewrite_node(
                            pool,
                            Extract {
                                hi: bit_hi - 1,
                                lo: bit_hi - pw,
                            },
                            &[other],
                            stats,
                        ));
                        bit_hi -= pw;
                    }
                    if !group_disabled("eq-split-free")
                        && slices.iter().any(|&s| s >= mark && !is_const(pool, s))
                    {
                        continue;
                    }
                    hit(stats, "eq-concat-split");
                    let mut conj: Vec<TermId> = Vec::with_capacity(parts.len());
                    for (part, slice) in parts.into_iter().zip(slices) {
                        conj.push(rewrite_node(pool, Eq, &[part, slice], stats));
                    }
                    return Step::Again(And, conj);
                }
                // Constant cancellation: (= (bvadd x c1) c2) -> (= x (c2-c1)).
                for (sum, other) in [(a, b), (b, a)] {
                    if group_disabled("eq-cancel") {
                        continue;
                    }
                    let Some(oc) = pool.as_bv_const(other).cloned() else {
                        continue;
                    };
                    if pool.op(sum) != BvAdd {
                        continue;
                    }
                    let sargs: Vec<TermId> = pool.args(sum).to_vec();
                    let Some(ci) = sargs.iter().position(|&s| is_const(pool, s)) else {
                        continue;
                    };
                    hit(stats, "eq-add-const-cancel");
                    let cval = pool.as_bv_const(sargs[ci]).unwrap().clone();
                    let rest: Vec<TermId> = sargs
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| *i != ci)
                        .map(|(_, &s)| s)
                        .collect();
                    let lhs = if rest.len() == 1 {
                        rest[0]
                    } else {
                        rewrite_node(pool, BvAdd, &rest, stats)
                    };
                    let rhs = pool.bv(oc.sub(&cval));
                    return Step::Again(Eq, vec![lhs, rhs]);
                }
                // (= (ite c t e) x) with constant branches: lift the ite.
                for (ite, other) in [(a, b), (b, a)] {
                    if pool.op(ite) != Ite || group_disabled("eq-ite") {
                        continue;
                    }
                    let [c, t, e] = [pool.args(ite)[0], pool.args(ite)[1], pool.args(ite)[2]];
                    if is_const(pool, t) && is_const(pool, e) {
                        hit(stats, "eq-ite-const-lift");
                        let et = rewrite_node(pool, Eq, &[t, other], stats);
                        let ee = rewrite_node(pool, Eq, &[e, other], stats);
                        return Step::Again(Ite, vec![c, et, ee]);
                    }
                }
            }
            Step::NoChange
        }
        Distinct => {
            let mut sorted = args.to_vec();
            sorted.sort_unstable();
            for w in sorted.windows(2) {
                if w[0] == w[1] {
                    hit(stats, "distinct-dup");
                    return Step::Done(pool.false_term);
                }
            }
            // Pigeonhole: more than 2^w distinct values of width w is impossible.
            if let Some(w) = pool.sort(args[0]).bv_width() {
                if w < 30 && args.len() as u64 > 1u64 << w {
                    hit(stats, "distinct-pigeonhole");
                    return Step::Done(pool.false_term);
                }
            } else if pool.sort(args[0]) == smtrs_core::Sort::Bool && args.len() > 2 {
                hit(stats, "distinct-pigeonhole");
                return Step::Done(pool.false_term);
            }
            if args.len() == 2 {
                // distinct a b == not (= a b)
                let eq = rewrite_node(pool, Eq, args, stats);
                hit(stats, "distinct-to-eq");
                return Step::Again(Not, vec![eq]);
            }
            Step::NoChange
        }
        Ite => {
            let [c, t, e] = [args[0], args[1], args[2]];
            if c == pool.true_term {
                hit(stats, "ite-true");
                return Step::Done(t);
            }
            if c == pool.false_term {
                hit(stats, "ite-false");
                return Step::Done(e);
            }
            if t == e {
                hit(stats, "ite-same");
                return Step::Done(t);
            }
            if pool.op(c) == Not {
                hit(stats, "ite-not");
                let inner = pool.args(c)[0];
                return Step::Again(Ite, vec![inner, e, t]);
            }
            if t == pool.true_term && e == pool.false_term {
                hit(stats, "ite-bool");
                return Step::Done(c);
            }
            if t == pool.false_term && e == pool.true_term {
                hit(stats, "ite-bool");
                return Step::Again(Not, vec![c]);
            }
            Step::NoChange
        }

        // ---- BV ----
        BvNot => match pool.op(args[0]) {
            Op::BvNot => {
                hit(stats, "bvnot-bvnot");
                Step::Done(pool.args(args[0])[0])
            }
            // `~y == -y - 1`, so `~(-x) == x - 1`. Two nodes become one sum
            // with a constant, which is the form linear normalization can
            // collect and cancel.
            Op::BvNeg => {
                hit(stats, "bvnot-bvneg");
                let inner = pool.args(args[0])[0];
                let ones = pool.bv(Bv::ones(pool.width(inner)));
                Step::Again(BvAdd, vec![inner, ones])
            }
            _ => Step::NoChange,
        },
        BvMul
            if !group_disabled("mul-hoist")
                && args
                    .iter()
                    .any(|&a| matches!(pool.op(a), Op::BvShl | Op::BvNeg)) =>
        {
            // Normalization that makes AC-equal products syntactically equal:
            //   mul(..., shl(b, k), ...) -> shl(mul(..., b, ...), k)
            //   mul(..., neg(b), ...)    -> neg(mul(..., b, ...))
            // (x*2^k mod 2^w distributes; shl >= w zeroes both sides.)
            let idx = args
                .iter()
                .position(|&a| matches!(pool.op(a), Op::BvShl | Op::BvNeg))
                .unwrap();
            let inner_op = pool.op(args[idx]);
            let inner_args: Vec<TermId> = pool.args(args[idx]).to_vec();
            let mut rest: Vec<TermId> = args.to_vec();
            rest[idx] = inner_args[0];
            let new_mul = rewrite_node(pool, BvMul, &rest, stats);
            match inner_op {
                Op::BvShl => {
                    hit(stats, "mul-shl-hoist");
                    Step::Again(BvShl, vec![new_mul, inner_args[1]])
                }
                _ => {
                    hit(stats, "mul-neg-hoist");
                    Step::Again(BvNeg, vec![new_mul])
                }
            }
        }
        BvNeg => match pool.op(args[0]) {
            Op::BvNeg => {
                hit(stats, "bvneg-bvneg");
                Step::Done(pool.args(args[0])[0])
            }
            // The mirror of `bvnot-bvneg`: `-(~x) == x + 1`.
            Op::BvNot => {
                hit(stats, "bvneg-bvnot");
                let inner = pool.args(args[0])[0];
                let one = pool.bv_u64(pool.width(inner), 1);
                Step::Again(BvAdd, vec![inner, one])
            }
            _ => Step::NoChange,
        },
        BvAdd | BvMul | BvAnd | BvOr | BvXor => nary_bv(pool, op, args, stats),
        BvSub => {
            let [a, b] = [args[0], args[1]];
            let w = pool.width(a);
            if a == b {
                hit(stats, "sub-self");
                return Step::Done(bv_zero(pool, w));
            }
            if let Some(c) = pool.as_bv_const(b) {
                if c.is_zero() {
                    hit(stats, "sub-zero");
                    return Step::Done(a);
                }
                // a - c == a + (-c): joins the AC add normalization.
                hit(stats, "sub-const-to-add");
                let negc = pool.bv(c.neg());
                return Step::Again(BvAdd, vec![a, negc]);
            }
            if pool.as_bv_const(a).map(|c| c.is_zero()) == Some(true) {
                hit(stats, "zero-sub");
                return Step::Again(BvNeg, vec![b]);
            }
            Step::NoChange
        }
        BvShl | BvLshr | BvAshr => {
            let [a, b] = [args[0], args[1]];
            let w = pool.width(a);
            // Shifting by a term's own value. Every bit-vector `x` satisfies
            // `x < 2^x` over the integers, so bits `x` and above of `x` are
            // zero; and once `x` reaches the width the shift saturates. Either
            // way a right shift of `x` by `x` keeps nothing of `x`.
            if a == b {
                match op {
                    BvLshr => {
                        hit(stats, "shift-self");
                        return Step::Done(bv_zero(pool, w));
                    }
                    BvAshr => {
                        // ...except for the sign, which an arithmetic shift
                        // replicates: `x >>a x` is `x`'s msb, w times over.
                        hit(stats, "shift-self");
                        let msb = rewrite_node(
                            pool,
                            Extract {
                                hi: w - 1,
                                lo: w - 1,
                            },
                            &[a],
                            stats,
                        );
                        return Step::Again(Concat, vec![msb; w as usize]);
                    }
                    _ => {}
                }
            }
            // The same fact one level down: bits `x` and above of `x` are
            // zero, so bits `x` and above of `bvnot x` are all one, and
            // `~x >>u x` cannot depend on `x` at all.
            if op == BvLshr && pool.op(a) == BvNot && pool.args(a)[0] == b {
                hit(stats, "lshr-not-self");
                let ones = pool.bv(Bv::ones(w));
                return Step::Again(BvLshr, vec![ones, b]);
            }
            if let Some(c) = pool.as_bv_const(b) {
                if c.is_zero() {
                    hit(stats, "shift-zero");
                    return Step::Done(a);
                }
                match c.as_u64() {
                    Some(n) if n < w as u64 => {
                        // Constant shifts are pure wiring: turn into
                        // concat/extract so the blaster never sees them.
                        let n = n as u32;
                        hit(stats, "shift-const");
                        match op {
                            BvShl => {
                                let keep = rewrite_node(
                                    pool,
                                    Extract {
                                        hi: w - n - 1,
                                        lo: 0,
                                    },
                                    &[a],
                                    stats,
                                );
                                let zeros = bv_zero(pool, n);
                                return Step::Again(Concat, vec![keep, zeros]);
                            }
                            BvLshr => {
                                let keep =
                                    rewrite_node(pool, Extract { hi: w - 1, lo: n }, &[a], stats);
                                let zeros = bv_zero(pool, n);
                                return Step::Again(Concat, vec![zeros, keep]);
                            }
                            _ => {
                                let keep =
                                    rewrite_node(pool, Extract { hi: w - 1, lo: n }, &[a], stats);
                                let msb = rewrite_node(
                                    pool,
                                    Extract {
                                        hi: w - 1,
                                        lo: w - 1,
                                    },
                                    &[a],
                                    stats,
                                );
                                let mut parts = vec![msb; n as usize];
                                parts.push(keep);
                                return Step::Again(Concat, parts);
                            }
                        }
                    }
                    _ => {
                        // Shift amount >= width saturates.
                        hit(stats, "shift-saturate");
                        match op {
                            BvAshr => {
                                let msb = rewrite_node(
                                    pool,
                                    Extract {
                                        hi: w - 1,
                                        lo: w - 1,
                                    },
                                    &[a],
                                    stats,
                                );
                                return Step::Again(Concat, vec![msb; w as usize]);
                            }
                            _ => return Step::Done(bv_zero(pool, w)),
                        }
                    }
                }
            }
            Step::NoChange
        }
        Concat => {
            // Flatten nested concats; merge adjacent constants; merge adjacent
            // contiguous extracts of the same term.
            let mut flat: Vec<TermId> = Vec::with_capacity(args.len());
            let mut changed = false;
            for &a in args {
                if pool.op(a) == Concat {
                    flat.extend_from_slice(pool.args(a));
                    changed = true;
                } else {
                    flat.push(a);
                }
            }
            let mut merged: Vec<TermId> = Vec::with_capacity(flat.len());
            for a in flat {
                if let Some(&prev) = merged.last() {
                    // Adjacent constants merge.
                    if let (Some(c1), Some(c2)) = (pool.as_bv_const(prev), pool.as_bv_const(a)) {
                        let joined = c1.concat(c2);
                        merged.pop();
                        merged.push(pool.bv(joined));
                        changed = true;
                        continue;
                    }
                    // x[k+j:i] ++ x[i-1:l] -> x[k+j:l]
                    if let (Op::Extract { hi: _, lo: lo1 }, Op::Extract { hi: hi2, lo: lo2 }) =
                        (pool.op(prev), pool.op(a))
                    {
                        if pool.args(prev)[0] == pool.args(a)[0] && lo1 == hi2 + 1 {
                            let base = pool.args(prev)[0];
                            let hi1 = match pool.op(prev) {
                                Op::Extract { hi, .. } => hi,
                                _ => unreachable!(),
                            };
                            merged.pop();
                            let joined =
                                rewrite_node(pool, Extract { hi: hi1, lo: lo2 }, &[base], stats);
                            merged.push(joined);
                            changed = true;
                            continue;
                        }
                    }
                }
                merged.push(a);
            }
            if merged.len() == 1 {
                hit(stats, "concat-collapse");
                return Step::Done(merged[0]);
            }
            if changed {
                hit(stats, "concat-merge");
                return Step::Done(mk(pool, Concat, &merged));
            }
            Step::NoChange
        }
        Extract { hi, lo } => {
            let a = args[0];
            let w = pool.width(a);
            if lo == 0 && hi == w - 1 {
                hit(stats, "extract-full");
                return Step::Done(a);
            }
            match pool.op(a) {
                Op::Extract { hi: _, lo: lo2 } => {
                    hit(stats, "extract-extract");
                    let base = pool.args(a)[0];
                    Step::Again(
                        Extract {
                            hi: lo2 + hi,
                            lo: lo2 + lo,
                        },
                        vec![base],
                    )
                }
                Op::Concat => {
                    // Narrow to the operands actually covered.
                    let parts: Vec<TermId> = pool.args(a).to_vec();
                    let mut covered: Vec<TermId> = Vec::new();
                    let mut bit_hi = w; // exclusive upper bit of current part
                    for &part in &parts {
                        let pw = pool.width(part);
                        let part_lo = bit_hi - pw;
                        let sel_hi = hi.min(bit_hi - 1);
                        let sel_lo = lo.max(part_lo);
                        if sel_hi >= sel_lo && hi >= part_lo && lo < bit_hi {
                            let e = rewrite_node(
                                pool,
                                Extract {
                                    hi: sel_hi - part_lo,
                                    lo: sel_lo - part_lo,
                                },
                                &[part],
                                stats,
                            );
                            covered.push(e);
                        }
                        bit_hi = part_lo;
                    }
                    hit(stats, "extract-concat");
                    if covered.len() == 1 {
                        Step::Done(covered[0])
                    } else {
                        Step::Again(Concat, covered)
                    }
                }
                Op::Ite => {
                    // Push extract through ite of constants only (cheap win).
                    let [c, t, e] = [pool.args(a)[0], pool.args(a)[1], pool.args(a)[2]];
                    if is_const(pool, t) && is_const(pool, e) {
                        hit(stats, "extract-ite-const");
                        let t2 = rewrite_node(pool, Extract { hi, lo }, &[t], stats);
                        let e2 = rewrite_node(pool, Extract { hi, lo }, &[e], stats);
                        return Step::Again(Ite, vec![c, t2, e2]);
                    }
                    Step::NoChange
                }
                // Bitwise ops are bit-parallel: extraction commutes.
                Op::BvNot | Op::BvAnd | Op::BvOr | Op::BvXor
                    if !group_disabled("extract-push") && !conservative() =>
                {
                    hit(stats, "extract-bitwise");
                    let inner_op = pool.op(a);
                    let inner: Vec<TermId> = pool
                        .args(a)
                        .to_vec()
                        .iter()
                        .map(|&x| rewrite_node(pool, Extract { hi, lo }, &[x], stats))
                        .collect();
                    Step::Again(inner_op, inner)
                }
                // Low bits of arithmetic depend only on low operand bits.
                // Narrowing a *shared* multiplier duplicates it; leave those.
                // The guard spells "not (a shared multiply)" directly; the
                // De-Morganed form clippy 1.94 asks for buries that reading.
                #[allow(clippy::nonminimal_bool)]
                Op::BvAdd | Op::BvMul | Op::BvSub | Op::BvNeg
                    if lo == 0
                        && !group_disabled("extract-push")
                        && !conservative()
                        && !(pool.op(a) == Op::BvMul && term_shared(a)) =>
                {
                    hit(stats, "extract-arith-low");
                    let inner_op = pool.op(a);
                    let inner: Vec<TermId> = pool
                        .args(a)
                        .to_vec()
                        .iter()
                        .map(|&x| rewrite_node(pool, Extract { hi, lo: 0 }, &[x], stats))
                        .collect();
                    Step::Again(inner_op, inner)
                }
                _ => Step::NoChange,
            }
        }
        BvUlt | BvUle | BvSlt | BvSle => {
            let [a, b] = [args[0], args[1]];
            let w = pool.width(a);
            if a == b {
                hit(stats, "cmp-refl");
                return Step::Done(pool.bool_const(matches!(op, BvUle | BvSle)));
            }
            let (ca, cb) = (pool.as_bv_const(a).cloned(), pool.as_bv_const(b).cloned());
            match op {
                BvUlt => {
                    if cb.as_ref().map(|c| c.is_zero()) == Some(true) {
                        hit(stats, "ult-zero");
                        return Step::Done(pool.false_term);
                    }
                    if cb.as_ref().map(|c| c.is_one()) == Some(true) {
                        hit(stats, "ult-one");
                        let z = bv_zero(pool, w);
                        return Step::Again(Eq, vec![a, z]);
                    }
                    if ca.as_ref().map(|c| c.is_ones()) == Some(true) {
                        hit(stats, "ones-ult");
                        return Step::Done(pool.false_term);
                    }
                }
                BvUle => {
                    if ca.as_ref().map(|c| c.is_zero()) == Some(true) {
                        hit(stats, "zero-ule");
                        return Step::Done(pool.true_term);
                    }
                    if cb.as_ref().map(|c| c.is_ones()) == Some(true) {
                        hit(stats, "ule-ones");
                        return Step::Done(pool.true_term);
                    }
                    if cb.as_ref().map(|c| c.is_zero()) == Some(true) {
                        hit(stats, "ule-zero");
                        let z = bv_zero(pool, w);
                        return Step::Again(Eq, vec![a, z]);
                    }
                }
                BvSlt => {
                    let min = signed_min(w);
                    if cb.as_ref() == Some(&min) {
                        hit(stats, "slt-min");
                        return Step::Done(pool.false_term);
                    }
                    if ca.as_ref() == Some(&signed_max(w)) {
                        hit(stats, "max-slt");
                        return Step::Done(pool.false_term);
                    }
                }
                BvSle => {
                    if ca.as_ref() == Some(&signed_min(w)) {
                        hit(stats, "min-sle");
                        return Step::Done(pool.true_term);
                    }
                    if cb.as_ref() == Some(&signed_max(w)) {
                        hit(stats, "sle-max");
                        return Step::Done(pool.true_term);
                    }
                }
                _ => unreachable!(),
            }
            Step::NoChange
        }
        BvUdiv | BvUrem => {
            let [a, b] = [args[0], args[1]];
            let w = pool.width(a);
            if let Some(c) = pool.as_bv_const(b).cloned() {
                if c.is_one() {
                    hit(stats, "div-one");
                    return match op {
                        BvUdiv => Step::Done(a),
                        _ => Step::Done(bv_zero(pool, w)),
                    };
                }
                // Unsigned division by 2^k is a shift; the remainder is the
                // low k bits. Both replace a divider circuit with wiring.
                if let Some(k) = power_of_two_log(&c) {
                    if !group_disabled("div-pow2") {
                        return match op {
                            BvUdiv => {
                                hit(stats, "udiv-pow2");
                                let amount = pool.bv(Bv::from_u64(w, k as u64));
                                Step::Again(BvLshr, vec![a, amount])
                            }
                            _ => {
                                hit(stats, "urem-pow2");
                                let low =
                                    rewrite_node(pool, Extract { hi: k - 1, lo: 0 }, &[a], stats);
                                let zeros = bv_zero(pool, w - k);
                                Step::Again(Concat, vec![zeros, low])
                            }
                        };
                    }
                }
            }
            Step::NoChange
        }
        _ => Step::NoChange,
    }
}

/// Recursion depth for `nonzero_mask`. Deep enough for the byte-at-a-time
/// assembly trees SAGE/Sydr emit (one level per byte, plus the shift and
/// extension wrappers), cheap enough to run on every `bvor`.
pub(crate) const MASK_DEPTH: u32 = 24;

/// Largest concat the disjoint-`or` rule will build. A 64-bit word assembled
/// byte-wise needs 8 slices; the cap only rules out pathological operands.
const MAX_OR_SLICES: usize = 32;

/// Widest `bvor` the rule will analyse. The mask walk and the per-bit owner
/// map are both O(width), which is fine for machine words and wasteful for
/// the multi-kilobit vectors the string/FP lowerings can produce.
const MAX_OR_WIDTH: u32 = 4_096;

/// Node budget for one `nonzero_mask` walk. The walk is not memoized, so on a
/// shared DAG its cost is the size of the *unfolded* depth-limited cone —
/// exponential in the depth for the two-input adder chains SAGE emits. The
/// budget bounds that directly; running out yields `ones`, the safe answer.
const MASK_BUDGET: u32 = 4_000;

/// Over-approximation of which bits of `t` can be 1: a set bit means "may be
/// 1", a clear bit means "provably 0". Past the depth limit everything is
/// assumed possibly-1, which is the safe direction.
pub(crate) fn nonzero_mask(pool: &TermPool, t: TermId, depth: u32) -> Bv {
    let mut budget = MASK_BUDGET;
    mask_rec(pool, t, depth, &mut budget)
}

/// `Some(k)` when every bit of `m` at or above `k` is provably 0.
fn mask_msb(m: &Bv) -> Option<u32> {
    (0..m.width()).rev().find(|&i| m.bit(i))
}

/// All bits strictly below `n` set — the mask of "value < 2^n".
fn mask_below(w: u32, n: u32) -> Bv {
    if n >= w {
        Bv::ones(w)
    } else {
        Bv::from_bits(w, |i| i < n)
    }
}

fn mask_rec(pool: &TermPool, t: TermId, depth: u32, budget: &mut u32) -> Bv {
    let w = pool.width(t);
    if depth == 0 || *budget == 0 {
        return Bv::ones(w);
    }
    *budget -= 1;
    let arg_mask = |i: usize, budget: &mut u32| mask_rec(pool, pool.args(t)[i], depth - 1, budget);
    let const_arg = |i: usize| pool.as_bv_const(pool.args(t)[i]).cloned();
    match pool.op(t) {
        Op::BvConst(_) => pool.as_bv_const(t).cloned().unwrap_or_else(|| Bv::ones(w)),
        Op::Concat => {
            let mut acc: Option<Bv> = None;
            for i in 0..pool.args(t).len() {
                let m = arg_mask(i, budget);
                acc = Some(match acc {
                    None => m,
                    Some(a) => a.concat(&m),
                });
            }
            acc.unwrap_or_else(|| Bv::ones(w))
        }
        Op::ZeroExtend(n) => arg_mask(0, budget).zero_extend(n),
        // Sign extension only replicates a bit that is provably 0, in which
        // case it *is* zero extension. Otherwise the copies are unknown.
        Op::SignExtend(n) => {
            let m = arg_mask(0, budget);
            match m.sign_bit() {
                false => m.zero_extend(n),
                true => Bv::ones(w),
            }
        }
        Op::Extract { hi, lo } => arg_mask(0, budget).extract(hi, lo),
        Op::BvShl => match const_arg(1).and_then(|c| c.as_u64()) {
            Some(k) if k < w as u64 => arg_mask(0, budget).shl_small(k as u32),
            Some(_) => Bv::zero(w),
            None => Bv::ones(w),
        },
        Op::BvLshr => match const_arg(1).and_then(|c| c.as_u64()) {
            Some(k) if k < w as u64 => arg_mask(0, budget).lshr_small(k as u32),
            Some(_) => Bv::zero(w),
            None => Bv::ones(w),
        },
        // and: a bit can be 1 only where *every* operand can be 1.
        Op::BvAnd => (0..pool.args(t).len())
            .map(|i| arg_mask(i, budget))
            .reduce(|a, b| a.and(&b))
            .unwrap_or_else(|| Bv::ones(w)),
        // or/xor: a bit can be 1 where *any* operand can be 1.
        Op::BvOr | Op::BvXor => (0..pool.args(t).len())
            .map(|i| arg_mask(i, budget))
            .reduce(|a, b| a.or(&b))
            .unwrap_or_else(|| Bv::ones(w)),
        Op::Ite => arg_mask(1, budget).or(&arg_mask(2, budget)),
        // A sum is bounded by the sum of its operands' bounds, so if that
        // total does not itself overflow `w` bits, every bit above its top
        // set bit is provably 0. Zero-extended bytes summed into a machine
        // word — the dominant SAGE shape — stay narrow this way. When the
        // operands are pairwise disjoint there are no carries at all and the
        // bitwise union is exact; both bounds are sound, so take their
        // intersection.
        Op::BvAdd => {
            let masks: Vec<Bv> = (0..pool.args(t).len())
                .map(|i| arg_mask(i, budget))
                .collect();
            let mut total = Bv::zero(w);
            let mut union = Bv::zero(w);
            let mut disjoint = true;
            let mut overflow = false;
            for m in &masks {
                let next = total.add(m);
                // Unsigned wrap: the running total can only grow.
                overflow |= next.ult(&total);
                total = next;
                disjoint &= union.and(m).is_zero();
                union = union.or(m);
            }
            let magnitude = match (overflow, mask_msb(&total)) {
                (false, Some(hi)) => mask_below(w, hi + 1),
                (false, None) => Bv::zero(w),
                (true, _) => Bv::ones(w),
            };
            match disjoint {
                true => magnitude.and(&union),
                false => magnitude,
            }
        }
        // Multiplication by 2^k is a left shift, exactly.
        Op::BvMul if pool.args(t).len() == 2 => {
            let pow2 = |i: usize| const_arg(i).as_ref().and_then(power_of_two_log);
            match (pow2(0), pow2(1)) {
                (Some(k), _) => arg_mask(1, budget).shl_small(k),
                (None, Some(k)) => arg_mask(0, budget).shl_small(k),
                (None, None) => Bv::ones(w),
            }
        }
        _ => Bv::ones(w),
    }
}

/// True when no two operands can set the same bit.
///
/// Cheap rejection first: every operand has to be an op the mask analysis can
/// say something about, and at least one has to be word-assembly structure.
/// Without that gate the (unmemoized) mask walk would run on every `bvadd` in
/// the corpus to conclude "a plain variable may set every bit".
fn operands_disjoint(pool: &TermPool, args: &[TermId], w: u32) -> bool {
    if args.len() < 2 || w > MAX_OR_WIDTH {
        return false;
    }
    let mut assembly = false;
    for &a in args {
        match pool.op(a) {
            Op::Concat | Op::ZeroExtend(_) | Op::BvShl | Op::BvLshr | Op::BvMul => assembly = true,
            Op::BvConst(_) | Op::Extract { .. } | Op::BvAnd | Op::BvOr | Op::BvXor | Op::Ite => {}
            // A plain variable (or any opaque term) may set every bit, so a
            // sum containing one is never disjoint.
            _ => return false,
        }
    }
    if !assembly {
        return false;
    }
    let mut union = Bv::zero(w);
    for &a in args {
        let m = nonzero_mask(pool, a, MASK_DEPTH);
        if !union.and(&m).is_zero() {
            return false;
        }
        union = union.or(&m);
    }
    true
}

/// `(bvor a1 ... an)` where the operands can never set the same bit is a
/// concatenation of their live ranges — no gates at all, where the `or` cost
/// one per bit and left the byte-assembly opaque to concat/extract rules.
///
/// Sound because the analysis only ever *under*-claims zero bits: if bit `b`
/// is provably 0 in every operand but one, the `or` at `b` is that operand's
/// bit. Slices are cut at owner changes, so each slice has a single source.
fn or_disjoint_concat(
    pool: &mut TermPool,
    args: &[TermId],
    w: u32,
    stats: &mut Stats,
) -> Option<Step> {
    // The analysis and the per-bit owner map are both linear in the width;
    // cap it so a pathologically wide vector cannot dominate rewriting.
    if args.len() < 2 || w > MAX_OR_WIDTH {
        return None;
    }
    // Gate on visible structure: an `or` of plain variables can never be
    // disjoint, and the mask walk should not run on every bitwise term.
    let structured = args.iter().any(|&a| {
        matches!(
            pool.op(a),
            Op::Concat | Op::ZeroExtend(_) | Op::BvShl | Op::BvLshr | Op::BvConst(_)
        )
    });
    if !structured {
        return None;
    }
    // owner[b] = index of the unique operand that may set bit b.
    const NONE: usize = usize::MAX;
    let mut owner = vec![NONE; w as usize];
    for (i, &a) in args.iter().enumerate() {
        let m = nonzero_mask(pool, a, MASK_DEPTH);
        for b in 0..w {
            if m.bit(b) {
                if owner[b as usize] != NONE {
                    return None; // operands overlap: not pure wiring
                }
                owner[b as usize] = i;
            }
        }
    }
    // Count runs before building anything, so a bail costs no pool churn.
    let runs = 1
        + (1..w)
            .filter(|&b| owner[b as usize] != owner[(b - 1) as usize])
            .count();
    if runs > MAX_OR_SLICES {
        return None;
    }
    if runs == 1 {
        hit(stats, "or-disjoint-concat");
        let o = owner[0];
        return Some(match o {
            NONE => Step::Done(bv_zero(pool, w)),
            _ => Step::Done(args[o]),
        });
    }
    // Term ids are dense indices, so anything at or past this mark is a term
    // the rebuild had to invent.
    let mark = TermId(pool.num_terms() as u32);
    let mut parts: Vec<TermId> = Vec::with_capacity(runs);
    let mut hi = w - 1;
    loop {
        let o = owner[hi as usize];
        let mut lo = hi;
        while lo > 0 && owner[(lo - 1) as usize] == o {
            lo -= 1;
        }
        parts.push(match o {
            NONE => bv_zero(pool, hi - lo + 1),
            _ => rewrite_node(pool, Op::Extract { hi, lo }, &[args[o]], stats),
        });
        if lo == 0 {
            break;
        }
        hi = lo - 1;
    }
    // The claim this rule makes is that the `or` was *pure wiring*: every
    // slice must already exist as a term, so the rebuild costs one concat and
    // saves w and-gates. When a slice has to be invented instead — an operand
    // whose live range does not line up with an existing concat boundary — the
    // "simplification" adds an extract per slice and splits the surrounding
    // equalities into more assertions. That was measured: it cost
    // uclid/catchconv/convert-jpg2gif-query-1200 (16.8s -> timeout, term nodes
    // 8228 -> 9446), so those rebuilds are declined.
    if parts.iter().any(|&p| p >= mark && !is_const(pool, p)) {
        return None;
    }
    hit(stats, "or-disjoint-concat");
    Some(Step::Again(Op::Concat, parts))
}

/// A linear form over the ring Z/2^w: `sum(coeff_i * base_i) + konst`.
///
/// bvadd/bvsub/bvmul/bvneg are exactly +, -, *, unary- in that ring, so
/// collecting a term into this form and rebuilding it is sound at every
/// width — including the distribution `c * (a + b) = c*a + c*b`, which is
/// just ring distributivity.
struct LinForm {
    coeffs: FxHashMap<TermId, Bv>,
    konst: Bv,
    width: u32,
}

impl LinForm {
    fn new(width: u32) -> Self {
        LinForm {
            coeffs: FxHashMap::default(),
            konst: Bv::zero(width),
            width,
        }
    }

    fn add_atom(&mut self, base: TermId, coef: &Bv) {
        let w = self.width;
        let e = self.coeffs.entry(base).or_insert_with(|| Bv::zero(w));
        *e = e.add(coef);
    }

    /// Size of the term this form rebuilds to: one node per surviving
    /// summand, plus one more for each summand that needs an explicit
    /// `bvmul` (coefficients 1 and -1 rebuild as the base / a `bvneg`).
    fn cost(&self) -> usize {
        let mut c = usize::from(!self.konst.is_zero());
        for v in self.coeffs.values() {
            if v.is_zero() {
                continue;
            }
            c += 1;
            if !v.is_one() && !v.is_ones() {
                c += 1;
            }
        }
        c
    }
}

/// Visit budget for one linear-form extraction. Distribution through nested
/// sums is worst-case exponential in the multiplier nesting depth; past the
/// budget the remaining subterms are taken as opaque atoms (still sound,
/// merely less normalized).
const LIN_BUDGET: u32 = 4_000;

/// How aggressively a linear-form extraction breaks nested sums apart.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LinMode {
    /// Nested sums stay opaque. Reproduces the pre-existing behaviour:
    /// `ac-flatten` has already merged the unshared ones, and re-associating
    /// the shared ones destroys blaster reuse.
    Shallow,
    /// Distribute only through a coefficient — `c * (a + b)` and
    /// `-(a + b)` — the shapes that hide cancellable coefficients.
    Scaled,
    /// Distribute through every nested sum. Needed when the *same* shared sum
    /// appears both scaled and unscaled: expanding only the scaled occurrence
    /// would leave the two halves unable to cancel.
    Full,
}

/// Accumulate `coef * t` into `form`. `scaled` records that the traversal has
/// already passed through a coefficient (a constant multiplier or a negation).
fn lin_accumulate(
    pool: &mut TermPool,
    t: TermId,
    coef: &Bv,
    form: &mut LinForm,
    budget: &mut u32,
    mode: LinMode,
    scaled: bool,
) {
    if *budget == 0 {
        form.add_atom(t, coef);
        return;
    }
    *budget -= 1;
    if let Some(c) = pool.as_bv_const(t) {
        let prod = coef.mul(c);
        form.konst = form.konst.add(&prod);
        return;
    }
    let distribute = match mode {
        LinMode::Shallow => false,
        LinMode::Scaled => scaled,
        LinMode::Full => true,
    };
    match pool.op(t) {
        Op::BvAdd if distribute => {
            for a in pool.args(t).to_vec() {
                lin_accumulate(pool, a, coef, form, budget, mode, scaled);
            }
        }
        Op::BvSub if distribute => {
            let (a, b) = (pool.args(t)[0], pool.args(t)[1]);
            lin_accumulate(pool, a, coef, form, budget, mode, scaled);
            lin_accumulate(pool, b, &coef.neg(), form, budget, mode, true);
        }
        Op::BvNeg => {
            let a = pool.args(t)[0];
            lin_accumulate(pool, a, &coef.neg(), form, budget, mode, true);
        }
        Op::BvMul => {
            let margs: Vec<TermId> = pool.args(t).to_vec();
            let mut c = coef.clone();
            let mut rest: Vec<TermId> = Vec::with_capacity(margs.len());
            for m in margs {
                match pool.as_bv_const(m) {
                    Some(k) => c = c.mul(k),
                    None => rest.push(m),
                }
            }
            match rest.len() {
                // Every factor constant: the rewriter folds these, but a
                // budget-truncated form can still land here.
                0 => form.konst = form.konst.add(&c),
                1 => lin_accumulate(pool, rest[0], &c, form, budget, mode, true),
                _ => {
                    let base = mk(pool, Op::BvMul, &rest);
                    form.add_atom(base, &c);
                }
            }
        }
        _ => form.add_atom(t, coef),
    }
}

/// Linear normalization of a bvadd argument list: decompose each argument
/// into coefficient/base pairs, sum coefficients per base, and rebuild.
///
/// Three forms are computed — leaving nested sums opaque, distributing only
/// through coefficients, and distributing through everything — and the
/// smallest rebuild wins. Distribution is what exposes cancellation in
/// SAGE-style path conditions (`2*y + (-2)*(y + 4)` is `-8`), but it
/// duplicates work when nothing cancels, so a more aggressive mode is taken
/// only when it strictly shrinks the term. That cost test is also what keeps
/// shared sums nested: expanding one without cancellation always grows the
/// summand count, so `ac-flatten`'s sharing guard is respected by
/// construction.
///
/// Returns None when nothing changes.
fn collect_add_coefficients(
    pool: &mut TermPool,
    args: &[TermId],
    w: u32,
    stats: &mut Stats,
) -> Option<Step> {
    let build = |pool: &mut TermPool, mode: LinMode| {
        let mut form = LinForm::new(w);
        let mut budget = LIN_BUDGET;
        let one = Bv::from_u64(w, 1);
        for &a in args {
            lin_accumulate(pool, a, &one, &mut form, &mut budget, mode, false);
        }
        form
    };
    let mut form = build(pool, LinMode::Shallow);
    let mut distributed = false;
    // Only worth further traversals when some argument carries a coefficient
    // or a nested sum for the distribution to act on.
    let worth_trying = args.iter().any(|&a| {
        matches!(pool.op(a), Op::BvNeg | Op::BvAdd | Op::BvSub)
            || (pool.op(a) == Op::BvMul
                && pool.args(a).iter().any(|&m| pool.as_bv_const(m).is_some()))
    });
    if worth_trying && !group_disabled("add-distribute") {
        for mode in [LinMode::Scaled, LinMode::Full] {
            let deep = build(pool, mode);
            if deep.cost() < form.cost() {
                form = deep;
                distributed = true;
            }
        }
    }

    // Rebuild deterministically.
    let mut keys: Vec<TermId> = form.coeffs.keys().copied().collect();
    keys.sort_unstable();
    let mut new_args: Vec<TermId> = Vec::with_capacity(keys.len() + 1);
    for base in keys {
        let c = form.coeffs[&base].clone();
        if c.is_zero() {
            continue;
        }
        if c.is_one() {
            new_args.push(base);
        } else if c.is_ones() {
            new_args.push(rewrite_node(pool, Op::BvNeg, &[base], stats));
        } else {
            let ct = pool.bv(c);
            new_args.push(rewrite_node(pool, Op::BvMul, &[ct, base], stats));
        }
    }
    if !form.konst.is_zero() || new_args.is_empty() {
        let k = form.konst.clone();
        new_args.push(pool.bv(k));
    }
    new_args.sort_unstable();
    if new_args == args {
        return None;
    }
    hit(stats, "add-collect-coeffs");
    if distributed {
        hit(stats, "add-distribute");
    }
    Some(match new_args.len() {
        1 => Step::Done(new_args[0]),
        _ => Step::Done(mk(pool, Op::BvAdd, &new_args)),
    })
}

/// A summand of a `bvadd` seen as `konst * product(factors)`, with `factors`
/// sorted so that multisets can be intersected by a merge.
struct Monomial {
    konst: Bv,
    factors: Vec<TermId>,
}

/// Decompose one `bvadd` argument into constant coefficient and non-constant
/// factors. `None` for a summand with no non-constant factor at all (a bare
/// constant), which can never contribute to a common factor.
fn as_monomial(pool: &TermPool, t: TermId, w: u32) -> Option<Monomial> {
    let (konst, base) = match pool.op(t) {
        Op::BvNeg => (Bv::ones(w), pool.args(t)[0]),
        _ => (Bv::from_u64(w, 1), t),
    };
    let mut konst = konst;
    let mut factors: Vec<TermId> = Vec::new();
    let parts: &[TermId] = if pool.op(base) == Op::BvMul {
        pool.args(base)
    } else {
        std::slice::from_ref(&base)
    };
    for &p in parts {
        match pool.as_bv_const(p) {
            Some(c) => konst = konst.mul(c),
            None => factors.push(p),
        }
    }
    if factors.is_empty() {
        return None;
    }
    factors.sort_unstable();
    Some(Monomial { konst, factors })
}

/// Is `t` a product (possibly negated) of more than one non-constant factor?
fn is_product(pool: &TermPool, t: TermId) -> bool {
    let base = match pool.op(t) {
        Op::BvNeg => pool.args(t)[0],
        _ => t,
    };
    pool.op(base) == Op::BvMul
        && pool
            .args(base)
            .iter()
            .filter(|&&p| pool.as_bv_const(p).is_none())
            .count()
            > 1
}

/// Multiset intersection of two sorted factor lists.
fn intersect_sorted(a: &[TermId], b: &[TermId]) -> Vec<TermId> {
    let (mut i, mut j) = (0, 0);
    let mut out = Vec::new();
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {
                out.push(a[i]);
                i += 1;
                j += 1;
            }
        }
    }
    out
}

/// Remove one occurrence of each element of the sorted `common` from the
/// sorted `factors`.
fn remove_sorted(factors: &[TermId], common: &[TermId]) -> Vec<TermId> {
    let mut out = Vec::with_capacity(factors.len() - common.len());
    let mut j = 0;
    for &f in factors {
        if j < common.len() && common[j] == f {
            j += 1;
        } else {
            out.push(f);
        }
    }
    out
}

/// Pull a factor shared by every summand out of a `bvadd`:
/// `a*b + a*c` becomes `a*(b + c)`, and `s*t - t` becomes `t*(s - 1)`.
///
/// This is the direction that *removes* multipliers — `n` summands sharing
/// `k` factors go from `n*k` multiplications to `k + n - 1` — so unlike
/// distribution it needs no cost test. It runs after coefficient collection,
/// on the collected argument list, and only when no summand is shared with
/// the rest of the assertion set: rewriting `a*b` away is only a saving if
/// nothing else still needs it.
///
/// Two of Noetzli's rewrite-candidate benchmarks are exactly this identity
/// stated as a disequality (`s*s + s*t` against `s*(s + t)`); factoring makes
/// the two sides the same term.
fn factor_common_multiplier(
    pool: &mut TermPool,
    args: &[TermId],
    w: u32,
    stats: &mut Stats,
) -> Option<Step> {
    if args.len() < 2 || group_disabled("add-factor") {
        return None;
    }
    let mut monos: Vec<Monomial> = Vec::with_capacity(args.len());
    let mut common: Vec<TermId> = Vec::new();
    for (i, &a) in args.iter().enumerate() {
        // Only a product node is actually dissolved by factoring. If one is
        // shared it survives anyway and the rewrite adds a multiplier instead
        // of removing one. A shared *leaf* summand is untouched by the
        // rewrite -- it only ever becomes a factor or a `1` -- so it does not
        // block.
        if term_shared(a) && is_product(pool, a) {
            return None;
        }
        let m = as_monomial(pool, a, w)?;
        common = if i == 0 {
            m.factors.clone()
        } else {
            intersect_sorted(&common, &m.factors)
        };
        if common.is_empty() {
            return None;
        }
        monos.push(m);
    }
    // Rebuild each summand divided by the common factors, then the product.
    let mut quotients: Vec<TermId> = Vec::with_capacity(monos.len());
    for m in &monos {
        let rest = remove_sorted(&m.factors, &common);
        let mut parts: Vec<TermId> = rest;
        if !m.konst.is_one() {
            let k = pool.bv(m.konst.clone());
            parts.push(k);
        }
        quotients.push(match parts.len() {
            0 => pool.bv_u64(w, 1),
            1 => parts[0],
            _ => rewrite_node(pool, Op::BvMul, &parts, stats),
        });
    }
    let sum = rewrite_node(pool, Op::BvAdd, &quotients, stats);
    let mut factors = common;
    factors.push(sum);
    hit(stats, "add-factor");
    Some(Step::Done(rewrite_node(pool, Op::BvMul, &factors, stats)))
}

/// `Some(k)` when the constant is exactly 2^k with k >= 1. (k == 0 is the
/// multiplicative identity and is already handled as a unit element.)
fn power_of_two_log(c: &Bv) -> Option<u32> {
    let w = c.width();
    let mut found = None;
    for i in 0..w {
        if c.bit(i) {
            if found.is_some() {
                return None;
            }
            found = Some(i);
        }
    }
    found.filter(|&k| k >= 1)
}

fn signed_min(w: u32) -> Bv {
    Bv::zero(w).not().shl_small(w - 1) // 100...0
}

fn signed_max(w: u32) -> Bv {
    signed_min(w).not() // 011...1
}

/// Shared handling for commutative n-ary BV ops: fold constants together,
/// apply unit/absorbing elements, cancel/dedup where sound.
fn nary_bv(pool: &mut TermPool, op: Op, args: &[TermId], stats: &mut Stats) -> Step {
    use Op::*;
    let w = pool.width(args[0]);
    // AC-flatten nested applications of the same op. For the expensive
    // circuits (add/mul), only flatten through children no other parent
    // shares — re-associating shared arithmetic destroys blaster reuse.
    let arith = matches!(op, BvAdd | BvMul);
    let flattenable = |pool: &TermPool, a: TermId| pool.op(a) == op && (!arith || !term_shared(a));
    // One pass over the arguments answers both questions: is there anything to
    // flatten, and did the sharing guard refuse anything. The second count is
    // what says whether the guarded and unguarded encodings can differ at all.
    let (mut any_flat, mut any_blocked) = (false, false);
    for &a in args {
        if pool.op(a) != op {
            continue;
        }
        if !arith || !term_shared(a) {
            any_flat = true;
        } else {
            any_blocked = true;
        }
    }
    if any_blocked {
        hit(
            stats,
            if op == BvAdd {
                "share-block-add"
            } else {
                "share-block-mul"
            },
        );
    }
    if any_flat {
        hit(stats, "ac-flatten");
        let mut flat: Vec<TermId> = Vec::with_capacity(args.len() * 2);
        let mut stack: Vec<TermId> = args.iter().rev().copied().collect();
        while let Some(a) = stack.pop() {
            if flattenable(pool, a) {
                stack.extend(pool.args(a).iter().rev().copied());
            } else {
                flat.push(a);
            }
        }
        return Step::Again(op, flat);
    }
    // Linear normalization for add: collect per-term coefficients so that
    // x + x -> 2x, x + 3x -> 4x, 2x + (-2)x -> 0. Makes AC-equal sums
    // syntactically equal and cancels opposites.
    if op == BvAdd && !group_disabled("add-coeffs") {
        if let Some(step) = collect_add_coefficients(pool, args, w, stats) {
            return step;
        }
        if let Some(step) = factor_common_multiplier(pool, args, w, stats) {
            return step;
        }
    }
    // `x` and `x << x` never share a set bit: the low `x` bits of `x << x` are
    // zero, and bits `x` and above of `x` are zero because `x < 2^x`. So the
    // addition carries nowhere and is a disjunction -- one gate per bit
    // instead of a ripple adder.
    if op == BvAdd && args.len() == 2 {
        let shl_self = |pool: &TermPool, s: TermId, x: TermId| {
            pool.op(s) == BvShl && pool.args(s)[0] == x && pool.args(s)[1] == x
        };
        if shl_self(pool, args[0], args[1]) || shl_self(pool, args[1], args[0]) {
            hit(stats, "add-shl-self");
            return Step::Again(BvOr, args.to_vec());
        }
    }
    // An `or` whose operands touch pairwise-disjoint bit ranges is pure
    // wiring: rebuild it as a concat. Byte-assembly (`(a << 8) | b`) is the
    // dominant shape in symbolic-execution path conditions.
    if op == BvOr && !group_disabled("or-disjoint") {
        if let Some(step) = or_disjoint_concat(pool, args, w, stats) {
            return step;
        }
    }
    // Byte assembly is written with `+` at least as often as with `|` — SAGE
    // emits both, sometimes in the same benchmark. With pairwise-disjoint
    // operands no bit position ever has two 1s, so no carry is ever generated
    // and the sum is exactly the bitwise or; likewise `xor`, which differs
    // from `or` only where two operands are both 1. Handing it to `or` puts
    // it in front of the rule above, which turns it into a concat and hence
    // into something `eq-concat-split` can slice.
    if matches!(op, BvAdd | BvXor)
        && !group_disabled("disjoint-or")
        && operands_disjoint(pool, args, w)
    {
        hit(stats, "disjoint-to-or");
        return Step::Again(BvOr, args.to_vec());
    }
    // Partition into constant accumulator and the rest (args are sorted, so
    // identical terms are adjacent).
    let mut acc: Option<Bv> = None;
    let mut rest: Vec<TermId> = Vec::with_capacity(args.len());
    let mut changed = false;
    let mut i = 0;
    while i < args.len() {
        let a = args[i];
        if let Some(c) = pool.as_bv_const(a) {
            acc = Some(match acc {
                None => c.clone(),
                Some(prev) => {
                    changed = true;
                    match op {
                        BvAdd => prev.add(c),
                        BvMul => prev.mul(c),
                        BvAnd => prev.and(c),
                        BvOr => prev.or(c),
                        BvXor => prev.xor(c),
                        _ => unreachable!(),
                    }
                }
            });
            i += 1;
            continue;
        }
        // Adjacent-equal handling.
        if i + 1 < args.len() && args[i + 1] == a {
            match op {
                BvXor => {
                    // x xor x = 0.
                    hit(stats, "bvxor-cancel");
                    changed = true;
                    i += 2;
                    continue;
                }
                BvAnd | BvOr => {
                    // Idempotent: drop the duplicate.
                    hit(stats, "bv-idempotent");
                    changed = true;
                    rest.push(a);
                    i += 2;
                    continue;
                }
                _ => {}
            }
        }
        rest.push(a);
        i += 1;
    }
    // Complement pairs for and/or.
    if matches!(op, BvAnd | BvOr) {
        for x in 0..rest.len() {
            for y in x + 1..rest.len() {
                if is_not_of(pool, rest[x], rest[y]) {
                    hit(stats, "bv-complement");
                    return Step::Done(match op {
                        BvAnd => bv_zero(pool, w),
                        _ => pool.bv(Bv::ones(w)),
                    });
                }
            }
        }
    }
    // Multiplication by a constant with special structure is pure wiring:
    //   x * (-1)  -> -x            (found missing by the opportunity finder:
    //                               Bitwuzla discharges bv-term-small-rw_679
    //                               in 0.01s where we timed out at 10s)
    //   x * 2^k   -> x << k
    if op == BvMul && rest.len() == 1 {
        if let Some(c) = &acc {
            if *c == Bv::ones(w) && !group_disabled("mul-minus-one") {
                hit(stats, "mul-minus-one");
                return Step::Again(BvNeg, vec![rest[0]]);
            }
            // `x * 2^k -> x << k` is deliberately NOT done. It looks like a
            // free win, but the bit-blaster already folds a single-bit
            // constant multiplier into wiring (every other partial product is
            // zero), so it buys nothing — while the constant shift it creates
            // is rewritten on into concat/extract, which restructures the term
            // and pushes extracts down through the operand. Measured 3x slower
            // (8.3s -> 24.3s) on uclid/catchconv/convert-jpg2gif-query-1200,
            // with no instance gained anywhere. See docs/CHANGELOG-PERF.md.
        }
    }
    // Unsigned divide/remainder by a power of two are shifts and masks.
    // Fold the constant accumulator in (identity/absorbing element handling).
    if let Some(c) = &acc {
        let (identity, absorbs) = match op {
            BvAdd => (c.is_zero(), false),
            BvMul => (c.is_one(), c.is_zero()),
            BvAnd => (c.is_ones(), c.is_zero()),
            BvOr => (c.is_zero(), c.is_ones()),
            BvXor => (c.is_zero(), false),
            _ => unreachable!(),
        };
        if absorbs {
            hit(stats, "bv-absorb");
            return Step::Done(value_term(pool, Value::Bv(c.clone())));
        }
        if identity && !rest.is_empty() {
            changed = true;
            acc = None;
        }
    }
    let mut new_args = rest;
    if let Some(c) = acc {
        new_args.push(pool.bv(c));
    }
    match new_args.len() {
        0 => {
            hit(stats, "bv-empty");
            // Only Add/Xor can become empty (identity dropped): result 0.
            Step::Done(bv_zero(pool, w))
        }
        1 => {
            hit(stats, "bv-single");
            Step::Done(new_args[0])
        }
        _ if changed => {
            hit(stats, "bv-nary-shrink");
            Step::Done(mk(pool, op, &new_args))
        }
        _ => Step::NoChange,
    }
}
