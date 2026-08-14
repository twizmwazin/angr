//! The facts both string analyses read out of the term DAG, defined once.
//!
//! [`crate::bounds`] and [`crate::length`] answer different questions —
//! "is the bounded encoding complete?" against "do the lengths alone refute
//! this?" — but they read the *same shapes* out of the same DAG, and every one
//! of those shapes carries a subtlety that a second copy eventually loses.
//! Both files have shipped a wrong `unsat` through one of them:
//!
//! - **Integer literals.** `int_literal` yields a `u64` and `as i64` on it is a
//!   reinterpretation, not a conversion: a numeral in `[2^64 - 32768, 2^64 - 1]`
//!   came back as a small *negative* number, survived the `i16` gate and was
//!   clamped to 0 by the length harvest, so
//!   `(not (>= (str.len x) 18446744073709551615))` — true of every string —
//!   yielded `|x| <= 0` and a wrong `unsat`. [`int_const`] widens to `i128`,
//!   where the conversion is total and exact, so the mistake is no longer
//!   expressible.
//! - **Interval arithmetic.** Folding bounds in the machine's own width wraps.
//!   Thirteen nested `str.len`s over a 32-character string multiply out to
//!   `32^13 = 2^65`, which wrapped to exactly `(0, 0)` — back *inside* the
//!   `i16` gate, certifying 16-bit arithmetic as exact and answering `unsat` on
//!   a satisfiable formula. [`Iv`] computes in `i128` and drops any endpoint
//!   past [`HUGE`] to infinity, so a bound can only ever get *weaker* than the
//!   truth, never stronger.
//! - **Chained comparisons.** `(< a b c)` abbreviates `(and (< a b) (< b c))`,
//!   so every adjacent pair may be harvested — but the *negation* of a chain is
//!   a disjunction, and no link of it may be. Encoding only the first pair once
//!   dropped a constraint outright and produced a wrong `sat`.
//!   [`comparison_rel`] is the single place that decision is made.
//!
//! Nothing here decides *policy*. Each analysis still chooses what to do with a
//! fact; this module only says what the fact is.

use crate::int_literal;
use smtrs_core::{Op, Sort, TermId, TermPool};

/// The head symbol of an uninterpreted application, borrowed rather than
/// cloned: this is called once per term per fixpoint round in
/// [`crate::bounds::lengths`], where an owned `String` per call was pure
/// allocation.
pub(crate) fn op_name(pool: &TermPool, t: TermId) -> Option<&str> {
    match pool.op(t) {
        Op::Other { name, .. } => Some(pool.symbol(name).name.as_str()),
        _ => None,
    }
}

/// Integer literals, including the `int-neg` wrapper the parser puts around a
/// negative numeral.
///
/// The result is `i128` deliberately. `int_literal` yields a `u64`, so every
/// numeral SMT-LIB can write is representable and the widening is exact; there
/// is no width at which a caller could reinterpret a large numeral as a small
/// negative one. See the module docs for the wrong `unsat` that cost.
pub(crate) fn int_const(pool: &TermPool, t: TermId) -> Option<i128> {
    if let Op::Var(sym) = pool.op(t) {
        if pool.symbol(sym).sort == Sort::Int {
            return int_literal(&pool.symbol(sym).name).map(i128::from);
        }
    }
    if op_name(pool, t) == Some("int-neg") {
        return int_const(pool, pool.args(t)[0]).map(|v| -v);
    }
    // Bit-vector constants appear on the far side of the `int2bv` bridge:
    // a client comparing `(_ int2bv 64)(str.len x)` against a numeral writes
    // that numeral as a bit-vector. Its unsigned value is exact in `i128` for
    // anything up to 64 bits; wider constants with high limbs set yield `None`
    // and are simply not harvested.
    if let Some(c) = pool.as_bv_const(t) {
        return c.as_u64().map(i128::from);
    }
    None
}

/// The first `re.comp`/`re.diff` anywhere under `roots`.
///
/// Both analyses refuse complement, for the same reason stated two ways: the
/// automaton is built over *bytes* while SMT-LIB strings range over a larger
/// alphabet, so the byte language is in general a subset of the real one. Union,
/// concatenation, star and intersection preserve enough of the correspondence to
/// reason through; complement does not — the complement of a full byte range is
/// empty over bytes and contains every character above `0xff` in reality. That
/// is not a missing model, it is a *contradicted* one, and it shipped as a wrong
/// `unsat`.
pub(crate) fn complement_op(pool: &TermPool, roots: &[TermId]) -> Option<&'static str> {
    let mut found: Option<&'static str> = None;
    pool.post_order(roots, |pool, t| {
        if found.is_none() {
            match op_name(pool, t) {
                Some("re.comp") => found = Some("re.comp"),
                Some("re.diff") => found = Some("re.diff"),
                _ => {}
            }
        }
    });
    found
}

/// Is `t` a regex whose byte automaton has the same word lengths as the real
/// language? See [`complement_op`].
pub(crate) fn complement_free(pool: &TermPool, t: TermId) -> bool {
    complement_op(pool, &[t]).is_none()
}

/// The relation an arithmetic comparison forces on each *adjacent pair* of its
/// operands, given that the comparison itself holds with polarity `positive`.
///
/// `Some((swap, strict))` means every window `[a, b]` of the operands satisfies
/// `a < b` when `strict` and `a <= b` otherwise, with `a` and `b` exchanged
/// when `swap`. `None` means nothing may be harvested.
///
/// Two subtleties, and they are the whole reason this is one function:
///
/// - The comparisons are **`:chainable`**, so `(< a b c)` abbreviates
///   `(and (< a b) (< b c))` and *every* adjacent pair holds. Reading only the
///   first pair drops a conjunct; that shipped as a wrong `sat`.
/// - Under a negation that is false. The complement of a chain is a
///   *disjunction* — `(not (< a b c))` is `a >= b or b >= c` — which constrains
///   no pair at all. A negated comparison is therefore usable at exactly two
///   operands, which is the one arity whose complement is again a comparison.
pub(crate) fn comparison_rel(pool: &TermPool, c: TermId, positive: bool) -> Option<(bool, bool)> {
    let args = pool.args(c);
    if args.len() < 2 || (!positive && args.len() != 2) {
        return None;
    }
    // *Unsigned* bit-vector comparisons, for `int2bv`-bridged lengths (see
    // `bv2nat` in the crate root): bit-vector clients state `|x| < k` as
    // `(bvult ((_ int2bv 64) (str.len x)) k)`. An unsigned comparison is the
    // natural-number order of the operands' unsigned values, so every fact
    // derived from one here is a true fact about those values in every model.
    // Signed comparisons are deliberately excluded: `bvslt` does not agree
    // with the unsigned-value order (0xff <s 0 while 255 > 0), and this
    // function's callers reason about the operands as integers. These are
    // binary by construction (the pool enforces arity 2), so chainability is
    // moot.
    match (pool.op(c), positive) {
        (Op::BvUlt, true) | (Op::BvUge, false) => return Some((false, true)),
        (Op::BvUle, true) | (Op::BvUgt, false) => return Some((false, false)),
        (Op::BvUgt, true) | (Op::BvUle, false) => return Some((true, true)),
        (Op::BvUge, true) | (Op::BvUlt, false) => return Some((true, false)),
        _ => {}
    }
    // `(swap, strict)`, normalising every case to `lhs < rhs` or `lhs <= rhs`.
    match (op_name(pool, c)?, positive) {
        ("<", true) | (">=", false) => Some((false, true)),
        ("<=", true) | (">", false) => Some((false, false)),
        (">", true) | ("<=", false) => Some((true, true)),
        (">=", true) | ("<", false) => Some((true, false)),
        _ => None,
    }
}

/// Endpoint magnitude past which an interval bound is dropped to infinity.
/// Propagating a system with no solution walks the bounds apart without limit;
/// this stops them long before `i128` arithmetic could wrap, at no cost to the
/// answer — the contradiction is caught the moment the bounds cross, which is
/// well before either reaches this.
pub(crate) const HUGE: i128 = 1 << 100;

/// Half-window a term's interval must fit inside to be *snug*. Well below the
/// signed maximum of [`crate::length::W`], the width the length abstraction is
/// emitted in, so that nothing emitted can reach the wrap point.
pub(crate) const SNUG: i128 = 1 << 28;

/// An interval valid in every model. `None` is an infinite endpoint.
///
/// Every operation widens rather than wraps: arithmetic is `i128` and checked,
/// and an endpoint that escapes [`HUGE`] becomes infinite. A caller therefore
/// only ever learns *less* than the truth about a term, which is the safe
/// direction for both analyses — an unbounded term blocks completeness in
/// [`crate::bounds`] and emits no comparison in [`crate::length`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Iv {
    pub(crate) lo: Option<i128>,
    pub(crate) hi: Option<i128>,
}

impl Iv {
    pub(crate) const TOP: Iv = Iv { lo: None, hi: None };

    pub(crate) fn nonneg() -> Iv {
        Iv {
            lo: Some(0),
            hi: None,
        }
    }

    pub(crate) fn exact(v: i128) -> Iv {
        Iv {
            lo: Some(v),
            hi: Some(v),
        }
    }

    /// An endpoint past [`HUGE`] is dropped to infinity. Widening an interval
    /// is always sound, and it keeps every arithmetic rule far from the `i128`
    /// range where a wrap could invent a bound out of nothing.
    pub(crate) fn new(lo: Option<i128>, hi: Option<i128>) -> Iv {
        Iv {
            lo: lo.filter(|v| v.abs() <= HUGE),
            hi: hi.filter(|v| v.abs() <= HUGE),
        }
    }

    /// Is this interval empty, i.e. does it say the term has no value at all?
    /// Only reachable when the problem has no model, since every rule that
    /// builds an interval states a fact true in every model.
    pub(crate) fn empty(self) -> bool {
        matches!((self.lo, self.hi), (Some(l), Some(h)) if l > h)
    }

    /// Both endpoints, when both are finite and consistent. `None` covers an
    /// infinite endpoint and an empty interval alike: neither is a value a
    /// caller may encode against.
    pub(crate) fn finite(self) -> Option<(i128, i128)> {
        match (self.lo, self.hi) {
            (Some(l), Some(h)) if l <= h => Some((l, h)),
            _ => None,
        }
    }

    /// Intersection: both facts hold, so the tighter of each endpoint does.
    pub(crate) fn meet(self, o: Iv) -> Iv {
        Iv::new(
            match (self.lo, o.lo) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (a, b) => a.or(b),
            },
            match (self.hi, o.hi) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            },
        )
    }

    /// Union: one or the other holds, so the looser of each endpoint does.
    pub(crate) fn join(self, o: Iv) -> Iv {
        Iv::new(
            match (self.lo, o.lo) {
                (Some(a), Some(b)) => Some(a.min(b)),
                _ => None,
            },
            match (self.hi, o.hi) {
                (Some(a), Some(b)) => Some(a.max(b)),
                _ => None,
            },
        )
    }

    pub(crate) fn add(self, o: Iv) -> Iv {
        Iv::new(
            opt2(self.lo, o.lo, |a, b| a.checked_add(b)),
            opt2(self.hi, o.hi, |a, b| a.checked_add(b)),
        )
    }

    pub(crate) fn neg(self) -> Iv {
        Iv::new(
            self.hi.and_then(|v| v.checked_neg()),
            self.lo.and_then(|v| v.checked_neg()),
        )
    }

    pub(crate) fn sub(self, o: Iv) -> Iv {
        self.add(o.neg())
    }

    /// Four-corner multiplication; any infinite endpoint makes the product
    /// unbounded on the side it can reach, and we simply give up on both.
    pub(crate) fn mul(self, o: Iv) -> Iv {
        let (Some(al), Some(ah), Some(bl), Some(bh)) = (self.lo, self.hi, o.lo, o.hi) else {
            return Iv::TOP;
        };
        let mut lo = None;
        let mut hi = None;
        for (x, y) in [(al, bl), (al, bh), (ah, bl), (ah, bh)] {
            let Some(c) = x.checked_mul(y) else {
                return Iv::TOP;
            };
            lo = Some(lo.map_or(c, |v: i128| v.min(c)));
            hi = Some(hi.map_or(c, |v: i128| v.max(c)));
        }
        Iv::new(lo, hi)
    }

    /// The interval as a pair when it is *snug*: finite and comfortably inside
    /// the signed [`crate::length::W`]-bit range, so the canonical valuation
    /// does not wrap it.
    pub(crate) fn snug(self) -> Option<(i64, i64)> {
        self.finite()
            .filter(|&(l, h)| l >= -SNUG && h <= SNUG)
            .map(|(l, h)| (l as i64, h as i64))
    }
}

fn opt2(a: Option<i128>, b: Option<i128>, f: impl Fn(i128, i128) -> Option<i128>) -> Option<i128> {
    match (a, b) {
        (Some(x), Some(y)) => f(x, y),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smtrs_parser::{parse_script, Command};

    /// The assertions of a script, in order.
    fn asserts(input: &str) -> (TermPool, Vec<TermId>) {
        let mut pool = TermPool::new();
        let script = parse_script(input, &mut pool).expect("parse");
        let roots = script
            .commands
            .iter()
            .filter_map(|c| match c {
                Command::Assert(t, _) => Some(*t),
                _ => None,
            })
            .collect();
        (pool, roots)
    }

    /// The `n`th operand of the first assertion.
    fn operand(input: &str, n: usize) -> (TermPool, TermId) {
        let (pool, roots) = asserts(input);
        let t = pool.args(roots[0])[n];
        (pool, t)
    }

    /// Every numeral SMT-LIB can write, widened exactly. `2^64 - 1`
    /// reinterpreted as `i64` is `-1`, which the length harvest clamps to a
    /// bound of 0 — that shipped as a wrong `unsat`. In `i128` it is the large
    /// positive number it actually is, and bounds nothing.
    #[test]
    fn int_const_never_wraps() {
        for v in [0u64, 1, 32768, i64::MAX as u64, 1 << 63, u64::MAX] {
            let (pool, t) = operand(&format!("(declare-const n Int)(assert (= n {v}))"), 1);
            assert_eq!(int_const(&pool, t), Some(i128::from(v)), "numeral {v}");
        }
    }

    /// The parser wraps a negative numeral in `int-neg`, which is a constant
    /// like any other.
    #[test]
    fn int_const_sees_through_int_neg() {
        let (pool, t) = operand("(declare-const n Int)(assert (= n (- 5)))", 1);
        assert_eq!(int_const(&pool, t), Some(-5));
    }

    /// An interval whose endpoints would wrap a machine word becomes infinite,
    /// never a small one. This is the `32^13 = 2^65 -> (0, 0)` shape.
    #[test]
    fn a_product_that_would_wrap_becomes_unbounded_not_zero() {
        let mut v = Iv::exact(32);
        for _ in 0..13 {
            v = v.mul(Iv::exact(32));
        }
        // 32^14 is well inside `i128`, so it is still a real bound here...
        assert_eq!(v.finite(), Some((32i128.pow(14), 32i128.pow(14))));
        // ...and pushing it past `HUGE` drops it to infinity rather than
        // wrapping it back into a small, false, and much *tighter* interval.
        for _ in 0..14 {
            v = v.mul(Iv::exact(32));
        }
        assert_eq!(v.finite(), None);
    }

    /// An empty interval is not a usable pair. Both `finite` and `snug` refuse
    /// it, so a crossed pair can never be emitted as `lo <= x <= hi`.
    #[test]
    fn an_empty_interval_is_not_finite() {
        let v = Iv {
            lo: Some(5),
            hi: Some(4),
        };
        assert!(v.empty());
        assert_eq!(v.finite(), None);
        assert_eq!(v.snug(), None);
    }

    /// Every case of the comparison table, positive and negated, against the
    /// relation each one actually means. Read `(swap, strict)` as: each
    /// adjacent pair `[a, b]` satisfies `a < b` (`strict`) or `a <= b`, with
    /// the two exchanged when `swap`.
    #[test]
    fn comparison_rel_covers_both_polarities() {
        const DECL: &str = "(declare-const a Int)(declare-const b Int)(declare-const c Int)";
        for (rel, pos, want) in [
            ("<", true, Some((false, true))),   // a < b
            ("<=", true, Some((false, false))), // a <= b
            (">", true, Some((true, true))),    // b < a
            (">=", true, Some((true, false))),  // b <= a
            ("<", false, Some((true, false))),  // not (a < b)  ==  b <= a
            ("<=", false, Some((true, true))),  // not (a <= b) ==  b < a
            (">", false, Some((false, false))), // not (a > b)  ==  a <= b
            (">=", false, Some((false, true))), // not (a >= b) ==  a < b
        ] {
            let (pool, roots) = asserts(&format!("{DECL}(assert ({rel} a b))"));
            assert_eq!(comparison_rel(&pool, roots[0], pos), want, "{rel} at {pos}");
        }
        // A chain is harvestable positively — every adjacent pair holds — and
        // not at all under a negation, whose complement is a disjunction.
        for rel in ["<", "<=", ">", ">="] {
            let (pool, roots) = asserts(&format!("{DECL}(assert ({rel} a b c))"));
            assert!(
                comparison_rel(&pool, roots[0], true).is_some(),
                "{rel} chain"
            );
            assert_eq!(
                comparison_rel(&pool, roots[0], false),
                None,
                "negated {rel} chain"
            );
        }
        // Anything that is not a comparison yields nothing at either polarity.
        let (pool, roots) = asserts(&format!("{DECL}(assert (= a b))"));
        assert_eq!(comparison_rel(&pool, roots[0], true), None);
        assert_eq!(comparison_rel(&pool, roots[0], false), None);
    }
}
