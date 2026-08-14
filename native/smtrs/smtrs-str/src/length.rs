//! Length abstraction: reason about how *long* the strings are, never about
//! what is in them.
//!
//! Many string problems are unsatisfiable for a purely arithmetic reason.
//! `(= (str.++ x t t y) (str.++ y "b" x))` forces `|x| + 2|t| + |y| =
//! |y| + 1 + |x|`, i.e. `2|t| = 1`, which no integer satisfies — and that
//! argument needs no bound on the characters, so it goes through where the
//! bounded encoding in [`crate::bounds`] has to give up.
//!
//! This module builds an over-approximation of the problem over *lengths
//! alone*: every string-sorted term `t` is replaced by an integer standing for
//! `|t|`, every integer-sorted term by an integer standing for its value, and
//! every atom the abstraction cannot express becomes a fresh Boolean. The
//! Boolean structure is kept exactly. Because every model of the original
//! induces an assignment satisfying the abstraction, **unsat of the
//! abstraction proves unsat of the original**; a satisfiable abstraction says
//! nothing at all, so this is only ever consulted on paths that would
//! otherwise answer `unknown`.
//!
//! # The overflow argument
//!
//! There is no integer theory in this solver, so the abstraction is emitted as
//! [`W`]-bit vectors — and lengths are exactly the quantity we refuse to bound,
//! so "pick a width big enough for every value" is not available. Instead every
//! emitted constraint is checked against one invariant.
//!
//! Fix a model `M` of the original problem and define the *canonical
//! valuation* `v`: for a string term `t`, `v(t)` is `|M(t)| mod 2^W` as a
//! `W`-bit vector; for an integer term, `M(t) mod 2^W`; for a Boolean term, its
//! truth value in `M`. The abstraction is sound exactly when every constraint
//! it emits is satisfied by `v`, for every `M`. Two disjoint families of
//! constraint qualify:
//!
//! **1. Equalities and linear arithmetic — always.** Reduction mod `2^W` is a
//! ring homomorphism, so `a = b` over the integers implies `a = b` over
//! `Z/2^W`, and `+`, `-`, unary minus and `*` all commute with it. `|x ++ y| =
//! |x| + |y|` therefore survives wrapping unharmed: it is an identity in every
//! quotient ring. This is what proves `2|t| = 1` unsatisfiable — `2|t| = 1` has
//! no solution mod `2^W` either, for any `W >= 1`. Note that the *converse*
//! does not transfer: `a != b` over the integers does not imply `a != b`
//! mod `2^W`, so a disequality is never emitted from an unbounded term.
//!
//! **2. Comparisons — only on terms proved to fit.** [`Iv`] computes, for every
//! term, an interval valid in *every* model, by structural rules plus what
//! [`top_level_facts`] establishes. A term whose interval is finite and inside
//! `+-2^28` is *snug*: `v` maps it to its true value on the nose, with no
//! wrapping, so signed `W`-bit comparisons on it agree with the integers and
//! `lo <= x <= hi` may be asserted outright. A term that is not snug gets no
//! comparison, no range constraint, not even `x >= 0` — its abstract value is
//! genuinely allowed to be any residue. The margin between `2^28` and the
//! signed 32-bit maximum is slack: an interval is only ever declared snug after
//! it has been computed in `i128`, so a sum of snug terms that would leave the
//! window is caught by its own interval before anything is emitted.
//!
//! The two families compose because they constrain the same variables in the
//! same ring: the first is valid unconditionally, the second is valid on the
//! subset where `v` is injective on the reachable values.
//!
//! # What the intervals settle on their own
//!
//! Every interval is a fact about every model, so an *empty* one — a term whose
//! lower bound has passed its upper bound — is already a proof that no model
//! exists. That is the shortest path through this module and the one that
//! settles most of what it settles: the `restoreIpAddresses` family bounds
//! `|s|` from both sides out of its top-level conjuncts and then asks for a
//! `str.substr` window that does not fit. When it happens [`abstraction`]
//! returns the constant `false` and no bit-vector is emitted at all.
//!
//! The facts feeding that come from [`top_level_facts`], which is a little more
//! than "split the assertions on `and`": it also follows Boolean *definitions*,
//! because symbolic execution names its atoms rather than asserting them, and
//! `(assert T_5)` next to `(assert (= T_5 (< -1 n)))` says exactly as much
//! about `n` as asserting the comparison would.
//!
//! # Regular expressions
//!
//! A membership `(str.in_re x R)` bounds `|x|` between the shortest and longest
//! word of `R`, which [`Nfa::min_word_len`] and [`Nfa::max_word_len`] compute
//! even when the language is infinite in the other direction. The automaton is
//! built over *bytes* while SMT-LIB strings range over a larger alphabet, so
//! its language is in general a subset of the real one — but for a
//! complement-free regex the two have the *same set of word lengths*: every
//! character class in it is either a byte range (which no character above
//! `0xff` matches anyway) or `re.allchar`, which the byte automaton renders as
//! `[0x00-0xff]`, so any accepting derivation over the full alphabet maps to
//! one of the same length over bytes by rewriting each high character to
//! `0x00`. Complement breaks that (the complement of a byte range contains
//! high characters the byte automaton cannot represent), so
//! [`complement_free`] refuses `re.comp` and `re.diff`.
//!
//! An interval is a lossy way to hold a language's lengths, though: `(re.++
//! (str.to_re "L") (re.* (str.to_re "ppJpp")))` admits `{1, 6, 11, ...}` and
//! the same thing with a `"<"` on the end admits `{2, 7, 12, ...}`, two
//! disjoint sets that both read as "at least one". [`Nfa::length_set`] computes
//! them exactly — forget the alphabet and the automaton is unary, and its
//! subset construction is a single orbit that must eventually repeat — and
//! [`memberships_conflict`] intersects the sets asserted of one string, along
//! with its interval. That is a second way for the analysis to refute a problem
//! before any bit-vector is emitted.
//!
//! # What is deliberately left unmodelled
//!
//! Each of these gets a fresh unconstrained variable, which is always sound and
//! merely weak:
//!
//! - `str.replace_all`, except when the pattern is at least as long as the
//!   replacement. An unknown number of occurrences each trading `|p|`
//!   characters for `|r|` gives no length relation at all otherwise.
//! - `str.to_int` and `str.from_int`, whose length relation is logarithmic and
//!   so not linear arithmetic. (`str.to_int` still gets its `>= -1`, when the
//!   surrounding constraints make it snug.)
//! - `str.<` and `str.<=`, which order strings without saying anything about
//!   how long they are.
//! - `div` and `mod`, and multiplication of two non-constants beyond what
//!   `bvmul` gives for free.
//! - The negative side of everything about strings: `(not (= x y))`,
//!   `(not (str.contains h n))` and `(not (str.in_re x R))` all constrain no
//!   length, since two different strings can be the same length and a string
//!   outside a language can be any length the complement allows.

use crate::analysis::{comparison_rel, complement_free, int_const, op_name, Iv};
use crate::literal_char_len;
use crate::regex::Nfa;
use rustc_hash::FxHashMap;
use smtrs_core::{Op, Sort, TermId, TermPool};

/// Width of the bit-vectors the abstraction is emitted in. See the module
/// docs: equalities are sound at any width, comparisons only on snug terms.
/// `crate::analysis::SNUG`, the window an interval must fit for a comparison to
/// be emitted at all, is set well below this width's signed maximum.
pub(crate) const W: u32 = 32;

/// Give up on problems too large for a second solve to be worth it.
const MAX_TERMS: usize = 200_000;

/// Number of *characters* in a string literal, which the parser interns as a
/// variable named `str!"..."`. Unlike [`crate::literal_bytes`] this succeeds on
/// literals containing characters above `0xff`: their length is well defined
/// even though the bounded encoding cannot represent them.
fn literal_len(pool: &TermPool, t: TermId) -> Option<usize> {
    match pool.op(t) {
        Op::Var(sym) if pool.symbol(sym).sort == Sort::Str => {
            literal_char_len(&pool.symbol(sym).name)
        }
        _ => None,
    }
}

/// Formulas whose truth value is the same in *every* model, with that value.
///
/// The assertions are true, and that propagates through `not`, through the
/// conjuncts of a true `and`, and through the disjuncts of a false `or`. A
/// formula reachable only through a true `or` or an `ite` need not hold, so it
/// is not listed and [`harvest`] never sees it.
///
/// The last clause is what makes this more than "split on `and`": symbolic
/// execution names its atoms, emitting `(= T_5 (< -1 n))` alongside
/// `(assert T_5)`. A definition `(= a b)` between Booleans that is itself known
/// true transfers a known value from either side to the other, so the atom
/// behind the name becomes a fact like any other. Kaluza's output is almost
/// entirely of this shape.
fn top_level_facts(pool: &TermPool, roots: &[TermId]) -> Vec<(TermId, bool)> {
    let mut known: FxHashMap<TermId, bool> = FxHashMap::default();
    let mut out: Vec<(TermId, bool)> = Vec::new();
    let mut stack: Vec<(TermId, bool)> = roots.iter().map(|&r| (r, true)).collect();
    let mut defs: Vec<TermId> = Vec::new();

    let drain = |stack: &mut Vec<(TermId, bool)>,
                 known: &mut FxHashMap<TermId, bool>,
                 out: &mut Vec<(TermId, bool)>,
                 defs: &mut Vec<TermId>| {
        while let Some((t, pol)) = stack.pop() {
            match pool.op(t) {
                Op::Not => {
                    stack.push((pool.args(t)[0], !pol));
                    continue;
                }
                Op::And if pol => {
                    stack.extend(pool.args(t).iter().map(|&a| (a, true)));
                    continue;
                }
                Op::Or if !pol => {
                    stack.extend(pool.args(t).iter().map(|&a| (a, false)));
                    continue;
                }
                _ => {}
            }
            if known.insert(t, pol).is_some() {
                continue;
            }
            out.push((t, pol));
            if pol
                && matches!(pool.op(t), Op::Eq)
                && pool.args(t).len() == 2
                && pool.args(t).iter().all(|&a| pool.sort(a) == Sort::Bool)
            {
                defs.push(t);
            }
        }
    };

    drain(&mut stack, &mut known, &mut out, &mut defs);
    // A definition only pays off once one of its sides is known, and settling
    // one can settle the next, so sweep until nothing new appears. The rounds
    // are bounded by the number of definitions.
    for _ in 0..defs.len().min(64) + 1 {
        let before = known.len();
        for &d in &defs {
            let args = pool.args(d);
            let (a, b) = (args[0], args[1]);
            match (known.get(&a).copied(), known.get(&b).copied()) {
                (Some(v), None) => stack.push((b, v)),
                (None, Some(v)) => stack.push((a, v)),
                _ => {}
            }
        }
        drain(&mut stack, &mut known, &mut out, &mut defs);
        if known.len() == before {
            break;
        }
    }
    out
}

/// Intervals for every term of the problem: `len` holds a bound on `|t|` for
/// string-sorted `t`, `int` a bound on the value of an integer-sorted `t`.
struct Ivs {
    len: FxHashMap<TermId, Iv>,
    int: FxHashMap<TermId, Iv>,
    /// Set when some term's interval came out empty. Every interval states a
    /// fact true in every model, so an empty one is a proof that there is no
    /// model — the analysis has refuted the problem on its own.
    infeasible: bool,
}

impl Ivs {
    fn l(&self, t: TermId) -> Iv {
        self.len.get(&t).copied().unwrap_or(Iv::nonneg())
    }
    fn i(&self, t: TermId) -> Iv {
        self.int.get(&t).copied().unwrap_or(Iv::TOP)
    }
    fn tighten_l(&mut self, t: TermId, v: Iv) {
        let e = self.len.entry(t).or_insert(Iv::nonneg());
        *e = e.meet(v);
        self.infeasible |= e.empty();
    }
    fn tighten_i(&mut self, t: TermId, v: Iv) {
        let e = self.int.entry(t).or_insert(Iv::TOP);
        *e = e.meet(v);
        self.infeasible |= e.empty();
    }
}

/// Shortest and longest word of every regex we may read lengths off, with
/// `None` for a longest word meaning the language is infinite. Absent means the
/// regex tells us nothing, either because it is complemented or because no
/// automaton was built for it.
///
/// Computed once, and only for the regexes a `str.in_re` actually names: each
/// entry costs an epsilon-free view of the automaton, which is superlinear, and
/// `nfas` holds one automaton per *sub*-expression as well. The interval
/// fixpoint below would otherwise ask for the same view a dozen times a round.
type ReLens = FxHashMap<TermId, (Option<u32>, Option<u32>)>;

fn regex_lengths(pool: &TermPool, nfas: &FxHashMap<TermId, Nfa>, roots: &[TermId]) -> ReLens {
    let mut out = ReLens::default();
    pool.post_order(roots, |pool, t| {
        if op_name(pool, t) != Some("str.in_re") {
            return;
        }
        let r = pool.args(t)[1];
        if out.contains_key(&r) || !complement_free(pool, r) {
            return;
        }
        if let Some(n) = nfas.get(&r) {
            out.insert(r, (n.min_word_len(), n.max_word_len()));
        }
    });
    out
}

/// Structural interval rules, applied bottom-up. Each is a fact about `|t|` or
/// `t` that holds in every model.
fn forward(pool: &TermPool, order: &[TermId], ivs: &mut Ivs) {
    for &t in order {
        match pool.sort(t) {
            Sort::Str => {
                let args = pool.args(t);
                if let Some(n) = literal_len(pool, t) {
                    ivs.tighten_l(t, Iv::exact(n as i128));
                    continue;
                }
                let v = match op_name(pool, t) {
                    Some("str.++") => args
                        .iter()
                        .fold(Iv::exact(0), |acc, &a| acc.add(ivs.l(a)))
                        .meet(Iv::nonneg()),
                    Some("str.at") => Iv::new(Some(0), Some(1)),
                    Some("str.from_code") => Iv::new(Some(0), Some(1)),
                    Some("str.rev" | "str.to_lower" | "str.to_upper") => ivs.l(args[0]),
                    Some("str.substr") => substr_len(ivs, args),
                    Some("str.replace") => {
                        // The result is either the subject untouched, or the
                        // subject with one occurrence of the pattern swapped
                        // for the replacement.
                        let (s, p, r) = (ivs.l(args[0]), ivs.l(args[1]), ivs.l(args[2]));
                        s.join(s.sub(p).add(r)).meet(Iv::nonneg())
                    }
                    Some("str.replace_all") => {
                        // Each of an unknown number of occurrences trades `|p|`
                        // characters for `|r|`, so only a replacement no longer
                        // than a non-empty pattern keeps the length bounded.
                        let (s, p, r) = (ivs.l(args[0]), ivs.l(args[1]), ivs.l(args[2]));
                        let shrinks =
                            matches!((p.lo, r.hi), (Some(pl), Some(rh)) if pl >= 1 && rh <= pl);
                        if shrinks {
                            Iv::new(Some(0), s.hi)
                        } else {
                            Iv::nonneg()
                        }
                    }
                    _ if matches!(pool.op(t), Op::Ite) && args.len() == 3 => {
                        ivs.l(args[1]).join(ivs.l(args[2]))
                    }
                    _ => Iv::nonneg(),
                };
                ivs.tighten_l(t, v);
            }
            Sort::Int => {
                let args = pool.args(t);
                if let Some(k) = int_const(pool, t) {
                    ivs.tighten_i(t, Iv::exact(k));
                    continue;
                }
                let v = match op_name(pool, t) {
                    Some("str.len") => ivs.l(args[0]).meet(Iv::nonneg()),
                    Some("+") => args.iter().fold(Iv::exact(0), |acc, &a| acc.add(ivs.i(a))),
                    Some("-") => args[1..]
                        .iter()
                        .fold(ivs.i(args[0]), |acc, &a| acc.sub(ivs.i(a))),
                    Some("int-neg") => ivs.i(args[0]).neg(),
                    Some("*") => args.iter().fold(Iv::exact(1), |acc, &a| acc.mul(ivs.i(a))),
                    Some("abs") => {
                        let a = ivs.i(args[0]);
                        Iv::new(Some(0), a.join(a.neg()).hi)
                    }
                    // `str.indexof` reports -1 when the pattern is absent, and
                    // otherwise a position with the whole pattern still to
                    // come. The `max(-1)` matters: a pattern that cannot fit
                    // makes `|s| - |p|` negative, but the answer is still -1.
                    Some("str.indexof") => Iv::new(
                        Some(-1),
                        ivs.l(args[0]).sub(ivs.l(args[1])).hi.map(|h| h.max(-1)),
                    ),
                    Some("str.to_int" | "str.to.int") => Iv::new(Some(-1), None),
                    // SMT-LIB's alphabet tops out at 0x2ffff.
                    Some("str.to_code") => Iv::new(Some(-1), Some(0x2_ffff)),
                    _ if matches!(pool.op(t), Op::Ite) && args.len() == 3 => {
                        ivs.i(args[1]).join(ivs.i(args[2]))
                    }
                    _ => Iv::TOP,
                };
                ivs.tighten_i(t, v);
            }
            _ => {}
        }
    }
}

/// `(str.substr s i n)` is `n` characters from position `i`, truncated by the
/// end of `s`, and empty when `i` is outside `s` or `n` is negative.
fn substr_len(ivs: &Ivs, args: &[TermId]) -> Iv {
    let (s, i, n) = (ivs.l(args[0]), ivs.i(args[1]), ivs.i(args[2]));
    let hi = match (n.hi, s.hi, i.lo) {
        (a, Some(sh), Some(il)) => match a {
            Some(nh) => Some(nh.min(sh - il).max(0)),
            None => Some((sh - il).max(0)),
        },
        (Some(nh), _, _) => Some(nh.max(0)),
        _ => None,
    };
    // Nothing is truncated when the start is certainly inside the subject and
    // the count is certainly non-negative; then the length is exactly
    // `min(n, |s| - i)` and its minimum is over the worst corner.
    let lo = match (i.lo, i.hi, s.lo, n.lo) {
        (Some(il), Some(ih), Some(sl), Some(nl)) if il >= 0 && ih <= sl && nl >= 0 => {
            Some(nl.min(sl - ih).max(0))
        }
        _ => Some(0),
    };
    Iv::new(lo, hi)
}

/// Push intervals back down through the operators that determine an operand
/// from the result and its siblings.
fn backward(pool: &TermPool, order: &[TermId], ivs: &mut Ivs) {
    for &t in order.iter().rev() {
        let args: Vec<TermId> = pool.args(t).to_vec();
        match pool.sort(t) {
            Sort::Str => match op_name(pool, t) {
                Some("str.++") => {
                    let whole = ivs.l(t);
                    for (k, &a) in args.iter().enumerate() {
                        let others = args
                            .iter()
                            .enumerate()
                            .filter(|&(j, _)| j != k)
                            .fold(Iv::exact(0), |acc, (_, &o)| acc.add(ivs.l(o)));
                        ivs.tighten_l(a, whole.sub(others));
                    }
                }
                // A *non-empty* result means the start was inside the subject
                // and nothing was truncated past it, so `|s| >= i + |result|`.
                // An empty result says nothing at all — `i` may be anywhere.
                Some("str.substr") => {
                    let out = ivs.l(t);
                    let i = ivs.i(args[1]);
                    if matches!(out.lo, Some(l) if l >= 1) && matches!(i.lo, Some(l) if l >= 0) {
                        ivs.tighten_l(args[0], Iv::new(out.add(i).lo, None));
                    }
                }
                _ => {}
            },
            Sort::Int => match op_name(pool, t) {
                Some("str.len") => {
                    let v = ivs.i(t);
                    ivs.tighten_l(args[0], v);
                    let back = ivs.l(args[0]);
                    ivs.tighten_i(t, back);
                }
                Some("+") => {
                    let whole = ivs.i(t);
                    for (k, &a) in args.iter().enumerate() {
                        let others = args
                            .iter()
                            .enumerate()
                            .filter(|&(j, _)| j != k)
                            .fold(Iv::exact(0), |acc, (_, &o)| acc.add(ivs.i(o)));
                        ivs.tighten_i(a, whole.sub(others));
                    }
                }
                // `t = a - b - c` gives `a = t + b + c` and `b = a - c - t`.
                Some("-") if args.len() >= 2 => {
                    let whole = ivs.i(t);
                    let rest = args[1..]
                        .iter()
                        .fold(Iv::exact(0), |acc, &o| acc.add(ivs.i(o)));
                    ivs.tighten_i(args[0], whole.add(rest));
                    for (k, &a) in args.iter().enumerate().skip(1) {
                        let others = args[1..]
                            .iter()
                            .enumerate()
                            .filter(|&(j, _)| j + 1 != k)
                            .fold(Iv::exact(0), |acc, (_, &o)| acc.add(ivs.i(o)));
                        ivs.tighten_i(a, ivs.i(args[0]).sub(others).sub(whole));
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }
}

/// Tighten intervals with what [`top_level_facts`] established. Only formulas
/// that hold in every model are used, so a constraint under a disjunction
/// contributes nothing.
fn harvest(pool: &TermPool, re_lens: &ReLens, facts: &[(TermId, bool)], ivs: &mut Ivs) {
    for &(c, positive) in facts {
        let args: Vec<TermId> = pool.args(c).to_vec();
        // A negated comparison is a comparison: `not (<= a b)` is `a > b`. The
        // chainable and negated-chain subtleties live in `comparison_rel`.
        if let Some((swap, strict)) = comparison_rel(pool, c, positive) {
            for w in args.windows(2) {
                let (lhs, rhs) = if swap { (w[1], w[0]) } else { (w[0], w[1]) };
                let d = i128::from(strict);
                let (a, b) = (ivs.i(lhs), ivs.i(rhs));
                ivs.tighten_i(lhs, Iv::new(None, b.hi.map(|h| h - d)));
                ivs.tighten_i(rhs, Iv::new(a.lo.map(|l| l + d), None));
            }
            continue;
        }
        if !positive {
            continue;
        }
        if matches!(pool.op(c), Op::Eq) && args.len() >= 2 {
            if args.iter().all(|&a| pool.sort(a) == Sort::Int) {
                let m = args.iter().fold(Iv::TOP, |acc, &a| acc.meet(ivs.i(a)));
                for &a in &args {
                    ivs.tighten_i(a, m);
                }
            } else if args.iter().all(|&a| pool.sort(a) == Sort::Str) {
                let m = args.iter().fold(Iv::TOP, |acc, &a| acc.meet(ivs.l(a)));
                for &a in &args {
                    ivs.tighten_l(a, m);
                }
            }
            continue;
        }
        match op_name(pool, c) {
            Some("str.in_re") => {
                // An empty language makes the conjunct false, so every
                // interval is then vacuously valid and none is tightened.
                if let Some(&(Some(l), hi)) = re_lens.get(&args[1]) {
                    ivs.tighten_l(args[0], Iv::new(Some(l as i128), hi.map(|h| h as i128)));
                }
            }
            Some("str.contains") => {
                let (h, n) = (ivs.l(args[0]), ivs.l(args[1]));
                ivs.tighten_l(args[1], Iv::new(None, h.hi));
                ivs.tighten_l(args[0], Iv::new(n.lo, None));
            }
            Some("str.prefixof" | "str.suffixof") => {
                let (p, s) = (ivs.l(args[0]), ivs.l(args[1]));
                ivs.tighten_l(args[0], Iv::new(None, s.hi));
                ivs.tighten_l(args[1], Iv::new(p.lo, None));
            }
            _ => {}
        }
    }
}

/// Emitter state: the bit-vector image of every term, plus the side conditions
/// that tie the images together.
struct Emit<'a> {
    pool: &'a mut TermPool,
    re_lens: &'a ReLens,
    ivs: Ivs,
    len: FxHashMap<TermId, TermId>,
    int: FxHashMap<TermId, TermId>,
    bl: FxHashMap<TermId, TermId>,
    side: Vec<TermId>,
    /// Did anything beyond fresh unconstrained variables get emitted? If not
    /// the abstraction is just the Boolean skeleton and is not worth a solve.
    relations: usize,
    fresh: usize,
}

impl Emit<'_> {
    fn mk(&mut self, op: Op, args: &[TermId]) -> TermId {
        self.pool
            .mk(op, args)
            .expect("length abstraction builds well-sorted BV terms")
    }

    fn num(&mut self, v: i64) -> TermId {
        self.pool.bv_u64(W, v as u64)
    }

    fn fresh_bv(&mut self) -> TermId {
        self.fresh += 1;
        let s = self
            .pool
            .fresh_symbol(format!("len!{}", self.fresh), Sort::BitVec(W));
        self.pool.var(s)
    }

    fn fresh_bool(&mut self) -> TermId {
        self.fresh += 1;
        let s = self
            .pool
            .fresh_symbol(format!("lenp!{}", self.fresh), Sort::Bool);
        self.pool.var(s)
    }

    /// Assert `c` alongside the abstraction, and record that the abstraction
    /// carries real information.
    fn assert(&mut self, c: TermId) {
        if c != self.pool.true_term {
            self.relations += 1;
            self.side.push(c);
        }
    }

    fn eq(&mut self, a: TermId, b: TermId) -> TermId {
        self.mk(Op::Eq, &[a, b])
    }

    /// The image of a term, clamped to its interval when that is snug. The
    /// clamp is sound precisely because a snug term does not wrap: its image
    /// *is* its value.
    fn range(&mut self, iv: Iv, x: TermId) {
        if let Some((lo, hi)) = iv.snug() {
            let l = self.num(lo);
            let h = self.num(hi);
            let c1 = self.mk(Op::BvSge, &[x, l]);
            let c2 = self.mk(Op::BvSle, &[x, h]);
            let c = self.mk(Op::And, &[c1, c2]);
            self.assert(c);
        }
    }
}

/// Which of the three images a term has, by sort.
fn emit_all(e: &mut Emit, pool_order: &[TermId]) {
    for &t in pool_order {
        match e.pool.sort(t) {
            Sort::Str => {
                let x = emit_len(e, t);
                e.len.insert(t, x);
                let iv = e.ivs.l(t);
                e.range(iv, x);
            }
            Sort::Int => {
                let x = emit_int(e, t);
                e.int.insert(t, x);
                let iv = e.ivs.i(t);
                e.range(iv, x);
            }
            Sort::Bool => {
                let x = emit_bool(e, t);
                e.bl.insert(t, x);
            }
            _ => {}
        }
    }
}

fn emit_len(e: &mut Emit, t: TermId) -> TermId {
    if let Some(n) = literal_len(e.pool, t) {
        e.relations += 1;
        return e.num(n as i64);
    }
    let args: Vec<TermId> = e.pool.args(t).to_vec();
    let get = |e: &Emit, a: TermId| e.len.get(&a).copied();
    match op_name(e.pool, t) {
        Some("str.++") => {
            let parts: Option<Vec<TermId>> = args.iter().map(|&a| get(e, a)).collect();
            match parts {
                Some(p) if !p.is_empty() => {
                    e.relations += 1;
                    if p.len() == 1 {
                        p[0]
                    } else {
                        e.mk(Op::BvAdd, &p)
                    }
                }
                _ => e.fresh_bv(),
            }
        }
        Some("str.rev" | "str.to_lower" | "str.to_upper") => match get(e, args[0]) {
            Some(a) => {
                e.relations += 1;
                a
            }
            None => e.fresh_bv(),
        },
        Some("str.at") => match (
            e.ivs.i(args[1]).snug(),
            e.ivs.l(args[0]).snug(),
            e.int.get(&args[1]).copied(),
            get(e, args[0]),
        ) {
            (Some(_), Some(_), Some(i), Some(l)) => {
                let zero = e.num(0);
                let one = e.num(1);
                let ge = e.mk(Op::BvSge, &[i, zero]);
                let lt = e.mk(Op::BvSlt, &[i, l]);
                let c = e.mk(Op::And, &[ge, lt]);
                e.relations += 1;
                e.mk(Op::Ite, &[c, one, zero])
            }
            _ => e.fresh_bv(),
        },
        Some("str.substr") => emit_substr_len(e, &args),
        Some("str.replace") => {
            match (get(e, args[0]), get(e, args[1]), get(e, args[2])) {
                (Some(s), Some(p), Some(r)) => {
                    let v = e.fresh_bv();
                    // Either no occurrence (result is the subject) or one
                    // occurrence traded for the replacement. Both disjuncts are
                    // equalities, so this is sound at any width.
                    let d = e.mk(Op::BvSub, &[s, p]);
                    let d = e.mk(Op::BvAdd, &[d, r]);
                    let a = e.eq(v, s);
                    let b = e.eq(v, d);
                    let c = e.mk(Op::Or, &[a, b]);
                    e.assert(c);
                    v
                }
                _ => e.fresh_bv(),
            }
        }
        Some("str.replace_all") => e.fresh_bv(),
        _ if matches!(e.pool.op(t), Op::Ite) && args.len() == 3 => {
            match (
                e.bl.get(&args[0]).copied(),
                get(e, args[1]),
                get(e, args[2]),
            ) {
                (Some(c), Some(a), Some(b)) => {
                    e.relations += 1;
                    e.mk(Op::Ite, &[c, a, b])
                }
                _ => e.fresh_bv(),
            }
        }
        _ => e.fresh_bv(),
    }
}

/// `(str.substr s i n)`: `min(n, |s| - i)` characters, or none at all when the
/// start is outside the subject or the count is negative. Emitted only when
/// every operand is snug, since it is built entirely from comparisons.
fn emit_substr_len(e: &mut Emit, args: &[TermId]) -> TermId {
    let snug = e.ivs.l(args[0]).snug().is_some()
        && e.ivs.i(args[1]).snug().is_some()
        && e.ivs.i(args[2]).snug().is_some();
    let (Some(l), Some(i), Some(n)) = (
        e.len.get(&args[0]).copied(),
        e.int.get(&args[1]).copied(),
        e.int.get(&args[2]).copied(),
    ) else {
        return e.fresh_bv();
    };
    if !snug {
        return e.fresh_bv();
    }
    let zero = e.num(0);
    let neg_i = e.mk(Op::BvSlt, &[i, zero]);
    let past = e.mk(Op::BvSgt, &[i, l]);
    let neg_n = e.mk(Op::BvSlt, &[n, zero]);
    let empty = e.mk(Op::Or, &[neg_i, past, neg_n]);
    let rest = e.mk(Op::BvSub, &[l, i]);
    let short = e.mk(Op::BvSlt, &[n, rest]);
    let taken = e.mk(Op::Ite, &[short, n, rest]);
    e.relations += 1;
    e.mk(Op::Ite, &[empty, zero, taken])
}

fn emit_int(e: &mut Emit, t: TermId) -> TermId {
    if let Some(k) = int_const(e.pool, t) {
        e.relations += 1;
        return e.num(k as i64);
    }
    let args: Vec<TermId> = e.pool.args(t).to_vec();
    let ints: Option<Vec<TermId>> = args.iter().map(|a| e.int.get(a).copied()).collect();
    match op_name(e.pool, t) {
        Some("str.len") => match e.len.get(&args[0]).copied() {
            Some(l) => {
                e.relations += 1;
                l
            }
            None => e.fresh_bv(),
        },
        // `+`, `-`, unary minus and `*` all commute with reduction mod 2^W, so
        // they are emitted unconditionally.
        Some("+") => match ints {
            Some(v) if v.len() > 1 => {
                e.relations += 1;
                e.mk(Op::BvAdd, &v)
            }
            Some(v) if v.len() == 1 => v[0],
            _ => e.fresh_bv(),
        },
        Some("-") => match ints {
            Some(v) if v.len() >= 2 => {
                e.relations += 1;
                v[1..]
                    .iter()
                    .fold(v[0], |acc, &a| e.mk(Op::BvSub, &[acc, a]))
            }
            Some(v) if v.len() == 1 => {
                e.relations += 1;
                e.mk(Op::BvNeg, &[v[0]])
            }
            _ => e.fresh_bv(),
        },
        Some("int-neg") => match ints {
            Some(v) => {
                e.relations += 1;
                e.mk(Op::BvNeg, &[v[0]])
            }
            _ => e.fresh_bv(),
        },
        Some("*") => match ints {
            Some(v) if v.len() > 1 => {
                e.relations += 1;
                e.mk(Op::BvMul, &v)
            }
            Some(v) if v.len() == 1 => v[0],
            _ => e.fresh_bv(),
        },
        Some("str.indexof") => emit_indexof(e, &args),
        _ if matches!(e.pool.op(t), Op::Ite) && args.len() == 3 => {
            match (e.bl.get(&args[0]).copied(), ints) {
                (Some(c), Some(v)) if v.len() == 3 => {
                    e.relations += 1;
                    e.mk(Op::Ite, &[c, v[1], v[2]])
                }
                _ => e.fresh_bv(),
            }
        }
        _ => e.fresh_bv(),
    }
}

/// `(str.indexof s p i)` is -1, or a position at or after `i` with the whole
/// of `p` still fitting inside `s`. All three facts are comparisons, so they
/// need every operand snug.
fn emit_indexof(e: &mut Emit, args: &[TermId]) -> TermId {
    let v = e.fresh_bv();
    let snug = e.ivs.l(args[0]).snug().is_some()
        && e.ivs.l(args[1]).snug().is_some()
        && e.ivs.i(args[2]).snug().is_some();
    let (Some(s), Some(p), Some(i)) = (
        e.len.get(&args[0]).copied(),
        e.len.get(&args[1]).copied(),
        e.int.get(&args[2]).copied(),
    ) else {
        return v;
    };
    if !snug {
        return v;
    }
    let zero = e.num(0);
    let minus1 = e.num(-1);
    let absent = e.eq(v, minus1);
    let after = e.mk(Op::BvSge, &[v, i]);
    let nonneg = e.mk(Op::BvSge, &[v, zero]);
    let end = e.mk(Op::BvAdd, &[v, p]);
    let fits = e.mk(Op::BvSle, &[end, s]);
    let found = e.mk(Op::And, &[after, nonneg, fits]);
    let c = e.mk(Op::Or, &[absent, found]);
    e.assert(c);
    v
}

/// Boolean structure is preserved exactly; a theory atom becomes a fresh
/// Boolean plus whatever length facts its polarity licenses.
fn emit_bool(e: &mut Emit, t: TermId) -> TermId {
    let args: Vec<TermId> = e.pool.args(t).to_vec();
    let all_bool = args.iter().all(|&a| e.pool.sort(a) == Sort::Bool);
    let op = e.pool.op(t);
    match op {
        Op::True | Op::False | Op::Var(_) => return t,
        Op::Not | Op::Implies | Op::And | Op::Or | Op::Xor => {
            let mapped: Vec<TermId> = args.iter().map(|a| e.bl[a]).collect();
            return e.mk(op, &mapped);
        }
        Op::Eq | Op::Distinct | Op::Ite if all_bool => {
            let mapped: Vec<TermId> = args.iter().map(|a| e.bl[a]).collect();
            return e.mk(op, &mapped);
        }
        _ => {}
    }
    // Two atoms need no theory at all, and folding them is what lets the
    // skeleton see through the `(= x x)` that merged branches emit.
    if matches!(op, Op::Eq) && args.windows(2).all(|w| w[0] == w[1]) {
        return e.pool.true_term;
    }
    if matches!(op, Op::Distinct) {
        let mut s = args.clone();
        let n = s.len();
        s.sort_unstable();
        s.dedup();
        if s.len() < n {
            return e.pool.false_term;
        }
    }
    let p = e.fresh_bool();
    bridge(e, t, &args, p);
    p
}

/// Assert what `p`, the abstraction of atom `t`, licenses about lengths.
fn bridge(e: &mut Emit, t: TermId, args: &[TermId], p: TermId) {
    let str_args = !args.is_empty() && args.iter().all(|&a| e.pool.sort(a) == Sort::Str);
    let int_args = !args.is_empty() && args.iter().all(|&a| e.pool.sort(a) == Sort::Int);
    if matches!(e.pool.op(t), Op::Eq) && args.len() >= 2 {
        if str_args {
            // Equal strings have equal lengths. The converse is false, so this
            // is an implication and never an equivalence.
            let Some(ls) = args
                .iter()
                .map(|a| e.len.get(a).copied())
                .collect::<Option<Vec<_>>>()
            else {
                return;
            };
            let eqs: Vec<TermId> = ls.windows(2).map(|w| e.eq(w[0], w[1])).collect();
            let body = if eqs.len() == 1 {
                eqs[0]
            } else {
                e.mk(Op::And, &eqs)
            };
            let c = e.mk(Op::Implies, &[p, body]);
            e.assert(c);
        } else if int_args {
            let Some(vs) = args
                .iter()
                .map(|a| e.int.get(a).copied())
                .collect::<Option<Vec<_>>>()
            else {
                return;
            };
            let eqs: Vec<TermId> = vs.windows(2).map(|w| e.eq(w[0], w[1])).collect();
            let body = if eqs.len() == 1 {
                eqs[0]
            } else {
                e.mk(Op::And, &eqs)
            };
            // Equality transfers through the quotient unconditionally;
            // disequality only when every operand is snug, and so exact.
            let all_snug = args.iter().all(|&a| e.ivs.i(a).snug().is_some());
            let c = if all_snug {
                e.eq(p, body)
            } else {
                e.mk(Op::Implies, &[p, body])
            };
            e.assert(c);
        }
        return;
    }
    if matches!(e.pool.op(t), Op::Distinct) && int_args && args.len() == 2 {
        if args.iter().all(|&a| e.ivs.i(a).snug().is_some()) {
            if let (Some(a), Some(b)) = (e.int.get(&args[0]).copied(), e.int.get(&args[1]).copied())
            {
                let eq = e.eq(a, b);
                let ne = e.mk(Op::Not, &[eq]);
                let c = e.eq(p, ne);
                e.assert(c);
            }
        }
        return;
    }
    let name = op_name(e.pool, t).map(str::to_string);
    match name.as_deref() {
        Some(rel @ ("<" | "<=" | ">" | ">=")) if args.len() >= 2 => {
            if !args.iter().all(|&a| {
                e.pool.sort(a) == Sort::Int && e.ivs.i(a).snug().is_some() && e.int.contains_key(&a)
            }) {
                return;
            }
            let op = match rel {
                "<" => Op::BvSlt,
                "<=" => Op::BvSle,
                ">" => Op::BvSgt,
                _ => Op::BvSge,
            };
            let vs: Vec<TermId> = args.iter().map(|a| e.int[a]).collect();
            let parts: Vec<TermId> = vs.windows(2).map(|w| e.mk(op, &[w[0], w[1]])).collect();
            let body = if parts.len() == 1 {
                parts[0]
            } else {
                e.mk(Op::And, &parts)
            };
            let c = e.eq(p, body);
            e.assert(c);
        }
        // `contains`, `prefixof` and `suffixof` all say one string sits inside
        // another, so the inner one is no longer. Only the positive direction
        // transfers, and only on snug operands.
        Some("str.contains") => shorter_than(e, p, args[1], args[0]),
        Some("str.prefixof" | "str.suffixof") => shorter_than(e, p, args[0], args[1]),
        Some("str.in_re") => {
            let Some(&(lo, hi)) = e.re_lens.get(&args[1]) else {
                return;
            };
            let Some(x) = e.len.get(&args[0]).copied() else {
                return;
            };
            let Some(l) = lo else {
                // Empty language: the membership is false in every model.
                let c = e.mk(Op::Not, &[p]);
                e.assert(c);
                return;
            };
            if e.ivs.l(args[0]).snug().is_none() {
                return;
            }
            let mut parts = Vec::new();
            if l > 0 {
                let k = e.num(l as i64);
                parts.push(e.mk(Op::BvSge, &[x, k]));
            }
            if let Some(h) = hi {
                let k = e.num(h as i64);
                parts.push(e.mk(Op::BvSle, &[x, k]));
            }
            if parts.is_empty() {
                return;
            }
            let body = if parts.len() == 1 {
                parts[0]
            } else {
                e.mk(Op::And, &parts)
            };
            let c = e.mk(Op::Implies, &[p, body]);
            e.assert(c);
        }
        _ => {}
    }
}

/// `p -> |inner| <= |outer|`, emitted only when both lengths are snug.
fn shorter_than(e: &mut Emit, p: TermId, inner: TermId, outer: TermId) {
    if e.ivs.l(inner).snug().is_none() || e.ivs.l(outer).snug().is_none() {
        return;
    }
    let (Some(a), Some(b)) = (e.len.get(&inner).copied(), e.len.get(&outer).copied()) else {
        return;
    };
    let le = e.mk(Op::BvSle, &[a, b]);
    let c = e.mk(Op::Implies, &[p, le]);
    e.assert(c);
}

/// Work each membership's length set may cost, and the largest combined period
/// a group of them may have between them. Both are generous for the shapes that
/// motivate this — a concatenation of starred literals is a handful of states
/// and has a period equal to a literal's length — and the generated
/// several-hundred-state regexes fall off the first one immediately.
const ORBIT_BUDGET: usize = 200_000;
const PERIOD_CAP: usize = 8192;

/// Longest string [`memberships_conflict`] will reason about. Interval
/// endpoints are `i128` and a refuted system walks them far past anything a
/// scan could cover, so they are checked before being narrowed to `usize`.
const MAX_SCAN_LENGTH: i128 = 1 << 30;

/// Do the memberships asserted of one string demand lengths that no single
/// number satisfies?
///
/// The interval analysis only sees each language's shortest and longest word,
/// which cannot tell `{1, 6, 11, ...}` from `{2, 7, 12, ...}` — both are "at
/// least one". [`Nfa::length_set`] gives the sets exactly, and two ultimately
/// periodic sets are compared by scanning one combined period past the later of
/// their thresholds: beyond that, every length repeats one already looked at.
///
/// Only positive memberships count, and only over complement-free regexes; see
/// the module docs for why the byte automaton's word lengths are the real
/// language's.
fn memberships_conflict(
    pool: &TermPool,
    nfas: &FxHashMap<TermId, Nfa>,
    facts: &[(TermId, bool)],
    ivs: &Ivs,
) -> bool {
    let mut per_string: FxHashMap<TermId, Vec<&Nfa>> = FxHashMap::default();
    for &(c, positive) in facts {
        if !positive || op_name(pool, c) != Some("str.in_re") {
            continue;
        }
        let args = pool.args(c);
        if !complement_free(pool, args[1]) {
            continue;
        }
        if let Some(n) = nfas.get(&args[1]) {
            per_string.entry(args[0]).or_default().push(n);
        }
    }
    per_string.into_iter().any(|(s, ns)| {
        let sets: Vec<_> = match ns.iter().map(|n| n.length_set(ORBIT_BUDGET)).collect() {
            Some(v) => v,
            None => return false,
        };
        let iv = ivs.l(s);
        // The interval is a constraint in its own right: a language of lengths
        // `{1, 6, 11, ...}` and a subject known to be 2 or 3 characters long
        // conflict just as surely as two languages do. Endpoints are `i128` and
        // can be enormous — narrowing one to `usize` without checking would
        // turn a bound this scan cannot reach into a different, false one.
        let lo_i = iv.lo.unwrap_or(0).max(0);
        if lo_i > MAX_SCAN_LENGTH {
            return false;
        }
        let lo = lo_i as usize;
        let threshold = sets
            .iter()
            .map(crate::regex::LengthSet::threshold)
            .max()
            .unwrap_or(0)
            .max(lo);
        let period = sets
            .iter()
            .map(crate::regex::LengthSet::period)
            .try_fold(1usize, |acc, p| {
                let l = lcm(acc, p);
                (l <= PERIOD_CAP).then_some(l)
            });
        let Some(period) = period else {
            return false;
        };
        // An upper bound beyond the scan is no upper bound as far as this is
        // concerned; dropping it only weakens the check.
        let last = match iv.hi {
            Some(h) if h < lo_i => return false,
            Some(h) if h <= MAX_SCAN_LENGTH => (h as usize).min(threshold + period - 1),
            _ => threshold + period - 1,
        };
        !(lo..=last).any(|k| sets.iter().all(|set| set.contains(k)))
    })
}

fn lcm(a: usize, b: usize) -> usize {
    fn gcd(a: usize, b: usize) -> usize {
        if b == 0 {
            a
        } else {
            gcd(b, a % b)
        }
    }
    if a == 0 || b == 0 {
        0
    } else {
        a / gcd(a, b) * b
    }
}

/// Build the length abstraction of `roots`. The returned terms are Bool-sorted
/// and mention only Bool and `BitVec` symbols, so the ordinary pipeline solves
/// them. `None` when the abstraction carries no length information at all and a
/// second solve would only re-derive the Boolean skeleton.
pub fn abstraction(pool: &mut TermPool, roots: &[TermId]) -> Option<Vec<TermId>> {
    if roots.is_empty() {
        return None;
    }
    // Size is measured over the *original* problem, not the pool: by the time
    // this runs the pool also holds the bounded encoding, which is orders of
    // magnitude larger and says nothing about how big this work is. A hundred
    // word equations over long literals blow the pool past two million terms
    // while the length system stays a few hundred.
    let mut order: Vec<TermId> = Vec::new();
    pool.post_order(roots, |_, t| order.push(t));
    if order.len() > MAX_TERMS {
        return None;
    }
    let nfas = crate::regex::build_all(pool, roots).unwrap_or_default();
    let re_lens = regex_lengths(pool, &nfas, roots);
    let facts = top_level_facts(pool, roots);

    let mut ivs = Ivs {
        len: FxHashMap::default(),
        int: FxHashMap::default(),
        infeasible: false,
    };
    // Alternate structural propagation with what the top-level conjuncts say
    // until nothing moves. Intervals only ever shrink, so this terminates; the
    // round cap keeps the cost predictable on large inputs.
    for _ in 0..6 {
        let before_len = ivs.len.clone();
        let before_int = ivs.int.clone();
        forward(pool, &order, &mut ivs);
        harvest(pool, &re_lens, &facts, &mut ivs);
        backward(pool, &order, &mut ivs);
        if ivs.infeasible {
            // Some term was shown to have no possible value, so the problem
            // has no model. Nothing left to encode: hand back the refutation.
            return Some(vec![pool.false_term]);
        }
        if ivs.len == before_len && ivs.int == before_int {
            break;
        }
    }
    if memberships_conflict(pool, &nfas, &facts, &ivs) {
        return Some(vec![pool.false_term]);
    }

    let mut e = Emit {
        pool,
        re_lens: &re_lens,
        ivs,
        len: FxHashMap::default(),
        int: FxHashMap::default(),
        bl: FxHashMap::default(),
        side: Vec::new(),
        relations: 0,
        fresh: 0,
    };
    emit_all(&mut e, &order);
    if e.relations == 0 {
        return None;
    }
    let mut out: Vec<TermId> = roots.iter().filter_map(|r| e.bl.get(r).copied()).collect();
    if out.len() != roots.len() {
        return None;
    }
    out.extend(e.side.iter().copied());
    Some(out)
}

#[cfg(test)]
mod tests;
