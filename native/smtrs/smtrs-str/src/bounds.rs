//! Static analysis deciding when the bounded encoding is *complete*, i.e. when
//! `unsat` under it is real unsatisfiability rather than "no model within the
//! bound".
//!
//! # The soundness argument
//!
//! Lowering restricts every string to (a) at most `max_len` characters and
//! (b) an 8-bit character alphabet, and every integer to 16-bit two's
//! complement. Each restriction can only *remove* models, so `sat` is always
//! real; the analysis here establishes that, for a particular problem, no model
//! is removed — at which point `unsat` is real too.
//!
//! Let `M` be a model of the original problem over the SMT-LIB semantics
//! (unbounded strings, full alphabet, unbounded integers). We show `M` can be
//! turned into a model of the encoding when all three conditions below hold.
//!
//! **1. Lengths.** [`lengths`] derives, for every string-sorted subterm `t`, an
//! upper bound `B(t)` valid in *every* model: literals are exact, `str.++` sums
//! its operands, `str.substr`/`str.at` cannot exceed their source, `ite` takes
//! the larger branch, and free variables are bounded only by constraints
//! harvested from **top-level conjuncts** (a constraint under a disjunction or
//! an `ite` branch bounds nothing, so none is harvested). Bounds also flow
//! *downwards* — `|a| <= |a ++ b|` — and *sideways*, along relations that a
//! top-level conjunct forces to hold between two lengths: `(= a b)` equates
//! them, and `(str.contains x y)`, `(str.prefixof y x)`, `(str.suffixof y x)`
//! each give `|y| <= |x|`. A `(str.in_re x R)` gives the longest word of `R`,
//! but **only for a complement-free `R`**: the automaton is built over bytes,
//! and complement is the one construct under which the byte language's word
//! lengths are not the real language's — `(re.comp (re.* (re.range "\u{0}"
//! "\u{ff}")))` is empty over bytes and infinite over the real alphabet.
//! All of these are valid in every model.
//! If `B(t) <= max_len` for all `t` then `|M(t)| <= max_len`, so every slot
//! array is wide enough and every side condition the lowering emits
//! (`len <= max_len` on a fresh variable, `|x| + |y| <= max_len` on a
//! concatenation) is satisfied by `M`.
//!
//! One bound is not of that form and carries its own argument:
//! [`read_depths`] bounds a variable nothing ever looks past a fixed position
//! of, by *truncating* `M` rather than by observing a constraint. The
//! transformed model is again a model of the original problem, so the rest of
//! the analysis — every rule of which is valid in every model — applies to it
//! unchanged.
//!
//! A *negated* top-level conjunct is still a conjunct — `(not p)` holds in
//! every model exactly as `p` would — so the one shape whose negation is again
//! a usable constraint is harvested too: a two-operand arithmetic comparison,
//! whose complement is again a two-operand comparison. Nothing else is pushed
//! through a negation: `(not (and ..))` and the negation of a *chained*
//! comparison are disjunctions, and `(not (= x "lit"))` or
//! `(not (str.in_re x R))` bound nothing at all.
//!
//! **2. Alphabet.** Characters are 8 bits, so a model using a character above
//! `0xff` has no encoding. Let `S` be the set of bytes that some atom of the
//! problem can distinguish: every byte of every string literal, and every byte
//! of every `re.range`. (`re.allchar`/`re.all` are deliberately excluded: they
//! denote the whole alphabet, so they cannot tell a byte from a high
//! character.) Let `Z = [0,255] \ S`. Every atom of the problem tests a
//! character only by (i) equality with another character, (ii) equality with a
//! literal byte, or (iii) membership in a range — and a byte in `Z` gives the
//! same answer to (ii) and (iii) as any character above `0xff` does. So if
//! `|Z|` is at least the number of characters `M` assigns to free string
//! variables — at most the sum of their length bounds, and every other string
//! term is a function of those — there is an *injection* from the high
//! characters `M` uses into `Z`. Replacing them preserves (i) as well, hence
//! preserves regular-language membership (acceptance depends only on which
//! ranges each character falls in, so it is preserved through union,
//! concatenation, star, complement and intersection alike) and every string
//! (dis)equality, `contains`, `prefixof`, `suffixof`, `indexof`, `substr` and
//! `len`. The result is a model over bytes.
//!
//! **3. Integers.** [`ints`] derives an interval for every integer-sorted term
//! from the string bounds (`str.len` is in `[0, B(s)]`, `str.indexof` in
//! `[-1, B(s)]`) and constant folding. If every interval fits in `i16` then the
//! 16-bit arithmetic the lowering emits is exact and its signed comparisons
//! agree with the integers. A free `Int` variable has no interval, and an
//! integer literal that does not fit is rejected — the encoding would silently
//! truncate it.
//!
//! Anything the analysis cannot account for makes it refuse, which costs
//! nothing but a `unknown` we would have reported anyway.

use crate::analysis::{comparison_rel, complement_free, complement_op, int_const, op_name, Iv};
use crate::literal_bytes;
use crate::regex::Nfa;
use rustc_hash::{FxHashMap, FxHashSet};
use smtrs_core::{Op, Sort, TermId, TermPool};

/// Result of the analysis; see the module docs.
#[derive(Debug, Clone)]
pub struct Analysis {
    /// Largest length any string term can take, over all models. `None` when
    /// some string term could not be bounded.
    pub needed_len: Option<u32>,
    /// Why completeness could not be established, for `SMTRS_DEBUG`.
    pub blocker: Option<String>,
}

impl Analysis {
    /// Is the bounded encoding at `max_len` complete for this problem?
    pub fn complete_at(&self, max_len: u32) -> bool {
        self.blocker.is_none() && self.needed_len.is_some_and(|n| n <= max_len)
    }

    fn blocked(reason: impl Into<String>) -> Analysis {
        Analysis {
            needed_len: None,
            blocker: Some(reason.into()),
        }
    }
}

/// Is this term a string literal (which the parser interns as a variable named
/// `str!"..."`)? Returns its bytes.
///
/// Deliberately *not* [`crate::length`]'s `literal_len`, which counts
/// characters and so succeeds on a literal holding a character above `0xff`.
/// A literal this cannot render as bytes is one the bounded encoding cannot
/// represent, and leaving it unbounded is what blocks completeness on it.
fn literal_of(pool: &TermPool, t: TermId) -> Option<Vec<u8>> {
    match pool.op(t) {
        Op::Var(sym) if pool.symbol(sym).sort == Sort::Str => literal_bytes(&pool.symbol(sym).name),
        _ => None,
    }
}

/// The assertions, split on top-level `and`. A constraint reachable only
/// through a negation, a disjunction or an `ite` is *not* included: it need not
/// hold in a model, so it bounds nothing.
fn top_level_conjuncts(pool: &TermPool, roots: &[TermId]) -> Vec<TermId> {
    let mut out = Vec::new();
    let mut seen: FxHashSet<TermId> = FxHashSet::default();
    let mut stack: Vec<TermId> = roots.to_vec();
    while let Some(t) = stack.pop() {
        if !seen.insert(t) {
            continue;
        }
        if matches!(pool.op(t), Op::And) {
            stack.extend(pool.args(t).iter().copied());
        } else {
            out.push(t);
        }
    }
    out
}

/// Upper bounds on the length of every string-sorted subterm. Absent from the
/// map means "unbounded".
pub fn lengths(
    pool: &TermPool,
    roots: &[TermId],
    nfas: &FxHashMap<TermId, Nfa>,
) -> FxHashMap<TermId, u32> {
    let mut order: Vec<TermId> = Vec::new();
    pool.post_order(roots, |_, t| order.push(t));
    let strs: Vec<TermId> = order
        .iter()
        .copied()
        .filter(|&t| pool.sort(t) == Sort::Str)
        .collect();

    let mut bound: FxHashMap<TermId, u32> = FxHashMap::default();
    // Literals are exact.
    for &t in &strs {
        if let Some(bytes) = literal_of(pool, t) {
            bound.insert(t, bytes.len() as u32);
        }
    }

    // Harvest from the top-level conjuncts.
    let tighten = |bound: &mut FxHashMap<TermId, u32>, t: TermId, k: u32| {
        if pool.sort(t) != Sort::Str {
            return;
        }
        let e = bound.entry(t).or_insert(k);
        *e = (*e).min(k);
    };

    // Variables nothing ever looks past a fixed position of.
    for (v, d) in read_depths(pool, roots) {
        tighten(&mut bound, v, d);
    }
    // Top-level string equalities, kept for the fixpoint below: `(= a b)` holds
    // in every model, so `|M(a)| = |M(b)|` and any bound valid for one operand
    // is valid for all of them. Harvesting once is not enough — a bound reaching
    // one side later (through an operator rule) has to cross over too.
    let mut str_eqs: Vec<Vec<TermId>> = Vec::new();
    // `(shorter, longer)` pairs a top-level conjunct forces to satisfy
    // `|shorter| <= |longer|` in every model, so a bound on the second is a
    // bound on the first. Kept for the fixpoint below for the same reason
    // `str_eqs` is: the bound on `longer` may only arrive later.
    let mut le_pairs: Vec<(TermId, TermId)> = Vec::new();
    for c in top_level_conjuncts(pool, roots) {
        // A top-level `(not p)` holds in every model just as `p` would, so its
        // complement is harvestable — but only for the shapes whose complement
        // is itself a usable constraint. That is exactly a two-operand
        // arithmetic comparison; see the module docs.
        let (c, negated) = match pool.op(c) {
            Op::Not if pool.args(c).len() == 1 => (pool.args(c)[0], true),
            _ => (c, false),
        };
        let args = pool.args(c);
        if !negated
            && matches!(pool.op(c), Op::Eq)
            && args.iter().all(|&a| pool.sort(a) == Sort::Str)
        {
            str_eqs.push(args.to_vec());
        }
        // `(<= (str.len x) k)` and its three relatives, in either orientation.
        // Bit-vector clients wrap the length in the `int2bv` bridge —
        // `((_ int2bv 64) (str.len x))` — which changes nothing about which
        // string is being measured, so it is looked through here. The bridge
        // is exact for every value a length can take (see `bv2nat` in the
        // crate root), so a bound on the bridged term is a bound on the
        // length.
        let len_arg = |t: TermId| -> Option<TermId> {
            let t = match op_name(pool, t) {
                Some("int2bv") => pool.args(t).first().copied()?,
                _ => t,
            };
            match op_name(pool, t) {
                Some("str.len") => pool.args(t).first().copied(),
                _ => None,
            }
        };
        // The comparisons are `:chainable`, so every adjacent pair of a chain
        // holds in every model and every one may be harvested; the complement
        // of a chain is a disjunction and none of it may be. That decision is
        // `comparison_rel`'s, shared with the length abstraction, which needs
        // exactly the same one.
        if let Some((swap, strict)) = comparison_rel(pool, c, !negated) {
            for w in args.windows(2) {
                // Normalise to `len_side <op> const_side`.
                let (lhs, rhs) = if swap { (w[1], w[0]) } else { (w[0], w[1]) };
                if let (Some(s), Some(k)) = (len_arg(lhs), int_const(pool, rhs)) {
                    let k = if strict { k.saturating_sub(1) } else { k };
                    // A negative bound means the conjunct is unsatisfiable, so
                    // any bound is vacuously valid; 0 is the useful one.
                    // Above `u32::MAX` there is nothing to record, and clamping
                    // *down* would assert what the constraint does not say --
                    // `|x| < 2^64` does not give `|x| <= 2^32 - 1`. Every rule
                    // here has to hold in every model, so an out-of-range bound
                    // is dropped rather than narrowed. `Iv` widens to infinity
                    // for the same reason; this is the `u32` spelling of it.
                    if let Ok(k) = u32::try_from(k.max(0)) {
                        tighten(&mut bound, s, k);
                    }
                }
            }
        }
        match op_name(pool, c) {
            // The automaton is built over bytes, so its longest word is the
            // real language's only while the two have the same word lengths —
            // which complement breaks, and only complement does. `(re.comp
            // (re.* (re.range "\u{0}" "\u{ff}")))` is *empty* over bytes, so
            // `max_word_len` says 0, while the real complement is every string
            // holding a character above `0xff` and has words of every length.
            // Bounding on that removes every model. `analyze` refuses the whole
            // problem on `re.comp` further down, but that is a different check
            // in a different function and this must not lean on it;
            // [`crate::length`]'s `regex_lengths` guards the same way.
            Some("str.in_re") if !negated && args.len() == 2 && complement_free(pool, args[1]) => {
                if let Some(n) = nfas.get(&args[1]) {
                    if let Some(m) = n.max_word_len() {
                        tighten(&mut bound, args[0], m);
                    }
                }
            }
            // A needle is never longer than the haystack it is found in.
            // `(str.contains x y)` puts `y` inside `x`; `str.prefixof` and
            // `str.suffixof` take the needle first. Under a negation these say
            // nothing about lengths, so they are only harvested positively.
            Some("str.contains") if !negated && args.len() == 2 => {
                le_pairs.push((args[1], args[0]));
            }
            Some("str.prefixof" | "str.suffixof") if !negated && args.len() == 2 => {
                le_pairs.push((args[0], args[1]));
            }
            _ => {}
        }
        if !negated && matches!(pool.op(c), Op::Eq) {
            // `(= x "lit")`: every operand has the literal's length.
            if let Some(k) = args.iter().find_map(|&a| literal_of(pool, a)) {
                for &a in args {
                    tighten(&mut bound, a, k.len() as u32);
                }
            }
            // `(= (str.len x) k)`: every `str.len` operand is bounded by k.
            if let Some(k) = args.iter().find_map(|&a| int_const(pool, a)) {
                if k >= 0 {
                    for &a in args {
                        if let Some(s) = len_arg(a) {
                            tighten(&mut bound, s, k as u32);
                        }
                    }
                }
            }
        }
    }

    // Propagate: bottom-up through the string operators, then top-down through
    // the ones whose result is at least as long as an operand. Bounds only ever
    // shrink, so the loop terminates; the cap is belt and braces.
    for _ in 0..strs.len().min(64) + 1 {
        let before = bound.clone();
        for &t in &strs {
            let args: Vec<TermId> = pool.args(t).to_vec();
            let up = match op_name(pool, t) {
                Some("str.++") => args
                    .iter()
                    .try_fold(0u32, |acc, a| bound.get(a).map(|b| acc.saturating_add(*b))),
                Some("str.at") => Some(1),
                // `str.replace`/`str.replace_all` with a literal pattern and a
                // literal replacement no longer than it cannot grow its
                // subject: every occurrence consumes `|p|` characters and emits
                // `|r| <= |p|`, so the result has at most `|x|` characters.
                // Not growing is what makes this admissible at all — the
                // lowering excludes models where the result outgrows the slot
                // array, and that exclusion is vacuous only when the result
                // cannot outgrow the subject. See the note in `replace`.
                Some("str.replace" | "str.replace_all") if non_growing_replacement(pool, &args) => {
                    bound.get(&args[0]).copied()
                }
                Some("str.substr") => {
                    // `(str.substr s i n)` yields at most `n` characters, and at
                    // most the `|s| - i` that remain after the offset. A
                    // negative or non-constant `i` falls back on `|s|`, and a
                    // negative or non-constant `n` imposes nothing.
                    bound.get(&args[0]).copied().map(|src| {
                        let after_offset = match int_const(pool, args[1]) {
                            Some(i) if i >= 0 => {
                                src.saturating_sub(i.min(i128::from(u32::MAX)) as u32)
                            }
                            _ => src,
                        };
                        match int_const(pool, args[2]) {
                            Some(n) if n >= 0 => {
                                after_offset.min(n.min(i128::from(u32::MAX)) as u32)
                            }
                            _ => after_offset,
                        }
                    })
                }
                _ if matches!(pool.op(t), Op::Ite) && args.len() == 3 => {
                    match (bound.get(&args[1]), bound.get(&args[2])) {
                        (Some(a), Some(b)) => Some(*a.max(b)),
                        _ => None,
                    }
                }
                _ => None,
            };
            if let Some(u) = up {
                tighten(&mut bound, t, u);
            }
            // Downwards: a part is never longer than the whole.
            if let Some(&b) = bound.get(&t) {
                let pushes = match op_name(pool, t) {
                    Some("str.++") => args.clone(),
                    // Length preserving, so the bound flows down as well as up.
                    Some("str.replace" | "str.replace_all")
                        if same_length_replacement(pool, &args) =>
                    {
                        vec![args[0]]
                    }
                    _ if matches!(pool.op(t), Op::Ite) && args.len() == 3 => args[1..].to_vec(),
                    _ => Vec::new(),
                };
                for a in pushes {
                    tighten(&mut bound, a, b);
                }
            }
        }
        // Equated terms have equal lengths, so the tightest bound over an
        // equality class applies to every member of it.
        for group in &str_eqs {
            if let Some(k) = group.iter().filter_map(|a| bound.get(a)).min().copied() {
                for &a in group {
                    tighten(&mut bound, a, k);
                }
            }
        }
        // A bound on the haystack bounds the needle. Only this direction: a
        // short needle says nothing about how long the haystack may be.
        for &(short, long) in &le_pairs {
            if let Some(&k) = bound.get(&long) {
                tighten(&mut bound, short, k);
            }
        }
        if bound == before {
            break;
        }
    }
    bound
}

/// Free string variables *every* occurrence of which is a constant-position
/// read — `(str.at v i)` or `(str.substr v i n)` with `i` and `n` numerals —
/// paired with the last position any of those reads can reach.
///
/// This bound is of a different kind from the harvested ones and needs its own
/// argument. The others are facts about every model (`|M(v)| <= k` holds
/// outright); this one is a *small-model* property: given any model `M`, the
/// assignment `M'` that agrees with `M` except that `M'(v)` is `M(v)`
/// truncated to its first `d` characters is again a model, and it satisfies
/// `|M'(v)| <= d`.
///
/// The truncation changes no term's value. `v` occurs only as the subject of
/// reads that stop before position `d`: `(str.at v i)` with `i < d` yields
/// `M(v)[i]` exactly when `i < |M(v)|`, and `i < d` makes that the same test
/// against `M'(v)`, with the same character; `(str.substr v i n)` with
/// `i + n <= d` reads only positions below `d`, on which `M` and `M'` agree,
/// and sees the same ones as present. Every term containing `v` is built from
/// those, so all of them — and hence every assertion — keep their value.
///
/// The rest of the analysis then runs against `M'` rather than `M`, which is
/// sound because every other rule is valid in *every* model, `M'` included.
///
/// Because this argument is about a term's value and not about a constraint
/// holding, it does not care where in the formula the reads sit: a read under
/// a negation or a disjunction restricts `v` just as well. What it does
/// require is that *no other* use exists — a single `(str.len v)`,
/// `(= v ...)`, `(str.contains v ...)` or read at a computed position can
/// distinguish the truncation, and rejects `v` outright.
fn read_depths(pool: &TermPool, roots: &[TermId]) -> FxHashMap<TermId, u32> {
    let mut depth: FxHashMap<TermId, u32> = FxHashMap::default();
    let mut rejected: FxHashSet<TermId> = FxHashSet::default();
    let mut candidates: FxHashSet<TermId> = FxHashSet::default();
    pool.post_order(roots, |pool, t| {
        if pool.sort(t) == Sort::Str
            && matches!(pool.op(t), Op::Var(_))
            && literal_of(pool, t).is_none()
        {
            candidates.insert(t);
        }
        let args = pool.args(t);
        // One past the last position of its subject this term can read, when it
        // is a constant-position read at all.
        let reach = match op_name(pool, t) {
            Some("str.at") if args.len() == 2 => int_const(pool, args[1]).map(|i| {
                // A negative index yields "" whatever the subject holds.
                if i < 0 {
                    0
                } else {
                    i.saturating_add(1)
                }
            }),
            Some("str.substr") if args.len() == 3 => {
                match (int_const(pool, args[1]), int_const(pool, args[2])) {
                    (Some(i), Some(_)) if i < 0 => Some(0),
                    (Some(i), Some(n)) if n >= 0 => Some(i.saturating_add(n)),
                    _ => None,
                }
            }
            _ => None,
        };
        for (j, &a) in args.iter().enumerate() {
            if pool.sort(a) != Sort::Str {
                continue;
            }
            match reach {
                // Only the *subject* of a read is restricted; a string sitting
                // anywhere else in the term is inspected as a whole.
                Some(d) if j == 0 => match u32::try_from(d.max(0)) {
                    Ok(d) => {
                        let e = depth.entry(a).or_insert(0);
                        *e = (*e).max(d);
                    }
                    // A read past `u32::MAX` is a reach this cannot record.
                    // Clamping it down would claim the truncation point is
                    // *before* a read that still happens, which is exactly the
                    // model the argument must not lose; refusing the variable
                    // is the conservative move and costs only an `unknown`.
                    Err(_) => {
                        rejected.insert(a);
                    }
                },
                _ => {
                    rejected.insert(a);
                }
            }
        }
    });
    candidates
        .into_iter()
        .filter(|v| !rejected.contains(v))
        .filter_map(|v| depth.get(&v).map(|&d| (v, d)))
        .collect()
}

/// Lengths of a `str.replace`/`str.replace_all`'s pattern and replacement, when
/// both are literals.
fn replacement_lengths(pool: &TermPool, args: &[TermId]) -> Option<(usize, usize)> {
    if args.len() != 3 {
        return None;
    }
    let (t, r) = (literal_of(pool, args[1])?, literal_of(pool, args[2])?);
    Some((t.len(), r.len()))
}

/// Can this `str.replace`/`str.replace_all` not grow its subject? Then a bound
/// on the subject bounds the result.
fn non_growing_replacement(pool: &TermPool, args: &[TermId]) -> bool {
    replacement_lengths(pool, args).is_some_and(|(t, r)| r <= t)
}

/// Does this `str.replace`/`str.replace_all` preserve length exactly? Then the
/// bound flows the other way too — a bound on the result bounds the subject.
fn same_length_replacement(pool: &TermPool, args: &[TermId]) -> bool {
    replacement_lengths(pool, args).is_some_and(|(t, r)| r == t)
}

/// Interval bounds for the integer-sorted terms, given the string bounds.
/// `Err` for a term whose value the 16-bit encoding might not represent.
///
/// The arithmetic is [`Iv`]'s, which is [`crate::length`]'s: `i128`, checked,
/// and widening an endpoint past `analysis::HUGE` to infinity rather than
/// wrapping it. That matters here more than it does there. These intervals fold
/// `str.to_int` bounds as large as `10^18 - 1` over user-controlled arity, so a
/// machine-width overflow is genuinely reachable: thirteen nested `str.len`s of
/// a 32-character string multiply out to `32^13 = 2^65`, which wrapped to
/// exactly `(0, 0)` — back *inside* the `i16` gate below, certifying 16-bit
/// arithmetic as exact and answering `unsat` on a satisfiable formula. A
/// widening interval can only ever fail the gate, never sneak through it.
fn ints(pool: &TermPool, roots: &[TermId], lens: &FxHashMap<TermId, u32>) -> Result<(), String> {
    let mut order: Vec<TermId> = Vec::new();
    pool.post_order(roots, |_, t| order.push(t));
    let mut iv: FxHashMap<TermId, Iv> = FxHashMap::default();
    for t in order {
        if pool.sort(t) != Sort::Int {
            continue;
        }
        let args: Vec<TermId> = pool.args(t).to_vec();
        let get = |iv: &FxHashMap<TermId, Iv>, a: TermId| iv.get(&a).copied();
        let range: Option<Iv> = match pool.op(t) {
            // `int_const` widens the numeral to `i128`, where every numeral
            // SMT-LIB can write is exactly representable; one above `i16` is
            // then rejected by the gate below rather than reinterpreted as a
            // small negative number. See `analysis`.
            Op::Var(sym) => match int_const(pool, t) {
                Some(v) => Some(Iv::exact(v)),
                // A free `Int` variable ranges over all of Z; the 16-bit
                // encoding covers only a window of it.
                None => return Err(format!("free Int variable {}", pool.symbol(sym).name)),
            },
            _ => match op_name(pool, t) {
                Some("str.len") => lens
                    .get(&args[0])
                    .map(|&b| Iv::new(Some(0), Some(i128::from(b)))),
                Some("str.indexof") => lens
                    .get(&args[0])
                    .map(|&b| Iv::new(Some(-1), Some(i128::from(b)))),
                // `str.to_int` is -1 on anything that is not a non-empty digit
                // string, and at most `10^B - 1` on one of at most `B` digits.
                // Past five digits the upper end escapes `i16` and the term is
                // rejected below, which is the same line the `str.to_int` check
                // in `analyze` draws — an operand that long can denote more
                // than `INT_MAX`, and the encoding excludes those models rather
                // than representing them.
                Some("str.to_int" | "str.to.int") => lens.get(&args[0]).map(|&b| {
                    let hi = 10i128
                        .checked_pow(b.min(18))
                        .map_or(i128::MAX, |p| p.saturating_sub(1));
                    Iv::new(Some(-1), Some(hi))
                }),
                // The bit-vector bridge clamps to `[0, INT_MAX]` by
                // construction (see `bv2nat` in the crate root), which sits
                // exactly inside the 16-bit gate below.
                Some("bv2nat") => Some(Iv::new(Some(0), Some(i128::from(crate::INT_MAX)))),
                Some("+") => args
                    .iter()
                    .try_fold(Iv::exact(0), |acc, &a| Some(acc.add(get(&iv, a)?))),
                Some("-") => {
                    let Some(first) = get(&iv, args[0]) else {
                        return Err("integer operand is not statically bounded".into());
                    };
                    args[1..]
                        .iter()
                        .try_fold(first, |acc, &a| Some(acc.sub(get(&iv, a)?)))
                }
                Some("int-neg") => get(&iv, args[0]).map(Iv::neg),
                Some("*") => {
                    let Some(first) = get(&iv, args[0]) else {
                        return Err("integer operand is not statically bounded".into());
                    };
                    args[1..]
                        .iter()
                        .try_fold(first, |acc, &a| Some(acc.mul(get(&iv, a)?)))
                }
                _ => None,
            },
        };
        // An infinite endpoint and a crossed pair are both refusals: the first
        // is a term the analysis could not place, the second a term no model
        // gives a value, and neither may certify the encoding as exact.
        let Some((lo, hi)) = range.and_then(Iv::finite) else {
            return Err(format!(
                "integer term {} is not statically bounded",
                op_name(pool, t).unwrap_or("?")
            ));
        };
        if lo < i128::from(i16::MIN) || hi > i128::from(i16::MAX) {
            return Err(format!("integer term escapes 16 bits: [{lo}, {hi}]"));
        }
        iv.insert(t, Iv::new(Some(lo), Some(hi)));
    }
    Ok(())
}

/// Bytes that some atom of the problem can tell apart: literal characters and
/// `re.range` endpoints. `re.allchar`/`re.all` contribute nothing — they stand
/// for the whole alphabet and so cannot distinguish a byte from a character
/// above `0xff`.
fn distinguished_bytes(pool: &TermPool, roots: &[TermId]) -> [bool; 256] {
    let mut seen = [false; 256];
    pool.post_order(roots, |pool, t| {
        if let Some(bytes) = literal_of(pool, t) {
            for b in bytes {
                seen[b as usize] = true;
            }
        }
        if op_name(pool, t) == Some("re.range") {
            let args = pool.args(t);
            if let (Some(lo), Some(hi)) = (literal_of(pool, args[0]), literal_of(pool, args[1])) {
                if lo.len() == 1 && hi.len() == 1 {
                    for b in lo[0]..=hi[0] {
                        seen[b as usize] = true;
                    }
                }
            }
        }
    });
    seen
}

/// The string-producing operators whose output characters are always either
/// copied from an operand or taken from a literal in the term itself.
///
/// This is exactly the class the alphabet substitution commutes with: renaming
/// a high character to a spare byte renames it identically in the output, and
/// the choices these operators make (which position to copy, whether a pattern
/// matched) are decided by comparisons against literal bytes, which a spare
/// byte can never collide with. `str.from_int` is deliberately absent — it
/// manufactures digit characters out of an integer rather than copying them.
fn char_conservative(pool: &TermPool, t: TermId) -> bool {
    let mut ok = true;
    pool.post_order(&[t], |pool, n| {
        if pool.sort(n) != Sort::Str || !ok {
            return;
        }
        if matches!(pool.op(n), Op::Var(_) | Op::Ite) {
            return;
        }
        ok = matches!(
            op_name(pool, n),
            Some("str.++" | "str.at" | "str.substr" | "str.replace" | "str.replace_all")
        );
    });
    ok
}

/// The free string variables occurring in `t`.
fn str_vars_of(pool: &TermPool, t: TermId) -> FxHashSet<TermId> {
    let mut out = FxHashSet::default();
    pool.post_order(&[t], |pool, n| {
        if pool.sort(n) == Sort::Str
            && matches!(pool.op(n), Op::Var(_))
            && literal_of(pool, n).is_none()
        {
            out.insert(n);
        }
    });
    out
}

/// String variables whose value is *determined* by a top-level equation.
///
/// The alphabet argument (module docs, condition 2) builds one injection `σ`
/// from the high characters a model uses into the spare bytes `Z`, and applies
/// it to the whole model at once. A variable `v` pinned by a top-level
/// `(= v e)` satisfies `M(v) = e^M`, so `σ(M(v)) = e^{σ(M)}` whenever `e`
/// commutes with `σ` — which [`char_conservative`] is precisely the check for.
/// Such a `v` therefore introduces no high character that is not already
/// introduced by the variables `e` reads, and must not be counted twice against
/// the supply of spare bytes.
///
/// A definition is only usable once everything it reads is itself determined or
/// genuinely free, which is what rules out mutual definitions like
/// `x = y ++ "a"`, `y = x ++ "b"`: neither variable is ever free, so neither is
/// ever marked, and both keep paying for their own characters.
fn determined_vars(pool: &TermPool, roots: &[TermId]) -> FxHashSet<TermId> {
    let mut defs: FxHashMap<TermId, Vec<FxHashSet<TermId>>> = FxHashMap::default();
    for c in top_level_conjuncts(pool, roots) {
        if !matches!(pool.op(c), Op::Eq) {
            continue;
        }
        let args: Vec<TermId> = pool.args(c).to_vec();
        if args.iter().any(|&a| pool.sort(a) != Sort::Str) {
            continue;
        }
        for &v in &args {
            if !matches!(pool.op(v), Op::Var(_)) || literal_of(pool, v).is_some() {
                continue;
            }
            for &e in args.iter().filter(|&&e| e != v) {
                if !char_conservative(pool, e) {
                    continue;
                }
                let reads = str_vars_of(pool, e);
                if !reads.contains(&v) {
                    defs.entry(v).or_default().push(reads);
                }
            }
        }
    }
    let mut determined: FxHashSet<TermId> = FxHashSet::default();
    loop {
        let mut grew = false;
        for (&v, alts) in &defs {
            if determined.contains(&v) {
                continue;
            }
            let usable = alts.iter().any(|reads| {
                reads
                    .iter()
                    .all(|r| !defs.contains_key(r) || determined.contains(r))
            });
            if usable {
                determined.insert(v);
                grew = true;
            }
        }
        if !grew {
            return determined;
        }
    }
}

/// Decide whether the bounded encoding is complete for `roots`.
pub fn analyze(pool: &TermPool, roots: &[TermId], nfas: &FxHashMap<TermId, Nfa>) -> Analysis {
    // A chained arithmetic comparison used to block: the lowering read only the
    // first two operands, so `(< a b c)` was encoded as `a < b` alone — an
    // over-approximation no `unsat` could be trusted through. It now encodes
    // every adjacent pair (`lower`'s `windows(2)`), so the encoding of a chain
    // is the conjunction the `:chainable` annotation abbreviates, exactly as
    // for the two-operand case. Nothing else about a chain needs an argument of
    // its own: [`ints`] visits each operand individually and requires each to
    // fit in `i16`, which is what makes every one of the signed bit-vector
    // comparisons agree with the integer one, whatever the arity.
    let lens = lengths(pool, roots, nfas);

    // Every string term must fit, and the widest one tells the caller how few
    // slots would do.
    let mut needed = 0u32;
    let mut unbounded: Option<String> = None;
    pool.post_order(roots, |pool, t| {
        if pool.sort(t) != Sort::Str || unbounded.is_some() {
            return;
        }
        match lens.get(&t) {
            Some(&b) => needed = needed.max(b),
            None => {
                unbounded = Some(match pool.op(t) {
                    Op::Var(sym) => format!("string variable {}", pool.symbol(sym).name),
                    _ => format!("string term {}", op_name(pool, t).unwrap_or("?")),
                })
            }
        }
    });
    if let Some(w) = unbounded {
        return Analysis::blocked(format!("unbounded length: {w}"));
    }

    if let Err(e) = ints(pool, roots, &lens) {
        return Analysis::blocked(e);
    }

    // `str.to_int` asserts that a digit string never denotes more than
    // `INT_MAX`, which *removes models* rather than merely bounding lengths —
    // so an `unsat` under it is not trustworthy. Unless the operand is too
    // short to overflow: four digits reach at most 9999, well inside the signed
    // 16-bit range, and then the restriction is vacuous and excludes nothing.
    const MAX_NON_OVERFLOWING_DIGITS: u32 = 4;
    let mut overflowable: Option<u32> = None;
    pool.post_order(roots, |pool, t| {
        // The parser keeps the 2.5 spelling `str.to.int` as its own name, so
        // both have to be checked or the older one slips past.
        if overflowable.is_some() || !matches!(op_name(pool, t), Some("str.to_int" | "str.to.int"))
        {
            return;
        }
        let arg_bound = pool.args(t).first().and_then(|a| lens.get(a).copied());
        match arg_bound {
            Some(b) if b <= MAX_NON_OVERFLOWING_DIGITS => {}
            other => overflowable = Some(other.unwrap_or(u32::MAX)),
        }
    });
    if let Some(b) = overflowable {
        return Analysis::blocked(format!(
            "str.to_int over a string of up to {b} digits can exceed INT_MAX, \
             and the encoding excludes those models"
        ));
    }

    // Complement over the byte alphabet is not complement over the real one.
    // The alphabet argument below rests on every atom testing a character only
    // by equality or range membership, so that a spare byte answers exactly as
    // an out-of-alphabet character would. `re.comp` breaks that: the complement
    // of `(re.range "\u{0}" "\u{ff}")` is *empty* over bytes and contains every
    // character above 0xff in reality, so a model the encoding cannot see is
    // not merely unrepresented — it is contradicted. `re.diff` is complement in
    // disguise. Neither can be repaired by counting spare bytes, so completeness
    // is refused outright whenever either appears. [`crate::length`] refuses
    // both for the same reason stated over word lengths, so the two share the
    // one scan.
    if let Some(name) = complement_op(pool, roots) {
        return Analysis::blocked(format!(
            "{name} complements over the byte alphabet, not the real one, so an              `unsat` under it may exclude models using characters above 0xff"
        ));
    }

    // Alphabet: enough spare bytes to stand in for any character above 0xff a
    // model might use. Free string variables are the only source of characters
    // that are not already literal bytes.
    let determined = determined_vars(pool, roots);
    let mut free_chars: u64 = 0;
    pool.post_order(roots, |pool, t| {
        if pool.sort(t) == Sort::Str && literal_of(pool, t).is_none() {
            if let Op::Var(_) = pool.op(t) {
                if !determined.contains(&t) {
                    free_chars += lens.get(&t).copied().unwrap_or(0) as u64;
                }
            }
        }
    });
    let spare = distinguished_bytes(pool, roots)
        .iter()
        .filter(|b| !**b)
        .count() as u64;
    if spare < free_chars {
        return Analysis::blocked(format!(
            "only {spare} spare bytes for up to {free_chars} out-of-alphabet characters"
        ));
    }

    Analysis {
        needed_len: Some(needed),
        blocker: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smtrs_parser::{parse_script, Command};

    /// Run the analysis over a script's assertions.
    fn analyze_script(input: &str) -> (Analysis, TermPool, Vec<TermId>) {
        let mut pool = TermPool::new();
        let script = parse_script(input, &mut pool).expect("parse");
        let roots: Vec<TermId> = script
            .commands
            .iter()
            .filter_map(|c| match c {
                Command::Assert(t, _) => Some(*t),
                _ => None,
            })
            .collect();
        let nfas = crate::regex::build_all(&pool, &roots).expect("regex build");
        let a = analyze(&pool, &roots, &nfas);
        (a, pool, roots)
    }

    fn needed(input: &str) -> Option<u32> {
        analyze_script(input).0.needed_len
    }

    const DECL: &str = "(declare-const x String)(declare-const y String)";

    #[test]
    fn literals_are_exact() {
        assert_eq!(needed(r#"(assert (= "abc" "abc"))"#), Some(3));
    }

    /// Bit-vector clients (see `bv2nat`/`int2bv` in the crate root) state
    /// length constraints as unsigned comparisons and equalities over
    /// `((_ int2bv 64) (str.len x))`. The harvest must see through the bridge
    /// or every such problem loses bound completeness.
    #[test]
    fn bridged_length_constraints_bound_a_variable() {
        let mut pool = TermPool::new();
        let x = {
            let sym = pool.fresh_symbol("x", Sort::Str);
            pool.var(sym)
        };
        let str_len = pool.fresh_symbol("str.len", Sort::Bool); // op head; sort unused
        let len = pool.other(str_len, 0, 0, &[x], Sort::Int);
        let int2bv = pool.fresh_symbol("int2bv", Sort::Bool);
        let bridged = pool.other(int2bv, 64, 0, &[len], Sort::BitVec(64));
        let k = pool.bv_u64(64, 4);

        // (bvult ((_ int2bv 64) (str.len x)) 4) bounds |x| by 3.
        let ult = pool.mk(Op::BvUlt, &[bridged, k]).unwrap();
        let nfas = FxHashMap::default();
        let a = analyze(&pool, &[ult], &nfas);
        assert_eq!(a.needed_len, Some(3));

        // (= ((_ int2bv 64) (str.len x)) 4) bounds |x| by 4.
        let eq = pool.mk(Op::Eq, &[bridged, k]).unwrap();
        let a = analyze(&pool, &[eq], &nfas);
        assert_eq!(a.needed_len, Some(4));
    }

    #[test]
    fn unconstrained_variable_is_unbounded() {
        let (a, ..) = analyze_script(&format!(
            r#"{DECL}(assert (= x "ab"))(assert (str.contains y "q"))"#
        ));
        assert_eq!(a.needed_len, None);
        assert!(a.blocker.expect("blocked").contains("unbounded"));
    }

    #[test]
    fn length_constraints_bound_a_variable() {
        assert_eq!(
            needed(&format!("{DECL}(assert (<= (str.len x) 4))")),
            Some(4)
        );
        assert_eq!(
            needed(&format!("{DECL}(assert (< (str.len x) 4))")),
            Some(3)
        );
        assert_eq!(
            needed(&format!("{DECL}(assert (= (str.len x) 7))")),
            Some(7)
        );
        assert_eq!(
            needed(&format!("{DECL}(assert (>= 5 (str.len x)))")),
            Some(5)
        );
        assert_eq!(
            needed(&format!("{DECL}(assert (> 5 (str.len x)))")),
            Some(4)
        );
    }

    #[test]
    fn equality_with_a_literal_bounds_a_variable() {
        assert_eq!(needed(&format!(r#"{DECL}(assert (= x "hello"))"#)), Some(5));
    }

    /// A bound is only valid if the constraint holds in every model. Under a
    /// negation it does not, so nothing may be harvested.
    #[test]
    fn negated_length_constraint_is_not_harvested() {
        let (a, ..) = analyze_script(&format!("{DECL}(assert (not (<= (str.len x) 4)))"));
        assert_eq!(a.needed_len, None);
        let (a, ..) = analyze_script(&format!(r#"{DECL}(assert (not (= x "hi")))"#));
        assert_eq!(a.needed_len, None);
        let (a, ..) = analyze_script(&format!(
            "{DECL}(assert (not (str.in_re x (str.to_re \"ab\"))))"
        ));
        assert_eq!(a.needed_len, None);
    }

    /// A disjunction bounds a variable at its *widest* branch, or not at all —
    /// never at the narrow one.
    #[test]
    fn disjunctive_length_constraint_is_not_harvested_at_the_small_branch() {
        let (a, ..) = analyze_script(&format!(
            "{DECL}(assert (or (= (str.len x) 2) (= (str.len x) 99)))"
        ));
        assert!(
            a.needed_len.is_none() || a.needed_len == Some(99),
            "bounded at {:?}, which excludes the 99-character branch",
            a.needed_len
        );
    }

    /// Under an `ite` condition a constraint need not hold either.
    #[test]
    fn ite_branch_constraint_is_not_harvested() {
        let (a, ..) = analyze_script(&format!(
            "{DECL}(declare-const b Bool)(assert (ite b (<= (str.len x) 2) (str.contains x \"z\")))"
        ));
        assert_eq!(a.needed_len, None);
    }

    #[test]
    fn concat_sums_its_operands() {
        assert_eq!(
            needed(&format!(
                "{DECL}(assert (<= (str.len x) 3))(assert (<= (str.len y) 4))
                 (assert (str.contains (str.++ x y) \"q\"))"
            )),
            Some(7)
        );
        // One unbounded operand leaves the concatenation unbounded.
        let (a, ..) = analyze_script(&format!(
            "{DECL}(assert (<= (str.len x) 3))(assert (str.contains (str.++ x y) \"q\"))"
        ));
        assert_eq!(a.needed_len, None);
    }

    /// `|a| <= |a ++ b|`, so a bound on the whole bounds each part.
    #[test]
    fn concat_bound_flows_down_to_its_parts() {
        let a = analyze_script(&format!("{DECL}(assert (= (str.len (str.++ x y)) 5))")).0;
        assert_eq!(a.needed_len, Some(5));
    }

    /// A replacement of the same length as its pattern preserves length, so the
    /// bound crosses it in both directions — up from the subject and, via the
    /// equality, back down a whole chain of definitions.
    #[test]
    fn equal_length_replacement_preserves_the_bound() {
        assert_eq!(
            needed(
                r#"(declare-const a String)(declare-const b String)
                   (assert (= b (str.replace_all a "u" "A")))
                   (assert (= b "AAAAA"))"#
            ),
            Some(5)
        );
        assert_eq!(
            needed(
                r#"(declare-const a String)(declare-const b String)
                   (assert (= b (str.replace a "uv" "AB")))
                   (assert (= b "ABAB"))"#
            ),
            Some(4)
        );
    }

    /// A replacement that can *grow* its subject still bounds nothing: the
    /// lowering excludes the over-long models, so trusting an `unsat` under it
    /// would be trusting an exclusion.
    #[test]
    fn growing_replacement_still_blocks() {
        let a = analyze_script(
            r#"(declare-const a String)(declare-const b String)
               (assert (= b (str.replace_all a "u" "AB")))
               (assert (= b "ABAB"))"#,
        )
        .0;
        assert_eq!(a.needed_len, None);
        assert!(a.blocker.expect("blocked").contains("unbounded"));
    }

    /// A variable pinned by a top-level equation to a character-conserving term
    /// introduces no characters of its own, so it must not be charged against
    /// the supply of spare bytes a second time.
    #[test]
    fn defined_variables_do_not_pay_for_their_characters_twice() {
        // Four chained 200-character definitions: 1000 characters counted
        // naively, which exceeds any spare-byte supply, but only `y` is free.
        let mut s = String::from("(declare-const y String)");
        for i in 1..=4 {
            s.push_str(&format!("(declare-const y{i} String)"));
        }
        s.push_str(r#"(assert (= y1 (str.replace_all y "u" "A")))"#);
        for i in 2..=4 {
            s.push_str(&format!(
                r#"(assert (= y{i} (str.replace_all y{} "u" "A")))"#,
                i - 1
            ));
        }
        s.push_str(&format!(r#"(assert (= y4 "{}"))"#, "A".repeat(200)));
        let a = analyze_script(&s).0;
        assert_eq!(a.blocker, None, "should be complete");
        assert_eq!(a.needed_len, Some(200));

        // Mutually defined variables are determined by nothing — neither
        // definition ever becomes usable — so both keep paying and the
        // spare-byte supply runs out.
        let mutual = r#"(declare-const p String)(declare-const q String)
               (assert (= p (str.replace_all q "u" "A")))
               (assert (= q (str.replace_all p "a" "T")))
               (assert (<= (str.len p) 200))"#;
        let a = analyze_script(mutual).0;
        assert!(
            a.blocker
                .as_deref()
                .is_some_and(|b| b.contains("spare bytes")),
            "mutual definitions should not be treated as determined: {:?}",
            a.blocker
        );
    }

    #[test]
    fn substr_and_at_are_bounded_by_their_source() {
        assert_eq!(
            needed(&format!(
                "{DECL}(assert (= (str.len x) 6))(assert (= (str.at x 2) \"a\"))
                 (assert (str.contains (str.substr x 1 2) \"b\"))"
            )),
            Some(6)
        );
    }

    #[test]
    fn finite_regex_bounds_a_variable() {
        // (ab|cde) accepts words of length at most 3.
        assert_eq!(
            needed(&format!(
                r#"{DECL}(assert (str.in_re x (re.union (str.to_re "ab") (str.to_re "cde"))))"#
            )),
            Some(3)
        );
        // re.opt of a 2-character word: still finite.
        assert_eq!(
            needed(&format!(
                r#"{DECL}(assert (str.in_re x (re.++ (str.to_re "ab") (re.opt (str.to_re "cd")))))"#
            )),
            Some(4)
        );
    }

    #[test]
    fn starred_regex_does_not_bound_a_variable() {
        let (a, ..) = analyze_script(&format!(
            r#"{DECL}(assert (str.in_re x (re.++ (str.to_re "ab") (re.* (str.to_re "c")))))"#
        ));
        assert_eq!(a.needed_len, None);
    }

    /// A bound too large for the `u32` the analysis records is dropped, never
    /// narrowed to `u32::MAX`. `|x| < 2^64 - 1` is true of every string and
    /// says nothing; recording it as `|x| <= 2^32 - 1` would be asserting a
    /// bound no constraint gives, and every rule here must hold in every model.
    ///
    /// This is the `u32` spelling of what `Iv` does by widening to infinity,
    /// and it is the shape of the first wrong `unsat` this project shipped:
    /// the same numeral, read as `i64`, came back as `-1` and clamped to 0.
    #[test]
    fn a_bound_past_u32_is_dropped_not_narrowed() {
        for k in ["18446744073709551615", "5000000000"] {
            let (a, ..) = analyze_script(&format!("{DECL}(assert (<= (str.len x) {k}))"));
            assert_eq!(a.needed_len, None, "recorded a narrowed bound for {k}");
            assert!(a.blocker.is_some());
        }
        // The same shape the wrong `unsat` came in: negated, and true of every
        // string. It must bound nothing at all.
        let (a, ..) = analyze_script(&format!(
            "{DECL}(assert (not (>= (str.len x) 18446744073709551615)))"
        ));
        assert_eq!(a.needed_len, None);
        // A read whose reach is past `u32::MAX` rejects the variable rather
        // than truncating it before the read that still happens.
        let (a, ..) = analyze_script(&format!(r#"{DECL}(assert (= (str.at x 5000000000) "a"))"#));
        assert_eq!(a.needed_len, None);
        // Bounds that do fit are unaffected.
        assert_eq!(
            needed(&format!("{DECL}(assert (<= (str.len x) 12))")),
            Some(12)
        );
    }

    /// A *complemented* regex bounds nothing, even when its byte automaton
    /// says otherwise — this is the same refusal [`crate::length`] makes in
    /// `regex_lengths`, and the reason both now go through `complement_free`.
    ///
    /// `(re.* (re.range "\u{0}" "\u{ff}"))` is every byte string, so over
    /// bytes its complement is *empty* and `max_word_len` reports 0. Over the
    /// real alphabet the complement is every string holding a character above
    /// `0xff`, which has words of every length. Harvesting the byte answer
    /// bounds `x` at 0 and removes every model there is.
    ///
    /// `analyze` refuses the whole problem on `re.comp` a few lines later, so
    /// this never reached an answer — but that is a different check in a
    /// different function, and `lengths` must not depend on it.
    #[test]
    fn a_complemented_regex_bounds_nothing() {
        let (_, pool, roots) = analyze_script(&format!(
            r#"{DECL}(assert (str.in_re x (re.comp (re.* (re.range "\u{{0}}" "\u{{ff}}")))))"#
        ));
        let nfas = crate::regex::build_all(&pool, &roots).expect("regex build");
        let lens = lengths(&pool, &roots, &nfas);
        let x = lens
            .iter()
            .find(|(&t, _)| matches!(pool.op(t), Op::Var(s) if pool.symbol(s).name == "x"))
            .map(|(_, &b)| b);
        assert_eq!(x, None, "bounded x at {x:?} off a complemented automaton");
    }

    /// An empty language is finite, so it bounds its variable — here at 0,
    /// leaving the 8-character literals as the widest string term.
    #[test]
    fn empty_language_regex_is_finite() {
        let (a, pool, roots) = analyze_script(&format!(
            r#"{DECL}(assert (str.in_re x (re.inter (str.to_re "abcdefgh") (str.to_re "ijklmnop"))))"#
        ));
        assert_eq!(a.needed_len, Some(8));
        let nfas = crate::regex::build_all(&pool, &roots).expect("regex build");
        let lens = lengths(&pool, &roots, &nfas);
        let x = *lens
            .iter()
            .find(|(&t, _)| matches!(pool.op(t), Op::Var(s) if pool.symbol(s).name == "x"))
            .expect("x is bounded")
            .1;
        assert_eq!(x, 0);
    }

    #[test]
    fn free_int_variable_blocks() {
        let (a, ..) = analyze_script(&format!(
            "{DECL}(declare-const n Int)(assert (= (str.len x) 3))(assert (< n (str.len x)))"
        ));
        assert!(a.blocker.expect("blocked").contains("free Int"));
    }

    /// An integer literal past 16 bits is silently truncated by the encoding,
    /// so no `unsat` may be trusted through it.
    #[test]
    fn oversized_integer_literal_blocks() {
        let (a, ..) = analyze_script(&format!(
            "{DECL}(assert (= x \"ab\"))(assert (< (str.len x) 100000))"
        ));
        assert!(a.blocker.expect("blocked").contains("16 bits"));
    }

    /// Characters above 0xff have no encoding; the argument that this excludes
    /// no model needs a spare byte per character a free variable can hold.
    #[test]
    fn alphabet_headroom_is_required() {
        // A 300-character variable outruns the 256-byte alphabet.
        let (a, ..) = analyze_script(&format!("{DECL}(assert (<= (str.len x) 300))"));
        assert!(a.blocker.expect("blocked").contains("spare bytes"));
    }

    /// `re.comp` complements over the byte alphabet, which is not the real one.
    /// This exact shape returned `unsat` on a satisfiable formula while the
    /// analysis reported "complete": the real complement of a full byte range
    /// contains every character above 0xff, and the byte automaton's is empty.
    #[test]
    fn complement_blocks_because_the_byte_alphabet_is_not_the_real_one() {
        let (a, _, _) = analyze_script(
            r#"(declare-const x String)
               (assert (= (str.len x) 1))
               (assert (str.in_re x (re.comp (re.range "a" "z"))))"#,
        );
        assert!(a.blocker.expect("blocked").contains("re.comp"));
    }

    #[test]
    fn difference_blocks_for_the_same_reason() {
        let (a, _, _) = analyze_script(
            r#"(declare-const x String)
               (assert (= (str.len x) 1))
               (assert (str.in_re x (re.diff re.allchar (str.to_re "a"))))"#,
        );
        assert!(a.blocker.expect("blocked").contains("re.diff"));
        // A short one does not.
        assert_eq!(
            needed(&format!("{DECL}(assert (<= (str.len x) 10))")),
            Some(10)
        );
    }

    /// A chained comparison is `:chainable`, so every adjacent pair holds and
    /// the lowering encodes every one of them. It no longer blocks, and each
    /// link is harvestable.
    #[test]
    fn chained_comparison_no_longer_blocks() {
        let (a, ..) = analyze_script(&format!(
            "{DECL}(assert (= x \"ab\"))(assert (< 0 (str.len x) 5))"
        ));
        assert_eq!(a.blocker, None);
        assert_eq!(a.needed_len, Some(2));

        // The *second* link is the one that bounds `x`; harvesting only the
        // first pair would leave it unbounded.
        assert_eq!(
            needed(&format!("{DECL}(assert (< 0 (str.len x) 5))")),
            Some(4)
        );
        // And in the reversed orientation, where the bounding link is first.
        assert_eq!(
            needed(&format!("{DECL}(assert (>= 6 (str.len x) 0))")),
            Some(6)
        );
    }

    /// `(not p)` holds in every model exactly as a positive conjunct does, so
    /// the complement of a two-operand comparison may be harvested.
    #[test]
    fn negated_comparison_is_harvested() {
        assert_eq!(
            needed(&format!("{DECL}(assert (not (> (str.len x) 12)))")),
            Some(12)
        );
        assert_eq!(
            needed(&format!("{DECL}(assert (not (>= (str.len x) 12)))")),
            Some(11)
        );
        assert_eq!(
            needed(&format!("{DECL}(assert (not (< 12 (str.len x))))")),
            Some(12)
        );
        assert_eq!(
            needed(&format!("{DECL}(assert (not (<= 12 (str.len x))))")),
            Some(11)
        );
    }

    /// The complement of a *chain* is a disjunction — `(not (< a b c))` is
    /// `a >= b or b >= c` — so no link of it may be harvested.
    #[test]
    fn negated_chained_comparison_is_not_harvested() {
        let (a, ..) = analyze_script(&format!("{DECL}(assert (not (< 3 (str.len x) 12)))"));
        assert_eq!(a.needed_len, None);
        // Nor with the bounding link first.
        let (a, ..) = analyze_script(&format!("{DECL}(assert (not (> 12 (str.len x) 3)))"));
        assert_eq!(a.needed_len, None);
    }

    /// A negation may only be pushed through the one shape whose complement is
    /// itself a bound. Everything else under a `not` still bounds nothing.
    #[test]
    fn negation_is_not_pushed_through_anything_else() {
        // `(not (and ...))` is a disjunction; neither conjunct need hold.
        let (a, ..) = analyze_script(&format!(
            "{DECL}(assert (not (and (<= (str.len x) 4) (<= (str.len y) 4))))"
        ));
        assert_eq!(a.needed_len, None);
        // A doubly negated constraint is not harvested either — it would be
        // sound, but the analysis deliberately stops at one level.
        let (a, ..) = analyze_script(&format!("{DECL}(assert (not (not (> (str.len x) 12))))"));
        assert_eq!(a.needed_len, None);
        // `(not (= x "hi"))` and `(not (str.in_re ...))` bound nothing; covered
        // by `negated_length_constraint_is_not_harvested` above.
    }

    /// A bound found under a disjunction must never be used, negated or not.
    #[test]
    fn bounds_under_a_disjunction_are_never_used() {
        for c in [
            "(or (not (> (str.len x) 4)) (str.contains x \"z\"))",
            "(or (str.contains x \"z\") (< (str.len x) 4))",
            "(or (str.prefixof x \"abcd\") (str.contains x \"z\"))",
            "(not (or (> (str.len x) 4) (str.contains x \"z\")))",
        ] {
            let (a, ..) = analyze_script(&format!("{DECL}(assert {c})"));
            assert_eq!(a.needed_len, None, "harvested a bound from {c}");
        }
    }

    /// `(str.contains x y)` puts `y` inside `x`, so a bound on `x` bounds `y`;
    /// `str.prefixof`/`str.suffixof` take the needle first.
    #[test]
    fn containment_bounds_the_needle() {
        assert_eq!(
            needed(&format!(
                "{DECL}(assert (<= (str.len x) 6))(assert (str.contains x y))"
            )),
            Some(6)
        );
        assert_eq!(
            needed(&format!(
                "{DECL}(assert (<= (str.len x) 6))(assert (str.prefixof y x))"
            )),
            Some(6)
        );
        assert_eq!(
            needed(&format!(
                "{DECL}(assert (<= (str.len x) 6))(assert (str.suffixof y x))"
            )),
            Some(6)
        );
        // The needle bound may arrive only after the haystack's does, so the
        // relation has to be replayed to the fixpoint: here `y` is bounded
        // through `x`, and `x` through the concatenation it sits in.
        assert_eq!(
            needed(&format!(
                "{DECL}(assert (= (str.len (str.++ x \"abc\")) 9))
                 (assert (str.contains x y))"
            )),
            Some(9)
        );
    }

    /// Only the needle is bounded. A short needle says nothing about how long
    /// the haystack may be, and a containment under a negation says nothing at
    /// all.
    #[test]
    fn containment_does_not_bound_the_haystack() {
        let (a, ..) = analyze_script(&format!(
            "{DECL}(assert (<= (str.len y) 6))(assert (str.contains x y))"
        ));
        assert_eq!(a.needed_len, None);
        let (a, ..) = analyze_script(&format!(
            "{DECL}(assert (<= (str.len x) 6))(assert (not (str.contains x y)))"
        ));
        assert_eq!(a.needed_len, None);
        let (a, ..) = analyze_script(&format!(
            "{DECL}(assert (<= (str.len x) 6))(assert (not (str.prefixof y x)))"
        ));
        assert_eq!(a.needed_len, None);
    }

    /// A constant offset shortens what is left to take, and a constant count
    /// caps it; neither direction says anything about the *source*.
    #[test]
    fn substr_offset_tightens_but_does_not_flow_back() {
        let (a, pool, roots) = analyze_script(&format!(
            "{DECL}(assert (= (str.len x) 10))(assert (= y (str.substr x 7 100)))"
        ));
        assert_eq!(a.blocker, None);
        let nfas = crate::regex::build_all(&pool, &roots).expect("regex build");
        let lens = lengths(&pool, &roots, &nfas);
        let y = *lens
            .iter()
            .find(|(&t, _)| matches!(pool.op(t), Op::Var(s) if pool.symbol(s).name == "y"))
            .expect("y is bounded")
            .1;
        assert_eq!(y, 3, "10 characters less an offset of 7");

        // A bounded substring leaves its source unbounded: the source may be
        // arbitrarily long past the window the substring reads. The
        // `str.contains` is there to keep the read-depth rule — which *would*
        // bound `x`, by a different argument — out of the way.
        let (a, ..) = analyze_script(&format!(
            r#"{DECL}(assert (= y (str.substr x 0 4)))(assert (= (str.len y) 4))
               (assert (str.contains x "q"))"#
        ));
        assert_eq!(a.needed_len, None);
    }

    /// A replacement *shorter* than its pattern shrinks the subject, so the
    /// bound still flows up — but not back down.
    #[test]
    fn shrinking_replacement_bounds_upwards_only() {
        assert_eq!(
            needed(
                r#"(declare-const a String)(declare-const b String)
                   (assert (<= (str.len a) 6))
                   (assert (= b (str.replace_all a "uv" "A")))"#
            ),
            Some(6)
        );
        // Downwards it must not flow: `b` short does not make `a` short.
        let a = analyze_script(
            r#"(declare-const a String)(declare-const b String)
               (assert (= b (str.replace_all a "uv" "A")))
               (assert (= b "AA"))"#,
        )
        .0;
        assert_eq!(a.needed_len, None);
    }

    /// A variable read only at fixed positions can be truncated past the last
    /// of them, so that depth bounds it — wherever in the formula the reads
    /// sit, since the argument is about a term's value and not about a
    /// constraint holding.
    #[test]
    fn a_variable_read_only_at_fixed_positions_is_bounded() {
        // The rewrite-rule shape: `x` is only ever `(str.at x 1)`.
        let (a, ..) = analyze_script(&format!(
            "{DECL}(assert (not (= (str.at (str.at x 1) 0) (str.at x 1))))"
        ));
        assert_eq!(a.blocker, None);
        assert_eq!(a.needed_len, Some(2), "one past the highest index read");

        // Several reads take the furthest.
        assert_eq!(
            needed(&format!(
                r#"{DECL}(assert (or (= (str.at x 4) "a") (= (str.substr x 1 2) "bc")))"#
            )),
            Some(5)
        );
        // `str.substr` reaches offset plus count.
        assert_eq!(
            needed(&format!(r#"{DECL}(assert (= (str.substr x 3 4) "abcd"))"#)),
            Some(7)
        );
    }

    /// One use that can see the whole string rejects the variable: the
    /// truncation would then be observable.
    #[test]
    fn any_other_use_defeats_the_read_depth_bound() {
        for c in [
            // `str.len` sees past every read.
            r#"(and (= (str.at x 0) "a") (> (str.len x) 9))"#,
            // An equality constrains the whole value.
            r#"(and (= (str.at x 0) "a") (= x y))"#,
            // Containment inspects every position.
            r#"(and (= (str.at x 0) "a") (str.contains x "zz"))"#,
            // A concatenation carries the whole string along.
            r#"(and (= (str.at x 0) "a") (= (str.++ x "q") y))"#,
            // A computed position can read arbitrarily far.
            r#"(and (= (str.at x 0) "a") (= (str.at x (str.indexof x "q" 0)) "b"))"#,
            // A non-constant count likewise.
            r#"(and (= (str.at x 0) "a") (= (str.substr x 0 (str.indexof x "q" 0)) "b"))"#,
        ] {
            let (a, ..) = analyze_script(&format!("{DECL}(declare-const n Int)(assert {c})"));
            assert_eq!(a.needed_len, None, "bounded {c} through a read depth");
        }
        // Being the *needle* of a containment is not being the subject of a
        // read either. Here another rule does bound `x` — by the haystack, at
        // 3 — and the read depth of 1 must not be the answer.
        assert_eq!(
            needed(&format!(
                r#"{DECL}(assert (and (= (str.at x 0) "a") (str.contains "abc" x)))"#
            )),
            Some(3)
        );
    }

    /// `str.to_int` of a `B`-digit string is at most `10^B - 1`, so a short
    /// enough operand keeps the whole problem inside 16 bits — and a longer one
    /// is rejected on exactly the line the overflow check draws.
    #[test]
    fn to_int_is_bounded_by_its_operand_length() {
        assert_eq!(
            needed(&format!(
                "{DECL}(assert (<= (str.len x) 4))(assert (< (str.to_int x) 3))"
            )),
            Some(4)
        );
        // Five digits reach 99999, past `i16`; the encoding excludes those
        // models, so completeness must not be claimed.
        let (a, ..) = analyze_script(&format!(
            "{DECL}(assert (<= (str.len x) 5))(assert (< (str.to_int x) 3))"
        ));
        assert!(a.blocker.is_some(), "5 digits should still block");
        // An unbounded operand blocks on its length, as before.
        let (a, ..) = analyze_script(&format!("{DECL}(assert (< (str.to_int x) 3))"));
        assert!(a.blocker.expect("blocked").contains("unbounded"));
    }

    #[test]
    fn complete_at_respects_the_bound() {
        let (a, ..) = analyze_script(&format!("{DECL}(assert (= (str.len x) 20))"));
        assert_eq!(a.needed_len, Some(20));
        assert!(!a.complete_at(16));
        assert!(a.complete_at(20));
        assert!(a.complete_at(64));
    }
}
