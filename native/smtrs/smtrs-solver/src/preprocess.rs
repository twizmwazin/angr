//! Assertion-level preprocessing: and-flattening, variable substitution, and
//! equality propagation.
//!
//! Variable substitution eliminates `(= x t)` assertions (x a variable, t
//! x-free) by substituting t for x everywhere. It runs in rounds: within a
//! round, a definition is only accepted if its RHS mentions no variable
//! already defined *this round* — rejected definitions simply wait for the
//! next round (after which their RHS has been substituted). This keeps each
//! round a single simultaneous substitution over all survivors, O(total term
//! size), instead of incrementally closing the map (which is quadratic in the
//! number of definitions — SAGE benchmarks have thousands).
//!
//! Model reconstruction: evaluate `defs` in reverse recording order. A
//! round-r RHS never mentions a variable defined in rounds <= r, so every
//! variable it needs is either surviving or recorded later.

use rustc_hash::{FxHashMap, FxHashSet};
use smtrs_core::{Op, Sort, SymbolId, TermId, TermPool};
use smtrs_rewrite::Rewriter;

pub struct Preprocessed {
    /// Assertions to bit-blast (no top-level Ands, no `true`).
    pub roots: Vec<TermId>,
    /// Eliminated variables with their (raw, per-round) defining terms.
    pub defs: Vec<(SymbolId, TermId)>,
    /// Rounds of substitution performed (chain depth bound for closure).
    pub rounds: u32,
}

pub const MAX_ROUNDS: u32 = 4;

/// `None` means the assertion set is trivially unsat.
pub fn preprocess(
    pool: &mut TermPool,
    rewriter: &mut Rewriter,
    roots: &[TermId],
    allow_subst: bool,
) -> Option<Preprocessed> {
    let mut work: Vec<TermId> = Vec::with_capacity(roots.len());
    for &r in roots {
        let rw = rewriter.rewrite(pool, r);
        if !flatten_into(pool, rw, &mut work) {
            return None;
        }
    }

    let mut defs: Vec<(SymbolId, TermId)> = Vec::new();
    let mut rounds = 0u32;
    if allow_subst {
        for _round in 0..MAX_ROUNDS {
            let round = substitution_round(pool, rewriter, &work)?;
            if round.defs.is_empty() {
                break;
            }
            rounds += 1;
            defs.extend(round.defs);
            work = round.work;
        }
    }

    Some(Preprocessed {
        roots: work,
        defs,
        rounds,
    })
}

/// Install parent counts over `roots` into the rewriter, for its
/// sharing-aware flattening decisions. Must be redone whenever the assertion
/// set is rebuilt, or the counts describe a graph that no longer exists.
pub fn count_parents(pool: &TermPool, roots: &[TermId], rewriter: &mut Rewriter) {
    if !rewriter.share_guard {
        // The caller asked for the unguarded encoding. With no counts installed
        // `term_shared` reports everything unshared, which is exactly the
        // alternative the solver wants to compare against.
        rewriter.refcounts.clear();
        return;
    }
    let mut refcounts: FxHashMap<TermId, u32> = FxHashMap::default();
    pool.post_order(roots, |pool, t| {
        for &c in pool.args(t) {
            *refcounts.entry(c).or_insert(0) += 1;
        }
    });
    rewriter.refcounts = refcounts;
}

struct Round {
    work: Vec<TermId>,
    defs: Vec<(SymbolId, TermId)>,
}

/// One simultaneous-substitution round over `work`.
///
/// A definition x := rhs is deferred to the next round if (a) rhs mentions a
/// variable already defined *this* round, or (b) x already occurs in an
/// accepted RHS this round — either would break the single simultaneous
/// substitution at the end. Returns `None` when the assertion set is trivially
/// unsat.
fn substitution_round(
    pool: &mut TermPool,
    rewriter: &mut Rewriter,
    work: &[TermId],
) -> Option<Round> {
    let mut subst: FxHashMap<TermId, TermId> = FxHashMap::default();
    let mut defined_this_round: FxHashSet<TermId> = FxHashSet::default();
    let mut used_in_rhs: FxHashSet<TermId> = FxHashSet::default();
    let mut defining = vec![false; work.len()];
    let mut defs: Vec<(SymbolId, TermId)> = Vec::new();
    for (i, &a) in work.iter().enumerate() {
        let Some((var, sym, rhs)) = defining_equality(pool, a) else {
            continue;
        };
        if defined_this_round.contains(&var) || used_in_rhs.contains(&var) {
            continue;
        }
        if pool.contains_any(rhs, &|t| t == var || defined_this_round.contains(&t)) {
            continue;
        }
        // Record rhs's variables so later candidates defining them defer.
        let mut stack = vec![rhs];
        let mut seen: FxHashSet<TermId> = FxHashSet::default();
        while let Some(t) = stack.pop() {
            if !seen.insert(t) {
                continue;
            }
            if matches!(pool.op(t), Op::Var(_)) {
                used_in_rhs.insert(t);
            }
            stack.extend_from_slice(pool.args(t));
        }
        subst.insert(var, rhs);
        defined_this_round.insert(var);
        defs.push((sym, rhs));
        defining[i] = true;
    }
    if subst.is_empty() {
        return Some(Round {
            work: work.to_vec(),
            defs,
        });
    }
    let survivors: Vec<TermId> = work
        .iter()
        .enumerate()
        .filter(|(i, _)| !defining[*i])
        .map(|(_, &a)| a)
        .collect();
    let substituted = pool
        .substitute_many(&survivors, &subst)
        .expect("substitution is sort-preserving");
    // The rewriter's sharing-aware flattening consults parent counts computed
    // on the term graph as it was *before* this round. Substitution rebuilds
    // every assertion that mentions a defined variable, and a rebuilt term has
    // no entry, so `term_shared` reports it unshared — which is exactly the
    // licence `ac-flatten` and the linear normalizer need to re-associate a
    // chain of partial sums that a hundred other assertions share, blasting one
    // adder per assertion instead of one for the chain. Recount first.
    count_parents(pool, &substituted, rewriter);
    let mut out: Vec<TermId> = Vec::with_capacity(substituted.len());
    for s in substituted {
        let rw = rewriter.rewrite(pool, s);
        if !flatten_into(pool, rw, &mut out) {
            return None;
        }
    }
    Some(Round { work: out, defs })
}

/// Split nested top-level `and`s; drop `true`; false -> trivially unsat.
fn flatten_into(pool: &TermPool, t: TermId, out: &mut Vec<TermId>) -> bool {
    if t == pool.true_term {
        return true;
    }
    if t == pool.false_term {
        return false;
    }
    if pool.op(t) == Op::And {
        let mut stack: Vec<TermId> = pool.args(t).to_vec();
        while let Some(a) = stack.pop() {
            if a == pool.true_term {
                continue;
            }
            if a == pool.false_term {
                return false;
            }
            if pool.op(a) == Op::And {
                stack.extend_from_slice(pool.args(a));
            } else {
                out.push(a);
            }
        }
        true
    } else {
        out.push(t);
        true
    }
}

/// Recognize the *shape* of a defining assertion (set-based deferral checks
/// happen at the call site):
///   (= x t)   x variable -> x := t
///   x         Bool variable -> x := true
///   (not x)   Bool variable -> x := false
fn defining_equality(pool: &TermPool, a: TermId) -> Option<(TermId, SymbolId, TermId)> {
    let var_sym = |t: TermId| match pool.op(t) {
        Op::Var(sym) => {
            matches!(pool.symbol(sym).sort, Sort::Bool | Sort::BitVec(_)).then_some(sym)
        }
        _ => None,
    };

    match pool.op(a) {
        Op::Var(_) => {
            let sym = var_sym(a)?;
            Some((a, sym, pool.true_term))
        }
        Op::Not => {
            let inner = pool.args(a)[0];
            let sym = var_sym(inner)?;
            Some((inner, sym, pool.false_term))
        }
        Op::Eq => {
            let args = pool.args(a);
            if args.len() != 2 {
                return None;
            }
            let [u, v] = [args[0], args[1]];
            for (var, other) in [(u, v), (v, u)] {
                if var_sym(var).is_some() {
                    return Some((var, var_sym(var).unwrap(), other));
                }
            }
            None
        }
        _ => None,
    }
}
