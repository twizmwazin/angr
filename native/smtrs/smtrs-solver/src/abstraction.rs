//! Propositional abstraction: the Boolean skeleton of a formula.
//!
//! Every maximal non-Boolean-structural subformula (a theory atom such as
//! `(= x "")`, `(bvult a b)`, `(fp.leq p q)`) is replaced by a fresh Boolean
//! variable, one per distinct term. Boolean connectives and Boolean variables
//! are kept exactly, so the result is an *over-approximation*: every model of
//! the original induces a model of the skeleton.
//!
//! That direction is the useful one. If the skeleton is unsatisfiable, the
//! original is unsatisfiable — with no appeal to whatever theory reasoning we
//! do or do not implement. This turns `unknown` into `unsat` for formulas whose
//! contradiction is purely propositional, which is common in symbolic-execution
//! output: a path condition that asserts both a predicate and its negation
//! because two branches were merged. Kaluza's unsat family, for instance,
//! asserts `T_1 <-> not (= "" v)` and `T_4 <-> (= "" v)` and then asserts both
//! `T_1` and `T_4`.
//!
//! A satisfiable skeleton says nothing at all, so this is only ever consulted
//! on paths that would otherwise answer `unknown`.

use rustc_hash::FxHashMap;
use smtrs_core::{Op, Sort, TermId, TermPool};

/// True when `t` is Boolean *structure* that the abstraction should preserve
/// rather than replace with a fresh variable. Boolean variables and constants
/// count: keeping them is what lets a contradiction between two occurrences of
/// the same variable survive into the skeleton.
fn structural(pool: &TermPool, t: TermId) -> bool {
    if pool.sort(t) != Sort::Bool {
        return false;
    }
    match pool.op(t) {
        Op::True | Op::False | Op::Var(_) => true,
        Op::Not | Op::Implies | Op::And | Op::Or | Op::Xor => true,
        // `=`, `distinct` and `ite` are connectives only when they range over
        // Bool; over any other sort they are theory atoms (or, for `ite`, not
        // Bool-sorted at all and so never reached).
        Op::Eq | Op::Distinct | Op::Ite => pool.args(t).iter().all(|&a| pool.sort(a) == Sort::Bool),
        _ => false,
    }
}

/// Two theory atoms are decidable with no theory reasoning at all: an equality
/// between syntactically identical terms holds, and a `distinct` with a repeated
/// argument does not. Folding them here rather than minting a free variable is
/// what lets the skeleton see through `(= x x)` — which symbolic execution emits
/// whenever two merged branches agree on a value.
fn trivial_atom(pool: &TermPool, t: TermId) -> Option<bool> {
    let args = pool.args(t);
    match pool.op(t) {
        Op::Eq => args.windows(2).all(|w| w[0] == w[1]).then_some(true),
        Op::Distinct => {
            let mut sorted = args.to_vec();
            let n = sorted.len();
            sorted.sort_unstable();
            sorted.dedup();
            (sorted.len() < n).then_some(false)
        }
        _ => None,
    }
}

/// Build the Boolean skeleton of `roots`. The returned terms are in the same
/// order and are all Bool-sorted.
pub fn boolean_abstraction(pool: &mut TermPool, roots: &[TermId]) -> Vec<TermId> {
    let mut memo: FxHashMap<TermId, TermId> = FxHashMap::default();
    // Explicit worklist: only Boolean structure is descended into, so theory
    // terms (which in string problems are by far the bulk of the DAG) are never
    // traversed. `true` marks a node whose children are already done.
    let mut stack: Vec<(TermId, bool)> = roots.iter().rev().map(|&r| (r, false)).collect();

    while let Some((t, expanded)) = stack.pop() {
        if memo.contains_key(&t) {
            continue;
        }
        if !structural(pool, t) {
            let abs = match trivial_atom(pool, t) {
                Some(true) => pool.true_term,
                Some(false) => pool.false_term,
                None => {
                    let sym = pool.fresh_symbol(format!("abs!{}", t.0), Sort::Bool);
                    pool.var(sym)
                }
            };
            memo.insert(t, abs);
            continue;
        }
        let args: Vec<TermId> = pool.args(t).to_vec();
        if args.is_empty() {
            memo.insert(t, t);
            continue;
        }
        if !expanded {
            stack.push((t, true));
            stack.extend(args.into_iter().rev().map(|a| (a, false)));
            continue;
        }
        let new_args: Vec<TermId> = args.iter().map(|a| memo[a]).collect();
        let nt = pool
            .mk(pool.op(t), &new_args)
            .expect("abstraction preserves sorts: Bool connectives over Bool");
        memo.insert(t, nt);
    }

    roots.iter().map(|r| memo[r]).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Kaluza shape: two Boolean definitions of the same theory atom, one
    /// negated, both asserted. Propositionally unsat, no theory needed.
    #[test]
    fn contradictory_definitions_of_one_atom() {
        let mut pool = TermPool::new();
        let x = {
            let s = pool.fresh_symbol("x", Sort::BitVec(8));
            pool.var(s)
        };
        let zero = pool.bv_u64(8, 0);
        let atom = pool.mk(Op::Eq, &[x, zero]).unwrap();
        let t1 = {
            let s = pool.fresh_symbol("t1", Sort::Bool);
            pool.var(s)
        };
        let t4 = {
            let s = pool.fresh_symbol("t4", Sort::Bool);
            pool.var(s)
        };
        let not_atom = pool.mk(Op::Not, &[atom]).unwrap();
        let d1 = pool.mk(Op::Eq, &[t1, not_atom]).unwrap();
        let d4 = pool.mk(Op::Eq, &[t4, atom]).unwrap();
        let roots = vec![d1, t1, d4, t4];

        let abs = boolean_abstraction(&mut pool, &roots);
        // Both definitions must reference the *same* abstract variable, or the
        // contradiction is lost.
        let mut solver = crate::Solver::new();
        for r in &abs {
            solver.assert(*r);
        }
        assert!(matches!(
            solver.check_sat(&mut pool, &[]),
            crate::Answer::Unsat
        ));
    }

    /// A theory-only contradiction must *not* be claimed by the abstraction:
    /// `x < 0 && x > 0` over BV is unsat, but its skeleton is two unrelated
    /// variables and is satisfiable.
    #[test]
    fn theory_contradiction_is_not_visible() {
        let mut pool = TermPool::new();
        let x = {
            let s = pool.fresh_symbol("x", Sort::BitVec(8));
            pool.var(s)
        };
        let zero = pool.bv_u64(8, 0);
        let lt = pool.mk(Op::BvUlt, &[x, zero]).unwrap();
        let gt = pool.mk(Op::BvUgt, &[x, zero]).unwrap();
        let abs = boolean_abstraction(&mut pool, &[lt, gt]);
        let mut solver = crate::Solver::new();
        for r in &abs {
            solver.assert(*r);
        }
        assert!(matches!(
            solver.check_sat(&mut pool, &[]),
            crate::Answer::Sat
        ));
    }

    /// Distinct occurrences of one atom share an abstract variable; different
    /// atoms do not.
    #[test]
    fn atoms_are_shared_by_identity() {
        let mut pool = TermPool::new();
        let x = {
            let s = pool.fresh_symbol("x", Sort::BitVec(8));
            pool.var(s)
        };
        let y = {
            let s = pool.fresh_symbol("y", Sort::BitVec(8));
            pool.var(s)
        };
        let a = pool.mk(Op::BvUlt, &[x, y]).unwrap();
        let b = pool.mk(Op::BvUlt, &[y, x]).unwrap();
        let na = pool.mk(Op::Not, &[a]).unwrap();
        let abs = boolean_abstraction(&mut pool, &[a, na, b]);
        // abs[1] is `not abs[0]`.
        assert_eq!(pool.op(abs[1]), Op::Not);
        assert_eq!(pool.args(abs[1])[0], abs[0]);
        assert_ne!(abs[0], abs[2]);
    }
}
