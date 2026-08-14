//! Ground evaluation of terms under a variable assignment.
//!
//! This is the semantic ground truth for the whole project: the rewriter's
//! constant folding, the harness's model validation, and the solver's
//! debug-mode self-checks all go through here.

use crate::bvconst::BvConst;
use crate::op::Op;
use crate::pool::{SymbolId, TermId, TermPool};
use rustc_hash::FxHashMap;

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Value {
    Bool(bool),
    Bv(BvConst),
}

impl Value {
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_bv(&self) -> Option<&BvConst> {
        match self {
            Value::Bv(c) => Some(c),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub enum EvalError {
    /// Term contains an operator outside the supported fragment.
    Unsupported(String),
    /// A variable has no value in the assignment.
    UnassignedVar(String),
}

impl std::fmt::Display for EvalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvalError::Unsupported(s) => write!(f, "cannot evaluate unsupported op {s}"),
            EvalError::UnassignedVar(s) => write!(f, "variable {s} has no assigned value"),
        }
    }
}

impl std::error::Error for EvalError {}

/// Apply a supported non-leaf operator to already-evaluated operand values.
/// Returns None for leaves and `Op::Other`. This single function defines the
/// concrete semantics of every operator; the evaluator and the rewriter's
/// constant folding both call it.
pub fn apply_op(op: Op, vals: &[Value]) -> Option<Value> {
    let b = |i: usize| vals[i].as_bool().expect("sort-checked bool");
    let bv = |i: usize| vals[i].as_bv().expect("sort-checked bv");
    let fold = |f: fn(&BvConst, &BvConst) -> BvConst| {
        let mut acc = bv(0).clone();
        for v in &vals[1..] {
            acc = f(&acc, v.as_bv().expect("sort-checked bv"));
        }
        Value::Bv(acc)
    };

    Some(match op {
        Op::True | Op::False | Op::BvConst(_) | Op::Var(_) | Op::Other { .. } => return None,
        // FP is lowered to BV before solving (smtrs-fp), so by the time any
        // term reaches the evaluator its FP operators are already gone.
        // Listed explicitly rather than via a catch-all so that adding a new
        // BV/Bool operator still fails exhaustiveness here.
        Op::RmConst(_)
        | Op::FpFromBits
        | Op::FpNan
        | Op::FpInf(_)
        | Op::FpZero(_)
        | Op::FpAbs
        | Op::FpNeg
        | Op::FpAdd
        | Op::FpSub
        | Op::FpMul
        | Op::FpDiv
        | Op::FpSqrt
        | Op::FpFma
        | Op::FpRoundToIntegral
        | Op::FpRem
        | Op::FpMin
        | Op::FpMax
        | Op::FpLeq
        | Op::FpLt
        | Op::FpGeq
        | Op::FpGt
        | Op::FpEq
        | Op::FpIsNormal
        | Op::FpIsSubnormal
        | Op::FpIsZero
        | Op::FpIsInfinite
        | Op::FpIsNan
        | Op::FpIsNegative
        | Op::FpIsPositive
        | Op::FpFromIeeeBv { .. }
        | Op::FpToFp { .. }
        | Op::FpFromSignedBv { .. }
        | Op::FpFromUnsignedBv { .. }
        | Op::FpToIeeeBv
        | Op::FpToUbv(_)
        | Op::FpToSbv(_) => return None,

        Op::Not => Value::Bool(!b(0)),
        Op::Implies => {
            // Right-associative chain: a => b => c  ==  a => (b => c).
            let mut result = b(vals.len() - 1);
            for i in (0..vals.len() - 1).rev() {
                result = !b(i) || result;
            }
            Value::Bool(result)
        }
        Op::And => Value::Bool((0..vals.len()).all(b)),
        Op::Or => Value::Bool((0..vals.len()).any(b)),
        Op::Xor => Value::Bool((0..vals.len()).filter(|&i| b(i)).count() % 2 == 1),
        Op::Eq => Value::Bool(vals.windows(2).all(|w| w[0] == w[1])),
        Op::Distinct => {
            let mut ok = true;
            for i in 0..vals.len() {
                for j in i + 1..vals.len() {
                    if vals[i] == vals[j] {
                        ok = false;
                    }
                }
            }
            Value::Bool(ok)
        }
        Op::Ite => {
            if b(0) {
                vals[1].clone()
            } else {
                vals[2].clone()
            }
        }

        Op::BvNeg => Value::Bv(bv(0).neg()),
        Op::BvNot => Value::Bv(bv(0).not()),
        Op::BvAdd => fold(|a, x| a.add(x)),
        Op::BvSub => Value::Bv(bv(0).sub(bv(1))),
        Op::BvMul => fold(|a, x| a.mul(x)),
        Op::BvUdiv => Value::Bv(bv(0).udiv(bv(1))),
        Op::BvUrem => Value::Bv(bv(0).urem(bv(1))),
        Op::BvSdiv => Value::Bv(bv(0).sdiv(bv(1))),
        Op::BvSrem => Value::Bv(bv(0).srem(bv(1))),
        Op::BvSmod => Value::Bv(bv(0).smod(bv(1))),
        Op::BvAnd => fold(|a, x| a.and(x)),
        Op::BvOr => fold(|a, x| a.or(x)),
        Op::BvXor => fold(|a, x| a.xor(x)),
        Op::BvNand => Value::Bv(bv(0).and(bv(1)).not()),
        Op::BvNor => Value::Bv(bv(0).or(bv(1)).not()),
        Op::BvXnor => Value::Bv(bv(0).xor(bv(1)).not()),
        Op::BvComp => Value::Bv(BvConst::from_u64(1, (bv(0) == bv(1)) as u64)),
        Op::BvShl => Value::Bv(bv(0).shl(bv(1))),
        Op::BvLshr => Value::Bv(bv(0).lshr(bv(1))),
        Op::BvAshr => Value::Bv(bv(0).ashr(bv(1))),
        Op::Concat => fold(|a, x| a.concat(x)),
        Op::Extract { hi, lo } => Value::Bv(bv(0).extract(hi, lo)),
        Op::ZeroExtend(n) => Value::Bv(bv(0).zero_extend(n)),
        Op::SignExtend(n) => Value::Bv(bv(0).sign_extend(n)),
        Op::RotateLeft(n) => Value::Bv(bv(0).rotate_left(n)),
        Op::RotateRight(n) => Value::Bv(bv(0).rotate_right(n)),
        Op::Repeat(n) => Value::Bv(bv(0).repeat(n)),
        Op::BvUlt => Value::Bool(bv(0).ult(bv(1))),
        Op::BvUle => Value::Bool(bv(0).ule(bv(1))),
        Op::BvUgt => Value::Bool(bv(1).ult(bv(0))),
        Op::BvUge => Value::Bool(bv(1).ule(bv(0))),
        Op::BvSlt => Value::Bool(bv(0).slt(bv(1))),
        Op::BvSle => Value::Bool(bv(0).sle(bv(1))),
        Op::BvSgt => Value::Bool(bv(1).slt(bv(0))),
        Op::BvSge => Value::Bool(bv(1).sle(bv(0))),
    })
}

/// Value of one node, given values for all of its operands. Shared by the
/// one-shot [`eval`] and by [`Evaluator`] so that the two cannot drift apart.
fn node_value(
    pool: &TermPool,
    t: TermId,
    assignment: &FxHashMap<SymbolId, Value>,
    cache: &FxHashMap<TermId, Value>,
) -> Result<Value, EvalError> {
    Ok(match pool.op(t) {
        Op::True => Value::Bool(true),
        Op::False => Value::Bool(false),
        Op::BvConst(id) => Value::Bv(pool.bv_const(id).clone()),
        Op::Var(sym) => match assignment.get(&sym) {
            Some(v) => v.clone(),
            None => return Err(EvalError::UnassignedVar(pool.symbol(sym).name.clone())),
        },
        Op::Other { name, .. } => {
            return Err(EvalError::Unsupported(pool.symbol(name).name.clone()))
        }
        op => {
            let vals: Vec<Value> = pool.args(t).iter().map(|a| cache[a].clone()).collect();
            apply_op(op, &vals).expect("non-leaf op")
        }
    })
}

/// Evaluate `roots` under `assignment`, returning the value of each root.
/// Unassigned variables produce an error (callers wanting model completion
/// should complete the assignment first).
///
/// One-shot. A caller evaluating a *sequence* of terms over one pool under a
/// growing assignment wants [`Evaluator`] instead.
pub fn eval(
    pool: &TermPool,
    roots: &[TermId],
    assignment: &FxHashMap<SymbolId, Value>,
) -> Result<Vec<Value>, EvalError> {
    let mut cache: FxHashMap<TermId, Value> = FxHashMap::default();
    let mut error: Option<EvalError> = None;
    pool.post_order(roots, |pool, t| {
        if error.is_some() {
            return;
        }
        match node_value(pool, t, assignment, &cache) {
            Ok(v) => {
                cache.insert(t, v);
            }
            Err(e) => error = Some(e),
        }
    });
    if let Some(e) = error {
        return Err(e);
    }
    Ok(roots.iter().map(|r| cache[r].clone()).collect())
}

/// An evaluation that outlives a single call, so that a *sequence* of
/// evaluations over one term pool shares one traversal and one value cache.
///
/// This is what model reconstruction needs. Eliminating `n` variables leaves
/// `n` defining terms to evaluate, their cones overlap heavily, and a
/// standalone [`eval`] per term re-walks the shared part once per definition
/// and allocates a fresh cache each time — work quadratic in the pool. One
/// `Evaluator` threaded through the sequence makes the total proportional to
/// the reachable set, visited once.
///
/// **Contract.** The caller may *extend* `assignment` between calls but must
/// never change a value already in it, and must not mutate the pool's existing
/// nodes: cached term values are never invalidated. Growing the pool is fine.
/// (Both hold for model reconstruction: each definition's value is inserted
/// once and never revised.) An `Err` leaves the evaluator empty rather than
/// half-populated, so it stays usable — see the abandoned-traversal note in
/// [`TermPool::post_order_memo`].
#[derive(Default)]
pub struct Evaluator {
    seen: Vec<bool>,
    cache: FxHashMap<TermId, Value>,
}

impl Evaluator {
    /// Value of each of `roots`, reusing everything already computed.
    pub fn eval(
        &mut self,
        pool: &TermPool,
        roots: &[TermId],
        assignment: &FxHashMap<SymbolId, Value>,
    ) -> Result<Vec<Value>, EvalError> {
        // Disjoint field borrows: the visit map is threaded through the
        // traversal while the closure holds the cache.
        let Evaluator { seen, cache } = self;
        let mut error: Option<EvalError> = None;
        pool.post_order_memo(seen, roots, |pool, t| {
            if error.is_some() {
                return;
            }
            match node_value(pool, t, assignment, cache) {
                Ok(v) => {
                    cache.insert(t, v);
                }
                Err(e) => error = Some(e),
            }
        });
        if let Some(e) = error {
            // The abandoned traversal marked nodes visited that never got a
            // value, so the shared state is no longer a consistent memo.
            self.seen.clear();
            self.cache.clear();
            return Err(e);
        }
        Ok(roots.iter().map(|r| self.cache[r].clone()).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sort::Sort;

    #[test]
    fn eval_basic() {
        let mut p = TermPool::new();
        let xs = p.fresh_symbol("x", Sort::BitVec(8));
        let x = p.var(xs);
        let five = p.bv_u64(8, 5);
        let sum = p.mk(Op::BvAdd, &[x, five]).unwrap();
        let ten = p.bv_u64(8, 10);
        let cmp = p.mk(Op::BvUlt, &[sum, ten]).unwrap();

        let mut asg = FxHashMap::default();
        asg.insert(xs, Value::Bv(BvConst::from_u64(8, 3)));
        let vals = eval(&p, &[sum, cmp], &asg).unwrap();
        assert_eq!(vals[0], Value::Bv(BvConst::from_u64(8, 8)));
        assert_eq!(vals[1], Value::Bool(true));

        asg.insert(xs, Value::Bv(BvConst::from_u64(8, 250)));
        let vals = eval(&p, &[sum, cmp], &asg).unwrap();
        assert_eq!(vals[0], Value::Bv(BvConst::from_u64(8, 255)));
        assert_eq!(vals[1], Value::Bool(false));
    }

    #[test]
    fn unassigned_var_errors() {
        let mut p = TermPool::new();
        let xs = p.fresh_symbol("x", Sort::Bool);
        let x = p.var(xs);
        assert!(matches!(
            eval(&p, &[x], &FxHashMap::default()),
            Err(EvalError::UnassignedVar(_))
        ));
    }

    /// The property the solver relies on: over a sequence of evaluations under
    /// a *growing* assignment, a shared `Evaluator` returns exactly what a
    /// fresh one-shot `eval` returns at each step. This is model
    /// reconstruction's shape — a chain of definitions, each evaluated after
    /// the previous one's value has been added to the assignment — so if
    /// sharing the memo across the sequence could ever be wrong, it is wrong
    /// here.
    #[test]
    fn evaluator_sequence_matches_a_fresh_eval_at_every_step() {
        let mut p = TermPool::new();
        let bs: Vec<SymbolId> = (0..4)
            .map(|i| p.fresh_symbol(format!("b{i}"), Sort::BitVec(16)))
            .collect();
        let bvars: Vec<TermId> = bs.iter().map(|&s| p.var(s)).collect();

        // t0 = b0 + b1; t[i] = (t[i-1] ^ b[i%4]) * (t[i-1] + 3) ... a chain
        // whose cones nest, plus reuse of the earlier links.
        let mut defs: Vec<(SymbolId, TermId)> = Vec::new();
        let three = p.bv_u64(16, 3);
        let mut rhs = p.mk(Op::BvAdd, &[bvars[0], bvars[1]]).unwrap();
        for i in 0..8usize {
            let sym = p.fresh_symbol(format!("t{i}"), Sort::BitVec(16));
            defs.push((sym, rhs));
            let v = p.var(sym);
            let a = p.mk(Op::BvXor, &[v, bvars[i % 4]]).unwrap();
            let b = p.mk(Op::BvAdd, &[v, three]).unwrap();
            rhs = p.mk(Op::BvMul, &[a, b]).unwrap();
        }

        let mut assignment: FxHashMap<SymbolId, Value> = FxHashMap::default();
        for (i, &s) in bs.iter().enumerate() {
            assignment.insert(s, Value::Bv(BvConst::from_u64(16, 1000 + i as u64 * 37)));
        }

        let mut ev = Evaluator::default();
        for (sym, rhs) in &defs {
            let want = eval(&p, &[*rhs], &assignment).expect("one-shot");
            let got = ev.eval(&p, &[*rhs], &assignment).expect("shared");
            assert_eq!(
                got,
                want,
                "shared evaluator diverged on {}",
                p.symbol(*sym).name
            );
            assignment.insert(*sym, got[0].clone());
        }
        // And a final multi-root evaluation over the whole chain, the way
        // model validation re-checks every assertion.
        let roots: Vec<TermId> = defs.iter().map(|&(_, r)| r).collect();
        assert_eq!(
            ev.eval(&p, &roots, &assignment).expect("shared"),
            eval(&p, &roots, &assignment).expect("one-shot")
        );
    }

    /// An `Err` must leave the evaluator empty rather than half-populated: the
    /// abandoned traversal marked nodes it never gave a value to, and a
    /// surviving mark would silently skip that node — and read a stale or
    /// missing value — on the next call.
    #[test]
    fn evaluator_recovers_from_an_error() {
        let mut p = TermPool::new();
        let xs = p.fresh_symbol("x", Sort::BitVec(8));
        let x = p.var(xs);
        let ys = p.fresh_symbol("y", Sort::BitVec(8));
        let y = p.var(ys);
        let sum = p.mk(Op::BvAdd, &[x, y]).unwrap();

        let mut asg: FxHashMap<SymbolId, Value> = FxHashMap::default();
        asg.insert(xs, Value::Bv(BvConst::from_u64(8, 5)));

        let mut ev = Evaluator::default();
        assert!(matches!(
            ev.eval(&p, &[sum], &asg),
            Err(EvalError::UnassignedVar(_))
        ));
        // Now supply `y` and re-run: nothing from the abandoned walk may
        // survive, so the answer must be the one a fresh evaluator gives.
        asg.insert(ys, Value::Bv(BvConst::from_u64(8, 9)));
        assert_eq!(
            ev.eval(&p, &[sum], &asg).expect("now complete"),
            eval(&p, &[sum], &asg).expect("one-shot")
        );
    }
}
