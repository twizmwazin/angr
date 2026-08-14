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

/// Evaluate `roots` under `assignment`, returning the value of each root.
/// Unassigned variables produce an error (callers wanting model completion
/// should complete the assignment first).
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
        let v = match pool.op(t) {
            Op::True => Value::Bool(true),
            Op::False => Value::Bool(false),
            Op::BvConst(id) => Value::Bv(pool.bv_const(id).clone()),
            Op::Var(sym) => match assignment.get(&sym) {
                Some(v) => v.clone(),
                None => {
                    error = Some(EvalError::UnassignedVar(pool.symbol(sym).name.clone()));
                    return;
                }
            },
            Op::Other { name, .. } => {
                error = Some(EvalError::Unsupported(pool.symbol(name).name.clone()));
                return;
            }
            op => {
                let vals: Vec<Value> = pool.args(t).iter().map(|a| cache[a].clone()).collect();
                apply_op(op, &vals).expect("non-leaf op")
            }
        };
        cache.insert(t, v);
    });
    if let Some(e) = error {
        return Err(e);
    }
    Ok(roots.iter().map(|r| cache[r].clone()).collect())
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
}
