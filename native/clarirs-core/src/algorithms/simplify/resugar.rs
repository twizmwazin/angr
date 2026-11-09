//! The last step of simplification: re-expressing sums of negated terms as subtractions.
//!
//! The rewrite rules know subtraction only as `a + -b`, which lets the `Add` rules fold and
//! cancel every term of a sum. That form is not what a reader wants to see, so the finished
//! result is rewritten once more: `a + -b` becomes `a - b` and `a + 0xff..fb` becomes `a - 5`.
//!
//! This runs once per `simplify` call, on the final result only. Nodes it produces are
//! flagged `resugared` and recorded as their own simplified form, so neither this pass nor
//! the rewrite rules descend into them again when they turn up inside a later expression:
//! the `Add` rules read a subtraction's terms directly instead of first undoing it.

use std::sync::{Arc, atomic::Ordering};

use crate::{
    algorithms::walk::walk,
    cache::{Cache, GenericCache},
    prelude::*,
};

pub(super) fn resugar<'c>(
    ast: &AstRef<'c>,
    respect_annotations: bool,
    simplified_nodes: &[(AstRef<'c>, AstRef<'c>)],
) -> Result<AstRef<'c>, ClarirsError> {
    if ast.resugared.load(Ordering::Relaxed) {
        return Ok(ast.clone());
    }

    let done: GenericCache<u64, AstRef<'c>> = GenericCache::default();
    let result = walk(
        ast.clone(),
        |node| {
            let skip = node.resugared.load(Ordering::Relaxed)
                || (respect_annotations && super::is_blocked(node));
            Ok(skip.then(|| node.clone()))
        },
        |node, children| {
            let rebuilt = if node
                .child_iter()
                .zip(children)
                .all(|(a, b)| Arc::ptr_eq(&a, b))
            {
                node.clone()
            } else {
                node.context().make_ast_exact(
                    node.op().with_children(children),
                    node.annotations().clone(),
                )?
            };
            let sugared = match rebuilt.op() {
                AstOp::Add(args) => match sum_to_sub(&rebuilt, args)? {
                    Some(op) => node
                        .context()
                        .make_ast_exact(op, node.annotations().clone())?,
                    None => rebuilt,
                },
                _ => rebuilt,
            };
            // The output is final: later calls return it as it is, at no cost.
            sugared.resugared.store(true, Ordering::Relaxed);
            sugared.simplified.store(sugared.hash(), Ordering::Relaxed);
            Ok(sugared)
        },
        &done,
    )?;

    // Point the nodes simplified in this call at the final form of their result, which is
    // the form that stays alive. Nothing changed below the root unless the root did.
    if !Arc::ptr_eq(&result, ast) {
        for (node, simplified) in simplified_nodes {
            if let Some(sugared) = done.get(&simplified.hash()) {
                node.simplified.store(sugared.hash(), Ordering::Relaxed);
            }
        }
    }

    Ok(result)
}

/// Returns the subtraction (or negation) equal to the sum `args`, if it has a term to
/// subtract: a negated term, or a constant that is negative as a signed number.
fn sum_to_sub<'c>(
    sum: &AstRef<'c>,
    args: &[AstRef<'c>],
) -> Result<Option<AstOp<'c>>, ClarirsError> {
    let ctx = sum.context();

    // The magnitude of the constant term, if subtracting it reads better than adding it.
    // The minimum signed value is its own negation and stays as it is.
    let subtracted_constant = |arg: &AstRef<'c>| match arg.op() {
        AstOp::BVV(v) if v.signed_lt(&BitVec::zeros(v.len())).unwrap_or(false) => {
            (-v.clone()).ok().filter(|negated| negated != v)
        }
        _ => None,
    };
    let negated_term = |arg: &AstRef<'c>| match arg.op() {
        AstOp::Neg(inner) if arg.annotations().is_empty() => Some(inner.clone()),
        _ => None,
    };

    let mut added: Vec<AstRef<'c>> = Vec::with_capacity(args.len());
    let mut subtracted: Vec<AstRef<'c>> = Vec::new();
    let mut constant: Option<&AstRef<'c>> = None;
    for arg in args {
        if let Some(inner) = negated_term(arg) {
            subtracted.push(inner);
        } else if matches!(arg.op(), AstOp::BVV(_)) && constant.is_none() {
            constant = Some(arg);
        } else {
            added.push(arg.clone());
        }
    }

    match constant {
        // c + -a => c - a: a lone constant is the minuend whatever its sign.
        Some(constant) if added.is_empty() => added.push(constant.clone()),
        Some(constant) => match subtracted_constant(constant) {
            Some(magnitude) => subtracted.push(ctx.bvv(magnitude)?),
            None => added.push(constant.clone()),
        },
        None => {}
    }
    if subtracted.is_empty() {
        return Ok(None);
    }

    let sum_of = |mut terms: Vec<AstRef<'c>>| match terms.len() {
        1 => Ok(terms.pop().unwrap()),
        _ => ctx.add_many(terms),
    };
    let subtrahend = sum_of(subtracted)?;
    Ok(Some(if added.is_empty() {
        // -a + -b => -(a + b)
        AstOp::Neg(subtrahend)
    } else {
        AstOp::Sub(sum_of(added)?, subtrahend)
    }))
}
