#![allow(clippy::mutable_key_type)]

use std::cell::OnceCell;
use std::cmp::Reverse;
use std::collections::HashMap;
use std::iter;
use std::mem::discriminant;
use std::sync::Arc;

use crate::{algorithms::walk, cache::GenericCache, prelude::*};

/// The operands of `op` when it is associative and commutative, so that the
/// order and grouping of its operands carry no meaning; `None` otherwise.
fn commutative_operands<'a, 'c>(op: &'a AstOp<'c>) -> Option<&'a [AstRef<'c>]> {
    match op {
        AstOp::And(v)
        | AstOp::Or(v)
        | AstOp::Xor(v)
        | AstOp::Add(v)
        | AstOp::Mul(v)
        | AstOp::Union(v)
        | AstOp::Intersection(v) => Some(v),
        _ => None,
    }
}

/// Rebuilds `node` from its replaced `children`, first substituting every
/// `(from, to)` in `patterns` whose `from` is the same commutative op as
/// `node` and whose operands are all among `node`'s original operands, as
/// often as they are. The `to`s follow the unmatched operands (which keep
/// their replaced forms), and a lone operand is returned bare.
fn substitute_operands<'c, 'p>(
    ctx: &'c Context<'c>,
    node: &AstRef<'c>,
    children: &[AstRef<'c>],
    patterns: impl FnOnce() -> &'p [(&'p AstRef<'c>, &'p AstRef<'c>)],
) -> Result<AstRef<'c>, ClarirsError>
where
    'c: 'p,
{
    let Some(operands) = commutative_operands(node.op()) else {
        return ctx.make_ast(node.op().with_children(children));
    };
    let patterns = patterns();
    if patterns.is_empty() {
        return ctx.make_ast(node.op().with_children(children));
    }
    // The multiset of `asts`, as hash → number of occurrences.
    let multiset = |asts: &[AstRef<'c>]| {
        asts.iter().fold(HashMap::new(), |mut counts, ast| {
            *counts.entry(ast.hash()).or_insert(0usize) += 1;
            counts
        })
    };
    // Match each pattern as often as its operands fit in the unmatched ones.
    let (mut unmatched, substituted) = patterns
        .iter()
        .filter(|(from, _)| discriminant(from.op()) == discriminant(node.op()))
        .try_fold(
            (multiset(operands), Vec::new()),
            |(mut unmatched, mut substituted), (from, to)| {
                let needed = multiset(commutative_operands(from.op()).unwrap_or_default());
                let times = needed
                    .iter()
                    .map(|(hash, n)| unmatched.get(hash).unwrap_or(&0) / n)
                    .min()
                    .unwrap_or(0);
                if times > 0 && to.ast_type() != node.ast_type() {
                    return Err(ClarirsError::TypeError(
                        "Replace types must match!".to_string(),
                    ));
                }
                for (hash, n) in &needed {
                    unmatched.entry(*hash).and_modify(|left| *left -= times * n);
                }
                substituted.extend(iter::repeat_n((*to).clone(), times));
                Ok((unmatched, substituted))
            },
        )?;
    if substituted.is_empty() {
        return ctx.make_ast(node.op().with_children(children));
    }
    // The unmatched operands, in their replaced forms, then the substitutes.
    let new_children: Vec<_> = operands
        .iter()
        .zip(children)
        .filter(|(operand, _)| match unmatched.get_mut(&operand.hash()) {
            Some(left) if *left > 0 => {
                *left -= 1;
                true
            }
            _ => false,
        })
        .map(|(_, child)| child.clone())
        .chain(substituted)
        .collect();
    match new_children.as_slice() {
        [only] => Ok(only.clone()),
        _ => ctx.make_ast(node.op().with_children(&new_children)),
    }
}

impl<'c> AstNode<'c> {
    /// Replaces every occurrence of `from` in this AST with `to`.
    ///
    /// When `from` is an associative and commutative op (`And`, `Or`, `Xor`,
    /// `Add`, `Mul`, `Union`, `Intersection`), it also matches, in any
    /// order, a subset of the operands of a larger node of the same op:
    /// `(a + b + c).replace(a + c, d)` gives `b + d`.
    pub fn replace<T: Clone + Into<AstRef<'c>>>(
        self: &Arc<Self>,
        from: &T,
        to: &T,
    ) -> Result<AstRef<'c>, ClarirsError> {
        let from = from.clone().into();
        let to = to.clone().into();
        self.replace_many(&HashMap::from([(from, to)]))
    }

    /// Applies every `from → to` in `replacements` in a single pass. Each
    /// `from` matches as described on [`replace`](Self::replace); a matched
    /// node or operand is taken as it was, and nothing inside `to` is replaced.
    ///
    /// Every replacement must preserve the sort of what it replaces,
    /// including bitvector width and float format; a mismatch is a
    /// [`ClarirsError::TypeError`].
    pub fn replace_many(
        self: &Arc<Self>,
        replacements: &HashMap<AstRef<'c>, AstRef<'c>>,
    ) -> Result<AstRef<'c>, ClarirsError> {
        if replacements.is_empty() {
            return Ok(self.clone());
        }

        // Operand-subset patterns, most operands first so that the most
        // specific one wins, then by hash for determinism. Collected once the
        // walk reaches a commutative node, as replacements are mostly leaves.
        let patterns = OnceCell::new();
        let patterns = || {
            patterns
                .get_or_init(|| {
                    let mut patterns: Vec<_> = replacements
                        .iter()
                        .filter(|(from, _)| {
                            commutative_operands(from.op()).is_some_and(|v| !v.is_empty())
                        })
                        .collect();
                    patterns
                        .sort_by_key(|(from, _)| (Reverse(from.op().num_children()), from.hash()));
                    patterns
                })
                .as_slice()
        };

        let ctx = self.context();
        walk(
            self.clone(),
            |node| match replacements.get(node) {
                // Comparing the cached types covers width and float format.
                Some(replacement) if replacement.ast_type() != node.ast_type() => Err(
                    ClarirsError::TypeError("Replace types must match!".to_string()),
                ),
                replacement => Ok(replacement.cloned()),
            },
            |node, children| substitute_operands(ctx, &node, children, patterns),
            &GenericCache::default(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replace() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let [a, b, c] = ["a", "b", "c"].map(|n| ctx.bvs(n, 32).unwrap());
        let expr = ctx.add(ctx.mul(&a, &b)?, &a)?;

        assert_eq!(expr.replace(&a, &c)?, ctx.add(ctx.mul(&c, &b)?, &c)?);
        assert_eq!(expr.replace(&ctx.mul(&a, &b)?, &c)?, ctx.add(&c, &a)?);
        // Nothing inside `to` is replaced.
        assert_eq!(
            expr.replace(&a, &ctx.neg(&a)?)?,
            ctx.add(ctx.mul(ctx.neg(&a)?, &b)?, ctx.neg(&a)?)?
        );
        assert_eq!(expr.replace(&c, &a)?, expr);
        Ok(())
    }

    #[test]
    fn test_replace_type_mismatch() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let a = ctx.bvs("a", 32)?;
        let expr = ctx.add(&a, &a)?;
        let narrow = ctx.bvs("n", 8)?;
        let boolean = ctx.bools("p")?;

        // Width and sort are both checked, by `replace` and `replace_many`,
        // for whole-node and operand matches alike.
        for wrong in [&narrow, &boolean] {
            assert!(matches!(
                expr.replace(&a, wrong),
                Err(ClarirsError::TypeError(_))
            ));
            assert!(matches!(
                expr.replace_many(&HashMap::from([(a.clone(), wrong.clone())])),
                Err(ClarirsError::TypeError(_))
            ));
            assert!(matches!(
                ctx.add_many([a.clone(), a.clone(), a.clone()])?
                    .replace(&expr, wrong),
                Err(ClarirsError::TypeError(_))
            ));
        }
        // The check applies only to replacements that match.
        assert_eq!(expr.replace(&narrow, &boolean)?, expr);
        Ok(())
    }

    #[test]
    fn test_replace_operand_subset() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let [a, b, c, d, e] = ["a", "b", "c", "d", "e"].map(|n| ctx.bvs(n, 32).unwrap());
        let from = ctx.add(&a, &c)?;
        let abc = ctx.add_many([a.clone(), b.clone(), c.clone()])?;

        // (a + b + c).replace(a + c, d) -> b + d, in any operand order.
        assert_eq!(abc.replace(&from, &d)?, ctx.add(&b, &d)?);
        assert_eq!(abc.replace(&ctx.add(&c, &a)?, &d)?, ctx.add(&b, &d)?);
        assert_eq!(ctx.add(&c, &a)?.replace(&from, &d)?, d);
        assert_eq!(
            ctx.and([a.clone(), b.clone(), c.clone()])?
                .replace(&ctx.and2(&c, &b)?, &d)?,
            ctx.and2(&a, &d)?
        );
        // Every matching set of operands is replaced; repeats must be there
        // as often as in the pattern.
        assert_eq!(
            ctx.add_many([a.clone(), c.clone(), b.clone(), a.clone(), c.clone()])?
                .replace(&from, &d)?,
            ctx.add_many([b.clone(), d.clone(), d.clone()])?
        );
        assert_eq!(
            abc.replace(&ctx.add_many([a.clone(), a.clone(), c.clone()])?, &d)?,
            abc
        );
        // A missing operand, another op, a nested node of the same op, or a
        // non-commutative op leave the expression alone.
        assert_eq!(abc.replace(&ctx.add(&a, &e)?, &d)?, abc);
        assert_eq!(abc.replace(&ctx.mul(&a, &c)?, &d)?, abc);
        let nested = ctx.add(ctx.add(&a, &b)?, &c)?;
        assert_eq!(nested.replace(&from, &d)?, nested);
        let concat = ctx.concat([a.clone(), b.clone(), c.clone()])?;
        assert_eq!(
            concat.replace(&ctx.concat2(&a, &c)?, &ctx.bvs("w", 64)?)?,
            concat
        );
        // Matches inside other ops; the unmatched operands still get their
        // own replacements, a matched operand is taken as it was.
        let replacements = HashMap::from([(from.clone(), d.clone()), (b.clone(), e.clone())]);
        let expr = ctx.mul(
            ctx.add_many([a.clone(), ctx.neg(&from)?, c.clone()])?,
            ctx.add_many([b.clone(), abc.clone()])?,
        )?;
        assert_eq!(
            expr.replace_many(&replacements)?,
            ctx.mul(ctx.add(ctx.neg(&d)?, &d)?, ctx.add(&e, ctx.add(&e, &d)?)?)?
        );
        // The pattern with more operands takes precedence.
        let replacements = HashMap::from([(from.clone(), d.clone()), (abc.clone(), e.clone())]);
        assert_eq!(
            ctx.add_many([a.clone(), b.clone(), c.clone(), c.clone()])?
                .replace_many(&replacements)?,
            ctx.add(&c, &e)?
        );
        Ok(())
    }
}
