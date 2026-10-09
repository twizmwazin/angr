use std::collections::HashSet;
use std::sync::Arc;

use crate::{algorithms::walk, ast::op::AstOp, cache::GenericCache, prelude::*};

impl<'c> AstNode<'c> {
    /// Expands every `MultiValue` in this AST, returning the expressions it can
    /// stand for, simplified and without duplicates.
    ///
    /// A `MultiValue` node denotes one choice among its members, and every
    /// occurrence of the same node takes the same choice: `x - x` for
    /// `x = MultiValue(a, b)` expands to `[0]`, not `[0, a - b, b - a]`. This
    /// matches how the simplifier treats repeated subexpressions. Two distinct
    /// `MultiValue` nodes are independent, so `MultiValue(a, b) +
    /// MultiValue(c, d)` expands to all four sums.
    ///
    /// Returns `None` when there would be more than `limit` alternatives. An
    /// AST without any `MultiValue` expands to itself.
    pub fn excavate_multi_value(
        self: &Arc<Self>,
        limit: Option<usize>,
    ) -> Result<Option<Vec<AstRef<'c>>>, ClarirsError> {
        let mut pending: Vec<AstRef<'c>> = vec![self.clone()];
        let mut seen_pending: HashSet<u64> = HashSet::from([self.hash()]);
        let mut done: Vec<AstRef<'c>> = Vec::new();
        let mut seen_done: HashSet<u64> = HashSet::new();
        let mut next = 0;

        while next < pending.len() {
            let expr = pending[next].clone();
            next += 1;
            match find_multi_value(&expr) {
                None => {
                    let simplified = expr.simplify()?;
                    if seen_done.insert(simplified.hash()) {
                        done.push(simplified);
                    }
                }
                Some(multi_value) => {
                    let AstOp::MultiValue(members) = multi_value.op() else {
                        unreachable!("find_multi_value returned a non-MultiValue node");
                    };
                    for member in members {
                        let substituted = substitute(&expr, &multi_value, member)?;
                        if seen_pending.insert(substituted.hash()) {
                            pending.push(substituted);
                        }
                    }
                }
            }
            // Every expression still pending yields at least one alternative.
            if limit.is_some_and(|limit| done.len() + (pending.len() - next) > limit) {
                return Ok(None);
            }
        }

        Ok(Some(done))
    }
}

/// Returns the first `MultiValue` node found walking `ast` top-down.
fn find_multi_value<'c>(ast: &AstRef<'c>) -> Option<AstRef<'c>> {
    let mut stack = vec![ast.clone()];
    let mut visited: HashSet<u64> = HashSet::new();
    while let Some(node) = stack.pop() {
        if !visited.insert(node.hash()) {
            continue;
        }
        if matches!(node.op(), AstOp::MultiValue(..)) {
            return Some(node);
        }
        // Push in reverse so the leftmost child is examined first.
        let children: Vec<_> = node.child_iter().collect();
        stack.extend(children.into_iter().rev());
    }
    None
}

/// Replaces every occurrence of `from` in `ast` with `to`. Rebuilt nodes keep
/// their own annotations and gain the relocatable annotations of their new
/// children, so a member's annotations reach the expressions built from it.
fn substitute<'c>(
    ast: &AstRef<'c>,
    from: &AstRef<'c>,
    to: &AstRef<'c>,
) -> Result<AstRef<'c>, ClarirsError> {
    let ctx = ast.context();
    walk(
        ast.clone(),
        |node| Ok((node == from).then(|| to.clone())),
        |node, children| {
            let unchanged = node
                .child_iter()
                .zip(children)
                .all(|(old, new)| &old == new);
            if unchanged {
                return Ok(node);
            }
            match node.op().with_children(children) {
                Some(op) => ctx.make_ast_annotated(op, node.annotations().clone()),
                None => Ok(node),
            }
        },
        &GenericCache::default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bvv<'c>(ctx: &'c Context<'c>, value: u64) -> AstRef<'c> {
        ctx.bvv(BitVec::from((value, 32))).unwrap()
    }

    fn hashes(values: &[AstRef<'_>]) -> HashSet<u64> {
        values.iter().map(|v| v.hash()).collect()
    }

    #[test]
    fn test_no_multi_value_expands_to_itself() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let x = ctx.bvs("x", 32)?;
        let expr = ctx.add(&x, bvv(&ctx, 1))?;
        let result = expr.excavate_multi_value(None)?.unwrap();
        assert_eq!(result, vec![expr.simplify()?]);
        Ok(())
    }

    #[test]
    fn test_distributes_over_operation() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let x = ctx.bvs("x", 32)?;
        let mv = ctx.multi_value([bvv(&ctx, 1), x.clone()])?;
        let expr = ctx.add(&mv, bvv(&ctx, 2))?;
        let result = expr.excavate_multi_value(None)?.unwrap();
        let expected = [bvv(&ctx, 3), ctx.add(&x, bvv(&ctx, 2))?.simplify()?];
        assert_eq!(hashes(&result), hashes(&expected));
        Ok(())
    }

    #[test]
    fn test_same_node_is_correlated() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mv = ctx.multi_value([bvv(&ctx, 1), bvv(&ctx, 5)])?;
        let expr = ctx.sub(&mv, &mv)?;
        let result = expr.excavate_multi_value(None)?.unwrap();
        assert_eq!(result, vec![bvv(&ctx, 0)]);
        Ok(())
    }

    #[test]
    fn test_distinct_nodes_are_independent() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let a = ctx.multi_value([bvv(&ctx, 1), bvv(&ctx, 2)])?;
        let b = ctx.multi_value([bvv(&ctx, 10), bvv(&ctx, 20)])?;
        let expr = ctx.add(&a, &b)?;
        let result = expr.excavate_multi_value(None)?.unwrap();
        let expected = [11, 21, 12, 22].map(|v| bvv(&ctx, v));
        assert_eq!(hashes(&result), hashes(&expected));
        Ok(())
    }

    #[test]
    fn test_nested_multi_value_in_member() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let x = ctx.bvs("x", 32)?;
        let inner = ctx.multi_value([bvv(&ctx, 1), bvv(&ctx, 2)])?;
        let outer = ctx.multi_value([ctx.add(&x, &inner)?, bvv(&ctx, 7)])?;
        let result = outer.excavate_multi_value(None)?.unwrap();
        let expected = [
            ctx.add(&x, bvv(&ctx, 1))?.simplify()?,
            ctx.add(&x, bvv(&ctx, 2))?.simplify()?,
            bvv(&ctx, 7),
        ];
        assert_eq!(hashes(&result), hashes(&expected));
        Ok(())
    }

    #[test]
    fn test_limit() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let a = ctx.multi_value([bvv(&ctx, 1), bvv(&ctx, 2)])?;
        let b = ctx.multi_value([bvv(&ctx, 10), bvv(&ctx, 20)])?;
        let expr = ctx.add(&a, &b)?;
        assert!(expr.excavate_multi_value(Some(3))?.is_none());
        assert_eq!(expr.excavate_multi_value(Some(4))?.unwrap().len(), 4);
        Ok(())
    }

    #[test]
    fn test_member_annotations_reach_results() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let tag = Annotation::new(AnnotationType::Uninitialized, false, true);
        let a = ctx.bvs("a", 32)?.annotate([tag.clone()])?;
        let b = ctx.bvs("b", 32)?;
        let mv = ctx.multi_value([a, b])?;
        let expr = ctx.add(&mv, bvv(&ctx, 1))?;
        assert!(expr.annotations().is_empty());
        let result = expr.excavate_multi_value(None)?.unwrap();
        assert_eq!(result.len(), 2);
        let tagged = result
            .iter()
            .filter(|r| r.annotations().contains(&tag))
            .count();
        assert_eq!(tagged, 1);
        Ok(())
    }
}
