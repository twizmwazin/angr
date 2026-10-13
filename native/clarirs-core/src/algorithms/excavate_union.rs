use std::collections::HashSet;
use std::sync::Arc;

use crate::{algorithms::walk, ast::op::AstOp, cache::GenericCache, prelude::*};

impl<'c> AstNode<'c> {
    /// Expands every `Union` in this AST, returning the expressions it can
    /// stand for, simplified and without duplicates.
    ///
    /// A `Union` node denotes one choice among its members, and every
    /// occurrence of the same node takes the same choice: `x - x` for
    /// `x = Union(a, b)` expands to `[0]`, not `[0, a - b, b - a]`. This
    /// matches how the simplifier treats repeated subexpressions. Two distinct
    /// `Union` nodes are independent, so `Union(a, b) +
    /// Union(c, d)` expands to all four sums.
    ///
    /// Returns `None` when there would be more than `limit` alternatives. An
    /// AST without any `Union` expands to itself.
    pub fn excavate_union(
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
            match find_union(&expr)? {
                None => {
                    let simplified = expr.simplify()?;
                    if seen_done.insert(simplified.hash()) {
                        done.push(simplified);
                    }
                }
                Some(union_node) => {
                    let AstOp::Union(members) = union_node.op() else {
                        unreachable!("find_union returned a non-Union node");
                    };
                    for member in members {
                        let substituted = expr.replace(&union_node, member)?;
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

/// Returns a `Union` node in `ast`, if there is one.
fn find_union<'c>(ast: &AstRef<'c>) -> Result<Option<AstRef<'c>>, ClarirsError> {
    walk(
        ast.clone(),
        |node| Ok(matches!(node.op(), AstOp::Union(..)).then(|| Some(node.clone()))),
        |_, children| Ok(children.iter().find_map(Clone::clone)),
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
    fn test_no_union_node_expands_to_itself() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let x = ctx.bvs("x", 32)?;
        let expr = ctx.add(&x, bvv(&ctx, 1))?;
        let result = expr.excavate_union(None)?.unwrap();
        assert_eq!(result, vec![expr.simplify()?]);
        Ok(())
    }

    #[test]
    fn test_distributes_over_operation() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let x = ctx.bvs("x", 32)?;
        let mv = ctx.union([bvv(&ctx, 1), x.clone()])?;
        let expr = ctx.add(&mv, bvv(&ctx, 2))?;
        let result = expr.excavate_union(None)?.unwrap();
        let expected = [bvv(&ctx, 3), ctx.add(&x, bvv(&ctx, 2))?.simplify()?];
        assert_eq!(hashes(&result), hashes(&expected));
        Ok(())
    }

    #[test]
    fn test_same_node_is_correlated() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mv = ctx.union([bvv(&ctx, 1), bvv(&ctx, 5)])?;
        let expr = ctx.sub(&mv, &mv)?;
        let result = expr.excavate_union(None)?.unwrap();
        assert_eq!(result, vec![bvv(&ctx, 0)]);
        Ok(())
    }

    #[test]
    fn test_distinct_nodes_are_independent() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let a = ctx.union([bvv(&ctx, 1), bvv(&ctx, 2)])?;
        let b = ctx.union([bvv(&ctx, 10), bvv(&ctx, 20)])?;
        let expr = ctx.add(&a, &b)?;
        let result = expr.excavate_union(None)?.unwrap();
        let expected = [11, 21, 12, 22].map(|v| bvv(&ctx, v));
        assert_eq!(hashes(&result), hashes(&expected));
        Ok(())
    }

    #[test]
    fn test_nested_union_node_in_member() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let x = ctx.bvs("x", 32)?;
        let inner = ctx.union([bvv(&ctx, 1), bvv(&ctx, 2)])?;
        let outer = ctx.union([ctx.add(&x, &inner)?, bvv(&ctx, 7)])?;
        let result = outer.excavate_union(None)?.unwrap();
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
        let a = ctx.union([bvv(&ctx, 1), bvv(&ctx, 2)])?;
        let b = ctx.union([bvv(&ctx, 10), bvv(&ctx, 20)])?;
        let expr = ctx.add(&a, &b)?;
        assert!(expr.excavate_union(Some(3))?.is_none());
        assert_eq!(expr.excavate_union(Some(4))?.unwrap().len(), 4);
        Ok(())
    }

    #[test]
    fn test_member_annotations_reach_results() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let tag = Annotation::new(AnnotationType::Uninitialized, false, true);
        let a = ctx.bvs("a", 32)?.annotate([tag.clone()])?;
        let b = ctx.bvs("b", 32)?;
        let mv = ctx.union([a, b])?;
        let expr = ctx.add(&mv, bvv(&ctx, 1))?;
        let result = expr.excavate_union(None)?.unwrap();
        assert_eq!(result.len(), 2);
        let from_a = result
            .iter()
            .find(|r| r.variables().iter().any(|v| v.as_str() == "a"))
            .unwrap();
        assert!(from_a.annotations().contains(&tag));
        Ok(())
    }
}
