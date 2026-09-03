use crate::cache::GenericCache;
use crate::prelude::*;

use super::walk::walk;

/// Walks the AST in pre-order, with the option to short-circuit subtrees.
///
/// Two callbacks control the traversal:
/// - `pre_visit`: Called when a node is first encountered, before its children
///   are processed. Return `Some(result)` to skip the entire subtree, or `None`
///   to descend into children.
/// - `post_visit`: Called after all children have been visited and transformed.
///   Receives the original node and the transformed children. Only called when
///   `pre_visit` returned `None`.
///
/// Shared subtrees (same `hash`) are only processed once; subsequent
/// encounters reuse the cached result.
pub fn walk_pre_order<'c>(
    ast: AstRef<'c>,
    pre_visit: impl FnMut(&AstRef<'c>) -> Result<Option<AstRef<'c>>, ClarirsError>,
    post_visit: impl FnMut(AstRef<'c>, &[AstRef<'c>]) -> Result<AstRef<'c>, ClarirsError>,
) -> Result<AstRef<'c>, ClarirsError> {
    walk(ast, pre_visit, post_visit, &GenericCache::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_walk_pre_order_leaf() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let x = ctx.bvs("x", 64)?;

        let result = walk_pre_order(x.clone(), |_| Ok(None), |node, _children| Ok(node))?;

        assert_eq!(result, x.clone());
        Ok(())
    }

    #[test]
    fn test_walk_pre_order_short_circuit() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let x = ctx.bvs("x", 64)?;
        let y = ctx.bvs("y", 64)?;
        let add = ctx.add(&x, &y)?;

        let replacement = ctx.bvv(BitVec::from((99, 64)))?.clone();

        // Short-circuit the entire tree
        let result = walk_pre_order(
            add.clone(),
            |_| Ok(Some(replacement.clone())),
            |_, _| panic!("post_visit should not be called"),
        )?;

        assert_eq!(result, replacement);
        Ok(())
    }

    #[test]
    fn test_walk_pre_order_children_processed() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let x = ctx.bvs("x", 64)?;
        let y = ctx.bvs("y", 64)?;
        let add = ctx.add(&x, &y)?;

        let mut pre_visit_count = 0;
        let mut post_visit_count = 0;

        walk_pre_order(
            add.clone(),
            |_| {
                pre_visit_count += 1;
                Ok(None) // descend into all children
            },
            |node, _children| {
                post_visit_count += 1;
                Ok(node) // identity
            },
        )?;

        assert_eq!(pre_visit_count, 3); // add, x, y
        assert_eq!(post_visit_count, 3); // x, y, add
        Ok(())
    }

    #[test]
    fn test_walk_pre_order_selective_short_circuit() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let x = ctx.bvs("x", 64)?;
        let y = ctx.bvs("y", 64)?;
        let z = ctx.bvs("z", 64)?;
        let add = ctx.add(&x, &y)?;

        let from = x.clone();
        let to = z.clone();

        // Replace x with z in add(x, y)
        let result = walk_pre_order(
            add.clone(),
            |node| {
                if *node == from {
                    Ok(Some(to.clone()))
                } else {
                    Ok(None)
                }
            },
            |node, children| {
                if children.is_empty() {
                    Ok(node)
                } else {
                    // Rebuild add with new children
                    let lhs = children[0].clone();
                    let rhs = children[1].clone();
                    Ok(ctx.add(&lhs, &rhs)?.clone())
                }
            },
        )?;

        let expected = ctx.add(&z, &y)?.clone();
        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn test_walk_pre_order_shared_subtrees_cached() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let x = ctx.bvs("x", 64)?;
        let y = ctx.bvs("y", 64)?;

        // Create shared subtree: mul(add(x, y), add(x, y))
        let add = ctx.add(&x, &y)?;
        let mul = ctx.mul(&add, &add)?;

        let mut pre_visit_count = 0;

        walk_pre_order(
            mul.clone(),
            |_| {
                pre_visit_count += 1;
                Ok(None)
            },
            |node, _children| Ok(node),
        )?;

        // mul is visited once, add(x,y) is visited once (second time is cached),
        // x and y are visited once each (from the first add)
        // Total pre_visit calls: mul + add + x + y = 4
        assert_eq!(pre_visit_count, 4);
        Ok(())
    }
}
