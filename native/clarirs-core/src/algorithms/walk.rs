use crate::cache::Cache;
use crate::prelude::*;

/// Walks the AST depth-first with an explicit stack, calling `pre_visit` when
/// a node is first reached and `post_visit` once all of its children have been
/// visited (children before parents).
///
/// `pre_visit` returns `Some(result)` to short-circuit: the subtree is skipped,
/// `post_visit` is not called for the node, and `result` stands in for it.
/// Returning `None` descends into the children, whose results are passed to
/// `post_visit` in child order.
///
/// Every result is stored in `cache` under the node's hash, and a node whose
/// hash is already cached is not visited at all, so shared subtrees (ASTs are
/// DAGs) are processed once per cache lifetime. Pass `&()` to disable caching.
pub fn walk<'c, T>(
    ast: AstRef<'c>,
    mut pre_visit: impl FnMut(&AstRef<'c>) -> Result<Option<T>, ClarirsError>,
    mut post_visit: impl FnMut(AstRef<'c>, &[T]) -> Result<T, ClarirsError>,
    cache: &impl Cache<u64, T>,
) -> Result<T, ClarirsError> {
    struct NodeState<'c, T> {
        node: AstRef<'c>,
        num_children: usize,
        child_results: Vec<T>,
    }

    impl<'c, T> NodeState<'c, T> {
        fn new(node: AstRef<'c>) -> Self {
            let num_children = node.child_iter().len();
            NodeState {
                node,
                num_children,
                child_results: Vec::with_capacity(num_children),
            }
        }
    }

    let mut stack = vec![NodeState::new(ast)];
    let mut last_result: Option<T> = None;

    while let Some(mut state) = stack.pop() {
        // Collect result from a completed child
        if let Some(result) = last_result.take() {
            state.child_results.push(result);
        }

        let children_done = state.child_results.len();

        if children_done == 0 {
            // First visit — check cache, then pre_visit
            if let Some(cached) = cache.get(&state.node.hash()) {
                last_result = Some(cached);
                continue;
            }
            if let Some(result) = pre_visit(&state.node)? {
                cache.insert(state.node.hash(), &result);
                last_result = Some(result);
                continue;
            }
        }

        if children_done < state.num_children {
            // Descend into the next child
            let child = state.node.get_child(children_done).unwrap();
            stack.push(state);
            stack.push(NodeState::new(child));
        } else {
            // All children done — call post_visit
            let result = cache.get_or_insert(state.node.hash(), || {
                post_visit(state.node.clone(), &state.child_results)
            })?;
            last_result = Some(result);
        }
    }

    last_result.ok_or(ClarirsError::EmptyTraversal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_walk_visits_all_nodes() -> Result<(), ClarirsError> {
        let ctx = Context::new();

        let ast = ctx.add(
            &ctx.bvs("a", 64)?,
            &ctx.mul(&ctx.bvs("b", 64)?, &ctx.bvs("c", 64)?)?,
        )?;
        let var_ast = ast.clone();
        let mut visited = Vec::new();

        walk(
            var_ast,
            |node| {
                visited.push(node.clone());
                Ok(None)
            },
            |_, _| Ok(()),
            &(),
        )
        .unwrap();

        assert_eq!(visited.len(), 5);

        Ok(())
    }
}
