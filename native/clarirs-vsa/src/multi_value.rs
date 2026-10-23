//! Helpers for bitvectors that stand for several alternative values.
//!
//! Static analyses track every value a register, temporary or memory location
//! may hold as one bitvector. A value with several alternatives is a `Union`;
//! a value whose bytes have independently tracked alternatives is a `Concat`
//! of such pieces, the most significant piece first:
//!
//! * `x`: a single value;
//! * `Union(a, b)`: either `a` or `b`, which have the same size;
//! * `Concat(Union(a, b), c)`: the high bytes are `a` or `b`, the low bytes
//!   are `c`.
//!
//! Byte offsets count from the most significant byte, and a byte is always 8
//! bits wide.

use std::collections::HashSet;

use clarirs_core::algorithms::walk;
use clarirs_core::cache::GenericCache;
use clarirs_core::prelude::*;

/// How many values a piece holding Unions is expanded into before it is
/// treated as opaque.
pub const UNION_EXPANSION_LIMIT: usize = 256;

/// The pieces of a value as `(byte offset, alternatives)` pairs.
pub type Segments<'c> = Vec<(u32, Vec<AstRef<'c>>)>;

/// Reading values that stand for several alternatives.
pub trait MultiValue<'c> {
    /// The pieces of this value as `(byte offset, alternatives)` pairs,
    /// ordered by offset. Adjacent single-valued pieces are joined into one.
    fn mv_segments(&self) -> Result<Segments<'c>, ClarirsError>;

    /// The alternatives of a value that is a single piece, or `None` for a
    /// value made of several independently tracked pieces.
    fn mv_eval(&self) -> Result<Option<Vec<AstRef<'c>>>, ClarirsError>;

    /// The single value this value stands for, or `None`.
    fn mv_eval_one(&self) -> Result<Option<AstRef<'c>>, ClarirsError>;
}

impl<'c> MultiValue<'c> for AstRef<'c> {
    fn mv_segments(&self) -> Result<Segments<'c>, ClarirsError> {
        let ctx = self.context();
        let mut segments: Segments<'c> = Vec::new();
        let mut offset = 0;
        // split the value into the pieces its alternatives are tracked in,
        // most significant first
        let mut stack = vec![self.clone()];
        while let Some(piece) = stack.pop() {
            match piece.op() {
                AstOp::Concat(args) => {
                    stack.extend(args.iter().rev().cloned());
                    continue;
                }
                // the simplifier turns Concat(0, x) into ZeroExt(x)
                AstOp::ZeroExt(inner, amount) if *amount > 0 && amount % 8 == 0 => {
                    stack.push(inner.clone());
                    stack.push(ctx.bvv(BitVec::zeros(*amount))?);
                    continue;
                }
                _ => {}
            }
            let alternatives = expand_unions(&piece)?;
            let piece_offset = offset;
            offset += piece.size() / 8;
            // join adjacent single-valued pieces
            if alternatives.len() == 1
                && let Some((_, last)) = segments.last_mut()
                && last.len() == 1
            {
                last[0] = ctx
                    .concat([last[0].clone(), alternatives[0].clone()])?
                    .simplify()?;
                continue;
            }
            segments.push((piece_offset, alternatives));
        }
        Ok(segments)
    }

    fn mv_eval(&self) -> Result<Option<Vec<AstRef<'c>>>, ClarirsError> {
        let mut segments = self.mv_segments()?;
        Ok(if segments.len() == 1 {
            segments.pop().map(|(_, values)| values)
        } else {
            None
        })
    }

    fn mv_eval_one(&self) -> Result<Option<AstRef<'c>>, ClarirsError> {
        Ok(self
            .mv_eval()?
            .filter(|values| values.len() == 1)
            .and_then(|mut values| values.pop()))
    }
}

/// The values `piece` can take once every Union in it is expanded, simplified
/// and without duplicates, or `[piece]` when there are more than
/// [`UNION_EXPANSION_LIMIT`] of them. A Union is always symbolic, so a concrete
/// piece is a single value.
///
/// A Union node denotes one choice among its members, and every occurrence of
/// the same node takes the same choice: `x * x` for `x = Union(a, b)` expands
/// to `[a * a, b * b]`. Two distinct Union nodes are independent, so
/// `Union(a, b) + Union(c, d)` expands to all four sums.
fn expand_unions<'c>(piece: &AstRef<'c>) -> Result<Vec<AstRef<'c>>, ClarirsError> {
    if !piece.symbolic() {
        return Ok(vec![piece.clone()]);
    }
    let mut pending = vec![piece.clone()];
    let mut done: Vec<AstRef<'c>> = Vec::new();
    let mut seen = HashSet::new();
    while let Some(expr) = pending.pop() {
        let union_node = walk(
            expr.clone(),
            |node| Ok(matches!(node.op(), AstOp::Union(..)).then(|| Some(node.clone()))),
            |_, children| Ok(children.iter().find_map(Clone::clone)),
            &GenericCache::default(),
        )?;
        if let Some(union_node) = union_node
            && let AstOp::Union(members) = union_node.op()
        {
            for member in members.iter().rev() {
                pending.push(expr.replace(&union_node, member)?);
            }
        } else {
            let simplified = expr.simplify()?;
            if seen.insert(simplified.hash()) {
                done.push(simplified);
            }
        }
        // every expression still pending yields at least one value
        if done.len() + pending.len() > UNION_EXPANSION_LIMIT {
            return Ok(vec![piece.clone()]);
        }
    }
    Ok(done)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_value() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let v = ctx.bvv(BitVec::from((0x1337u64, 32)))?;
        assert_eq!(v.mv_eval_one()?, Some(v.clone()));
        assert_eq!(v.mv_segments()?, vec![(0, vec![v.clone()])]);
        let x = ctx.bvs("x", 32)?;
        assert_eq!(x.mv_eval_one()?, Some(x.clone()));
        Ok(())
    }

    #[test]
    fn test_alternatives() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let a = ctx.bvv(BitVec::from((1u64, 32)))?;
        let b = ctx.bvv(BitVec::from((2u64, 32)))?;
        let mv = ctx.union([a.clone(), b.clone()])?.simplify()?;
        assert_eq!(mv.mv_eval_one()?, None);
        assert_eq!(mv.mv_eval()?, Some(vec![a, b]));
        Ok(())
    }

    #[test]
    fn test_union_under_operation() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let x = ctx.bvs("x", 32)?;
        let two = ctx.bvv(BitVec::from((2u64, 32)))?;
        let mv = ctx
            .union([ctx.bvv(BitVec::from((1u64, 32)))?, x.clone()])?
            .simplify()?;
        let expr = ctx.add(&mv, &two)?.simplify()?;
        assert_eq!(
            expr.mv_eval()?,
            Some(vec![
                ctx.bvv(BitVec::from((3u64, 32)))?,
                ctx.add(&x, &two)?.simplify()?,
            ])
        );
        Ok(())
    }

    #[test]
    fn test_segments() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let x = ctx.bvs("x", 32)?;
        let a = ctx.bvv(BitVec::from((1u64, 32)))?;
        let b = ctx.bvv(BitVec::from((2u64, 32)))?;
        let value = ctx
            .concat([x.clone(), ctx.union([a.clone(), b.clone()])?])?
            .simplify()?;
        assert_eq!(value.mv_segments()?, vec![(0, vec![x]), (4, vec![a, b])]);
        assert_eq!(value.mv_eval()?, None);
        Ok(())
    }

    #[test]
    fn test_symbolic_value_without_union() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let x = ctx.bvs("x", 32)?;
        let expr = ctx.add(&x, ctx.bvv(BitVec::from((1u64, 32)))?)?;
        assert_eq!(expr.mv_eval()?, Some(vec![expr.simplify()?]));
        Ok(())
    }

    #[test]
    fn test_same_union_node_is_correlated() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mv = ctx.union([
            ctx.bvv(BitVec::from((1u64, 32)))?,
            ctx.bvv(BitVec::from((5u64, 32)))?,
        ])?;
        let expr = ctx.mul(&mv, &mv)?;
        assert_eq!(
            expr.mv_eval()?,
            Some(vec![
                ctx.bvv(BitVec::from((1u64, 32)))?,
                ctx.bvv(BitVec::from((25u64, 32)))?,
            ])
        );
        Ok(())
    }

    #[test]
    fn test_distinct_union_nodes_are_independent() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let a = ctx.union([
            ctx.bvv(BitVec::from((1u64, 32)))?,
            ctx.bvv(BitVec::from((2u64, 32)))?,
        ])?;
        let b = ctx.union([
            ctx.bvv(BitVec::from((10u64, 32)))?,
            ctx.bvv(BitVec::from((20u64, 32)))?,
        ])?;
        let expr = ctx.add(&a, &b)?;
        let expected = [11u64, 21, 12, 22]
            .into_iter()
            .map(|v| ctx.bvv(BitVec::from((v, 32))))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(expr.mv_eval()?, Some(expected));
        Ok(())
    }

    #[test]
    fn test_too_many_values_are_kept_as_is() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        // 17 * 17 distinct sums
        let values = |stride: u64| {
            ctx.union(
                (0..17u64)
                    .map(|v| ctx.bvv(BitVec::from((v * stride, 32))))
                    .collect::<Result<Vec<_>, _>>()?,
            )
        };
        let expr = ctx.add(&values(1)?, &values(17)?)?;
        assert_eq!(expr.mv_eval()?, Some(vec![expr.clone()]));
        Ok(())
    }

    #[test]
    fn test_nested_union_in_member() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let x = ctx.bvs("x", 32)?;
        let one = ctx.bvv(BitVec::from((1u64, 32)))?;
        let two = ctx.bvv(BitVec::from((2u64, 32)))?;
        let seven = ctx.bvv(BitVec::from((7u64, 32)))?;
        let inner = ctx.union([one.clone(), two.clone()])?;
        let outer = ctx.union([ctx.add(&x, &inner)?, seven.clone()])?;
        assert_eq!(
            outer.mv_eval()?,
            Some(vec![
                ctx.add(&x, &one)?.simplify()?,
                ctx.add(&x, &two)?.simplify()?,
                seven,
            ])
        );
        Ok(())
    }

    #[test]
    fn test_expansion_keeps_member_annotations() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let tag = Annotation::new(AnnotationType::Uninitialized, false, true);
        let a = ctx.bvs("a", 32)?.annotate([tag.clone()])?;
        let mv = ctx.union([a, ctx.bvs("b", 32)?])?;
        let expr = ctx.add(&mv, ctx.bvv(BitVec::from((1u64, 32)))?)?;
        let result = expr.mv_eval()?.unwrap();
        assert_eq!(result.len(), 2);
        assert!(result[0].annotations().contains(&tag));
        Ok(())
    }
}
