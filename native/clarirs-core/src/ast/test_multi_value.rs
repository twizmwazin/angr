use crate::prelude::*;

fn bvv<'c>(ctx: &'c Context<'c>, value: u64) -> AstRef<'c> {
    ctx.bvv(BitVec::from((value, 32))).unwrap()
}

#[test]
fn test_members_are_canonical() -> Result<(), ClarirsError> {
    let ctx = Context::new();
    let (a, b, c) = (bvv(&ctx, 1), bvv(&ctx, 2), ctx.bvs("c", 32)?);
    let abc = ctx.multi_value([a.clone(), b.clone(), c.clone()])?;
    let cab = ctx.multi_value([c.clone(), a.clone(), b.clone(), a.clone()])?;
    assert_eq!(abc, cab);
    let AstOp::MultiValue(members) = abc.op() else {
        panic!("expected a MultiValue, got {:?}", abc.op());
    };
    assert_eq!(members.len(), 3);
    assert!(members.windows(2).all(|w| w[0].hash() < w[1].hash()));
    Ok(())
}

#[test]
fn test_nested_sets_are_flattened() -> Result<(), ClarirsError> {
    let ctx = Context::new();
    let (a, b, c) = (bvv(&ctx, 1), bvv(&ctx, 2), bvv(&ctx, 3));
    let inner = ctx.multi_value([a.clone(), b.clone()])?;
    let nested = ctx.multi_value([inner, c.clone()])?;
    assert_eq!(nested, ctx.multi_value([a, b, c])?);
    Ok(())
}

#[test]
fn test_single_member_is_returned_as_is() -> Result<(), ClarirsError> {
    let ctx = Context::new();
    let a = bvv(&ctx, 1);
    assert_eq!(ctx.multi_value([a.clone()])?, a);
    assert_eq!(ctx.multi_value([a.clone(), a.clone()])?, a);
    Ok(())
}

#[test]
fn test_invalid_members_are_rejected() -> Result<(), ClarirsError> {
    let ctx = Context::new();
    assert!(ctx.multi_value(Vec::<AstRef>::new()).is_err());
    let narrow = ctx.bvv(BitVec::from((1u64, 8)))?;
    assert!(ctx.multi_value([bvv(&ctx, 1), narrow]).is_err());
    assert!(ctx.multi_value([bvv(&ctx, 1), ctx.fpv(1.0f32)?]).is_err());
    assert!(ctx.multi_value([ctx.true_()?, ctx.false_()?]).is_err());
    Ok(())
}

#[test]
fn test_type_and_symbolic() -> Result<(), ClarirsError> {
    let ctx = Context::new();
    let bv = ctx.multi_value([bvv(&ctx, 1), bvv(&ctx, 2)])?;
    assert_eq!(bv.ast_type(), AstType::BitVec(32));
    assert!(bv.symbolic());
    assert!(bv.variables().is_empty());
    let fp = ctx.multi_value([ctx.fpv(1.0f32)?, ctx.fpv(2.0f32)?])?;
    assert_eq!(fp.ast_type(), ctx.fpv(1.0f32)?.ast_type());
    Ok(())
}

#[test]
fn test_member_annotations_do_not_leak() -> Result<(), ClarirsError> {
    let ctx = Context::new();
    let tag = Annotation::new(AnnotationType::Uninitialized, false, true);
    let a = ctx.bvs("a", 32)?.annotate([tag.clone()])?;
    let mv = ctx.multi_value([a.clone(), bvv(&ctx, 1)])?;
    assert!(mv.annotations().is_empty());
    // Rebuilding through the generic path must not leak them either.
    let rebuilt = ctx.make_ast(mv.op().clone())?;
    assert_eq!(rebuilt, mv);
    assert!(ctx.add(&mv, bvv(&ctx, 2))?.annotations().is_empty());
    assert!(mv.simplify()?.annotations().is_empty());
    Ok(())
}

#[test]
fn test_simplify_dedups_members() -> Result<(), ClarirsError> {
    let ctx = Context::new();
    let x = ctx.bvs("x", 32)?;
    let one_plus_one = ctx.add(bvv(&ctx, 1), bvv(&ctx, 1))?;
    let mv = ctx.multi_value([one_plus_one, bvv(&ctx, 2), x.clone()])?;
    assert_eq!(mv.simplify()?, ctx.multi_value([bvv(&ctx, 2), x])?);

    let collapses = ctx.multi_value([ctx.add(bvv(&ctx, 1), bvv(&ctx, 1))?, bvv(&ctx, 2)])?;
    assert_eq!(collapses.simplify()?, bvv(&ctx, 2));
    Ok(())
}
