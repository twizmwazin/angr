use crate::prelude::*;

fn not<'c>(ctx: &'c Context<'c>, a: &AstRef<'c>) -> AstRef<'c> {
    ctx.not(a).unwrap().simplify().unwrap()
}

fn and<'c>(ctx: &'c Context<'c>, args: &[&AstRef<'c>]) -> AstRef<'c> {
    ctx.and(args.iter().map(|&a| a.clone()))
        .unwrap()
        .simplify()
        .unwrap()
}

fn or<'c>(ctx: &'c Context<'c>, args: &[&AstRef<'c>]) -> AstRef<'c> {
    ctx.or(args.iter().map(|&a| a.clone()))
        .unwrap()
        .simplify()
        .unwrap()
}

#[test]
fn test_merges_minterms() {
    let ctx = Context::new();
    let x = ctx.bools("x").unwrap();
    let y = ctx.bools("y").unwrap();
    let z = ctx.bools("z").unwrap();
    let (nx, ny, nz) = (not(&ctx, &x), not(&ctx, &y), not(&ctx, &z));

    // (!x && !y && !z) || (!x && !y && z) == !x && !y
    let expr = or(
        &ctx,
        &[&and(&ctx, &[&nx, &ny, &nz]), &and(&ctx, &[&nx, &ny, &z])],
    );
    assert_eq!(expr.simplify_logic(8).unwrap(), and(&ctx, &[&nx, &ny]));
}

#[test]
fn test_absorption() {
    let ctx = Context::new();
    let x = ctx.bools("x").unwrap();
    let y = ctx.bools("y").unwrap();

    // x || (x && y) == x
    let expr = or(&ctx, &[&x, &and(&ctx, &[&x, &y])]);
    assert_eq!(expr.simplify_logic(8).unwrap(), x);

    // (x || y) && (x || !y) == x
    let ny = not(&ctx, &y);
    let expr = and(&ctx, &[&or(&ctx, &[&x, &y]), &or(&ctx, &[&x, &ny])]);
    assert_eq!(expr.simplify_logic(8).unwrap(), x);
}

#[test]
fn test_constants() {
    let ctx = Context::new();
    let x = ctx.bools("x").unwrap();
    let y = ctx.bools("y").unwrap();
    let nx = not(&ctx, &x);

    let tautology = ctx
        .or([x.clone(), ctx.and2(&nx, &y).unwrap(), nx.clone()])
        .unwrap();
    assert!(tautology.simplify_logic(8).unwrap().is_true());
    let contradiction = ctx.and([x.clone(), y.clone(), nx.clone()]).unwrap();
    assert!(contradiction.simplify_logic(8).unwrap().is_false());
    assert!(ctx.true_().unwrap().simplify_logic(8).unwrap().is_true());
    assert_eq!(x.simplify_logic(8).unwrap(), x);
}

#[test]
fn test_keeps_operand_order() {
    let ctx = Context::new();
    // Name the predicates so that neither their names nor their hashes
    // follow the order in which they are passed.
    let terms = ["e", "b", "f", "a", "d", "c"]
        .iter()
        .map(|name| ctx.bools(name).unwrap())
        .collect::<Vec<_>>();
    for expr in [
        ctx.or(terms.iter().cloned()).unwrap(),
        ctx.and(terms.iter().cloned()).unwrap(),
    ] {
        let simplified = expr.simplify_logic(8).unwrap();
        assert_eq!(simplified.op(), expr.op());
    }
}

#[test]
fn test_unifies_comparisons() {
    let ctx = Context::new();
    let a = ctx.bvs("a", 32).unwrap();
    let b = ctx.bvs("b", 32).unwrap();
    let ugt = ctx.ugt(&a, &b).unwrap();
    let ule = ctx.ule(&a, &b).unwrap();
    let neq = ctx.neq(&a, &b).unwrap();
    let eq = ctx.eq_(&a, &b).unwrap();

    // a >u b || a <=u b == true
    assert!(or(&ctx, &[&ugt, &ule]).simplify_logic(8).unwrap().is_true());
    // (a != b && a >u b) || (a == b && a >u b) == a >u b
    let expr = or(&ctx, &[&and(&ctx, &[&neq, &ugt]), &and(&ctx, &[&eq, &ugt])]);
    assert_eq!(expr.simplify_logic(8).unwrap(), ugt);
}

#[test]
fn test_predicate_limit() {
    let ctx = Context::new();
    let x = ctx.bools("x").unwrap();
    let y = ctx.bools("y").unwrap();
    let z = ctx.bools("z").unwrap();

    // x || (x && y && z) is x, but only once all three predicates are allowed.
    let expr = ctx.or2(&x, ctx.and([x.clone(), y, z]).unwrap()).unwrap();
    assert_eq!(expr.simplify_logic(3).unwrap(), x);
    let limited = expr.simplify_logic(2).unwrap();
    assert!(matches!(limited.op(), AstOp::Or(args) if args.len() == 2));
    // Double negations are still removed over the limit.
    let nnx = ctx.not(ctx.not(&x).unwrap()).unwrap();
    assert_eq!(ctx.or2(&nnx, &x).unwrap().simplify_logic(0).unwrap(), x);
}

#[test]
fn test_rejects_non_bool() {
    let ctx = Context::new();
    let a = ctx.bvs("a", 32).unwrap();
    assert!(a.simplify_logic(8).is_err());
}
