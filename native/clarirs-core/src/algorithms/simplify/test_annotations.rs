//! Annotations are part of AST identity, so a rule that folds `f(x, x)` must
//! only fire when both operands carry the *same* annotations. Comparing
//! `lhs.op() == rhs.op()` looks right but silently ignores the annotations of
//! the two nodes being compared, so it folds `f(x@a, x@b)` too.
//!
//! Consumers depend on this: angr's variable recovery gives every unknown value
//! the same singleton `top` symbol and distinguishes them purely by their
//! annotations, so an annotation-blind fold turns two unrelated unknowns into a
//! provably-equal pair.
//!
//! These tests run every reflexive rule twice -- once with matching annotations
//! (must fold) and once with differing ones (must not) -- so a newly added rule
//! that reaches for op-level equality fails here.

use anyhow::Result;
use num_bigint::BigUint;

use crate::{
    ast::annotation::{Annotation, AnnotationType},
    prelude::*,
};

/// Non-eliminatable, relocatable: the flags angr's `VariableAnnotation` uses.
fn anno(id: &str) -> Annotation {
    Annotation::new(
        AnnotationType::Region {
            region_id: id.to_string(),
            region_base_addr: BigUint::from(0u32),
        },
        false,
        true,
    )
}

/// Every binary op with a reflexive simplification, as
/// (name, constructor, result when the operands really are the same value).
#[allow(clippy::type_complexity)]
fn reflexive_ops<'c>() -> Vec<(
    &'static str,
    fn(&'c Context<'c>, &AstRef<'c>, &AstRef<'c>) -> Result<AstRef<'c>, ClarirsError>,
    bool,
)> {
    vec![
        ("sub", |c, a, b| c.sub(a, b), false),
        ("eq", |c, a, b| c.eq_(a, b), true),
        ("neq", |c, a, b| c.neq(a, b), false),
        ("ult", |c, a, b| c.ult(a, b), false),
        ("ule", |c, a, b| c.ule(a, b), true),
        ("ugt", |c, a, b| c.ugt(a, b), false),
        ("uge", |c, a, b| c.uge(a, b), true),
        ("slt", |c, a, b| c.slt(a, b), false),
        ("sle", |c, a, b| c.sle(a, b), true),
        ("sgt", |c, a, b| c.sgt(a, b), false),
        ("sge", |c, a, b| c.sge(a, b), true),
    ]
}

#[test]
fn reflexive_rules_fold_when_annotations_match() -> Result<()> {
    let ctx = Context::new();
    let x = ctx.bvs("x", 32)?;
    let left = ctx.annotate(&x, vec![anno("r0")])?;
    let right = ctx.annotate(&x, vec![anno("r0")])?;

    for (name, build, _) in reflexive_ops() {
        let simplified = build(&ctx, &left, &right)?.simplify()?;
        assert!(
            !simplified.symbolic(),
            "{name}: identical operands should still fold, got {simplified:?}"
        );
    }
    Ok(())
}

#[test]
fn reflexive_rules_do_not_fold_across_differing_annotations() -> Result<()> {
    let ctx = Context::new();
    let x = ctx.bvs("x", 32)?;
    let left = ctx.annotate(&x, vec![anno("r0")])?;
    let right = ctx.annotate(&x, vec![anno("r1")])?;

    for (name, build, _) in reflexive_ops() {
        let simplified = build(&ctx, &left, &right)?.simplify()?;
        assert!(
            simplified.symbolic(),
            "{name}: operands differ by annotation and must not fold, got {simplified:?}"
        );
    }
    Ok(())
}

#[test]
fn ite_branch_identity_respects_annotations() -> Result<()> {
    let ctx = Context::new();
    let c = ctx.bools("c")?;
    let cond = ctx.annotate(&c, vec![anno("r0")])?;
    let other = ctx.annotate(&c, vec![anno("r1")])?;
    let (t, f) = (ctx.true_()?, ctx.false_()?);

    // ite(c, true, c) / ite(c, c, false) collapse to `c`; ite(c, false, c) and
    // ite(c, c, true) collapse to a constant. None may fire when the branch is
    // the condition-with-a-different-annotation.
    for (name, built) in [
        ("ite(c, true, other)", ctx.ite(&cond, &t, &other)?),
        ("ite(c, false, other)", ctx.ite(&cond, &f, &other)?),
        ("ite(c, other, true)", ctx.ite(&cond, &other, &t)?),
        ("ite(c, other, false)", ctx.ite(&cond, &other, &f)?),
    ] {
        let simplified = built.simplify()?;
        assert!(
            matches!(simplified.op(), AstOp::ITE(..)),
            "{name}: branch differs from the condition by annotation and must not \
             collapse, got {simplified:?}"
        );
    }

    // ...and the same shapes still collapse when the annotations do match.
    // Compare ops: relocatable annotations propagate from the children onto the
    // constructed node and survive simplification, so the collapsed results are
    // annotated copies of `c` / of the constant rather than bare nodes.
    let same = ctx.annotate(&c, vec![anno("r0")])?;
    for (name, built, expected) in [
        (
            "ite(c, true, c)",
            ctx.ite(&cond, &t, &same)?,
            AstOp::BoolS(ctx.intern_string("c")),
        ),
        (
            "ite(c, false, c)",
            ctx.ite(&cond, &f, &same)?,
            AstOp::BoolV(false),
        ),
        (
            "ite(c, c, true)",
            ctx.ite(&cond, &same, &t)?,
            AstOp::BoolV(true),
        ),
        (
            "ite(c, c, false)",
            ctx.ite(&cond, &same, &f)?,
            AstOp::BoolS(ctx.intern_string("c")),
        ),
    ] {
        let simplified = built.simplify()?;
        assert_eq!(
            simplified.op(),
            &expected,
            "{name}: identical annotations should still collapse"
        );
    }
    Ok(())
}
