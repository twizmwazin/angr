//! claripy AST -> AIL expression conversion.
//!
//! This is the Rust port of ``ConditionProcessor.convert_claripy_bool_ast``,
//! the reverse of [`crate::ailment::to_claripy`]: once the decompiler is done
//! reasoning about a condition as a claripy formula, the formula is turned
//! back into an AIL expression. Symbols and annotated constants are looked up
//! in ``condition_mapping`` (which the forward conversion filled); operators
//! are rebuilt as AIL operators, with the tags the forward conversion
//! recorded in ``ast2annotations``.
//!
//! The conversion is one function: a [`walk`] over the claripy AST whose
//! post-visit is a single match over the claripy operators, building each node
//! from its already converted children. Subtrees are memoized by claripy hash,
//! and every node that is built is handed to the caller's ``optimize`` callback
//! (the peephole rules), bottom-up.

use std::cell::RefCell;
use std::sync::Arc;

use num_bigint::{BigInt, BigUint};
use pyo3::exceptions::{PyNotImplementedError, PyRuntimeError};
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict};

use crate::ailment::ail_expr::{AilExpression, ExprHeader, ExprInner, Expression};
use crate::ailment::const_value::ConstValue;
use crate::ailment::enums::ConvertType;
use crate::ailment::tags::Tags;
use crate::claripy::ast::GLOBAL_CONTEXT;
use crate::claripy::ast::base::Base;
use crate::claripy::ast::not as claripy_not;
use crate::claripy::ast::opstring::ToOpString;
use crate::claripy::error::ClaripyError;
use clarirs_core::algorithms::walk;
use clarirs_core::ast::AstFactory;
use clarirs_core::prelude::{AstOp, AstRef, BitVec, ClarirsError};

/// A converted expression: a Python ``Expression``.
type Ail<'py> = Bound<'py, PyAny>;

fn const_value(value: BigInt) -> ConstValue {
    match i128::try_from(&value) {
        Ok(value) => ConstValue::Int(value),
        Err(_) => ConstValue::BigInt(value),
    }
}

/// The width of a ``BinaryOp``, as the Python constructor infers it.
fn binary_op_bits(op: &str, lhs: &AilExpression, rhs: &AilExpression) -> u32 {
    match op {
        "CmpEQ" | "CmpNE" | "CmpLT" | "CmpLE" | "CmpGT" | "CmpGE" => 1,
        "Concat" => lhs.header.bits + rhs.header.bits,
        _ => lhs.header.bits,
    }
}

fn constant(idx: i64, value: ConstValue, bits: u32, tags: &Tags) -> AilExpression {
    AilExpression {
        header: ExprHeader::new(idx, 0, bits, tags.clone()),
        inner: ExprInner::Const { value },
    }
}

fn binary_op(
    idx: i64,
    op: &str,
    lhs: AilExpression,
    rhs: AilExpression,
    signed: bool,
    tags: &Tags,
) -> AilExpression {
    let depth = lhs.header.depth.max(rhs.header.depth) + 1;
    let bits = binary_op_bits(op, &lhs, &rhs);
    AilExpression {
        header: ExprHeader::new(idx, depth, bits, tags.clone()),
        inner: ExprInner::BinaryOp {
            op: op.to_string(),
            operands: [Arc::new(lhs), Arc::new(rhs)],
            signed,
            floating_point: false,
            rounding_mode: None,
            vector_count: None,
            vector_size: None,
        },
    }
}

/// The tags recorded for ``cond`` (or, failing that, for its negation),
/// without the floating-point flag, which is returned separately.
fn tags_of<'py>(
    ast2annotations: &Bound<'py, PyAny>,
    cond: &Bound<'py, Base>,
    is_comparison: bool,
) -> PyResult<(Tags, bool)> {
    let py = cond.py();
    let is_fp = |tags: &Bound<'py, PyAny>| -> PyResult<bool> {
        Ok(tags
            .call_method1("get", ("floating_point",))?
            .is(&*PyBool::new(py, true)))
    };
    let negated = || claripy_not(py, cond.clone());

    let recorded = if ast2annotations.contains(cond)? {
        Some(ast2annotations.get_item(cond)?)
    } else {
        let negated = negated()?;
        if ast2annotations.contains(&negated)? {
            Some(ast2annotations.get_item(&negated)?)
        } else {
            None
        }
    };
    let mut floating_point = match &recorded {
        Some(tags) => is_fp(tags)?,
        None => false,
    };
    if !floating_point && is_comparison {
        // a comparison claripy derived by negating an FP comparison is an FP comparison too
        let negated = negated()?;
        if ast2annotations.contains(&negated)? {
            floating_point = is_fp(&ast2annotations.get_item(&negated)?)?;
        }
    }
    let mut tags: Tags = match recorded {
        Some(tags) => tags.extract()?,
        None => Tags::default(),
    };
    if floating_point {
        tags.clear("floating_point");
    }
    Ok((tags, floating_point))
}

/// Convert a claripy AST back into an AIL expression.
///
/// ``condition_mapping`` and ``ast2annotations`` are the tables that
/// ``claripy_ast_from_ail`` filled. ``memo`` maps the claripy hash of every
/// subtree converted so far to its AIL expression; pass the same dict to
/// several calls to share conversions between them. ``optimize`` is called
/// with every expression the conversion builds and returns the expression to
/// use in its place.
#[pyfunction]
pub fn ail_from_claripy_ast<'py>(
    py: Python<'py>,
    cond: Bound<'py, Base>,
    condition_mapping: Bound<'py, PyAny>,
    ast2annotations: Bound<'py, PyAny>,
    ail_manager: Bound<'py, PyAny>,
    memo: Bound<'py, PyDict>,
    optimize: Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyAny>> {
    // `walk` only knows clarirs errors: a Python exception is parked here while the walk unwinds
    let raised: RefCell<Option<PyErr>> = RefCell::new(None);
    let park = |err: PyErr| {
        raised.replace(Some(err));
        ClarirsError::BackendError("python", "exception raised".to_string())
    };

    let next_atom = || -> PyResult<i64> { ail_manager.call_method0("next_atom")?.extract() };
    let wrap = |expr: AilExpression| -> PyResult<Ail<'py>> {
        Ok(Bound::new(py, Expression::wrap(expr))?.into_any())
    };
    let memoized = |ast: &AstRef<'static>| -> PyResult<Option<Ail<'py>>> {
        Ok(memo.get_item(ast.hash())?.filter(|hit| !hit.is_none()))
    };
    // Every converted node is optimized, then remembered
    let finish = |ast: &AstRef<'static>, converted: Ail<'py>| -> PyResult<Ail<'py>> {
        let converted = optimize.call1((converted,))?;
        memo.set_item(ast.hash(), &converted)?;
        Ok(converted)
    };

    // Leaves: a subtree converted before, or whatever the forward conversion made a symbol (or
    // an annotated constant) of
    let pre_visit = |ast: &AstRef<'static>| -> PyResult<Option<Ail<'py>>> {
        if let Some(hit) = memoized(ast)? {
            return Ok(Some(hit));
        }
        let cond = Base::from_ast(py, ast.clone())?;
        let leaf = if let AstOp::BoolV(true) = ast.op() {
            wrap(constant(
                next_atom()?,
                ConstValue::Int(1),
                1,
                &Tags::default(),
            ))?
        } else if condition_mapping.contains(&cond)? {
            condition_mapping.get_item(&cond)?
        } else if let AstOp::BVS(name, _) | AstOp::BoolS(name) = ast.op()
            && condition_mapping.contains(name.as_str())?
        {
            condition_mapping.get_item(name.as_str())?
        } else {
            return Ok(None);
        };
        finish(ast, leaf).map(Some)
    };

    // Operators, built from their converted children
    let post_visit = |ast: AstRef<'static>, children: &[Ail<'py>]| -> PyResult<Ail<'py>> {
        let cond = Base::from_ast(py, ast.clone())?;
        let is_bool = ast.ast_type().is_bool();
        let is_comparison = matches!(
            ast.op(),
            AstOp::Eq(..)
                | AstOp::Neq(..)
                | AstOp::ULT(..)
                | AstOp::ULE(..)
                | AstOp::UGT(..)
                | AstOp::UGE(..)
                | AstOp::SLT(..)
                | AstOp::SLE(..)
                | AstOp::SGT(..)
                | AstOp::SGE(..)
        );
        let (tags, floating_point) = tags_of(&ast2annotations, &cond, is_comparison)?;
        let tags = &tags;

        // A left-leaning chain of `op` over the operands. A single operand stands for itself.
        let fold = |op: &str, signed: bool, operands: &[Ail<'py>]| -> PyResult<Ail<'py>> {
            let (first, rest) = operands
                .split_first()
                .ok_or_else(|| PyRuntimeError::new_err(format!("{op} without operands")))?;
            let mut chain = first.clone();
            for operand in rest {
                let idx = next_atom()?;
                chain = wrap(binary_op(
                    idx,
                    op,
                    chain.extract()?,
                    operand.extract()?,
                    signed,
                    tags,
                ))?;
            }
            Ok(chain)
        };

        macro_rules! unop {
            ($op:literal) => {{
                let operand: AilExpression = children[0].extract()?;
                wrap(AilExpression {
                    header: ExprHeader::new(
                        next_atom()?,
                        operand.header.depth + 1,
                        operand.header.bits,
                        tags.clone(),
                    ),
                    inner: ExprInner::UnaryOp {
                        op: $op.to_string(),
                        operand: Arc::new(operand),
                        floating_point: false,
                    },
                })?
            }};
        }
        macro_rules! binop {
            ($op:literal) => {
                fold($op, false, children)?
            };
            ($op:literal, signed) => {
                fold($op, true, children)?
            };
        }
        // An (in)equality. A bit test like `(base & 0b100) != 0` is canonicalized by clarirs
        // into `Extract(hi, lo, base) != 0`. Lowering that extract literally yields
        // `(base >> lo) & mask`; re-express the comparison against zero as the in-place mask
        // `base & (mask << lo)` instead so it reads like the original `base & C`. This is only
        // valid because comparing to zero makes it a boolean test (the shifted-down and in-place
        // forms differ in value but not in truthiness). `lo == 0` extracts already lower to a
        // clean `base & mask` and are left alone.
        macro_rules! equality {
            ($op:literal, $a:expr, $b:expr) => {{
                let bit_test = [($a, $b), ($b, $a)]
                    .into_iter()
                    .find_map(|(extract, zero)| match (extract.op(), zero.op()) {
                        (AstOp::Extract(base, hi, lo), AstOp::BVV(value))
                            if value.is_zero() && *lo != 0 =>
                        {
                            Some((base, *hi, *lo))
                        }
                        _ => None,
                    });
                match bit_test {
                    Some((base, hi, lo)) => {
                        // the base was converted on the way to the extract
                        let base_ail: AilExpression = memoized(base)?
                            .ok_or_else(|| PyRuntimeError::new_err("unconverted extract base"))?
                            .extract()?;
                        let mask = ((BigInt::from(1) << (hi - lo + 1)) - 1) << lo;
                        let idx = next_atom()?;
                        let mask = constant(next_atom()?, const_value(mask), base.size(), tags);
                        let masked = binary_op(idx, "And", base_ail, mask, false, tags);
                        let idx = next_atom()?;
                        let zero = constant(next_atom()?, ConstValue::Int(0), base.size(), tags);
                        wrap(binary_op(idx, $op, masked, zero, false, tags))?
                    }
                    None => binop!($op),
                }
            }};
        }

        let mut converted = match ast.op() {
            // Polymorphic boolean/bitvector operations
            AstOp::Not(..) if is_bool => unop!("Not"),
            AstOp::Not(..) => unop!("BitwiseNeg"),
            AstOp::And(..) if is_bool => binop!("LogicalAnd"),
            AstOp::And(..) => binop!("And"),
            AstOp::Or(..) if is_bool => binop!("LogicalOr"),
            AstOp::Or(..) => binop!("Or"),
            AstOp::Xor(..) if !is_bool => binop!("Xor"),

            // Boolean leaves and predicates
            AstOp::BoolV(value) => wrap(constant(
                next_atom()?,
                ConstValue::Int(i128::from(*value)),
                1,
                tags,
            ))?,
            AstOp::Eq(a, b) => equality!("CmpEQ", a, b),
            AstOp::Neq(a, b) => equality!("CmpNE", a, b),
            AstOp::ULT(..) => binop!("CmpLT"),
            AstOp::ULE(..) => binop!("CmpLE"),
            AstOp::UGT(..) => binop!("CmpGT"),
            AstOp::UGE(..) => binop!("CmpGE"),
            AstOp::SLT(..) => binop!("CmpLT", signed),
            AstOp::SLE(..) => binop!("CmpLE", signed),
            AstOp::SGT(..) => binop!("CmpGT", signed),
            AstOp::SGE(..) => binop!("CmpGE", signed),

            // Bitvector leaves and operations
            AstOp::BVV(value) => {
                let value = const_value(BigInt::from(value.to_biguint()));
                wrap(constant(next_atom()?, value, ast.size(), tags))?
            }
            AstOp::Neg(..) => unop!("Neg"),
            AstOp::Add(..) => binop!("Add"),
            AstOp::Sub(..) => binop!("Sub"),
            AstOp::Mul(..) => binop!("Mul"),
            AstOp::UDiv(..) => binop!("Div"),
            AstOp::URem(..) => binop!("Mod"),
            AstOp::ShL(..) => binop!("Shl"),
            AstOp::LShR(..) => binop!("Shr"),
            AstOp::AShR(..) => binop!("Sar"),
            AstOp::ZeroExt(_, amount) => {
                // zero bits concatenated in front; the zero converts like any other constant
                let zero = GLOBAL_CONTEXT
                    .bvv(BitVec::from((BigUint::ZERO, *amount)))
                    .map_err(ClaripyError::from)?;
                let zero_ail = match memoized(&zero)? {
                    Some(hit) => hit,
                    None => {
                        let zero_cond = Base::from_ast(py, zero.clone())?;
                        let (zero_tags, _) = tags_of(&ast2annotations, &zero_cond, false)?;
                        let value = constant(next_atom()?, ConstValue::Int(0), *amount, &zero_tags);
                        finish(&zero, wrap(value)?)?
                    }
                };
                fold("Concat", false, &[zero_ail, children[0].clone()])?
            }
            AstOp::Extract(a, hi, lo) => {
                // ailment does not support Extract. We translate Extract(hi, lo, expr) to a
                // logical right shift by `lo` (dropping the low bits) followed by a Convert
                // that truncates to the extracted width.
                let mut operand: AilExpression = children[0].extract()?;
                if *lo != 0 {
                    let idx = next_atom()?;
                    let amount = constant(
                        next_atom()?,
                        ConstValue::Int(i128::from(*lo)),
                        a.size(),
                        tags,
                    );
                    operand = binary_op(idx, "Shr", operand, amount, false, tags);
                }
                wrap(AilExpression {
                    header: ExprHeader::new(
                        next_atom()?,
                        operand.header.depth + 1,
                        hi - lo + 1,
                        tags.clone(),
                    ),
                    inner: ExprInner::Convert {
                        operand: Arc::new(operand),
                        from_bits: a.size(),
                        to_bits: hi - lo + 1,
                        is_signed: false,
                        from_type: ConvertType::TypeInt,
                        to_type: ConvertType::TypeInt,
                        rounding_mode: None,
                        vector_count: None,
                    },
                })?
            }
            AstOp::Concat(..) => binop!("Concat"),

            _ => {
                return Err(PyNotImplementedError::new_err(format!(
                    "Condition variable {} has an unsupported operator {}. Consider implementing.",
                    cond.str()?,
                    ast.to_opstring()
                )));
            }
        };

        if floating_point && let Ok(expression) = converted.cast::<Expression>() {
            // claripy has no FP flavor of these operators; restore the flag on the rebuilt
            // expression
            let flagged = match &expression.borrow().expr {
                expr @ AilExpression {
                    inner:
                        ExprInner::BinaryOp {
                            op,
                            operands,
                            signed,
                            floating_point: false,
                            ..
                        },
                    ..
                } if matches!(
                    op.as_str(),
                    "CmpEQ"
                        | "CmpNE"
                        | "CmpLT"
                        | "CmpLE"
                        | "CmpGT"
                        | "CmpGE"
                        | "Add"
                        | "Sub"
                        | "Mul"
                        | "Div"
                ) =>
                {
                    let depth = operands[0].header.depth.max(operands[1].header.depth) + 1;
                    Some(AilExpression {
                        header: ExprHeader::new(
                            expr.header.idx,
                            depth,
                            expr.header.bits,
                            expr.header.tags.clone(),
                        ),
                        inner: ExprInner::BinaryOp {
                            op: op.clone(),
                            operands: operands.clone(),
                            signed: *signed,
                            floating_point: true,
                            rounding_mode: None,
                            vector_count: None,
                            vector_size: None,
                        },
                    })
                }
                _ => None,
            };
            if let Some(flagged) = flagged {
                converted = wrap(flagged)?;
            }
        }
        finish(&ast, converted)
    };

    walk(
        cond.get().ast(),
        |ast| pre_visit(ast).map_err(park),
        |ast, children| post_visit(ast, children).map_err(park),
        &(),
    )
    .map_err(|err| match raised.take() {
        Some(raised) => raised,
        None => ClaripyError::from(err).into(),
    })
}
