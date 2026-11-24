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
//! The conversion is one function, [`Converter::convert_node`]: a single match
//! over the claripy operators. Subtrees are memoized by claripy hash, and
//! every node that is built is handed to the caller's ``optimize`` callback
//! (the peephole rules), bottom-up.

use std::sync::Arc;

use num_bigint::{BigInt, BigUint};
use pyo3::exceptions::{PyNotImplementedError, PyRecursionError};
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
use clarirs_core::ast::AstFactory;
use clarirs_core::prelude::{AstOp, AstRef, BitVec};

/// How many claripy nodes deep the conversion may recurse before it gives up
/// with a ``RecursionError`` rather than exhausting the native stack.
const MAX_DEPTH: u32 = 300;

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

/// State of one conversion.
struct Converter<'a, 'py> {
    py: Python<'py>,
    /// Symbol name (or annotated constant) -> the AIL expression it stands for.
    condition_mapping: &'a Bound<'py, PyAny>,
    /// claripy AST -> tags of the AIL expression it was converted from.
    ast2annotations: &'a Bound<'py, PyAny>,
    ail_manager: &'a Bound<'py, PyAny>,
    /// claripy hash -> converted (and optimized) AIL expression.
    memo: &'a Bound<'py, PyDict>,
    /// Applied to every expression the conversion builds.
    optimize: &'a Bound<'py, PyAny>,
    depth: u32,
}

impl<'a, 'py> Converter<'a, 'py> {
    //
    // Building AIL expressions
    //

    fn next_atom(&self) -> PyResult<i64> {
        self.ail_manager.call_method0("next_atom")?.extract()
    }

    fn wrap(&self, expr: AilExpression) -> PyResult<Ail<'py>> {
        Ok(Bound::new(self.py, Expression::wrap(expr))?.into_any())
    }

    fn constant(&self, value: ConstValue, bits: u32, tags: &Tags) -> PyResult<AilExpression> {
        Ok(AilExpression {
            header: ExprHeader::new(self.next_atom()?, 0, bits, tags.clone()),
            inner: ExprInner::Const { value },
        })
    }

    fn binary_op(
        &self,
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

    /// Fold ``args`` into a left-leaning chain of ``op``. A single argument
    /// converts to itself.
    fn reduce<'r>(
        &mut self,
        op: &str,
        args: impl IntoIterator<Item = &'r AstRef<'static>>,
        signed: bool,
        tags: &Tags,
    ) -> PyResult<Ail<'py>> {
        let mut result: Option<Ail<'py>> = None;
        for arg in args {
            result = Some(match result {
                None => self.convert(arg)?,
                Some(lhs) => {
                    let idx = self.next_atom()?;
                    let rhs = self.convert(arg)?;
                    self.wrap(self.binary_op(
                        idx,
                        op,
                        lhs.extract()?,
                        rhs.extract()?,
                        signed,
                        tags,
                    ))?
                }
            });
        }
        Ok(result.unwrap_or_else(|| self.py.None().into_bound(self.py)))
    }

    //
    // The conversion
    //

    /// The tags recorded for ``cond`` (or, failing that, for its negation),
    /// without the floating-point flag, which is returned separately.
    fn tags_of(&self, cond: &Bound<'py, Base>, is_comparison: bool) -> PyResult<(Tags, bool)> {
        let py = self.py;
        let is_fp = |tags: &Bound<'py, PyAny>| -> PyResult<bool> {
            Ok(tags
                .call_method1("get", ("floating_point",))?
                .is(&*PyBool::new(py, true)))
        };
        let negated = || claripy_not(py, cond.clone());

        let recorded = if self.ast2annotations.contains(cond)? {
            Some(self.ast2annotations.get_item(cond)?)
        } else {
            let negated = negated()?;
            if self.ast2annotations.contains(&negated)? {
                Some(self.ast2annotations.get_item(&negated)?)
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
            if self.ast2annotations.contains(&negated)? {
                floating_point = is_fp(&self.ast2annotations.get_item(&negated)?)?;
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

    /// Convert ``ast``, reusing the conversion of a subtree seen before.
    fn convert(&mut self, ast: &AstRef<'static>) -> PyResult<Ail<'py>> {
        let key = ast.hash();
        if let Some(converted) = self.memo.get_item(key)?
            && !converted.is_none()
        {
            return Ok(converted);
        }
        if self.depth >= MAX_DEPTH {
            return Err(PyRecursionError::new_err(
                "maximum recursion depth exceeded while converting a claripy AST to an AIL expression",
            ));
        }
        self.depth += 1;
        let converted = self.convert_node(ast);
        self.depth -= 1;
        let converted = self.optimize.call1((converted?,))?;
        self.memo.set_item(key, &converted)?;
        Ok(converted)
    }

    fn convert_node(&mut self, ast: &AstRef<'static>) -> PyResult<Ail<'py>> {
        let py = self.py;
        let cond = Base::from_ast(py, ast.clone())?;

        // Leaves: whatever the forward conversion made a symbol (or an annotated constant) of
        if let AstOp::BoolV(true) = ast.op() {
            return self.wrap(self.constant(ConstValue::Int(1), 1, &Tags::default())?);
        }
        if self.condition_mapping.contains(&cond)? {
            return self.condition_mapping.get_item(&cond);
        }
        if let AstOp::BVS(name, _) | AstOp::BoolS(name) = ast.op()
            && self.condition_mapping.contains(name.as_str())?
        {
            return self.condition_mapping.get_item(name.as_str());
        }

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
        let (tags, floating_point) = self.tags_of(&cond, is_comparison)?;
        let tags = &tags;

        macro_rules! unop {
            ($op:literal, $a:expr) => {{
                let operand: AilExpression = self.convert($a)?.extract()?;
                self.wrap(AilExpression {
                    header: ExprHeader::new(
                        self.next_atom()?,
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
            ($op:literal, $a:expr, $b:expr) => {
                self.reduce($op, [$a, $b], false, tags)?
            };
            ($op:literal, $a:expr, $b:expr, signed) => {
                self.reduce($op, [$a, $b], true, tags)?
            };
        }
        macro_rules! naryop {
            ($op:literal, $args:expr) => {
                self.reduce($op, $args, false, tags)?
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
                        let mask = ((BigInt::from(1) << (hi - lo + 1)) - 1) << lo;
                        let base_ail: AilExpression = self.convert(base)?.extract()?;
                        let idx = self.next_atom()?;
                        let mask = self.constant(const_value(mask), base.size(), tags)?;
                        let masked = self.binary_op(idx, "And", base_ail, mask, false, tags);
                        let idx = self.next_atom()?;
                        let zero = self.constant(ConstValue::Int(0), base.size(), tags)?;
                        self.wrap(self.binary_op(idx, $op, masked, zero, false, tags))?
                    }
                    None => binop!($op, $a, $b),
                }
            }};
        }

        let converted = match ast.op() {
            // Polymorphic boolean/bitvector operations
            AstOp::Not(a) if is_bool => unop!("Not", a),
            AstOp::Not(a) => unop!("BitwiseNeg", a),
            AstOp::And(args) if is_bool => naryop!("LogicalAnd", args),
            AstOp::And(args) => naryop!("And", args),
            AstOp::Or(args) if is_bool => naryop!("LogicalOr", args),
            AstOp::Or(args) => naryop!("Or", args),
            AstOp::Xor(args) if !is_bool => naryop!("Xor", args),

            // Boolean leaves and predicates
            AstOp::BoolV(value) => {
                self.wrap(self.constant(ConstValue::Int(i128::from(*value)), 1, tags)?)?
            }
            AstOp::Eq(a, b) => equality!("CmpEQ", a, b),
            AstOp::Neq(a, b) => equality!("CmpNE", a, b),
            AstOp::ULT(a, b) => binop!("CmpLT", a, b),
            AstOp::ULE(a, b) => binop!("CmpLE", a, b),
            AstOp::UGT(a, b) => binop!("CmpGT", a, b),
            AstOp::UGE(a, b) => binop!("CmpGE", a, b),
            AstOp::SLT(a, b) => binop!("CmpLT", a, b, signed),
            AstOp::SLE(a, b) => binop!("CmpLE", a, b, signed),
            AstOp::SGT(a, b) => binop!("CmpGT", a, b, signed),
            AstOp::SGE(a, b) => binop!("CmpGE", a, b, signed),

            // Bitvector leaves and operations
            AstOp::BVV(value) => {
                let value = const_value(BigInt::from(value.to_biguint()));
                self.wrap(self.constant(value, ast.size(), tags)?)?
            }
            AstOp::Neg(a) => unop!("Neg", a),
            AstOp::Add(args) => naryop!("Add", args),
            AstOp::Sub(a, b) => binop!("Sub", a, b),
            AstOp::Mul(args) => naryop!("Mul", args),
            AstOp::UDiv(a, b) => binop!("Div", a, b),
            AstOp::URem(a, b) => binop!("Mod", a, b),
            AstOp::ShL(a, b) => binop!("Shl", a, b),
            AstOp::LShR(a, b) => binop!("Shr", a, b),
            AstOp::AShR(a, b) => binop!("Sar", a, b),
            AstOp::ZeroExt(a, amount) => {
                let zero = GLOBAL_CONTEXT
                    .bvv(BitVec::from((BigUint::ZERO, *amount)))
                    .map_err(ClaripyError::from)?;
                binop!("Concat", &zero, a)
            }
            AstOp::Extract(a, hi, lo) => {
                // ailment does not support Extract. We translate Extract(hi, lo, expr) to a
                // logical right shift by `lo` (dropping the low bits) followed by a Convert
                // that truncates to the extracted width.
                let mut operand: AilExpression = self.convert(a)?.extract()?;
                if *lo != 0 {
                    let idx = self.next_atom()?;
                    let amount = self.constant(ConstValue::Int(i128::from(*lo)), a.size(), tags)?;
                    operand = self.binary_op(idx, "Shr", operand, amount, false, tags);
                }
                self.wrap(AilExpression {
                    header: ExprHeader::new(
                        self.next_atom()?,
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
            AstOp::Concat(args) => naryop!("Concat", args),

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
            let expr = &expression.borrow().expr;
            if let ExprInner::BinaryOp {
                op,
                operands,
                signed,
                floating_point: false,
                ..
            } = &expr.inner
                && matches!(
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
                )
            {
                let depth = operands[0].header.depth.max(operands[1].header.depth) + 1;
                return self.wrap(AilExpression {
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
                });
            }
        }
        Ok(converted)
    }
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
    let mut converter = Converter {
        py,
        condition_mapping: &condition_mapping,
        ast2annotations: &ast2annotations,
        ail_manager: &ail_manager,
        memo: &memo,
        optimize: &optimize,
        depth: 0,
    };
    converter.convert(&cond.get().ast())
}
