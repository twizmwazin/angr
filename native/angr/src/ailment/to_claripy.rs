//! AIL expression -> claripy AST conversion.
//!
//! This is the Rust port of
//! ``ConditionProcessor.claripy_ast_from_ail_condition``. The decompiler turns
//! AIL conditions into claripy ASTs so that it can reason about them as boolean
//! formulas (reaching conditions, simplification, ...). Everything claripy has
//! an operator for is translated structurally; everything else becomes an
//! opaque, explicitly named symbol that is recorded in ``condition_mapping``
//! so that the reverse conversion can restore the original AIL expression.
//!
//! The walk over the AIL tree, the operator dispatch and the symbol naming all
//! happen here, on the native [`AilExpression`] tree. A Python ``Expression``
//! wrapper is only materialized for the nodes that end up in one of the
//! side tables. claripy operators are applied through the same entry points
//! Python code uses, so operand coercion and simplification stay identical.

use std::cell::OnceCell;
use std::sync::Arc;

use pyo3::basic::CompareOp;
use pyo3::exceptions::{PyOverflowError, PyRecursionError, PyTypeError, PyZeroDivisionError};
use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::types::{PyDict, PySlice};

use crate::ailment::ail_expr::{AilExpression, ExprHeader, ExprInner, Expression};
use crate::ailment::const_value::ConstValue;
use crate::ailment::enums::ConvertType;
use crate::ailment::tags::{Tags, TagsView};
use crate::claripy::ast::GLOBAL_CONTEXT;
use crate::claripy::ast::base::Base;
use crate::claripy::ast::bool::Bool;
use crate::claripy::ast::bv::{self, BV};
use crate::claripy::ast::{and as claripy_and, not as claripy_not, or as claripy_or};
use crate::claripy::error::ClaripyError;
use clarirs_core::ast::AstFactory;

/// The logger of the Python module this conversion belongs to.
const LOGGER_NAME: &str = "angr.analyses.decompiler.condition_processor";

/// How many AIL nodes deep the conversion may recurse before it gives up with
/// a ``RecursionError`` rather than exhausting the native stack.
const MAX_DEPTH: u32 = 300;

type Ast<'py> = Bound<'py, PyAny>;

/// A comparison operator and its claripy counterpart.
#[derive(Clone, Copy)]
enum Cmp {
    Eq,
    Ne,
    Ult,
    Ule,
    Ugt,
    Uge,
    Slt,
    Sle,
    Sgt,
    Sge,
}

/// A binary bit-vector operator whose second operand is brought to the width
/// of the first.
#[derive(Clone, Copy)]
enum Arith {
    Add,
    Sub,
    Mul,
    Xor,
    And,
    Or,
    Shr,
    Shl,
    Sar,
}

/// What to do with an AIL operator.
#[derive(Clone, Copy)]
enum OpHandler {
    LogicalAnd,
    LogicalOr,
    Cmp(Cmp),
    Arith(Arith),
    Div,
    Mod,
    Concat,
    Not,
    Neg,
    BitwiseNeg,
    /// No claripy counterpart: an opaque bit-vector symbol.
    OpaqueBv,
    /// No claripy counterpart: an opaque boolean symbol.
    OpaqueBool,
}

impl OpHandler {
    fn is_binary(self) -> bool {
        matches!(
            self,
            Self::LogicalAnd
                | Self::LogicalOr
                | Self::Cmp(_)
                | Self::Arith(_)
                | Self::Div
                | Self::Mod
                | Self::Concat
        )
    }

    fn is_unary(self) -> bool {
        matches!(self, Self::Not | Self::Neg | Self::BitwiseNeg)
    }
}

/// The handler of an AIL operator name, or ``None`` for an unknown operator.
fn op_handler(op: &str) -> Option<OpHandler> {
    use OpHandler as H;
    Some(match op {
        "LogicalAnd" => H::LogicalAnd,
        "LogicalOr" => H::LogicalOr,
        "CmpEQ" | "CasCmpEQ" => H::Cmp(Cmp::Eq),
        "CmpNE" | "CasCmpNE" => H::Cmp(Cmp::Ne),
        "CmpLE" | "CasCmpLE" => H::Cmp(Cmp::Ule),
        "CmpLEs" | "CasCmpLEs" => H::Cmp(Cmp::Sle),
        "CmpLT" | "CasCmpLT" => H::Cmp(Cmp::Ult),
        "CmpLTs" | "CasCmpLTs" => H::Cmp(Cmp::Slt),
        "CmpGE" | "CasCmpGE" => H::Cmp(Cmp::Uge),
        "CmpGEs" | "CasCmpGEs" => H::Cmp(Cmp::Sge),
        "CmpGT" | "CasCmpGT" => H::Cmp(Cmp::Ugt),
        "CmpGTs" | "CasCmpGTs" => H::Cmp(Cmp::Sgt),
        "Add" => H::Arith(Arith::Add),
        "Sub" => H::Arith(Arith::Sub),
        "Mul" => H::Arith(Arith::Mul),
        "Xor" => H::Arith(Arith::Xor),
        "And" => H::Arith(Arith::And),
        "Or" => H::Arith(Arith::Or),
        "Shr" => H::Arith(Arith::Shr),
        "Shl" => H::Arith(Arith::Shl),
        "Sar" => H::Arith(Arith::Sar),
        "Div" => H::Div,
        "Mod" => H::Mod,
        "Concat" => H::Concat,
        "Not" => H::Not,
        "Neg" => H::Neg,
        "BitwiseNeg" => H::BitwiseNeg,
        // There are no corresponding claripy operations for the following operations
        "CmpF" | "Mull" | "Mulls" | "Reinterpret" | "Rol" | "Ror" | "LogicalXor" | "Carry"
        | "SCarry" | "SBorrow" | "MovMskPD" | "MovMskPS" | "CmpEQV" | "GetMSBs" | "ShlNV"
        | "ShrNV" | "InterleaveLOV" | "InterleaveHIV" => H::OpaqueBv,
        // in case CmpORDRewriter fails
        "CmpORD" => H::OpaqueBv,
        "ExpCmpNE" | "CmpUN" | "IsNaN" | "SignBit" | "IsInf" | "IsFinite" | "IsNormal" => {
            H::OpaqueBool
        }
        _ => return None,
    })
}

/// An AIL node together with its Python wrapper, which is only created once
/// something needs it.
struct Node<'a, 'py> {
    expr: &'a AilExpression,
    obj: OnceCell<Bound<'py, Expression>>,
}

impl<'a, 'py> Node<'a, 'py> {
    fn new(expr: &'a AilExpression) -> Self {
        Self {
            expr,
            obj: OnceCell::new(),
        }
    }

    fn with_obj(expr: &'a AilExpression, obj: Bound<'py, Expression>) -> Self {
        Self {
            expr,
            obj: OnceCell::from(obj),
        }
    }

    fn bits(&self) -> u32 {
        self.expr.header.bits
    }

    /// The Python ``Expression`` for this node.
    fn obj(&self, py: Python<'py>) -> PyResult<&Bound<'py, Expression>> {
        if let Some(obj) = self.obj.get() {
            return Ok(obj);
        }
        let obj = Bound::new(py, Expression::wrap(self.expr.clone()))?;
        Ok(self.obj.get_or_init(|| obj))
    }

    fn repr(&self, py: Python<'py>) -> PyResult<String> {
        self.obj(py)?.borrow().__repr__(py)
    }
}

/// ``format(value, "x")`` for a Python ``int``.
fn fmt_hex(value: i128) -> String {
    if value < 0 {
        format!("-{:x}", value.unsigned_abs())
    } else {
        format!("{value:x}")
    }
}

/// ``str(ast.args[0])``.
fn first_arg_str(ast: &Ast<'_>) -> PyResult<String> {
    Ok(ast.getattr("args")?.get_item(0)?.str()?.to_string())
}

/// ``ast.hash()``.
fn ast_hash(ast: &Ast<'_>) -> PyResult<u64> {
    Ok(ast.cast::<Base>()?.get().hash())
}

fn is_bool(ast: &Ast<'_>) -> bool {
    ast.cast::<Bool>().is_ok()
}

fn cached_import<'py>(
    py: Python<'py>,
    cell: &'static PyOnceLock<Py<PyAny>>,
    module: &str,
    attr: &str,
) -> PyResult<Bound<'py, PyAny>> {
    Ok(cell
        .get_or_try_init(py, || -> PyResult<Py<PyAny>> {
            Ok(py.import(module)?.getattr(attr)?.unbind())
        })?
        .bind(py)
        .clone())
}

fn logger(py: Python<'_>) -> PyResult<Bound<'_, PyAny>> {
    static LOGGER: PyOnceLock<Py<PyAny>> = PyOnceLock::new();
    Ok(LOGGER
        .get_or_try_init(py, || -> PyResult<Py<PyAny>> {
            Ok(py
                .import("logging")?
                .getattr("getLogger")?
                .call1((LOGGER_NAME,))?
                .unbind())
        })?
        .bind(py)
        .clone())
}

/// State of one conversion: the side tables the conversion records into.
struct Converter<'a, 'py> {
    py: Python<'py>,
    /// Symbol name (or annotated constant) -> the AIL expression it stands for.
    condition_mapping: &'a Bound<'py, PyAny>,
    /// claripy AST -> tags of the AIL expression it was converted from.
    ast2annotations: &'a Bound<'py, PyAny>,
    ail_manager: &'a Bound<'py, PyAny>,
    /// The annotation that keeps a converted ``Const`` apart from other
    /// constants of the same value and size.
    const_annotation: &'a Bound<'py, PyAny>,
    /// The manager's ``VariableMap``, looked up on first use.
    variable_map: Option<Bound<'py, PyAny>>,
    depth: u32,
}

impl<'a, 'py> Converter<'a, 'py> {
    //
    // Symbols
    //

    fn bvs(&self, name: String, bits: u32) -> PyResult<Ast<'py>> {
        let ast = GLOBAL_CONTEXT
            .bvs(&name, bits)
            .map_err(ClaripyError::from)?;
        Ok(BV::new_with_name(self.py, &ast, Some(name))?.into_any())
    }

    fn bools(&self, name: String) -> PyResult<Ast<'py>> {
        let ast = GLOBAL_CONTEXT.bools(&name).map_err(ClaripyError::from)?;
        Ok(Bool::new_with_name(self.py, &ast, Some(name))?.into_any())
    }

    fn bool_value(&self, value: bool) -> PyResult<Ast<'py>> {
        let ast = GLOBAL_CONTEXT.boolv(value).map_err(ClaripyError::from)?;
        Ok(Bool::new(self.py, &ast)?.into_any())
    }

    /// Create the symbol ``name`` standing for ``node`` -- a boolean one if
    /// ``boolean``, else a bit-vector of ``bits`` bits -- and record it.
    fn symbol(
        &self,
        node: &Node<'_, 'py>,
        name: String,
        boolean: bool,
        bits: u32,
    ) -> PyResult<Ast<'py>> {
        self.condition_mapping.set_item(&name, node.obj(self.py)?)?;
        if boolean {
            self.bools(name)
        } else {
            self.bvs(name, bits)
        }
    }

    /// A symbol named after the node's width: boolean for 1-bit nodes.
    fn sized_symbol(&self, node: &Node<'_, 'py>, name: String) -> PyResult<Ast<'py>> {
        self.symbol(node, name, node.bits() == 1, node.bits())
    }

    /// An opaque symbol named after the expression itself.
    fn opaque(&self, node: &Node<'_, 'py>, suffix: &str, boolean: bool) -> PyResult<Ast<'py>> {
        let name = format!("ailexpr_{}{suffix}", node.repr(self.py)?);
        self.symbol(node, name, boolean, node.bits())
    }

    //
    // Leaves
    //

    /// The identifier of the variable associated with ``node``, if any.
    fn variable_ident(&mut self, node: &Node<'_, 'py>) -> PyResult<Option<String>> {
        static VARIABLE_MAP_OF: PyOnceLock<Py<PyAny>> = PyOnceLock::new();
        let py = self.py;
        let variable_map = match &self.variable_map {
            Some(variable_map) => variable_map.clone(),
            None => {
                let variable_map = cached_import(
                    py,
                    &VARIABLE_MAP_OF,
                    "angr.analyses.decompiler.variable_map",
                    "variable_map_of",
                )?
                .call1((self.ail_manager,))?;
                self.variable_map.insert(variable_map).clone()
            }
        };
        let variable = variable_map.call_method1("variable", (node.obj(py)?,))?;
        if variable.is_none() {
            return Ok(None);
        }
        Ok(Some(variable.getattr("ident")?.str()?.to_string()))
    }

    /// A ``Load``, ``Register`` or ``VirtualVariable``: one symbol per
    /// variable (or atom) and instruction.
    fn convert_variable(&mut self, node: &Node<'_, 'py>, ins_addr: i128) -> PyResult<Ast<'py>> {
        // SSA: the same vvar holds the same value at every instruction
        let ins_addr = match node.expr.inner {
            ExprInner::VirtualVariable { .. } => 0,
            _ => ins_addr,
        };
        // does it have a variable associated?
        let ident = match self.variable_ident(node)? {
            Some(ident) => ident,
            None => node.expr.header.idx.to_string(),
        };
        let name = format!(
            "ailexpr_{}-{ident}-{}",
            node.repr(self.py)?,
            fmt_hex(ins_addr)
        );
        self.sized_symbol(node, name)
    }

    /// The offset of an ``Extract`` / ``Insert`` as it appears in a symbol name.
    fn offset_str(&mut self, offset: &AilExpression, ins_addr: i128) -> PyResult<String> {
        if let ExprInner::Const { value } = &offset.inner {
            return Ok(value.into_pyobject(self.py)?.str()?.to_string());
        }
        first_arg_str(&self.convert(&Node::new(offset), false, false, ins_addr)?)
    }

    fn convert_const(&self, node: &Node<'_, 'py>, value: &ConstValue) -> PyResult<Ast<'py>> {
        let py = self.py;
        let bits = node.bits();
        let value = match value {
            // represent FP constants by their bit pattern
            ConstValue::Float(f) => match bits {
                64 => f.to_bits().into_pyobject(py)?.into_any(),
                32 => {
                    let single = *f as f32;
                    if single.is_infinite() && f.is_finite() {
                        return Err(PyOverflowError::new_err(
                            "float too large to pack with f format",
                        ));
                    }
                    single.to_bits().into_pyobject(py)?.into_any()
                }
                _ => {
                    return Err(PyTypeError::new_err(
                        "BVV value must be a int, bytes, or str",
                    ));
                }
            },
            value => value.into_pyobject(py)?,
        };
        let plain = bv::BVV(py, value, Some(bits))?;
        // we do not want to lose track of this constant
        let var = plain
            .as_any()
            .call_method1("annotate", (self.const_annotation,))?;
        self.condition_mapping.set_item(&var, node.obj(py)?)?;
        if bits == 1 {
            let one = plain
                .get()
                .concrete_value()?
                .is_some_and(|v| v == 1u8.into());
            return self.bool_value(one);
        }
        Ok(var)
    }

    //
    // Operators
    //

    fn apply_cmp(&self, cmp: Cmp, lhs: &Ast<'py>, rhs: &Ast<'py>) -> PyResult<Ast<'py>> {
        let py = self.py;
        let signed = |f: fn(
            Python<'py>,
            crate::claripy::ast::coerce::CoerceBV,
            crate::claripy::ast::coerce::CoerceBV,
        ) -> Result<Bound<'py, Bool>, ClaripyError>|
         -> PyResult<Ast<'py>> {
            Ok(f(py, lhs.extract()?, rhs.extract()?)?.into_any())
        };
        match cmp {
            Cmp::Eq => lhs.rich_compare(rhs, CompareOp::Eq),
            Cmp::Ne => lhs.rich_compare(rhs, CompareOp::Ne),
            Cmp::Ult => lhs.rich_compare(rhs, CompareOp::Lt),
            Cmp::Ule => lhs.rich_compare(rhs, CompareOp::Le),
            Cmp::Ugt => lhs.rich_compare(rhs, CompareOp::Gt),
            Cmp::Uge => lhs.rich_compare(rhs, CompareOp::Ge),
            Cmp::Slt => signed(bv::SLT),
            Cmp::Sle => signed(bv::SLE),
            Cmp::Sgt => signed(bv::SGT),
            Cmp::Sge => signed(bv::SGE),
        }
    }

    fn apply_arith(&self, op: Arith, lhs: &Ast<'py>, rhs: &Ast<'py>) -> PyResult<Ast<'py>> {
        match op {
            Arith::Add => lhs.add(rhs),
            Arith::Sub => lhs.sub(rhs),
            Arith::Mul => lhs.mul(rhs),
            Arith::Xor => lhs.bitxor(rhs),
            Arith::And => lhs.bitand(rhs),
            Arith::Or => lhs.bitor(rhs),
            Arith::Shl => lhs.lshift(rhs),
            Arith::Sar => lhs.rshift(rhs),
            Arith::Shr => Ok(bv::LShR(self.py, lhs.extract()?, rhs.extract()?)?.into_any()),
        }
    }

    /// A comparison. Its operands are brought to the same width first: an AIL
    /// comparison can end up with operands that convert to bit-vectors of
    /// different widths (an ill-formed expression from an earlier pass);
    /// claripy refuses to compare those, and a decompilation should not die on
    /// a condition.
    fn convert_cmp(
        &mut self,
        node: &Node<'_, 'py>,
        cmp: Cmp,
        operands: &[Arc<AilExpression>; 2],
        floating_point: bool,
        ins_addr: i128,
    ) -> PyResult<Ast<'py>> {
        let py = self.py;
        if floating_point && operands[0].likes(&operands[1]) {
            // x != x is the NaN test; claripy would fold it to a constant
            return self.opaque(node, "", true);
        }
        let mut converted = Vec::with_capacity(2);
        for operand in operands {
            let operand_node = Node::new(operand);
            let is_bitwise = matches!(
                &operand.inner,
                ExprInner::BinaryOp { op, .. } if matches!(op.as_str(), "And" | "Or" | "Xor")
            );
            converted.push(if floating_point && is_bitwise {
                // bit operations on an FP compare operand (fabs as x & 0x7fff...) must stay
                // opaque: claripy would simplify them into integer extracts and the compare
                // would lose its FP meaning
                self.opaque(&operand_node, "", false)?
            } else {
                self.convert(&operand_node, true, false, ins_addr)?
            });
        }
        let rhs = converted.pop().expect("two operands");
        let lhs = converted.pop().expect("two operands");
        let rhs = match (lhs.cast::<BV>(), rhs.cast::<BV>()) {
            (Ok(lhs_bv), Ok(rhs_bv)) => {
                let (lhs_size, rhs_size) = (lhs_bv.get().size(), rhs_bv.get().size());
                if rhs_size < lhs_size {
                    bv::ZeroExt(py, (lhs_size - rhs_size) as u32, rhs_bv.clone())?.into_any()
                } else if rhs_size > lhs_size {
                    let range = py.get_type::<PySlice>().call1((lhs_size as i64 - 1, 0))?;
                    BV::__getitem__(rhs_bv.clone(), range)?.into_any()
                } else {
                    rhs
                }
            }
            _ => rhs,
        };
        self.apply_cmp(cmp, &lhs, &rhs)
    }

    /// A binary operator whose second operand must be as wide as the first.
    fn convert_arith(
        &mut self,
        op: Arith,
        operands: &[Arc<AilExpression>; 2],
        ins_addr: i128,
    ) -> PyResult<Ast<'py>> {
        let py = self.py;
        let [operand0, operand1] = operands;
        if let ExprInner::Const { value } = &operand1.inner
            && value.is_int()
        {
            // amazing - we do the easy thing here: claripy sizes the integer itself
            let lhs = self.convert(&Node::new(operand0), true, false, ins_addr)?;
            return self.apply_arith(op, &lhs, &value.into_pyobject(py)?);
        }
        if operand1.header.bits == operand0.header.bits {
            let lhs = self.convert(&Node::new(operand0), true, false, ins_addr)?;
            let rhs = self.convert(&Node::new(operand1), true, false, ins_addr)?;
            return self.apply_arith(op, &lhs, &rhs);
        }
        // extension (or, for a shift amount wider than the value, truncation) is required
        let idx: i64 = self.ail_manager.call_method0("next_atom")?.extract()?;
        let resized = AilExpression {
            header: ExprHeader::new(
                idx,
                operand1.header.depth + 1,
                operand0.header.bits,
                Tags::default(),
            ),
            inner: ExprInner::Convert {
                operand: Arc::clone(operand1),
                from_bits: operand1.header.bits,
                to_bits: operand0.header.bits,
                is_signed: false,
                from_type: ConvertType::TypeInt,
                to_type: ConvertType::TypeInt,
                rounding_mode: None,
                vector_count: None,
            },
        };
        let lhs = self.convert(&Node::new(operand0), true, false, ins_addr)?;
        let rhs = self.convert(&Node::new(&resized), true, false, ins_addr)?;
        self.apply_arith(op, &lhs, &rhs)
    }

    fn convert_binary(
        &mut self,
        node: &Node<'_, 'py>,
        handler: OpHandler,
        operands: &[Arc<AilExpression>; 2],
        floating_point: bool,
        ins_addr: i128,
    ) -> PyResult<Ast<'py>> {
        let py = self.py;
        let [operand0, operand1] = operands;
        match handler {
            OpHandler::LogicalAnd | OpHandler::LogicalOr => {
                let args = vec![
                    self.convert(&Node::new(operand0), false, false, ins_addr)?,
                    self.convert(&Node::new(operand1), false, false, ins_addr)?,
                ];
                Ok(if matches!(handler, OpHandler::LogicalAnd) {
                    claripy_and(py, args)?
                } else {
                    claripy_or(py, args)?
                }
                .into_any())
            }
            OpHandler::Cmp(cmp) => self.convert_cmp(node, cmp, operands, floating_point, ins_addr),
            OpHandler::Arith(op) => self.convert_arith(op, operands, ins_addr),
            OpHandler::Div | OpHandler::Mod => {
                let lhs = self.convert(&Node::new(operand0), true, false, ins_addr)?;
                let rhs = self.convert(&Node::new(operand1), true, false, ins_addr)?;
                if matches!(handler, OpHandler::Div) {
                    lhs.div(rhs)
                } else {
                    lhs.rem(rhs)
                }
            }
            OpHandler::Concat => {
                let args = vec![
                    self.convert(&Node::new(operand0), false, false, ins_addr)?
                        .extract()?,
                    self.convert(&Node::new(operand1), false, false, ins_addr)?
                        .extract()?,
                ];
                Ok(bv::Concat(py, args)?.into_any())
            }
            OpHandler::OpaqueBool => self.opaque(node, "", true),
            _ => self.opaque(node, "", false),
        }
    }

    fn convert_unary(
        &mut self,
        node: &Node<'_, 'py>,
        handler: OpHandler,
        operand: &AilExpression,
        ins_addr: i128,
    ) -> PyResult<Ast<'py>> {
        match handler {
            OpHandler::Not => {
                let operand = self.convert(&Node::new(operand), false, false, ins_addr)?;
                Ok(claripy_not(self.py, operand.cast_into::<Base>()?)?.into_any())
            }
            OpHandler::Neg => self
                .convert(&Node::new(operand), false, false, ins_addr)?
                .neg(),
            OpHandler::BitwiseNeg => self
                .convert(&Node::new(operand), false, false, ins_addr)?
                .bitnot(),
            OpHandler::OpaqueBool => self.opaque(node, "", true),
            _ => self.opaque(node, "", false),
        }
    }

    /// Fall back to the catch-all handler for an operator nothing else handles.
    fn unsupported(&self, op: &str, verbose_op: &str) -> PyResult<OpHandler> {
        logger(self.py)?.call_method1(
            "debug",
            (
                "Unsupported AIL expression operation %s (or verbose: %s). Fall back to the default catch-all \
                 dummy option. Consider implementing.",
                op,
                verbose_op,
            ),
        )?;
        Ok(OpHandler::OpaqueBv)
    }

    /// Dispatch an operator-shaped expression to its handler.
    fn apply_operator(&mut self, node: &Node<'_, 'py>, ins_addr: i128) -> PyResult<Ast<'py>> {
        match &node.expr.inner {
            ExprInner::BinaryOp {
                op,
                operands,
                signed,
                floating_point,
                ..
            } => {
                // a signed integer operator is first looked up under its verbose name (CmpLEs)
                let verbose = (*signed && !*floating_point).then(|| format!("{op}s"));
                let handler = verbose
                    .as_deref()
                    .and_then(op_handler)
                    .or_else(|| op_handler(op))
                    .filter(|handler| !handler.is_unary());
                let handler = match handler {
                    Some(handler) => handler,
                    None => self.unsupported(op, verbose.as_deref().unwrap_or(op))?,
                };
                self.convert_binary(node, handler, operands, *floating_point, ins_addr)
            }
            ExprInner::UnaryOp { op, operand, .. } => {
                let handler = match op_handler(op).filter(|handler| !handler.is_binary()) {
                    Some(handler) => handler,
                    None => self.unsupported(op, op)?,
                };
                self.convert_unary(node, handler, operand, ins_addr)
            }
            ExprInner::Reinterpret { .. } => self.opaque(node, "", false),
            ExprInner::DirtyExpression(dirty) => {
                self.unsupported(&dirty.callee, &dirty.callee)?;
                self.opaque(node, "", false)
            }
            _ => {
                self.unsupported("let", "let")?;
                self.opaque(node, "", false)
            }
        }
    }

    /// The tags to remember for the AST converted from ``node``.
    fn annotations(&self, node: &Node<'_, 'py>) -> PyResult<Bound<'py, PyAny>> {
        let py = self.py;
        let tags = &node.expr.header.tags;
        // don't lose the floating-point flag of an FP comparison (claripy folds !(a == b) into
        // a != b, so the negation of an FP comparison annotates that comparison)
        let fp_source = match &node.expr.inner {
            ExprInner::UnaryOp { op, operand, .. } if op == "Not" => &**operand,
            _ => node.expr,
        };
        let floating_point = matches!(
            &fp_source.inner,
            ExprInner::BinaryOp {
                floating_point: true,
                ..
            } | ExprInner::UnaryOp {
                floating_point: true,
                ..
            }
        );
        if floating_point {
            let dict: Bound<'py, PyDict> = tags.to_py_dict(py)?;
            dict.set_item("floating_point", true)?;
            return Ok(dict.into_any());
        }
        let view = TagsView::with_parent(tags.clone(), node.obj(py)?.clone().into_any().unbind());
        Ok(Bound::new(py, view)?.into_any())
    }

    //
    // Entry point
    //

    /// Convert ``node``. With ``nobool`` an operator result is always a
    /// bit-vector; with ``must_bool`` a 1-bit result is always a boolean.
    fn convert(
        &mut self,
        node: &Node<'_, 'py>,
        nobool: bool,
        must_bool: bool,
        ins_addr: i128,
    ) -> PyResult<Ast<'py>> {
        if self.depth >= MAX_DEPTH {
            return Err(PyRecursionError::new_err(
                "maximum recursion depth exceeded while converting an AIL expression to a claripy AST",
            ));
        }
        self.depth += 1;
        let result = self.convert_inner(node, nobool, must_bool, ins_addr);
        self.depth -= 1;
        result
    }

    fn convert_inner(
        &mut self,
        node: &Node<'_, 'py>,
        nobool: bool,
        must_bool: bool,
        ins_addr: i128,
    ) -> PyResult<Ast<'py>> {
        let py = self.py;
        let expr = node.expr;
        let bits = node.bits();

        // Unpack a condition all the way to the leaves
        match &expr.inner {
            ExprInner::VEXCCallExpression { .. }
            | ExprInner::BasePointerOffset { .. }
            | ExprInner::StackBaseOffset { .. }
            | ExprInner::ITE { .. }
            | ExprInner::StringLiteral { .. } => return self.opaque(node, "", must_bool),
            ExprInner::Call { .. }
            | ExprInner::Macro { .. }
            | ExprInner::FunctionLikeMacro { .. } => {
                let call_addr = i128::from(expr.header.tags.ins_addr.unwrap_or(0));
                let suffix = if call_addr < 0 {
                    format!("-0x{:x}", call_addr.unsigned_abs())
                } else {
                    format!("0x{call_addr:x}")
                };
                return self.opaque(node, &suffix, must_bool);
            }
            ExprInner::Load { .. }
            | ExprInner::Register { .. }
            | ExprInner::VirtualVariable { .. } => return self.convert_variable(node, ins_addr),
            ExprInner::Extract {
                base,
                offset,
                endness,
            } => {
                let base = self.convert(&Node::new(base), false, false, ins_addr)?;
                let offset = self.offset_str(offset, ins_addr)?;
                let name = format!(
                    "ailexpr_Extract({bits}, {endness}, {offset}, {})",
                    ast_hash(&base)?
                );
                return self.symbol(node, name, false, bits);
            }
            ExprInner::Insert {
                base,
                offset,
                value,
                ..
            } => {
                let base = self.convert(&Node::new(base), false, false, ins_addr)?;
                let value = self.convert(&Node::new(value), false, false, ins_addr)?;
                let offset = self.offset_str(offset, ins_addr)?;
                let name = format!(
                    "ailexpr_Insert({offset}, {}, {})",
                    ast_hash(&value)?,
                    ast_hash(&base)?
                );
                return self.symbol(node, name, false, bits);
            }
            ExprInner::Convert {
                operand,
                from_bits,
                to_bits,
                ..
            } => {
                // convert is special. if it generates a 1-bit variable, it should be treated as
                // a BoolS
                let boolean = *to_bits == 1 && !nobool;
                let operand = self.convert(&Node::new(operand), false, false, ins_addr)?;
                let name = format!(
                    "{}_Conv({from_bits}->{to_bits}, {})",
                    if boolean { "ailcond" } else { "ailexpr" },
                    ast_hash(&operand)?
                );
                return self.symbol(node, name, boolean, *to_bits);
            }
            ExprInner::Const { value } => return self.convert_const(node, value),
            ExprInner::Tmp { tmp_idx } => {
                logger(py)?.call_method1(
                    "warning",
                    ("Left-over ailment.Tmp variable %s.", node.obj(py)?),
                )?;
                return self.sized_symbol(node, format!("ailtmp_{tmp_idx}"));
            }
            ExprInner::MultiStatementExpression { .. } => {
                // just cache it
                let name = format!("mstmtexpr_{}", python_hash(expr));
                return self.sized_symbol(node, name);
            }
            ExprInner::UnaryOp { .. }
            | ExprInner::BinaryOp { .. }
            | ExprInner::Reinterpret { .. }
            | ExprInner::Let { .. }
            | ExprInner::DirtyExpression(..) => {}
            _ => {
                // an atom without an operator (a struct literal, a phi, ...): keep it opaque
                let name = format!("ailexpr_opaque_{}", python_hash(expr));
                return self.sized_symbol(node, name);
            }
        }

        let mut r = match self.apply_operator(node, ins_addr) {
            Ok(r) if nobool && is_bool(&r) => {
                let name = format!("ailexpr_from_bool_{}", r.repr()?);
                self.symbol(node, name, false, 1)?
            }
            Ok(r) => r,
            // a constant division by zero: keep the expression opaque
            Err(err) if err.is_instance_of::<PyZeroDivisionError>(py) => {
                self.opaque(node, "", bits == 1 && !nobool)?
            }
            Err(err) => return Err(err),
        };

        // don't lose tags
        self.ast2annotations.set_item(&r, self.annotations(node)?)?;

        if must_bool
            && let Ok(r_bv) = r.cast::<BV>()
            && r_bv.get().size() == 1
        {
            // convert to a Bool
            r = if r_bv.as_any().getattr("op")?.eq("BVV")? {
                self.bool_value(!r_bv.as_any().getattr("args")?.get_item(0)?.eq(0)?)?
            } else {
                let name = format!("bool_from_bv1_{}", first_arg_str(&r)?);
                self.symbol(node, name, true, 1)?
            };
        }
        Ok(r)
    }
}

/// ``hash(expr)`` as Python computes it (which never yields ``-1``).
fn python_hash(expr: &AilExpression) -> i64 {
    match expr.cached_hash_or_compute() {
        -1 => -2,
        hash => hash,
    }
}

/// Convert an AIL expression into a claripy AST.
///
/// ``condition_mapping`` receives every opaque symbol (keyed by its name) and
/// every converted constant (keyed by its annotated AST) together with the AIL
/// expression it stands for; ``ast2annotations`` receives the tags of every
/// converted operator, keyed by the resulting AST. ``const_annotation`` is the
/// claripy annotation put on converted constants.
///
/// With ``nobool`` an operator always converts to a bit-vector; with
/// ``must_bool`` a 1-bit result is always a boolean. ``ins_addr`` tells apart
/// the values a register or memory location holds at different instructions.
///
/// A ``condition`` that already is a claripy AST is returned unchanged.
#[pyfunction]
#[pyo3(signature = (
    condition,
    condition_mapping,
    ast2annotations,
    ail_manager,
    const_annotation,
    *,
    nobool = false,
    must_bool = false,
    ins_addr = 0,
))]
#[allow(clippy::too_many_arguments)]
pub fn claripy_ast_from_ail<'py>(
    py: Python<'py>,
    condition: Bound<'py, PyAny>,
    condition_mapping: Bound<'py, PyAny>,
    ast2annotations: Bound<'py, PyAny>,
    ail_manager: Bound<'py, PyAny>,
    const_annotation: Bound<'py, PyAny>,
    nobool: bool,
    must_bool: bool,
    ins_addr: i128,
) -> PyResult<Bound<'py, PyAny>> {
    if condition.cast::<Base>().is_ok() {
        return Ok(condition);
    }
    let condition = condition.cast_into::<Expression>().map_err(|err| {
        PyTypeError::new_err(format!(
            "expected an AIL expression or a claripy AST, got {}",
            err.into_inner().get_type()
        ))
    })?;
    let borrowed = condition.borrow();
    let mut converter = Converter {
        py,
        condition_mapping: &condition_mapping,
        ast2annotations: &ast2annotations,
        ail_manager: &ail_manager,
        const_annotation: &const_annotation,
        variable_map: None,
        depth: 0,
    };
    let node = Node::with_obj(&borrowed.expr, condition.clone());
    converter.convert(&node, nobool, must_bool, ins_addr)
}
