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
//! The conversion is one function, [`Converter::convert_node`]: a match over
//! the expression variants that converts the leaves, followed by a single
//! operator table keyed by operator name and arity. It works on the native
//! [`AilExpression`] tree. A Python ``Expression``
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
    // Operands
    //

    /// The offset of an ``Extract`` / ``Insert`` as it appears in a symbol name.
    fn offset_str(&mut self, offset: &AilExpression, ins_addr: i128) -> PyResult<String> {
        if let ExprInner::Const { value } = &offset.inner {
            return Ok(value.into_pyobject(self.py)?.str()?.to_string());
        }
        first_arg_str(&self.convert(&Node::new(offset), false, false, ins_addr)?)
    }

    /// The converted operands of a comparison, or ``None`` for the NaN test
    /// ``x != x`` (which claripy would fold to a constant).
    ///
    /// The operands are brought to the same width: an AIL comparison can end up
    /// with operands that convert to bit-vectors of different widths (an
    /// ill-formed expression from an earlier pass); claripy refuses to compare
    /// those, and a decompilation should not die on a condition.
    fn cmp_operands(
        &mut self,
        lhs: &Arc<AilExpression>,
        rhs: &Arc<AilExpression>,
        floating_point: bool,
        ins_addr: i128,
    ) -> PyResult<Option<(Ast<'py>, Ast<'py>)>> {
        let py = self.py;
        if floating_point && lhs.likes(rhs) {
            return Ok(None);
        }
        let mut convert = |operand: &Arc<AilExpression>| {
            let node = Node::new(operand);
            let is_bitwise = matches!(
                &operand.inner,
                ExprInner::BinaryOp { op, .. } if matches!(op.as_str(), "And" | "Or" | "Xor")
            );
            if floating_point && is_bitwise {
                // bit operations on an FP compare operand (fabs as x & 0x7fff...) must stay
                // opaque: claripy would simplify them into integer extracts and the compare
                // would lose its FP meaning
                self.opaque(&node, "", false)
            } else {
                self.convert(&node, true, false, ins_addr)
            }
        };
        let lhs = convert(lhs)?;
        let rhs = convert(rhs)?;
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
        Ok(Some((lhs, rhs)))
    }

    /// The converted operands of a binary bit-vector operator, the second one
    /// as wide as the first.
    fn arith_operands(
        &mut self,
        lhs: &Arc<AilExpression>,
        rhs: &Arc<AilExpression>,
        ins_addr: i128,
    ) -> PyResult<(Ast<'py>, Ast<'py>)> {
        if let ExprInner::Const { value } = &rhs.inner
            && value.is_int()
        {
            // amazing - we do the easy thing here: claripy sizes the integer itself
            let lhs = self.convert(&Node::new(lhs), true, false, ins_addr)?;
            return Ok((lhs, value.into_pyobject(self.py)?));
        }
        if rhs.header.bits == lhs.header.bits {
            let lhs_ast = self.convert(&Node::new(lhs), true, false, ins_addr)?;
            let rhs_ast = self.convert(&Node::new(rhs), true, false, ins_addr)?;
            return Ok((lhs_ast, rhs_ast));
        }
        // extension (or, for a shift amount wider than the value, truncation) is required
        let idx: i64 = self.ail_manager.call_method0("next_atom")?.extract()?;
        let resized = AilExpression {
            header: ExprHeader::new(idx, rhs.header.depth + 1, lhs.header.bits, Tags::default()),
            inner: ExprInner::Convert {
                operand: Arc::clone(rhs),
                from_bits: rhs.header.bits,
                to_bits: lhs.header.bits,
                is_signed: false,
                from_type: ConvertType::TypeInt,
                to_type: ConvertType::TypeInt,
                rounding_mode: None,
                vector_count: None,
            },
        };
        let lhs = self.convert(&Node::new(lhs), true, false, ins_addr)?;
        let rhs = self.convert(&Node::new(&resized), true, false, ins_addr)?;
        Ok((lhs, rhs))
    }

    //
    // The conversion
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
        let result = self.convert_node(node, nobool, must_bool, ins_addr);
        self.depth -= 1;
        result
    }

    fn convert_node(
        &mut self,
        node: &Node<'_, 'py>,
        nobool: bool,
        must_bool: bool,
        ins_addr: i128,
    ) -> PyResult<Ast<'py>> {
        let py = self.py;
        let expr = node.expr;
        let bits = node.bits();

        // An operand as is / as a bit-vector.
        macro_rules! conv {
            ($operand:expr) => {
                self.convert(&Node::new($operand), false, false, ins_addr)?
            };
        }
        macro_rules! conv_bv {
            ($operand:expr) => {
                self.convert(&Node::new($operand), true, false, ins_addr)?
            };
        }
        // Unpack a condition all the way to the leaves. Leaves and other atoms are converted
        // right here; an operator goes on to the operator table below.
        let (op, operands, signed, floating_point): (&str, &[Arc<AilExpression>], bool, bool) =
            match &expr.inner {
                ExprInner::VEXCCallExpression { .. }
                | ExprInner::BasePointerOffset { .. }
                | ExprInner::StackBaseOffset { .. }
                | ExprInner::ITE { .. }
                | ExprInner::StringLiteral { .. } => return self.opaque(node, "", must_bool),
                ExprInner::Call { .. }
                | ExprInner::Macro { .. }
                | ExprInner::FunctionLikeMacro { .. } => {
                    // one symbol per call site
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
                | ExprInner::VirtualVariable { .. } => {
                    // one symbol per variable (or atom) and instruction
                    static VARIABLE_MAP_OF: PyOnceLock<Py<PyAny>> = PyOnceLock::new();
                    // SSA: the same vvar holds the same value at every instruction
                    let ins_addr = match expr.inner {
                        ExprInner::VirtualVariable { .. } => 0,
                        _ => ins_addr,
                    };
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
                    // does it have a variable associated?
                    let variable = variable_map.call_method1("variable", (node.obj(py)?,))?;
                    let ident = if variable.is_none() {
                        expr.header.idx.to_string()
                    } else {
                        variable.getattr("ident")?.str()?.to_string()
                    };
                    let name = format!("ailexpr_{}-{ident}-{}", node.repr(py)?, fmt_hex(ins_addr));
                    return self.sized_symbol(node, name);
                }
                ExprInner::Extract {
                    base,
                    offset,
                    endness,
                } => {
                    let base = conv!(base);
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
                    let base = conv!(base);
                    let value = conv!(value);
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
                    // convert is special. if it generates a 1-bit variable, it should be
                    // treated as a BoolS
                    let boolean = *to_bits == 1 && !nobool;
                    let operand = conv!(operand);
                    let name = format!(
                        "{}_Conv({from_bits}->{to_bits}, {})",
                        if boolean { "ailcond" } else { "ailexpr" },
                        ast_hash(&operand)?
                    );
                    return self.symbol(node, name, boolean, *to_bits);
                }
                ExprInner::Const { value } => {
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
                    return Ok(var);
                }
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
                ExprInner::UnaryOp { op, operand, .. } => {
                    (op, std::slice::from_ref(operand), false, false)
                }
                ExprInner::BinaryOp {
                    op,
                    operands,
                    signed,
                    floating_point,
                    ..
                } => (op, operands, *signed && !*floating_point, *floating_point),
                ExprInner::Reinterpret { .. } => ("Reinterpret", &[], false, false),
                ExprInner::DirtyExpression(dirty) => (&dirty.callee, &[], false, false),
                ExprInner::Let { .. } => ("let", &[], false, false),
                _ => {
                    // an atom without an operator (a struct literal, a phi, ...): keep it opaque
                    let name = format!("ailexpr_opaque_{}", python_hash(expr));
                    return self.sized_symbol(node, name);
                }
            };

        // A comparison of two operands of the same width.
        macro_rules! cmp {
            ($a:expr, $b:expr, ($x:ident, $y:ident) => $apply:expr) => {
                match self.cmp_operands($a, $b, floating_point, ins_addr)? {
                    Some(($x, $y)) => $apply,
                    None => self.opaque(node, "", true)?,
                }
            };
        }
        macro_rules! cmp_unsigned {
            ($a:expr, $b:expr, $op:ident) => {
                cmp!($a, $b, (x, y) => x.rich_compare(y, CompareOp::$op)?)
            };
        }
        macro_rules! cmp_signed {
            ($a:expr, $b:expr, $op:ident) => {
                cmp!($a, $b, (x, y) => bv::$op(py, x.extract()?, y.extract()?)?.into_any())
            };
        }
        // A bit-vector operator whose second operand is brought to the width of the first.
        macro_rules! arith {
            ($a:expr, $b:expr, $op:ident) => {{
                let (x, y) = self.arith_operands($a, $b, ins_addr)?;
                x.$op(y)?
            }};
        }
        // A division: dividing by a constant zero keeps the expression opaque.
        macro_rules! division {
            ($a:expr, $b:expr, $op:ident) => {{
                let (x, y) = (conv_bv!($a), conv_bv!($b));
                match x.$op(y) {
                    Err(err) if err.is_instance_of::<PyZeroDivisionError>(py) => {
                        self.opaque(node, "", bits == 1 && !nobool)?
                    }
                    result => result?,
                }
            }};
        }

        // The operator table, keyed by operator name and arity.
        let mut r = match (op, operands) {
            ("LogicalAnd", [a, b]) => claripy_and(py, vec![conv!(a), conv!(b)])?.into_any(),
            ("LogicalOr", [a, b]) => claripy_or(py, vec![conv!(a), conv!(b)])?.into_any(),
            ("Not", [a]) => claripy_not(py, conv!(a).cast_into::<Base>()?)?.into_any(),

            ("CmpEQ" | "CasCmpEQ", [a, b]) => cmp_unsigned!(a, b, Eq),
            ("CmpNE" | "CasCmpNE", [a, b]) => cmp_unsigned!(a, b, Ne),
            ("CmpLT" | "CasCmpLT", [a, b]) if !signed => cmp_unsigned!(a, b, Lt),
            ("CmpLE" | "CasCmpLE", [a, b]) if !signed => cmp_unsigned!(a, b, Le),
            ("CmpGT" | "CasCmpGT", [a, b]) if !signed => cmp_unsigned!(a, b, Gt),
            ("CmpGE" | "CasCmpGE", [a, b]) if !signed => cmp_unsigned!(a, b, Ge),
            ("CmpLT" | "CasCmpLT" | "CmpLTs" | "CasCmpLTs", [a, b]) => cmp_signed!(a, b, SLT),
            ("CmpLE" | "CasCmpLE" | "CmpLEs" | "CasCmpLEs", [a, b]) => cmp_signed!(a, b, SLE),
            ("CmpGT" | "CasCmpGT" | "CmpGTs" | "CasCmpGTs", [a, b]) => cmp_signed!(a, b, SGT),
            ("CmpGE" | "CasCmpGE" | "CmpGEs" | "CasCmpGEs", [a, b]) => cmp_signed!(a, b, SGE),

            ("Add", [a, b]) => arith!(a, b, add),
            ("Sub", [a, b]) => arith!(a, b, sub),
            ("Mul", [a, b]) => arith!(a, b, mul),
            ("Div", [a, b]) => division!(a, b, div),
            ("Mod", [a, b]) => division!(a, b, rem),
            ("Neg", [a]) => conv!(a).neg()?,
            ("And", [a, b]) => arith!(a, b, bitand),
            ("Or", [a, b]) => arith!(a, b, bitor),
            ("Xor", [a, b]) => arith!(a, b, bitxor),
            ("BitwiseNeg", [a]) => conv!(a).bitnot()?,
            ("Shl", [a, b]) => arith!(a, b, lshift),
            ("Sar", [a, b]) => arith!(a, b, rshift),
            ("Shr", [a, b]) => {
                let (x, y) = self.arith_operands(a, b, ins_addr)?;
                bv::LShR(py, x.extract()?, y.extract()?)?.into_any()
            }
            ("Concat", [a, b]) => {
                bv::Concat(py, vec![conv!(a).extract()?, conv!(b).extract()?])?.into_any()
            }

            // There are no corresponding claripy operations for the following operations
            ("ExpCmpNE" | "CmpUN" | "IsNaN" | "SignBit" | "IsInf" | "IsFinite" | "IsNormal", _) => {
                self.opaque(node, "", true)?
            }
            (
                "CmpF" | "Mull" | "Mulls" | "Reinterpret" | "Rol" | "Ror" | "LogicalXor" | "Carry"
                | "SCarry" | "SBorrow" | "MovMskPD" | "MovMskPS" | "CmpEQV" | "GetMSBs" | "ShlNV"
                | "ShrNV" | "InterleaveLOV" | "InterleaveHIV",
                _,
            ) => self.opaque(node, "", false)?,
            // in case CmpORDRewriter fails
            ("CmpORD", _) => self.opaque(node, "", false)?,

            // catch-all
            _ => {
                logger(py)?.call_method1(
                    "debug",
                    (
                        "Unsupported AIL expression operation %s (or verbose: %s). Fall back to the default \
                         catch-all dummy option. Consider implementing.",
                        op,
                        if signed { format!("{op}s") } else { op.to_string() },
                    ),
                )?;
                self.opaque(node, "", false)?
            }
        };

        if nobool && is_bool(&r) {
            let name = format!("ailexpr_from_bool_{}", r.repr()?);
            r = self.symbol(node, name, false, 1)?;
        }

        // don't lose tags, nor the floating-point flag of an FP comparison (claripy folds
        // !(a == b) into a != b, so the negation of an FP comparison annotates that comparison)
        let fp_source = match (op, operands) {
            ("Not", [operand]) => &**operand,
            _ => expr,
        };
        let tags = if matches!(
            &fp_source.inner,
            ExprInner::BinaryOp {
                floating_point: true,
                ..
            } | ExprInner::UnaryOp {
                floating_point: true,
                ..
            }
        ) {
            let tags: Bound<'py, PyDict> = expr.header.tags.to_py_dict(py)?;
            tags.set_item("floating_point", true)?;
            tags.into_any()
        } else {
            let parent = node.obj(py)?.clone().into_any().unbind();
            Bound::new(py, TagsView::with_parent(expr.header.tags.clone(), parent))?.into_any()
        };
        self.ast2annotations.set_item(&r, tags)?;

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
