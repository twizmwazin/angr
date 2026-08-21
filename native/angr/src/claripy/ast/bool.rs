#![allow(non_snake_case)]

use std::sync::LazyLock;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use ast::args::ExtractPyArgs;
use clarirs_vsa::reduce::Reduce;
use clarirs_vsa::strided_interval::ComparisonResult;
use dashmap::DashMap;
use pyo3::exceptions::PyValueError;
use pyo3::types::PyTuple;
use pyo3::types::{PyDict, PyWeakrefMethods, PyWeakrefReference};

use crate::claripy::ast::{and, not, or, xor};
use crate::claripy::prelude::*;

use super::r#if;

static BOOLS_COUNTER: AtomicUsize = AtomicUsize::new(0);
static PY_BOOL_CACHE: LazyLock<DashMap<u64, Py<PyWeakrefReference>>> = LazyLock::new(DashMap::new);

#[pyclass(extends=Base, subclass, frozen, weakref, module="angr.rustylib.claripy.ast.bool")]
pub struct Bool {
    pub(crate) inner: AstRef<'static>,
}

impl Bool {
    pub fn new<'py>(
        py: Python<'py>,
        inner: &AstRef<'static>,
    ) -> Result<Bound<'py, Bool>, ClaripyError> {
        Self::new_with_name(py, inner, None)
    }

    /// Wrap an AST without simplifying it, keeping its annotation set exactly as
    /// given.
    pub fn new_with_name<'py>(
        py: Python<'py>,
        inner: &AstRef<'static>,
        name: Option<String>,
    ) -> Result<Bound<'py, Bool>, ClaripyError> {
        if let Some(cache_hit) = PY_BOOL_CACHE.get(&inner.hash()).and_then(|cache_hit| {
            cache_hit
                .bind(py)
                .upgrade_as::<Bool>()
                .expect("bool cache poisoned")
        }) {
            Ok(cache_hit)
        } else {
            let this = Bound::new(
                py,
                PyClassInitializer::from(Base::new_with_name(py, inner, name)?).add_subclass(
                    Bool {
                        inner: inner.clone(),
                    },
                ),
            )?;
            let weakref = PyWeakrefReference::new(&this)?;
            PY_BOOL_CACHE.insert(inner.hash(), weakref.unbind());

            Ok(this)
        }
    }
}

impl Drop for Bool {
    fn drop(&mut self) {
        // Evict this wrapper's cache entry so dead hashes don't accumulate.
        // Our own weakref is already cleared by the time Drop runs, so a dead
        // upgrade means the entry is stale; a live upgrade means the entry was
        // re-populated with a new wrapper and must stay.
        Python::attach(|py| {
            PY_BOOL_CACHE.remove_if(&self.inner.hash(), |_, weakref| {
                weakref.bind(py).upgrade().is_none()
            });
        });
    }
}

#[pymethods]
impl Bool {
    #[new]
    #[pyo3(signature = (op, args, annotations=None))]
    pub fn py_new<'py>(
        py: Python<'py>,
        op: &str,
        args: Vec<Py<PyAny>>,
        annotations: Option<Vec<Bound<'py, PyAnnotation>>>,
    ) -> Result<Py<Bool>, ClaripyError> {
        let inner = match op {
            // Ops that are not a plain "call this context method on these args".
            "BoolS" => GLOBAL_CONTEXT.bools(&args[0].extract::<String>(py)?)?,
            "BoolV" => GLOBAL_CONTEXT.boolv(args[0].extract::<bool>(py)?)?,
            // (Dis)equality is polymorphic in the operand type.
            "__eq__" => {
                if args[0].cast_bound::<Bool>(py).is_ok() {
                    GLOBAL_CONTEXT.eq_(
                        &args[0].cast_bound::<Bool>(py)?.get().inner,
                        &args[1].cast_bound::<Bool>(py)?.get().inner,
                    )?
                } else if args[0].cast_bound::<BV>(py).is_ok() {
                    GLOBAL_CONTEXT.eq_(
                        &args[0].cast_bound::<BV>(py)?.get().inner,
                        &args[1].cast_bound::<BV>(py)?.get().inner,
                    )?
                } else {
                    GLOBAL_CONTEXT.eq_(
                        &args[0].cast_bound::<PyAstString>(py)?.get().inner,
                        &args[1].cast_bound::<PyAstString>(py)?.get().inner,
                    )?
                }
            }
            "__ne__" => {
                if args[0].cast_bound::<Bool>(py).is_ok() {
                    GLOBAL_CONTEXT.neq(
                        &args[0].cast_bound::<Bool>(py)?.get().inner,
                        &args[1].cast_bound::<Bool>(py)?.get().inner,
                    )?
                } else if args[0].cast_bound::<BV>(py).is_ok() {
                    GLOBAL_CONTEXT.neq(
                        &args[0].cast_bound::<BV>(py)?.get().inner,
                        &args[1].cast_bound::<BV>(py)?.get().inner,
                    )?
                } else {
                    GLOBAL_CONTEXT.neq(
                        &args[0].cast_bound::<PyAstString>(py)?.get().inner,
                        &args[1].cast_bound::<PyAstString>(py)?.get().inner,
                    )?
                }
            }
            _ => py_new_op_table! {
                py, args, op;
                "Not" => not(Bool[0]),
                "And" => and2(Bool[0], Bool[1]),
                "Or" => or2(Bool[0], Bool[1]),
                "Xor" => xor2(Bool[0], Bool[1]),
                "ULE" | "__le__" => ule(BV[0], BV[1]),
                "ULT" | "__lt__" => ult(BV[0], BV[1]),
                "UGE" | "__ge__" => uge(BV[0], BV[1]),
                "UGT" | "__gt__" => ugt(BV[0], BV[1]),
                "SLT" => slt(BV[0], BV[1]),
                "SLE" => sle(BV[0], BV[1]),
                "SGT" => sgt(BV[0], BV[1]),
                "SGE" => sge(BV[0], BV[1]),
                "fpEQ" => fp_eq(FP[0], FP[1]),
                "fpNEQ" => fp_neq(FP[0], FP[1]),
                "fpLT" => fp_lt(FP[0], FP[1]),
                "fpLEQ" => fp_leq(FP[0], FP[1]),
                "fpGT" => fp_gt(FP[0], FP[1]),
                "fpGEQ" => fp_geq(FP[0], FP[1]),
                "fpIsNan" => fp_is_nan(FP[0]),
                "fpIsInf" => fp_is_inf(FP[0]),
                "StrContains" => str_contains(PyAstString[0], PyAstString[1]),
                "StrPrefixOf" => str_prefix_of(PyAstString[0], PyAstString[1]),
                "StrSuffixOf" => str_suffix_of(PyAstString[0], PyAstString[1]),
                "StrIsDigit" => str_is_digit(PyAstString[0]),
                "If" => ite(Bool[0], Bool[1], Bool[2]),
            },
        };

        let inner_with_annotations = if let Some(annots) = annotations {
            let annots = annots
                .iter()
                .map(PyAnnotation::to_annotation)
                .collect::<Result<Vec<_>, _>>()?;
            GLOBAL_CONTEXT.annotate(&inner, annots)?
        } else {
            inner
        };

        // `__new__` reconstructs a node from (op, args, annotations) verbatim,
        // without simplifying (e.g. when unpickling).
        Ok(Bool::new(py, &inner_with_annotations)?.unbind())
    }

    pub fn size(&self) -> usize {
        1
    }

    pub fn __len__(&self) -> usize {
        self.size()
    }

    pub fn is_true(&self) -> Result<bool, ClaripyError> {
        Ok(self.inner.simplify()?.is_true())
    }

    pub fn is_false(&self) -> Result<bool, ClaripyError> {
        Ok(self.inner.simplify()?.is_false())
    }

    #[getter]
    pub fn concrete_value(&self) -> Result<Option<bool>, ClaripyError> {
        Ok(match self.inner.simplify_ext(false, false)?.op() {
            AstOp::BoolV(value) => Some(*value),
            _ => None,
        })
    }

    pub fn __invert__<'py>(&self, py: Python<'py>) -> Result<Bound<'py, Bool>, ClaripyError> {
        Bool::new(py, &GLOBAL_CONTEXT.not(&self.inner)?.simplify()?)
    }

    pub fn __and__<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBool,
    ) -> Result<Bound<'py, Bool>, ClaripyError> {
        bool_binop!(self, py, other, and2)
    }

    pub fn __or__<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBool,
    ) -> Result<Bound<'py, Bool>, ClaripyError> {
        bool_binop!(self, py, other, or2)
    }

    pub fn __xor__<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBool,
    ) -> Result<Bound<'py, Bool>, ClaripyError> {
        bool_binop!(self, py, other, xor2)
    }

    pub fn __eq__<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBool,
    ) -> Result<Bound<'py, Bool>, ClaripyError> {
        bool_binop!(self, py, other, eq_)
    }

    pub fn __ne__<'py>(
        &self,
        py: Python<'py>,
        other: CoerceBool,
    ) -> Result<Bound<'py, Bool>, ClaripyError> {
        bool_binop!(self, py, other, neq)
    }

    // `Base` defines `__hash__`, but Python makes a class unhashable if it
    // defines `__eq__` without its own `__hash__`, so it must be repeated here.
    pub fn __hash__(&self) -> usize {
        self.inner.hash() as usize
    }

    #[getter]
    pub fn cardinality(&self) -> Result<usize, ClaripyError> {
        match self.inner.reduce()?.into_bool()? {
            ComparisonResult::True => Ok(1),
            ComparisonResult::False => Ok(1),
            ComparisonResult::Maybe => Ok(2),
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn __reduce__<'py>(
        &self,
        py: Python<'py>,
    ) -> Result<
        (
            Bound<'py, PyAny>,
            (
                String,
                Vec<Bound<'py, PyAny>>,
                Vec<Bound<'py, PyAnnotation>>,
            ),
        ),
        ClaripyError,
    > {
        let class = py.get_type::<Bool>();
        let op = self.inner.to_opstring();
        let args = self.inner.extract_py_args(py)?;
        let annotations: Vec<Bound<'py, PyAnnotation>> = self
            .inner
            .annotations()
            .iter()
            .map(|annotation| PyAnnotation::from_annotation(py, annotation))
            .collect::<Result<_, _>>()?;
        Ok((class.into_any(), (op, args, annotations)))
    }
}

#[pyfunction(signature = (name, explicit_name = false))]
pub fn BoolS<'py>(
    py: Python<'py>,
    name: NameString,
    explicit_name: bool,
) -> Result<Bound<'py, Bool>, ClaripyError> {
    let mut name: String = name.into();
    if !explicit_name {
        let counter = BOOLS_COUNTER.fetch_add(1, Ordering::Relaxed);
        name = format!("{name}_{counter}");
    }
    Bool::new_with_name(py, &GLOBAL_CONTEXT.bools(&name)?, Some(name.clone()))
}

#[pyfunction]
pub fn BoolV(py: Python<'_>, value: bool) -> Result<Bound<'_, Bool>, ClaripyError> {
    Bool::new(py, &GLOBAL_CONTEXT.boolv(value)?)
}

#[pyfunction(name = "Eq")]
pub fn Eq_<'py>(
    py: Python<'py>,
    a: Bound<Bool>,
    b: Bound<Bool>,
) -> Result<Bound<'py, Bool>, ClaripyError> {
    Bool::new(
        py,
        &GLOBAL_CONTEXT
            .eq_(&a.get().inner, &b.get().inner)?
            .simplify()?,
    )
}

#[pyfunction]
pub fn Neq<'py>(
    py: Python<'py>,
    a: Bound<Bool>,
    b: Bound<Bool>,
) -> Result<Bound<'py, Bool>, ClaripyError> {
    Bool::new(
        py,
        &GLOBAL_CONTEXT
            .neq(&a.get().inner, &b.get().inner)?
            .simplify()?,
    )
}

#[pyfunction(name = "true")]
pub fn true_op(py: Python<'_>) -> Result<Bound<'_, Bool>, ClaripyError> {
    Bool::new(py, &GLOBAL_CONTEXT.true_()?)
}
#[pyfunction(name = "false")]
pub fn false_op(py: Python<'_>) -> Result<Bound<'_, Bool>, ClaripyError> {
    Bool::new(py, &GLOBAL_CONTEXT.false_()?)
}

/// Create an if-then-else tree from a list of condition-value pairs with a default value
///
/// # Arguments
///
/// * `cases` - A list of (condition, value) tuples
/// * `default` - The default value if none of the conditions are satisfied
///
/// # Returns
///
/// An expression encoding the result
#[pyfunction]
pub fn ite_cases<'py>(
    py: Python<'py>,
    cases: Bound<'py, PyAny>,
    default: Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyAny>> {
    let mut sofar = default;

    let cases_vec = cases.try_iter()?.collect::<Result<Vec<_>, _>>()?;

    // Process cases in reverse order
    for i in cases_vec.iter().rev() {
        let mut iter = i.try_iter()?;

        let cond = iter.next().ok_or_else(|| {
            PyValueError::new_err("Each case must be a (condition, value) tuple")
        })??;
        let cond_bool = cond.extract::<CoerceBool>()?;
        let value = iter.next().ok_or_else(|| {
            PyValueError::new_err("Each case must be a (condition, value) tuple")
        })??;

        // Create If expression: If(cond, value, sofar)
        sofar = r#if(py, cond_bool, value, sofar)?.as_any().clone();
    }

    Ok(sofar)
}

/// Given an expression created by `ite_cases`, produce the cases that generated it
///
/// # Arguments
///
/// * `ast` - The AST expression to reverse
///
/// # Returns
///
/// A list of (condition, value) tuples
#[pyfunction]
pub fn reverse_ite_cases<'py>(
    py: Python<'py>,
    ast: Bound<'py, PyAny>,
) -> PyResult<Vec<(Bound<'py, PyAny>, Bound<'py, PyAny>)>> {
    let mut queue: Vec<(Bound<'py, PyAny>, Bound<'py, PyAny>)> =
        vec![(true_op(py)?.into_any(), ast)];
    let mut results = Vec::new();

    while let Some((condition, current_ast)) = queue.pop() {
        // Check if this is an If node
        if let Ok(base) = current_ast.cast::<Base>() {
            let op = base.getattr("op")?;
            let op_str: String = op.extract()?;

            if op_str == "If" {
                // Get the three arguments: condition, true_branch, false_branch
                let args = base.getattr("args")?;
                let args_vec: Vec<Bound<'py, PyAny>> = args.extract()?;

                if args_vec.len() == 3 {
                    let if_cond = args_vec[0].clone();
                    let true_branch = args_vec[1].clone();
                    let false_branch = args_vec[2].clone();

                    // Queue: And(condition, if_cond)
                    let new_cond_true =
                        and(py, vec![condition.clone(), if_cond.clone()])?.into_any();
                    queue.push((new_cond_true, true_branch));

                    // Queue: And(condition, Not(if_cond))
                    let not_if_cond = not(py, if_cond.cast_into::<Base>()?)?;
                    let new_cond_false =
                        and(py, vec![condition.clone(), not_if_cond.into_any()])?.into_any();
                    queue.push((new_cond_false, false_branch));

                    continue;
                }
            }
        }

        // If not an If node, yield the condition and ast
        results.push((condition, current_ast));
    }

    Ok(results)
}

/// Create a binary search tree for large tables
///
/// # Arguments
///
/// * `i` - The variable which may take on multiple values
/// * `d` - A dictionary mapping possible values for i to values which the result could be
/// * `default` - A default value if i matches none of the keys of d
///
/// # Returns
///
/// An expression encoding the result
#[pyfunction]
pub fn ite_dict<'py>(
    py: Python<'py>,
    i: Bound<'py, Base>,
    d: Bound<'py, PyDict>,
    default: Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyAny>> {
    // For small dictionaries, just use ite_cases
    if d.len() <= 4 {
        let mut cases = Vec::new();
        for (k, v) in d.iter() {
            let cond = i.call_method1("__eq__", (k,))?;
            let tuple = PyTuple::new(py, &[cond, v])?;
            cases.push(tuple.into_any());
        }

        return ite_cases(py, cases.into_bound_py_any(py)?, default);
    }

    // Binary search
    // Find the median
    let keys = d.keys();

    // Sort the keys
    keys.getattr("sort")?.call0()?;

    let split_idx = (keys.len() - 1) / 2;
    let split_val = keys.get_item(split_idx)?;

    // Split the dictionary
    let dict_low = PyDict::new(py);
    let dict_high = PyDict::new(py);

    for (k, v) in d.iter() {
        let le = k.call_method1("__le__", (split_val.clone(),))?;
        let is_le: Bound<'py, Bool> = le.extract::<CoerceBool>()?.into();

        if is_le.get().inner.is_true() {
            dict_low.set_item(k, v)?;
        } else {
            dict_high.set_item(k, v)?;
        }
    }

    // Recursively build trees for each part
    let val_low = if dict_low.is_empty() {
        default.clone()
    } else {
        ite_dict(py, i.clone(), dict_low, default.clone())?
    };

    let val_high = if dict_high.is_empty() {
        default.clone()
    } else {
        ite_dict(py, i.clone(), dict_high, default.clone())?
    };

    // Combine with an if-then-else
    let cond = i
        .call_method1("__le__", (split_val,))?
        .cast_into::<Bool>()?;

    // Create If expression: If(cond, val_low, val_high)
    let result = r#if(py, CoerceBool(cond), val_low, val_high)?;
    Ok(result.into_any())
}

pub(crate) fn import(_: Python, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<Bool>()?;

    add_pyfunctions!(
        m,
        BoolS,
        BoolV,
        not,
        and,
        or,
        xor,
        Eq_,
        super::r#if,
        true_op,
        false_op,
        ite_cases,
        reverse_ite_cases,
        ite_dict,
    );

    Ok(())
}
