#![allow(non_snake_case)]

use std::sync::{
    LazyLock,
    atomic::{AtomicUsize, Ordering},
};

use dashmap::DashMap;
use pyo3::types::PyWeakrefReference;

use crate::claripy::prelude::*;

static STRINGS_COUNTER: AtomicUsize = AtomicUsize::new(0);
static PY_STRING_CACHE: LazyLock<DashMap<u64, Py<PyWeakrefReference>>> =
    LazyLock::new(DashMap::new);

#[pyclass(name="String", extends=Base, subclass, frozen, module="angr.rustylib.claripy.ast.strings")]
pub struct PyAstString {
    pub(crate) inner: AstRef<'static>,
}

impl PyAstString {
    pub fn new<'py>(
        py: Python<'py>,
        inner: &AstRef<'static>,
    ) -> Result<Bound<'py, PyAstString>, ClaripyError> {
        Self::new_with_name(py, inner, None)
    }

    /// Wrap an AST without simplifying it, keeping its annotation set exactly as
    /// given.
    pub fn new_with_name<'py>(
        py: Python<'py>,
        inner: &AstRef<'static>,
        name: Option<String>,
    ) -> Result<Bound<'py, PyAstString>, ClaripyError> {
        if let Some(cache_hit) = PY_STRING_CACHE.get(&inner.hash()).and_then(|cache_hit| {
            cache_hit
                .bind(py)
                .upgrade_as::<PyAstString>()
                .expect("bool cache poisoned")
        }) {
            Ok(cache_hit)
        } else {
            let this = Py::new(
                py,
                PyClassInitializer::from(Base::new_with_name(py, inner, name)?).add_subclass(
                    PyAstString {
                        inner: inner.clone(),
                    },
                ),
            )?;
            let weakref = PyWeakrefReference::new(this.bind(py))?;
            PY_STRING_CACHE.insert(inner.hash(), weakref.unbind());

            Ok(this.into_bound(py))
        }
    }
}

impl Drop for PyAstString {
    fn drop(&mut self) {
        // Evict this wrapper's cache entry so dead hashes don't accumulate.
        // Our own weakref is already cleared by the time Drop runs, so a dead
        // upgrade means the entry is stale; a live upgrade means the entry was
        // re-populated with a new wrapper and must stay.
        Python::attach(|py| {
            PY_STRING_CACHE.remove_if(&self.inner.hash(), |_, weakref| {
                weakref.bind(py).upgrade().is_none()
            });
        });
    }
}

#[pymethods]
impl PyAstString {
    #[new]
    #[pyo3(signature = (op, args, annotations=None))]
    pub fn py_new<'py>(
        py: Python<'py>,
        op: &str,
        args: Vec<Py<PyAny>>,
        annotations: Option<Vec<Bound<'py, PyAnnotation>>>,
    ) -> Result<Py<PyAstString>, ClaripyError> {
        let inner = match op {
            // Ops that are not a plain "call this context method on these args".
            "StringS" => GLOBAL_CONTEXT.strings(&args[0].extract::<String>(py)?)?,
            "StringV" => GLOBAL_CONTEXT.stringv(&args[0].extract::<String>(py)?)?,
            _ => py_new_op_table! {
                py, args, op;
                "StrConcat" => str_concat(PyAstString[0], PyAstString[1]),
                "StrSubstr" => str_substr(PyAstString[0], BV[1], BV[2]),
                "StrReplace" => str_replace(PyAstString[0], PyAstString[1], PyAstString[2]),
                "IntToStr" => bv_to_str(BV[0]),
                "If" => ite(Bool[0], PyAstString[1], PyAstString[2]),
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
        Ok(PyAstString::new(py, &inner_with_annotations)?.unbind())
    }

    #[getter]
    pub fn concrete_value(&self) -> Result<Option<String>, ClaripyError> {
        Ok(match self.inner.simplify_ext(false, false)?.op() {
            AstOp::StringV(value) => Some(value.clone()),
            _ => None,
        })
    }

    pub fn __add__<'py>(
        &self,
        py: Python<'py>,
        other: Bound<'py, PyAstString>,
    ) -> Result<Bound<'py, PyAstString>, ClaripyError> {
        str_binop!(PyAstString, self, py, other, str_concat)
    }

    pub fn __eq__<'py>(
        &self,
        py: Python<'py>,
        other: Bound<'py, PyAstString>,
    ) -> Result<Bound<'py, Bool>, ClaripyError> {
        str_binop!(Bool, self, py, other, str_eq)
    }

    pub fn __ne__<'py>(
        &self,
        py: Python<'py>,
        other: Bound<'py, PyAstString>,
    ) -> Result<Bound<'py, Bool>, ClaripyError> {
        str_binop!(Bool, self, py, other, str_neq)
    }

    // `Base` defines `__hash__`, but Python makes a class unhashable if it
    // defines `__eq__` without its own `__hash__`, so it must be repeated here.
    pub fn __hash__(&self) -> usize {
        self.inner.hash() as usize
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
        let class = py.get_type::<PyAstString>();
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
pub fn StringS<'py>(
    py: Python<'py>,
    name: NameString,
    explicit_name: bool,
) -> Result<Bound<'py, PyAstString>, ClaripyError> {
    let mut name: String = name.into();
    if !explicit_name {
        let counter = STRINGS_COUNTER.fetch_add(1, Ordering::Relaxed);
        name = format!("{name}_{counter}");
    }
    PyAstString::new_with_name(py, &GLOBAL_CONTEXT.strings(&name)?, Some(name))
}

#[pyfunction]
pub fn StringV<'py>(py: Python<'py>, value: &str) -> Result<Bound<'py, PyAstString>, ClaripyError> {
    PyAstString::new(py, &GLOBAL_CONTEXT.stringv(value)?)
}

#[pyfunction]
pub fn StrLen<'py>(
    py: Python<'py>,
    s: Bound<'py, PyAstString>,
) -> Result<Bound<'py, BV>, ClaripyError> {
    BV::new(
        py,
        &GLOBAL_CONTEXT
            .str_len(&s.get().inner)?
            .simplify_ext(true, true)?,
    )
}

#[pyfunction]
pub fn StrConcat<'py>(
    py: Python<'py>,
    s1: Bound<'py, PyAstString>,
    s2: Bound<'py, PyAstString>,
) -> Result<Bound<'py, PyAstString>, ClaripyError> {
    PyAstString::new(
        py,
        &GLOBAL_CONTEXT
            .str_concat(&s1.get().inner, &s2.get().inner)?
            .simplify()?,
    )
}

#[pyfunction]
pub fn StrSubstr<'py>(
    py: Python<'py>,
    start: CoerceBV<'py>,
    size: CoerceBV<'py>,
    base: Bound<'py, PyAstString>,
) -> Result<Bound<'py, PyAstString>, ClaripyError> {
    PyAstString::new(
        py,
        &GLOBAL_CONTEXT
            .str_substr(
                &base.get().inner,
                &start.unpack(py, 64, false)?.get().inner,
                &size.unpack(py, 64, false)?.get().inner,
            )?
            .simplify()?,
    )
}

/// A predicate over two strings, `StrX(a, b) -> Bool`. The argument names are
/// part of the Python API, so each op spells its own out.
macro_rules! str_cmp_fn {
    ($name:ident, $method:ident, $a:ident, $b:ident) => {
        #[pyfunction]
        pub fn $name<'py>(
            py: Python<'py>,
            $a: Bound<'py, PyAstString>,
            $b: Bound<'py, PyAstString>,
        ) -> Result<Bound<'py, Bool>, ClaripyError> {
            Bool::new(
                py,
                &GLOBAL_CONTEXT
                    .$method(&$a.get().inner, &$b.get().inner)?
                    .simplify()?,
            )
        }
    };
}

str_cmp_fn!(StrContains, str_contains, haystack, needle);

#[pyfunction]
pub fn StrIndexOf<'py>(
    py: Python<'py>,
    haystack: Bound<'py, PyAstString>,
    needle: Bound<'py, PyAstString>,
    start: CoerceBV<'py>,
) -> Result<Bound<'py, BV>, ClaripyError> {
    BV::new(
        py,
        &GLOBAL_CONTEXT
            .str_index_of(
                &haystack.get().inner,
                &needle.get().inner,
                &start.unpack(py, 64, false)?.get().inner,
            )?
            .simplify_ext(true, true)?,
    )
}

#[pyfunction]
pub fn StrReplace<'py>(
    py: Python<'py>,
    haystack: Bound<'py, PyAstString>,
    needle: Bound<'py, PyAstString>,
    replacement: Bound<'py, PyAstString>,
) -> Result<Bound<'py, PyAstString>, ClaripyError> {
    PyAstString::new(
        py,
        &GLOBAL_CONTEXT
            .str_replace(
                &haystack.get().inner,
                &needle.get().inner,
                &replacement.get().inner,
            )?
            .simplify()?,
    )
}

str_cmp_fn!(StrPrefixOf, str_prefix_of, needle, haystack);
str_cmp_fn!(StrSuffixOf, str_suffix_of, needle, haystack);

#[pyfunction]
pub fn StrToInt<'py>(
    py: Python<'py>,
    s: Bound<'py, PyAstString>,
) -> Result<Bound<'py, BV>, ClaripyError> {
    BV::new(
        py,
        &GLOBAL_CONTEXT
            .str_to_bv(&s.get().inner)?
            .simplify_ext(true, true)?,
    )
}

#[pyfunction]
pub fn IntToStr<'py>(
    py: Python<'py>,
    bv: Bound<'py, BV>,
) -> Result<Bound<'py, PyAstString>, ClaripyError> {
    PyAstString::new(py, &GLOBAL_CONTEXT.bv_to_str(&bv.get().inner)?.simplify()?)
}

#[pyfunction]
pub fn StrIsDigit<'py>(
    py: Python<'py>,
    s: Bound<'py, PyAstString>,
) -> Result<Bound<'py, Bool>, ClaripyError> {
    Bool::new(
        py,
        &GLOBAL_CONTEXT.str_is_digit(&s.get().inner)?.simplify()?,
    )
}

str_cmp_fn!(StrEq, str_eq, s1, s2);
str_cmp_fn!(StrNeq, str_neq, s1, s2);

pub(crate) fn import(_: Python, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<PyAstString>()?;

    add_pyfunctions!(
        m,
        StringS,
        StringV,
        StrLen,
        StrConcat,
        StrSubstr,
        StrContains,
        StrIndexOf,
        StrReplace,
        StrPrefixOf,
        StrSuffixOf,
        StrToInt,
        IntToStr,
        StrIsDigit,
        StrEq,
        StrNeq,
    );

    Ok(())
}
