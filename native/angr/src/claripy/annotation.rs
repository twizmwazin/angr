use std::sync::{Arc, LazyLock};

use clarirs_core::ast::annotation::Ignored;
use dashmap::DashMap;
use num_bigint::BigUint;
use pyo3::intern;
use pyo3::types::{PyDict, PyTuple, PyType};

use crate::claripy::prelude::*;

/// Per user-defined annotation class, keyed by the address of its type object.
static PY_ANNOTATION_CLASSES: LazyLock<DashMap<usize, Arc<UserClass>>> =
    LazyLock::new(DashMap::new);

struct UserClass {
    /// The class itself, kept alive so its address is not reused.
    ty: Py<PyType>,
    /// `module:class`.
    name: Arc<str>,
    /// The class attributes of the same names.
    eliminatable: bool,
    relocatable: bool,
}

/// `claripy.annotation.Annotation`
///
/// The base class for every annotation. User code can subclass it, and the
/// built-in annotations below are genuine subclasses.
#[pyclass(
    name = "Annotation",
    subclass,
    frozen,
    weakref,
    module = "angr.rustylib.claripy.annotation"
)]
pub struct PyAnnotation;

#[pymethods]
impl PyAnnotation {
    /// Accept (and ignore) arbitrary arguments so that Python subclasses with
    /// their own `__init__` signatures can be instantiated, mirroring the
    /// behaviour of `object.__new__` when `__init__` is overridden.
    #[new]
    #[pyo3(signature = (*_args, **_kwargs))]
    fn py_new(_args: &Bound<'_, PyTuple>, _kwargs: Option<&Bound<'_, PyDict>>) -> Self {
        PyAnnotation
    }

    #[classattr]
    fn relocatable() -> bool {
        false
    }

    #[classattr]
    fn eliminatable() -> bool {
        true
    }
}

impl PyAnnotation {
    /// Convert a Python annotation object (an instance of this class or any of
    /// its subclasses) into the core [`Annotation`] consumed by the solver.
    pub fn to_annotation(slf: &Bound<'_, PyAnnotation>) -> Result<Arc<Annotation>, ClaripyError> {
        let any = slf.as_any();
        let annotation = if any.cast::<SimplificationAvoidanceAnnotation>().is_ok() {
            Annotation::new(AnnotationType::SimplificationAvoidance, false, false)
        } else if let Ok(si) = any.cast::<StridedIntervalAnnotation>() {
            let si = si.get();
            Annotation::new(
                AnnotationType::StridedInterval {
                    stride: si.stride.clone(),
                    lower_bound: si.lower_bound.clone(),
                    upper_bound: si.upper_bound.clone(),
                },
                false,
                false,
            )
        } else if any.cast::<EmptyStridedIntervalAnnotation>().is_ok() {
            Annotation::new(AnnotationType::EmptyStridedInterval, false, false)
        } else if let Ok(region) = any.cast::<RegionAnnotation>() {
            let region = region.get();
            Annotation::new(
                AnnotationType::Region {
                    region_id: region.region_id.clone(),
                    region_base_addr: region.region_base_addr.clone(),
                },
                false,
                false,
            )
        } else if any.cast::<UninitializedAnnotation>().is_ok() {
            Annotation::new(AnnotationType::Uninitialized, false, true)
        } else {
            // User-defined annotation: hold on to the Python object itself.
            let ty = slf.get_type();
            let key = ty.as_ptr() as usize;
            let class = match PY_ANNOTATION_CLASSES.get(&key) {
                Some(entry) => {
                    debug_assert!(entry.ty.bind(ty.py()).is(&ty));
                    entry.clone()
                }
                None => {
                    let py = ty.py();
                    let flag = |name| ty.getattr(name).and_then(|v| v.extract::<bool>());
                    let module_name = ty.getattr(intern!(py, "__module__"))?.extract::<String>()?;
                    let class_name = ty.getattr(intern!(py, "__name__"))?.extract::<String>()?;
                    let class = Arc::new(UserClass {
                        name: format!("{module_name}:{class_name}").into(),
                        eliminatable: flag(intern!(py, "eliminatable")).unwrap_or(true),
                        relocatable: flag(intern!(py, "relocatable")).unwrap_or(false),
                        ty: ty.clone().unbind(),
                    });
                    PY_ANNOTATION_CLASSES.insert(key, class.clone());
                    class
                }
            };
            // Identify the annotation by the object's hash, not the object.
            let obj_hash = slf.hash()? as i64;
            Annotation::new(
                AnnotationType::PyAnnotation {
                    name: class.name.clone(),
                    object: Ignored(Arc::new(slf.clone().into_any().unbind())),
                    obj_hash,
                },
                class.eliminatable,
                class.relocatable,
            )
        };

        Ok(annotation)
    }

    /// Build a Python annotation object from a core [`Annotation`].
    pub fn from_annotation<'py>(
        py: Python<'py>,
        annotation: &Annotation,
    ) -> Result<Bound<'py, PyAnnotation>, ClaripyError> {
        match annotation.type_() {
            AnnotationType::PyAnnotation { object, .. } => {
                Ok(object.0.bind(py).clone().cast_into::<PyAnnotation>()?)
            }
            AnnotationType::SimplificationAvoidance => upcast(Bound::new(
                py,
                PyClassInitializer::from(PyAnnotation)
                    .add_subclass(SimplificationAvoidanceAnnotation),
            )?),
            AnnotationType::StridedInterval {
                stride,
                lower_bound,
                upper_bound,
            } => upcast(Bound::new(
                py,
                PyClassInitializer::from(PyAnnotation).add_subclass(StridedIntervalAnnotation {
                    stride: stride.clone(),
                    lower_bound: lower_bound.clone(),
                    upper_bound: upper_bound.clone(),
                }),
            )?),
            AnnotationType::EmptyStridedInterval => upcast(Bound::new(
                py,
                PyClassInitializer::from(PyAnnotation).add_subclass(EmptyStridedIntervalAnnotation),
            )?),
            AnnotationType::Region {
                region_id,
                region_base_addr,
            } => upcast(Bound::new(
                py,
                PyClassInitializer::from(PyAnnotation).add_subclass(RegionAnnotation {
                    region_id: region_id.clone(),
                    region_base_addr: region_base_addr.clone(),
                }),
            )?),
            AnnotationType::Uninitialized => upcast(Bound::new(
                py,
                PyClassInitializer::from(PyAnnotation).add_subclass(UninitializedAnnotation),
            )?),
        }
    }
}

/// Upcast a concrete annotation subclass instance to its `PyAnnotation` base.
fn upcast<'py, T>(bound: Bound<'py, T>) -> Result<Bound<'py, PyAnnotation>, ClaripyError> {
    Ok(bound.into_any().cast_into::<PyAnnotation>()?)
}

/// `claripy.annotation.SimplificationAvoidanceAnnotation`
#[derive(PartialEq, Eq, Hash)]
#[pyclass(extends = PyAnnotation, subclass, frozen, eq, hash, weakref, module = "angr.rustylib.claripy.annotation")]
pub struct SimplificationAvoidanceAnnotation;

#[pymethods]
impl SimplificationAvoidanceAnnotation {
    #[new]
    #[pyo3(signature = (*_args, **_kwargs))]
    fn py_new(
        _args: &Bound<'_, PyTuple>,
        _kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyClassInitializer<Self> {
        PyClassInitializer::from(PyAnnotation).add_subclass(SimplificationAvoidanceAnnotation)
    }

    #[classattr]
    fn relocatable() -> bool {
        false
    }

    #[classattr]
    fn eliminatable() -> bool {
        false
    }

    fn __reduce__<'py>(slf: PyRef<'py, Self>) -> (Bound<'py, PyType>, ()) {
        (slf.py().get_type::<Self>(), ())
    }

    fn __repr__(&self) -> &'static str {
        "SimplificationAvoidanceAnnotation()"
    }
}

/// `claripy.annotation.StridedIntervalAnnotation`
#[derive(PartialEq, Eq, Hash)]
#[pyclass(extends = PyAnnotation, subclass, frozen, eq, hash, weakref, module = "angr.rustylib.claripy.annotation")]
pub struct StridedIntervalAnnotation {
    #[pyo3(get)]
    stride: BigUint,
    #[pyo3(get)]
    lower_bound: BigUint,
    #[pyo3(get)]
    upper_bound: BigUint,
}

#[pymethods]
impl StridedIntervalAnnotation {
    #[new]
    fn py_new(
        stride: BigUint,
        lower_bound: BigUint,
        upper_bound: BigUint,
    ) -> PyClassInitializer<Self> {
        PyClassInitializer::from(PyAnnotation).add_subclass(StridedIntervalAnnotation {
            stride,
            lower_bound,
            upper_bound,
        })
    }

    #[classattr]
    fn relocatable() -> bool {
        false
    }

    #[classattr]
    fn eliminatable() -> bool {
        false
    }

    fn __reduce__<'py>(slf: PyRef<'py, Self>) -> (Bound<'py, PyType>, (BigUint, BigUint, BigUint)) {
        (
            slf.py().get_type::<Self>(),
            (
                slf.stride.clone(),
                slf.lower_bound.clone(),
                slf.upper_bound.clone(),
            ),
        )
    }

    fn __repr__(&self) -> String {
        format!(
            "StridedIntervalAnnotation(stride={}, lower_bound={}, upper_bound={})",
            self.stride, self.lower_bound, self.upper_bound
        )
    }
}

/// `claripy.annotation.EmptyStridedIntervalAnnotation`
#[derive(PartialEq, Eq, Hash)]
#[pyclass(extends = PyAnnotation, subclass, frozen, eq, hash, weakref, module = "angr.rustylib.claripy.annotation")]
pub struct EmptyStridedIntervalAnnotation;

#[pymethods]
impl EmptyStridedIntervalAnnotation {
    #[new]
    #[pyo3(signature = (*_args, **_kwargs))]
    fn py_new(
        _args: &Bound<'_, PyTuple>,
        _kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyClassInitializer<Self> {
        PyClassInitializer::from(PyAnnotation).add_subclass(EmptyStridedIntervalAnnotation)
    }

    #[classattr]
    fn relocatable() -> bool {
        false
    }

    #[classattr]
    fn eliminatable() -> bool {
        false
    }

    fn __reduce__<'py>(slf: PyRef<'py, Self>) -> (Bound<'py, PyType>, ()) {
        (slf.py().get_type::<Self>(), ())
    }

    fn __repr__(&self) -> &'static str {
        "EmptyStridedIntervalAnnotation()"
    }
}

/// `claripy.annotation.RegionAnnotation`
#[derive(PartialEq, Eq, Hash)]
#[pyclass(extends = PyAnnotation, subclass, frozen, eq, hash, weakref, module = "angr.rustylib.claripy.annotation")]
pub struct RegionAnnotation {
    #[pyo3(get)]
    region_id: String,
    #[pyo3(get)]
    region_base_addr: BigUint,
}

#[pymethods]
impl RegionAnnotation {
    #[new]
    fn py_new(region_id: String, region_base_addr: BigUint) -> PyClassInitializer<Self> {
        PyClassInitializer::from(PyAnnotation).add_subclass(RegionAnnotation {
            region_id,
            region_base_addr,
        })
    }

    #[classattr]
    fn relocatable() -> bool {
        false
    }

    #[classattr]
    fn eliminatable() -> bool {
        false
    }

    fn __reduce__<'py>(slf: PyRef<'py, Self>) -> (Bound<'py, PyType>, (String, BigUint)) {
        (
            slf.py().get_type::<Self>(),
            (slf.region_id.clone(), slf.region_base_addr.clone()),
        )
    }

    fn __repr__(&self) -> String {
        format!(
            "RegionAnnotation(region_id={}, region_base_addr={})",
            self.region_id, self.region_base_addr
        )
    }
}

/// `claripy.annotation.UninitializedAnnotation`
#[derive(PartialEq, Eq, Hash)]
#[pyclass(extends = PyAnnotation, subclass, frozen, eq, hash, weakref, module = "angr.rustylib.claripy.annotation")]
pub struct UninitializedAnnotation;

#[pymethods]
impl UninitializedAnnotation {
    #[new]
    #[pyo3(signature = (*_args, **_kwargs))]
    fn py_new(
        _args: &Bound<'_, PyTuple>,
        _kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyClassInitializer<Self> {
        PyClassInitializer::from(PyAnnotation).add_subclass(UninitializedAnnotation)
    }

    #[classattr]
    fn relocatable() -> bool {
        true
    }

    #[classattr]
    fn eliminatable() -> bool {
        false
    }

    fn __reduce__<'py>(slf: PyRef<'py, Self>) -> (Bound<'py, PyType>, ()) {
        (slf.py().get_type::<Self>(), ())
    }

    fn __repr__(&self) -> &'static str {
        "UninitializedAnnotation()"
    }
}

pub(crate) fn import(_: Python, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<PyAnnotation>()?;
    m.add_class::<SimplificationAvoidanceAnnotation>()?;
    m.add_class::<StridedIntervalAnnotation>()?;
    m.add_class::<EmptyStridedIntervalAnnotation>()?;
    m.add_class::<RegionAnnotation>()?;
    m.add_class::<UninitializedAnnotation>()?;
    Ok(())
}
