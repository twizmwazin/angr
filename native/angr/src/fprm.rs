//! The floating-point rounding mode type shared by claripy and AIL.

use clarirs_num::FPRM as NumFPRM;
use pyo3::prelude::*;
use pyo3::types::PyTuple;
use serde::{Deserialize, Serialize};

/// A floating-point rounding mode.
///
/// This is the single rounding mode type exposed to Python; it is available
/// as ``angr.rustylib.FPRM``, ``claripy.fp.RM`` and
/// ``angr.ailment.RoundingMode``, which are all the same class.
///
/// The first four integer values mirror VEX's 2-bit IRRoundingMode:
/// ``0 = NearestTiesEven``, ``1 = TowardsNegativeInf``,
/// ``2 = TowardsPositiveInf``, ``3 = TowardsZero``. VEX has no encoding for
/// ``NearestTiesAwayFromZero``, which takes the next value, ``4``.
///
/// The variant order (and so the serde encoding of the first four variants)
/// must not change: AIL serialization depends on it.
#[pyclass(
    name = "FPRM",
    module = "angr.rustylib",
    frozen,
    eq,
    eq_int,
    from_py_object
)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FPRM {
    #[default]
    #[pyo3(name = "RM_NearestTiesEven")]
    RmNearestTiesEven = 0,
    #[pyo3(name = "RM_TowardsNegativeInf")]
    RmTowardsNegativeInf = 1,
    #[pyo3(name = "RM_TowardsPositiveInf")]
    RmTowardsPositiveInf = 2,
    #[pyo3(name = "RM_TowardsZero")]
    RmTowardsZero = 3,
    #[pyo3(name = "RM_NearestTiesAwayFromZero")]
    RmNearestTiesAwayFromZero = 4,
}

#[pymethods]
impl FPRM {
    /// The default rounding mode, ``RM_NearestTiesEven``.
    #[staticmethod]
    #[allow(clippy::should_implement_trait)]
    pub fn default() -> FPRM {
        <FPRM as Default>::default()
    }

    #[getter]
    pub fn value(&self) -> u8 {
        *self as u8
    }

    #[getter]
    pub fn name(&self) -> &'static str {
        match self {
            Self::RmNearestTiesEven => "RM_NearestTiesEven",
            Self::RmTowardsNegativeInf => "RM_TowardsNegativeInf",
            Self::RmTowardsPositiveInf => "RM_TowardsPositiveInf",
            Self::RmTowardsZero => "RM_TowardsZero",
            Self::RmNearestTiesAwayFromZero => "RM_NearestTiesAwayFromZero",
        }
    }

    fn __repr__(&self) -> String {
        format!("<FPRM.{}: {}>", self.name(), *self as u8)
    }

    fn __int__(&self) -> u8 {
        *self as u8
    }

    // Equal to the hash of the integer value, as `eq_int` makes a mode
    // compare equal to it.
    fn __hash__(&self) -> u64 {
        *self as u64
    }

    #[staticmethod]
    fn _from_int_py(v: i64) -> PyResult<FPRM> {
        FPRM::from_int(v).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(format!("Unknown FPRM value: {}", v))
        })
    }

    fn __reduce__<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<(Bound<'py, PyAny>, Bound<'py, PyTuple>)> {
        let getattr = py.import("builtins")?.getattr("getattr")?;
        Ok((
            getattr,
            (py.get_type::<FPRM>(), self.name()).into_pyobject(py)?,
        ))
    }
}

impl FPRM {
    pub fn from_int(v: i64) -> Option<Self> {
        Some(match v {
            0 => Self::RmNearestTiesEven,
            1 => Self::RmTowardsNegativeInf,
            2 => Self::RmTowardsPositiveInf,
            3 => Self::RmTowardsZero,
            4 => Self::RmNearestTiesAwayFromZero,
            _ => return None,
        })
    }
}

impl From<FPRM> for NumFPRM {
    fn from(rm: FPRM) -> NumFPRM {
        match rm {
            FPRM::RmNearestTiesEven => NumFPRM::NearestTiesToEven,
            FPRM::RmNearestTiesAwayFromZero => NumFPRM::NearestTiesToAway,
            FPRM::RmTowardsZero => NumFPRM::TowardZero,
            FPRM::RmTowardsPositiveInf => NumFPRM::TowardPositive,
            FPRM::RmTowardsNegativeInf => NumFPRM::TowardNegative,
        }
    }
}

impl From<NumFPRM> for FPRM {
    fn from(rm: NumFPRM) -> FPRM {
        match rm {
            NumFPRM::NearestTiesToEven => FPRM::RmNearestTiesEven,
            NumFPRM::NearestTiesToAway => FPRM::RmNearestTiesAwayFromZero,
            NumFPRM::TowardZero => FPRM::RmTowardsZero,
            NumFPRM::TowardPositive => FPRM::RmTowardsPositiveInf,
            NumFPRM::TowardNegative => FPRM::RmTowardsNegativeInf,
        }
    }
}

impl From<&NumFPRM> for FPRM {
    fn from(rm: &NumFPRM) -> FPRM {
        (*rm).into()
    }
}
