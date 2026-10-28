use crate::claripy::prelude::*;

pub struct NameString(pub String);

impl<'a, 'py> FromPyObject<'a, 'py> for NameString {
    type Error = PyErr;

    fn extract(obj: Borrowed<'a, 'py, PyAny>) -> Result<Self, Self::Error> {
        if let Ok(str_val) = obj.extract::<&str>() {
            Ok(NameString(str_val.to_string()))
        } else if let Ok(bytes_val) = obj.extract::<&[u8]>() {
            Ok(NameString(String::from_utf8_lossy(bytes_val).to_string()))
        } else {
            Err(PyErr::new::<pyo3::exceptions::PyTypeError, _>(
                "Expected a string or bytes object",
            ))
        }
    }
}

impl From<NameString> for String {
    fn from(val: NameString) -> Self {
        val.0
    }
}

impl From<&str> for NameString {
    fn from(val: &str) -> Self {
        NameString(val.to_string())
    }
}

/// The Python value of a concrete leaf: `BVV` -> int, `BoolV` -> bool,
/// `FPV` -> float, `StringV` -> str. `None` for anything else, including an
/// `FPV` whose sort has no `f64` form.
pub fn concrete_py_value<'py>(
    py: Python<'py>,
    ast: &AstRef<'static>,
) -> PyResult<Option<Bound<'py, PyAny>>> {
    Ok(match ast.op() {
        AstOp::BVV(bv) => Some(bv.to_biguint().into_bound_py_any(py)?),
        AstOp::BoolV(b) => Some(b.into_bound_py_any(py)?),
        AstOp::FPV(fp) => fp.to_f64().map(|f| f.into_bound_py_any(py)).transpose()?,
        AstOp::StringV(s) => Some(s.into_bound_py_any(py)?),
        _ => None,
    })
}
