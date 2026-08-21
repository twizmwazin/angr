use crate::claripy::prelude::*;

/// Simplify `ast` and report the truth value of the result, if it has a
/// concrete one: `BoolV` yields its own value, `BVV` and `FPV` yield whether
/// they are non-zero. `Ok(None)` means the simplified AST is symbolic, or is a
/// concrete value with no truth value (such as a string).
///
/// Simplification failures are returned to the caller; sites that treat an
/// AST that cannot be simplified as neither true nor false discard the error.
pub fn concrete_bool(ast: &AstRef<'static>) -> Result<Option<bool>, ClarirsError> {
    Ok(match ast.simplify()?.op() {
        AstOp::BoolV(value) => Some(*value),
        AstOp::BVV(value) => Some(!value.is_zero()),
        AstOp::FPV(value) => Some(!value.is_zero()),
        _ => None,
    })
}

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
