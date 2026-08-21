use std::any::type_name;

use dashmap::DashMap;
use pyo3::PyClass;
use pyo3::types::PyWeakrefReference;

use crate::claripy::prelude::*;

/// The Python wrappers handed out for a single AST sort, keyed by
/// [`AstRef::hash`]. Entries are weak references, so equal ASTs share one
/// wrapper for as long as Python keeps it alive without the cache itself
/// keeping wrappers alive.
pub struct WrapperCache(DashMap<u64, Py<PyWeakrefReference>>);

impl WrapperCache {
    pub fn new() -> Self {
        WrapperCache(DashMap::new())
    }

    /// The live wrapper for `inner`, building one with `init` and caching it
    /// when no usable entry exists.
    pub fn get_or_create<'py, T, F>(
        &self,
        py: Python<'py>,
        inner: &AstRef<'static>,
        init: F,
    ) -> Result<Bound<'py, T>, ClaripyError>
    where
        T: PyClass,
        F: FnOnce() -> Result<PyClassInitializer<T>, ClaripyError>,
    {
        if let Some(cache_hit) = self.0.get(&inner.hash()).and_then(|cache_hit| {
            cache_hit
                .bind(py)
                .upgrade_as::<T>()
                .unwrap_or_else(|err| panic!("{} wrapper cache poisoned: {err}", type_name::<T>()))
        }) {
            return Ok(cache_hit);
        }

        let this = Bound::new(py, init()?)?;
        self.0.insert(
            inner.hash(),
            PyWeakrefReference::new(this.as_any())?.unbind(),
        );

        Ok(this)
    }

    /// Evict the entry of a wrapper that is being dropped so dead hashes don't
    /// accumulate. The dying wrapper's own weakref is already cleared by the
    /// time [`Drop`] runs, so a dead upgrade means the entry is stale; a live
    /// upgrade means the entry was re-populated with a new wrapper and must
    /// stay.
    pub fn evict(&self, hash: u64) {
        Python::attach(|py| {
            self.0
                .remove_if(&hash, |_, weakref| weakref.bind(py).upgrade().is_none());
        });
    }
}

impl Default for WrapperCache {
    fn default() -> Self {
        Self::new()
    }
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
