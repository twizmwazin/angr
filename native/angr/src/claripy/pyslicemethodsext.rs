use pyo3::intern;
use pyo3::types::PySlice;

use crate::claripy::prelude::*;

pub trait PySliceMethodsExt {
    fn start(&self) -> PyResult<Option<isize>>;
    fn stop(&self) -> PyResult<Option<isize>>;
    fn step(&self) -> PyResult<Option<isize>>;
}

impl PySliceMethodsExt for Bound<'_, PySlice> {
    fn start(&self) -> PyResult<Option<isize>> {
        self.as_any()
            .getattr(intern!(self.py(), "start"))?
            .extract()
    }

    fn stop(&self) -> PyResult<Option<isize>> {
        self.as_any().getattr(intern!(self.py(), "stop"))?.extract()
    }

    fn step(&self) -> PyResult<Option<isize>> {
        self.as_any().getattr(intern!(self.py(), "step"))?.extract()
    }
}
