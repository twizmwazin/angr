use crate::claripy::prelude::*;

#[pyclass(extends=Base, subclass, frozen, weakref, module="angr.rustylib.claripy.ast.bits")]
#[derive(Default)]
pub struct Bits;

impl Bits {
    pub fn new() -> Self {
        Bits {}
    }
}

#[pymethods]
impl Bits {
    pub fn size(self_: &Bound<'_, Self>) -> usize {
        self_.as_super().get().ast().size() as usize
    }

    pub fn __len__(self_: &Bound<'_, Self>) -> usize {
        Self::size(self_)
    }

    #[getter]
    pub fn length(self_: &Bound<'_, Self>) -> usize {
        Self::size(self_)
    }
}

pub(crate) fn import(_: Python, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<Bits>()?;
    Ok(())
}
