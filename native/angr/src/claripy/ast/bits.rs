use crate::claripy::prelude::*;

#[pyclass(extends=Base, subclass, frozen, weakref, module="angr.rustylib.claripy.ast.bits")]
#[derive(Default)]
pub struct Bits;

impl Bits {
    pub fn new() -> Self {
        Bits {}
    }
}

/// `Bits` is the base class of every AST that has a bit width — `BV` and `FP`.
/// The width lives on the wrapped AST rather than the sort-specific subclass,
/// so it is exposed here and inherited by both; `BV` and `FP` still override
/// these with their own equivalent implementations.
#[pymethods]
impl Bits {
    /// The width of this AST, in bits.
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
