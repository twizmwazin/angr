//! Rust port of `angr.ailment.manager.Manager`.
//!
//! The manager hands out monotonically increasing atom indices, which serve as
//! the identity of every AIL node: `__eq__` and `__hash__` fold `idx` in at
//! every node, and `VariableMap` keys its side tables on it. One manager is
//! built per `Clinic` invocation and threaded through every pass, so those
//! indices stay unique for the whole decompilation.

use pyo3::prelude::*;

#[pyclass(
    name = "Manager",
    module = "angr.rustylib.ailment",
    subclass,
    dict,
    get_all,
    set_all
)]
#[derive(Debug)]
pub struct Manager {
    /// Next atom index to hand out (the original used `itertools.count()`).
    pub atom_ctr: i64,
    /// Attached by Clinic so that optimization passes, peephole optimizations,
    /// and region simplifiers can use VariableMap.
    pub variable_map: Option<Py<PyAny>>,
}

#[pymethods]
impl Manager {
    #[new]
    fn new() -> Self {
        Self {
            atom_ctr: 0,
            variable_map: None,
        }
    }

    pub fn next_atom(&mut self) -> i64 {
        let v = self.atom_ctr;
        self.atom_ctr += 1;
        v
    }

    fn reset(&mut self) {
        self.atom_ctr = 0;
    }
}
