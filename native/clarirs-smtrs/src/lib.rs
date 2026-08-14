//! smtrs solver backend for clarirs.
//!
//! Replaces the Z3 backend (`clarirs-z3`) with the pure-Rust smtrs solver
//! stack vendored under `native/smtrs`. The public surface mirrors the old
//! `Z3Solver` exactly: the same constructors, the same [`Solver`] trait
//! implementation, and the same `unsat_core` inherent method, so the swap in
//! `native/angr` is mechanical.
//!
//! Like the Z3 backend, all solver-side state is thread-local: terms live in a
//! per-thread [`smtrs_core::TermPool`], conversions of clarirs nodes are
//! cached per thread, and each `SmtrsSolver`'s persistent incremental
//! [`smtrs_solver::Solver`] is kept in a per-thread cache keyed by the
//! solver's `cache_id`. `SmtrsSolver` itself stores only plain data, so it
//! stays `Send`; first use on a new thread rebuilds there.

mod convert;
mod solver;

pub use solver::SmtrsSolver;

use std::cell::RefCell;
use std::collections::HashMap;

use clarirs_core::error::ClarirsError;
use smtrs_core::{Sort, SymbolId, TermId, TermPool};

/// Per-thread conversion state: the term pool plus every cache that maps
/// clarirs-side identities onto smtrs-side ones.
pub(crate) struct PoolState {
    pub pool: TermPool,
    /// clarirs node hash -> converted term. clarirs ASTs are hash-consed, so
    /// the 64-bit node hash is their identity.
    pub terms: HashMap<u64, TermId>,
    /// (name, sort) -> symbol, so a clarirs variable always converts to the
    /// same smtrs symbol on this thread.
    pub symbols: HashMap<(String, Sort), SymbolId>,
    /// Heads for `Op::Other` applications (string/Int operators and the
    /// bit-vector bridge), interned by name.
    pub heads: HashMap<&'static str, SymbolId>,
    /// Every symbol minted for a clarirs variable or evaluation auxiliary.
    /// Installed as `Solver::declared` before each check so models are
    /// complete over them (unconstrained -> 0/false, matching Z3's model
    /// completion).
    pub declared: Vec<SymbolId>,
}

impl PoolState {
    fn new() -> Self {
        PoolState {
            pool: TermPool::new(),
            terms: HashMap::new(),
            symbols: HashMap::new(),
            heads: HashMap::new(),
            declared: Vec::new(),
        }
    }

    /// The symbol for a clarirs variable of the given name and sort,
    /// interning and declaring it on first use.
    pub fn symbol(&mut self, name: &str, sort: Sort) -> SymbolId {
        if let Some(&sym) = self.symbols.get(&(name.to_string(), sort)) {
            return sym;
        }
        let sym = self.pool.fresh_symbol(name, sort);
        self.symbols.insert((name.to_string(), sort), sym);
        self.declared.push(sym);
        sym
    }

    /// The head symbol for an `Op::Other` application. The symbol's sort is
    /// irrelevant (only its name identifies the operator); Bool is used as a
    /// placeholder, the same convention as the smtrs parser.
    pub fn head(&mut self, name: &'static str) -> SymbolId {
        if let Some(&sym) = self.heads.get(name) {
            return sym;
        }
        let sym = self.pool.fresh_symbol(name, Sort::Bool);
        self.heads.insert(name, sym);
        sym
    }
}

thread_local! {
    pub(crate) static STATE: RefCell<PoolState> = RefCell::new(PoolState::new());
}

/// Map an smtrs sort error onto the backend error the Z3 path used for its
/// conversion failures.
pub(crate) fn sort_err(e: smtrs_core::SortError) -> ClarirsError {
    ClarirsError::BackendError("smtrs", format!("{e:?}"))
}
