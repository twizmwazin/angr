//! A [`clarirs_core::solver::Solver`] backed by [smtrs](https://github.com/twizmwazin/smtrs),
//! a pure-Rust SMT solver built around the query stream symbolic execution
//! produces: a persistent, incrementally extended engine answering many small
//! checks that differ by one assumption, with native `minimize`/`maximize`,
//! value enumeration and cheap forking.
//!
//! The solver state that smtrs owns (a hash-consed term pool, and one engine
//! per live [`SmtrsSolver`]) lives in thread-local storage, keyed by a solver
//! id; the [`SmtrsSolver`] value itself holds only the constraint ASTs and
//! its configuration, so it is `Send` and `Clone` without copying a solver.
//! See [`backend`] for the ownership model.

mod backend;
mod convert;
mod deadline;
mod solver;

pub use solver::SmtrsSolver;
