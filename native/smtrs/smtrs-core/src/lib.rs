//! smtrs-core: sorts, hash-consed term DAG, bit-vector constants, and the
//! ground-truth model evaluator.

mod bvconst;
mod eval;
mod interrupt;
mod op;
mod pool;
mod sort;

pub use bvconst::BvConst;
pub use eval::{apply_op, eval, EvalError, Evaluator, Value};
pub use interrupt::{PollTick, POLL_PERIOD};
pub use op::Op;
pub use pool::{
    BvConstId, SortError, Symbol, SymbolId, TermId, TermPool, WalkCounters, MAX_BV_WIDTH,
    MAX_FP_EXP_WIDTH, MAX_FP_SIG_WIDTH,
};
pub use sort::Sort;
