mod astext;
mod cache;
mod rc;
mod solver;

pub use solver::Z3Solver;

use cache::Z3AstCache;
use clarirs_core::error::ClarirsError;
use std::sync::Arc;
use z3_sys::*;

thread_local! {
    static Z3_CONTEXT: Z3_context = unsafe {
        let cfg = Z3_mk_config().expect("Z3_mk_config returned null");
        let ctx = Z3_mk_context(cfg).expect("Z3_mk_context returned null");
        Z3_set_error_handler(ctx, None);
        Z3_del_config(cfg);
        // Cache entries are released from whichever thread drops the last
        // reference to a clarirs node; concurrent dec-ref mode makes those
        // cross-thread Z3_dec_ref calls safe (they are queued and reclaimed
        // by this thread during later API calls).
        Z3_enable_concurrent_dec_ref(ctx);
        ctx
    };

    static Z3_AST_CACHE: Arc<Z3AstCache> =
        Z3_CONTEXT.with(|&ctx| Z3AstCache::register_for_thread(ctx));
}

/// Convert a nullable `z3-sys` result into a [`ClarirsError`].
///
/// Pointer-returning Z3 functions yield `None` (rather than a null pointer) when
/// Z3 hits an internal error or an invalid request. Results that become an
/// [`RcAst`] are checked via `RcAst::try_from(Option<_>)`; this helper covers the
/// few intermediate handles (sorts, symbols, solvers, …) that are not. The
/// precise cause, when Z3 set one, is surfaced by [`check_z3_error`].
pub(crate) fn require<T>(value: Option<T>) -> Result<T, ClarirsError> {
    value.ok_or_else(|| ClarirsError::BackendError("Z3", "Z3 returned a null pointer".into()))
}

pub(crate) fn check_z3_error() -> Result<(), clarirs_core::error::ClarirsError> {
    Z3_CONTEXT.with(|z3_ctx| unsafe {
        let error_code = Z3_get_error_code(*z3_ctx);
        if error_code != ErrorCode::Ok {
            let err_msg = Z3_get_error_msg(*z3_ctx, error_code);
            let c_str = std::ffi::CStr::from_ptr(err_msg);
            let msg = c_str.to_string_lossy().into_owned();
            Err(clarirs_core::error::ClarirsError::BackendError("Z3", msg))
        } else {
            Ok(())
        }
    })
}
