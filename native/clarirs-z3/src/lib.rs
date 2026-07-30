mod astext;
mod rc;
mod solver;

pub use solver::Z3Solver;

use clarirs_core::cache::LruCache;
use clarirs_core::error::ClarirsError;
use rc::RcAst;
use z3_sys::*;

/// Bound on each thread's Z3 AST conversion cache. Entries hold strong Z3
/// references, so an unbounded cache pins every converted AST for the life of
/// the thread; beyond this many entries the least recently used are dropped.
const Z3_AST_CACHE_CAPACITY: usize = 4096;

thread_local! {
    static Z3_CONTEXT: Z3_context = unsafe {
        let cfg = Z3_mk_config().expect("Z3_mk_config returned null");
        let ctx = Z3_mk_context(cfg).expect("Z3_mk_context returned null");
        Z3_set_error_handler(ctx, None);
        Z3_del_config(cfg);
        ctx
    };

    static Z3_AST_CACHE: LruCache<u64, RcAst> = LruCache::new(Z3_AST_CACHE_CAPACITY);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::astext::AstExtZ3;
    use clarirs_core::prelude::*;

    /// Converting an AST with more unique nodes than the cache capacity must
    /// still succeed, and the per-thread conversion cache must stay bounded.
    #[test]
    fn test_z3_ast_cache_stays_bounded() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let mut ast = ctx.bvs("x", 64)?;
        // Each iteration adds two unique nodes (the constant and the sum), so
        // the walk inserts well over Z3_AST_CACHE_CAPACITY entries.
        for i in 0..(Z3_AST_CACHE_CAPACITY as u64 / 2 + 512) {
            ast = ctx.add(&ast, &ctx.bvv(BitVec::from((i, 64)))?)?;
        }
        ast.to_z3()?;
        Z3_AST_CACHE.with(|cache| {
            assert!(cache.len() <= Z3_AST_CACHE_CAPACITY);
            assert!(!cache.is_empty());
        });
        Ok(())
    }
}
