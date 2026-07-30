use std::collections::HashMap;
use std::sync::{Arc, Mutex, Once, Weak};
use std::thread::ThreadId;

use clarirs_core::cache::Cache;
use z3_sys::{Z3_ast, Z3_context, Z3_dec_ref, Z3_inc_ref};

use crate::rc::RcAst;

/// Per-thread map from a clarirs node's structural hash to its converted Z3
/// AST, kept in lockstep with the clarirs AST cache: when the last strong
/// reference to a node drops, the clarirs-core eviction hook removes the
/// node's entry from every thread's cache, releasing the Z3 reference.
///
/// Each entry owns one Z3 reference, taken on the owning thread at insert.
/// `get` and `insert` only run on the owning thread (during conversion);
/// `remove` may run on any thread, because nodes can drop anywhere. The
/// cross-thread `Z3_dec_ref` is safe because the context has
/// `Z3_enable_concurrent_dec_ref` set: foreign dec-refs are queued under a
/// Z3-internal mutex and reclaimed by the owning thread the next time it
/// allocates a Z3 API object (solver, model, params, ...).
pub(crate) struct Z3AstCache {
    ctx: Z3_context,
    owner: ThreadId,
    map: Mutex<HashMap<u64, Z3_ast>>,
}

// The raw pointers are only ever dereferenced through Z3 API calls: everything
// except `Z3_dec_ref` stays on the owning thread, and `Z3_dec_ref` is
// thread-safe under concurrent dec-ref mode.
unsafe impl Send for Z3AstCache {}
unsafe impl Sync for Z3AstCache {}

/// All live per-thread caches, so the eviction hook can reach every thread's
/// entries. Holds weak references; a cache dies with its thread (the strong
/// reference lives in the `Z3_AST_CACHE` thread-local).
static REGISTRY: Mutex<Vec<Weak<Z3AstCache>>> = Mutex::new(Vec::new());

/// Eviction hook: the node with this structural hash is gone from the clarirs
/// AST cache, so drop its converted Z3 AST (if any) in every thread's cache.
fn evict_hash(hash: u64) {
    for cache in REGISTRY.lock().unwrap().iter().filter_map(Weak::upgrade) {
        cache.remove(hash);
    }
}

impl Z3AstCache {
    /// Creates this thread's cache and registers it for cross-thread eviction.
    /// The first call also installs the clarirs-core eviction hook.
    pub(crate) fn register_for_thread(ctx: Z3_context) -> Arc<Self> {
        static HOOK: Once = Once::new();
        HOOK.call_once(|| clarirs_core::cache::register_eviction_hook(evict_hash));

        let cache = Arc::new(Self {
            ctx,
            owner: std::thread::current().id(),
            map: Mutex::new(HashMap::new()),
        });
        let mut registry = REGISTRY.lock().unwrap();
        registry.retain(|weak| weak.strong_count() > 0);
        registry.push(Arc::downgrade(&cache));
        cache
    }

    /// Removes `hash` and releases its Z3 reference. Callable from any thread.
    fn remove(&self, hash: u64) {
        // Dropping the map lock before the dec-ref is fine: the owning
        // thread's `get` takes its new reference under the lock, so it either
        // saw the entry (and now holds its own reference) or missed it.
        let ast = self.map.lock().unwrap().remove(&hash);
        if let Some(ast) = ast {
            unsafe { Z3_dec_ref(self.ctx, ast) };
        }
    }

    #[cfg(test)]
    pub(crate) fn contains(&self, hash: u64) -> bool {
        self.map.lock().unwrap().contains_key(&hash)
    }
}

impl Drop for Z3AstCache {
    /// Runs when the owning thread exits (or, if an eviction raced the exit,
    /// on the evicting thread — safe either way, see the dec-ref note above).
    fn drop(&mut self) {
        for (_, ast) in self.map.get_mut().unwrap().drain() {
            unsafe { Z3_dec_ref(self.ctx, ast) };
        }
    }
}

impl Cache<u64, RcAst> for Z3AstCache {
    fn get(&self, key: &u64) -> Option<RcAst> {
        debug_assert_eq!(std::thread::current().id(), self.owner);
        let map = self.map.lock().unwrap();
        map.get(key).map(|&ast| {
            // Take the handle's reference while the lock pins the entry's own
            // reference; a concurrent eviction dec-refs only after removing
            // the entry under this lock, so `ast` cannot be released yet.
            unsafe {
                Z3_inc_ref(self.ctx, ast);
                RcAst::from_raw(ast)
            }
        })
    }

    fn insert(&self, key: u64, value: &RcAst) {
        debug_assert_eq!(std::thread::current().id(), self.owner);
        let mut map = self.map.lock().unwrap();
        unsafe { Z3_inc_ref(self.ctx, **value) };
        if let Some(old) = map.insert(key, **value) {
            unsafe { Z3_dec_ref(self.ctx, old) };
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::Z3_AST_CACHE;
    use crate::astext::AstExtZ3;
    use clarirs_core::prelude::*;

    fn cache_contains(hash: u64) -> bool {
        Z3_AST_CACHE.with(|cache| cache.contains(hash))
    }

    #[test]
    fn entries_evicted_when_ast_drops() {
        let ctx = Context::new();
        let x = ctx.bvs("cache_evict_x", 64).unwrap();
        let expr = ctx
            .add(x.clone(), ctx.bvv(BitVec::from((42, 64))).unwrap())
            .unwrap();
        let (expr_hash, x_hash) = (expr.hash(), x.hash());

        drop(expr.to_z3().unwrap());
        assert!(cache_contains(expr_hash));
        assert!(cache_contains(x_hash));

        // `x` is still alive through its own handle, so only the sum's entry
        // (and the literal's) may be evicted.
        drop(expr);
        assert!(!cache_contains(expr_hash));
        assert!(cache_contains(x_hash));

        drop(x);
        assert!(!cache_contains(x_hash));
    }

    #[test]
    fn entries_evicted_on_cross_thread_drop() {
        let ctx = Context::new();
        let x = ctx.bvs("cache_evict_cross_thread_x", 64).unwrap();
        let expr = ctx.not(x).unwrap();
        let expr_hash = expr.hash();

        drop(expr.to_z3().unwrap());
        assert!(cache_contains(expr_hash));

        // Dropping the last reference on another thread must still evict this
        // thread's entries (via the queued cross-thread dec-ref).
        std::thread::scope(|s| {
            s.spawn(move || drop(expr));
        });
        assert!(!cache_contains(expr_hash));

        // The context stays fully usable afterwards: the queued dec-refs are
        // reclaimed during later API calls.
        let y = ctx.bvs("cache_evict_cross_thread_y", 64).unwrap();
        let eq = ctx.eq_(y, ctx.bvv(BitVec::from((7, 64))).unwrap()).unwrap();
        drop(eq.simplify_z3().unwrap());
    }

    #[test]
    fn reconversion_after_eviction() {
        let ctx = Context::new();
        let x = ctx.bvs("cache_reconvert_x", 32).unwrap();
        let hash = x.hash();

        drop(x.to_z3().unwrap());
        assert!(cache_contains(hash));
        drop(x);
        assert!(!cache_contains(hash));

        // Re-interning the same structure gets a fresh entry.
        let x = ctx.bvs("cache_reconvert_x", 32).unwrap();
        assert_eq!(x.hash(), hash);
        let z3 = x.to_z3().unwrap();
        assert_eq!(z3.symbol_name().as_deref(), Some("cache_reconvert_x"));
        assert!(cache_contains(hash));
    }
}
