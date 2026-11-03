use ahash::HashMap;
use std::{
    hash::Hash,
    sync::{Arc, RwLock, Weak},
};

use crate::prelude::*;

/// A trait for caching values based on a key. In the context of clarirs, this
/// is used to cache ASTs, as well as the results of various algorithms.
///
/// Implementations provide `get` and `insert`; `get_or_insert` is derived from
/// them, and need only be overridden when that default is insufficient.
pub trait Cache<K, V> {
    /// Probe the cache without computing a value on miss.
    fn get(&self, key: &K) -> Option<V>;

    fn insert(&self, key: K, value: &V);

    fn get_or_insert<E>(&self, key: K, value_cv: impl FnOnce() -> Result<V, E>) -> Result<V, E> {
        if let Some(value) = self.get(&key) {
            return Ok(value);
        }
        let value = value_cv()?;
        self.insert(key, &value);
        Ok(value)
    }
}

impl<K, V> Cache<K, V> for () {
    fn get(&self, _key: &K) -> Option<V> {
        None
    }

    fn insert(&self, _key: K, _value: &V) {
        // No-op
    }
}

/// A generic cache implementation that uses a `HashMap` to store key-value pairs.
#[derive(Debug)]
pub struct GenericCache<K, V>(RwLock<HashMap<K, V>>);

impl<K, V> Default for GenericCache<K, V> {
    fn default() -> Self {
        Self(RwLock::new(HashMap::default()))
    }
}

impl<K: Hash + Eq, V: Clone> Cache<K, V> for GenericCache<K, V> {
    fn get(&self, key: &K) -> Option<V> {
        self.0.read().unwrap().get(key).cloned()
    }

    fn insert(&self, key: K, value: &V) {
        self.0.write().unwrap().insert(key, value.clone());
    }
}

/// A special cache for when the result type is an AST. Unlike the generic cache,
/// this cache stores weak references to the AST nodes; the value is a
/// `Weak<AstNode>`.
#[derive(Debug, Default)]
pub struct AstCache<'c>(RwLock<HashMap<u64, Weak<AstNode<'c>>>>);

impl AstCache<'_> {
    /// Remove `key` if its entry is expired (no strong refs left). Called from
    /// `AstNode::drop` so dead nodes don't leave entries (and their pinned
    /// `ArcInner` allocations) behind.
    ///
    /// The liveness check makes this safe against two races:
    /// - Two threads can miss the cache and build the same node; the loser's
    ///   throwaway drop must not evict the live entry it duplicated.
    /// - Another thread can re-intern the same hash between our strong count
    ///   reaching zero and this call taking the lock.
    ///
    /// The hot path (entry still live, e.g. the throwaway-duplicate drop) is
    /// served with only the read lock; the write lock is taken just when the
    /// entry actually looks dead, and the check is repeated under it.
    ///
    /// Returns `true` when no live node is cached under `key` afterwards (the
    /// entry was expired and removed, or there was none), `false` when a live
    /// node still holds it.
    pub(crate) fn remove_if_expired(&self, key: u64) -> bool {
        {
            let inner = self.0.read().unwrap();
            match inner.get(&key) {
                Some(weak) if weak.strong_count() == 0 => {}
                Some(_) => return false,
                None => return true,
            }
        }
        let mut inner = self.0.write().unwrap();
        match inner.get(&key) {
            Some(weak) if weak.strong_count() == 0 => {
                inner.remove(&key);
                true
            }
            Some(_) => false,
            None => true,
        }
    }

    /// Remove `key` whether or not its value is still alive. For caches of
    /// algorithm results keyed by the *input* node's hash: once no node with
    /// that hash is alive the entry can't be hit again until the node is
    /// rebuilt, and the `Weak` it holds would otherwise keep the result's
    /// allocation pinned after the result dies too. The common case (nothing
    /// cached under `key`) costs only the read lock.
    pub(crate) fn remove(&self, key: u64) {
        if !self.0.read().unwrap().contains_key(&key) {
            return;
        }
        self.0.write().unwrap().remove(&key);
    }

    /// Number of entries currently in the cache (live or expired). For tests
    /// and diagnostics.
    pub fn len(&self) -> usize {
        self.0.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<'c> Cache<u64, AstRef<'c>> for AstCache<'c> {
    fn get(&self, key: &u64) -> Option<AstRef<'c>> {
        self.0.read().unwrap().get(key).and_then(Weak::upgrade)
    }

    fn insert(&self, key: u64, value: &AstRef<'c>) {
        let mut inner = self.0.write().unwrap();
        inner.insert(key, Arc::downgrade(value));
    }

    // Re-check under the write lock so concurrent builds of one term intern
    // one node.
    fn get_or_insert<E>(
        &self,
        key: u64,
        value_cv: impl FnOnce() -> Result<AstRef<'c>, E>,
    ) -> Result<AstRef<'c>, E> {
        if let Some(live) = self.get(&key) {
            return Ok(live);
        }
        // Declared before the guard so a losing duplicate drops after the
        // lock is released: its `Drop` takes the lock.
        let built = value_cv()?;
        let mut inner = self.0.write().unwrap();
        if let Some(live) = inner.get(&key).and_then(Weak::upgrade) {
            return Ok(live);
        }
        inner.insert(key, Arc::downgrade(&built));
        Ok(built)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ast_cache_basic() -> Result<(), ClarirsError> {
        let ctx = crate::context::Context::new();
        let cache = AstCache::default();

        // Create a simple AST
        let ast1 = ctx.bvv(BitVec::from((42, 64)))?;
        let hash1 = 12345u64; // Arbitrary hash for testing

        // Insert into cache
        let result1 = cache.get_or_insert::<ClarirsError>(hash1, || Ok(ast1.clone()))?;

        // Verify we can retrieve it without recomputing
        let result2 = cache.get_or_insert::<ClarirsError>(hash1, || {
            panic!("Should not compute new value when cached")
        })?;
        assert_eq!(result1, result2);
        Ok(())
    }

    #[test]
    fn test_ast_cache_different_hashes() -> Result<(), ClarirsError> {
        let ctx = crate::context::Context::new();
        let cache = AstCache::default();

        let ast1 = ctx.bvv(BitVec::from((42, 64)))?;
        let ast2 = ctx.bvv(BitVec::from((99, 64)))?;

        let result1 = cache.get_or_insert::<ClarirsError>(1, || Ok(ast1.clone()))?;
        let result2 = cache.get_or_insert::<ClarirsError>(2, || Ok(ast2.clone()))?;

        // Different hashes should cache different values
        assert_ne!(result1, result2);
        Ok(())
    }

    #[test]
    fn test_ast_cache_weak_reference_cleanup() -> Result<(), ClarirsError> {
        let ctx = crate::context::Context::new();
        let cache = AstCache::default();
        let hash = 999u64;

        {
            // Create and cache an AST
            let ast = ctx.bvv(BitVec::from((42, 64)))?;
            let _result = cache.get_or_insert::<ClarirsError>(hash, || Ok(ast.clone()))?;
            // ast and _result go out of scope here
        }

        // The weak reference should be expired now, so this should compute a new value
        let mut computed = false;
        let ast2 = ctx.bvv(BitVec::from((42, 64)))?;
        let _result = cache.get_or_insert::<ClarirsError>(hash, || {
            computed = true;
            Ok(ast2.clone())
        })?;

        assert!(
            computed,
            "Should have computed new value after weak ref expired"
        );
        Ok(())
    }

    #[test]
    fn test_ast_cache_entry_removed_on_drop() -> Result<(), ClarirsError> {
        let ctx = crate::context::Context::new();
        let baseline = ctx.ast_cache.len();
        {
            let _ast = ctx.bvv(BitVec::from((0xdead, 64)))?;
            assert_eq!(ctx.ast_cache.len(), baseline + 1);
        }
        // Dropping the last strong ref must evict the interning entry.
        assert_eq!(ctx.ast_cache.len(), baseline);
        Ok(())
    }

    /// `x + ite(c, a, b)` excavates to a distinct node, `ite(c, x + a, x + b)`.
    fn excavatable<'c>(ctx: &'c Context<'c>) -> Result<AstRef<'c>, ClarirsError> {
        let x = ctx.bvs("x", 64)?;
        let a = ctx.bvs("a", 64)?;
        let b = ctx.bvs("b", 64)?;
        let c = ctx.bools("c")?;
        let ite = ctx.ite(&c, &a, &b)?;
        ctx.add(&x, &ite)
    }

    #[test]
    fn test_excavate_ite_cache_entry_removed_on_drop() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let baseline = ctx.excavate_ite_cache.len();
        {
            let expr = excavatable(&ctx)?;
            let result = expr.excavate_ite()?;
            assert!(!Arc::ptr_eq(&expr, &result));
            assert!(ctx.excavate_ite_cache.len() > baseline);
            // The entry is keyed by `expr` and holds a `Weak` to `result`, so
            // drop the key first while the value is still alive: the entry
            // must go with the key rather than outlive both.
            drop(expr);
            drop(result);
        }
        assert_eq!(ctx.excavate_ite_cache.len(), baseline);
        Ok(())
    }

    #[test]
    fn test_excavate_ite_cache_entry_removed_on_drop_result_first() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let baseline = ctx.excavate_ite_cache.len();
        {
            let expr = excavatable(&ctx)?;
            let result = expr.excavate_ite()?;
            assert!(ctx.excavate_ite_cache.len() > baseline);
            drop(result);
            drop(expr);
        }
        assert_eq!(ctx.excavate_ite_cache.len(), baseline);
        Ok(())
    }

    #[test]
    fn test_excavate_ite_cache_identity_entry_removed_on_drop() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let baseline = ctx.excavate_ite_cache.len();
        {
            // No ITE to hoist: every node excavates to itself, so each entry's
            // key and value are the same node.
            let x = ctx.bvs("x", 64)?;
            let expr = ctx.add(&x, ctx.bvv(BitVec::from((1, 64)))?)?;
            let result = expr.excavate_ite()?;
            assert!(Arc::ptr_eq(&expr, &result));
            assert!(ctx.excavate_ite_cache.len() > baseline);
        }
        assert_eq!(ctx.excavate_ite_cache.len(), baseline);
        Ok(())
    }

    #[test]
    fn test_excavate_ite_cache_entry_survives_live_key() -> Result<(), ClarirsError> {
        let ctx = Context::new();
        let expr = excavatable(&ctx)?;
        let result = expr.excavate_ite()?;
        let n = ctx.excavate_ite_cache.len();
        // Dropping an extra handle to the key must not evict its entry: the
        // next excavation of the same node is still a cache hit.
        drop(expr.clone());
        assert_eq!(ctx.excavate_ite_cache.len(), n);
        let again = expr.excavate_ite()?;
        assert!(Arc::ptr_eq(&result, &again));
        assert_eq!(ctx.excavate_ite_cache.len(), n);
        Ok(())
    }

    #[test]
    fn test_ast_cache_hit_reuses_entry() -> Result<(), ClarirsError> {
        let ctx = crate::context::Context::new();
        let a = ctx.bvv(BitVec::from((7, 64)))?;
        let n = ctx.ast_cache.len();
        // Cache hit: the interned node is returned without building a
        // duplicate, so the entry count is unchanged.
        let b = ctx.bvv(BitVec::from((7, 64)))?;
        assert_eq!(ctx.ast_cache.len(), n);
        assert!(Arc::ptr_eq(&a, &b));
        Ok(())
    }

    #[test]
    fn test_ast_cache_concurrent_churn() {
        // Hammer the same small set of hashes from several threads so drops
        // race with re-interns; the liveness check in remove_if_expired must
        // never evict a just-re-created live entry or corrupt the map.
        let ctx = crate::context::Context::new();
        std::thread::scope(|s| {
            for _ in 0..4 {
                s.spawn(|| {
                    for i in 0..10_000u64 {
                        let ast = ctx.bvv(BitVec::from((i % 512, 64))).unwrap();
                        drop(ast);
                    }
                });
            }
        });
        // Every node is dead by now, so every entry must have been evicted.
        assert_eq!(ctx.ast_cache.len(), 0);
    }

    #[test]
    fn test_concurrent_builds_of_one_term_intern_one_node() {
        const THREADS: usize = 8;
        const TERMS: u64 = 2000;
        let ctx = crate::context::Context::new();
        let x = ctx.bvs("race_x", 64).unwrap();
        let barrier = std::sync::Barrier::new(THREADS);
        let built: Vec<Vec<AstRef>> = std::thread::scope(|s| {
            let handles: Vec<_> = (0..THREADS)
                .map(|_| {
                    s.spawn(|| {
                        (0..TERMS)
                            .map(|i| {
                                barrier.wait();
                                ctx.add(&x, ctx.bvv(BitVec::from((i, 64))).unwrap())
                                    .unwrap()
                            })
                            .collect()
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        for i in 0..TERMS as usize {
            for other in &built[1..] {
                assert!(
                    Arc::ptr_eq(&built[0][i], &other[i]),
                    "term {i} interned twice"
                );
            }
        }
    }

    #[test]
    fn test_generic_cache_basic() {
        let cache = GenericCache::<u64, String>::default();

        let result1 = cache
            .get_or_insert::<ClarirsError>(1, || Ok("hello".to_string()))
            .unwrap();
        let result2 = cache
            .get_or_insert::<ClarirsError>(1, || panic!("Should not compute when cached"))
            .unwrap();

        assert_eq!(result1, result2);
    }
}
