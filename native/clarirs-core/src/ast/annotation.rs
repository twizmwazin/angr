use std::cmp::Ordering;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use num_bigint::BigUint;

/// A wrapper excluded from identity: all `Ignored<T>` compare equal and hash to
/// nothing, so a field of this type is skipped by its container's derived
/// `Eq`/`Ord`/`Hash`. The wrapped value is still carried.
#[derive(Debug, Clone)]
pub struct Ignored<T>(pub T);

impl<T> PartialEq for Ignored<T> {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}
impl<T> Eq for Ignored<T> {}
impl<T> PartialOrd for Ignored<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl<T> Ord for Ignored<T> {
    fn cmp(&self, _: &Self) -> Ordering {
        Ordering::Equal
    }
}
impl<T> Hash for Ignored<T> {
    fn hash<H: Hasher>(&self, _: &mut H) {}
}
impl<T> From<T> for Ignored<T> {
    fn from(value: T) -> Self {
        Ignored(value)
    }
}

/// This struct is a sort of hack to allow us to access data in python
/// annotations, while supporting unknown annotations.
#[derive(Debug, PartialEq, Eq, Hash)]
pub enum AnnotationType {
    /// A user-defined Python annotation, held as the Python object itself.
    #[cfg(feature = "python")]
    PyAnnotation {
        /// `module:class` of the Python object. The module keeps same-named
        /// classes from different modules apart.
        name: Arc<str>,
        /// The Python object. `Ignored` excludes it from the annotation's identity.
        object: Ignored<pyo3::Py<pyo3::PyAny>>,
        /// Hash of the Python object; identifies the annotation.
        obj_hash: i64,
    },
    SimplificationAvoidance,
    StridedInterval {
        stride: BigUint,
        lower_bound: BigUint,
        upper_bound: BigUint,
    },
    EmptyStridedInterval,
    Region {
        region_id: String,
        region_base_addr: BigUint,
    },
    Uninitialized,
}

impl AnnotationType {
    fn rank(&self) -> u8 {
        match self {
            #[cfg(feature = "python")]
            AnnotationType::PyAnnotation { .. } => 0,
            AnnotationType::SimplificationAvoidance => 1,
            AnnotationType::StridedInterval { .. } => 2,
            AnnotationType::EmptyStridedInterval => 3,
            AnnotationType::Region { .. } => 4,
            AnnotationType::Uninitialized => 5,
        }
    }
}

impl PartialOrd for AnnotationType {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Orders like the derived `Ord` would (by variant, then by field), but two Python
/// annotations of the same class, which share their name allocation, skip the string
/// comparison. Same-class annotations are what annotation sets are mostly made of.
impl Ord for AnnotationType {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            #[cfg(feature = "python")]
            (
                AnnotationType::PyAnnotation {
                    name: a,
                    obj_hash: ha,
                    ..
                },
                AnnotationType::PyAnnotation {
                    name: b,
                    obj_hash: hb,
                    ..
                },
            ) => {
                if Arc::ptr_eq(a, b) {
                    ha.cmp(hb)
                } else {
                    a.cmp(b).then(ha.cmp(hb))
                }
            }
            (
                AnnotationType::StridedInterval {
                    stride: s1,
                    lower_bound: l1,
                    upper_bound: u1,
                },
                AnnotationType::StridedInterval {
                    stride: s2,
                    lower_bound: l2,
                    upper_bound: u2,
                },
            ) => (s1, l1, u1).cmp(&(s2, l2, u2)),
            (
                AnnotationType::Region {
                    region_id: i1,
                    region_base_addr: b1,
                },
                AnnotationType::Region {
                    region_id: i2,
                    region_base_addr: b2,
                },
            ) => (i1, b1).cmp(&(i2, b2)),
            _ => self.rank().cmp(&other.rank()),
        }
    }
}

/// An annotation attached to an AST node. Nodes hold them as `Arc<Annotation>`,
/// so copying annotation sets between nodes is cheap.
#[derive(Debug)]
pub struct Annotation {
    type_: AnnotationType,
    eliminatable: bool,
    relocatable: bool,
    /// Deterministic hash of the fields above, computed once.
    hash: u64,
}

impl Annotation {
    pub fn new(type_: AnnotationType, eliminatable: bool, relocatable: bool) -> Arc<Self> {
        let mut hasher = crate::context::deterministic_hasher();
        type_.hash(&mut hasher);
        eliminatable.hash(&mut hasher);
        relocatable.hash(&mut hasher);
        let hash = hasher.finish();
        Arc::new(Annotation {
            type_,
            eliminatable,
            relocatable,
            hash,
        })
    }

    /// The annotation's class name.
    pub fn name(&self) -> &str {
        match self.type_ {
            #[cfg(feature = "python")]
            AnnotationType::PyAnnotation { ref name, .. } => {
                name.rsplit_once(':').map_or(name, |(_, class)| class)
            }
            AnnotationType::SimplificationAvoidance => "SimplificationAvoidanceAnnotation",
            AnnotationType::StridedInterval { .. } => "StridedIntervalAnnotation",
            AnnotationType::EmptyStridedInterval => "EmptyStridedIntervalAnnotation",
            AnnotationType::Region { .. } => "RegionAnnotation",
            AnnotationType::Uninitialized => "UninitializedAnnotation",
        }
    }

    pub fn type_(&self) -> &AnnotationType {
        &self.type_
    }

    pub fn eliminatable(&self) -> bool {
        self.eliminatable
    }

    pub fn relocatable(&self) -> bool {
        self.relocatable
    }

    pub fn blocks_simplification(&self) -> bool {
        !self.eliminatable && !self.relocatable
    }

    pub fn identity_hash(&self) -> u64 {
        self.hash
    }

    fn key(&self) -> (&AnnotationType, bool, bool) {
        (&self.type_, self.eliminatable, self.relocatable)
    }
}

impl PartialEq for Annotation {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash && self.key() == other.key()
    }
}

impl Eq for Annotation {}

impl PartialOrd for Annotation {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Annotation {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key().cmp(&other.key())
    }
}

impl Hash for Annotation {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.hash);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn region(id: &str, base: u64) -> Arc<Annotation> {
        Annotation::new(
            AnnotationType::Region {
                region_id: id.to_owned(),
                region_base_addr: BigUint::from(base),
            },
            false,
            false,
        )
    }

    #[test]
    fn equal_by_value_not_pointer() {
        let a = region("stack", 1);
        let b = region("stack", 1);
        assert_eq!(a, b);
        assert_eq!(a.identity_hash(), b.identity_hash());
        assert_eq!(a.cmp(&b), Ordering::Equal);
        let mut set = BTreeSet::new();
        set.insert(a.clone());
        set.insert(b);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn flags_are_part_of_identity() {
        let sticky = Annotation::new(AnnotationType::Uninitialized, false, false);
        let floating = Annotation::new(AnnotationType::Uninitialized, false, true);
        assert_ne!(sticky, floating);
        assert_ne!(sticky.identity_hash(), floating.identity_hash());
        assert!(sticky.blocks_simplification());
        assert!(!floating.blocks_simplification());
    }

    #[test]
    fn order_matches_field_order() {
        assert_eq!(region("a", 5).cmp(&region("b", 0)), Ordering::Less);
        assert_eq!(region("a", 0).cmp(&region("a", 1)), Ordering::Less);
        assert_eq!(
            Annotation::new(AnnotationType::SimplificationAvoidance, false, false)
                .cmp(&Annotation::new(AnnotationType::Uninitialized, false, true)),
            Ordering::Less
        );
    }
}
