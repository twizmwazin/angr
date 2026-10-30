use std::any::Any;
use std::fmt;
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
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl<T> Ord for Ignored<T> {
    fn cmp(&self, _: &Self) -> std::cmp::Ordering {
        std::cmp::Ordering::Equal
    }
}
impl<T> std::hash::Hash for Ignored<T> {
    fn hash<H: std::hash::Hasher>(&self, _: &mut H) {}
}
impl<T> From<T> for Ignored<T> {
    fn from(value: T) -> Self {
        Ignored(value)
    }
}

/// An opaque object a host (e.g. the Python bindings) attaches to an unknown
/// annotation: the decoded form of its serialized `value`, kept so the host can
/// hand it back without decoding the bytes again. The core never inspects it.
#[derive(Clone, Default)]
pub struct HostObject(pub Option<Arc<dyn Any + Send + Sync>>);

impl HostObject {
    pub fn new<T: Any + Send + Sync>(object: T) -> Self {
        HostObject(Some(Arc::new(object)))
    }

    /// The attached object, if there is one and it is a `T`.
    pub fn get<T: Any>(&self) -> Option<&T> {
        self.0.as_deref()?.downcast_ref()
    }
}

impl fmt::Debug for HostObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("HostObject").finish_non_exhaustive()
    }
}

/// This struct is a sort of hack to allow us to access data in python
/// annotations, while supporting unknown annotations.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AnnotationType {
    Unknown {
        name: String,
        /// Pickled Python object, kept to reconstruct it when no `object` is
        /// attached; `Ignored` excludes it from the annotation's identity.
        value: Ignored<Vec<u8>>,
        /// The host object `value` decodes to, if the host attached one.
        /// `Ignored` excludes it from the annotation's identity.
        object: Ignored<HostObject>,
        /// Hash of the originating Python object; identifies the annotation.
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Annotation {
    type_: AnnotationType,
    eliminatable: bool,
    relocatable: bool,
}

impl Annotation {
    pub fn new(type_: AnnotationType, eliminatable: bool, relocatable: bool) -> Self {
        Annotation {
            type_,
            eliminatable,
            relocatable,
        }
    }

    pub fn name(&self) -> &str {
        match self.type_ {
            AnnotationType::Unknown { ref name, .. } => name,
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

    pub fn identity_hash(&self) -> u64 {
        let mut hasher = crate::context::deterministic_hasher();
        self.hash(&mut hasher);
        hasher.finish()
    }
}
