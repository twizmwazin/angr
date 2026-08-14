/// Sorts.
///
/// `Bool` and `BitVec` are the sorts the solving pipeline works in. `Float`,
/// `Str`, `RegLan` and the `Int` used for string lengths are all eliminated
/// before bit-blasting — by `smtrs-fp` and `smtrs-str` respectively — so they
/// are real, solvable sorts even though nothing downstream of lowering sees
/// them. `RoundingMode` is only ever a literal operand of an FP operator.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub enum Sort {
    Bool,
    BitVec(u32),
    Float(u32, u32),
    RoundingMode,
    Int,
    Str,
    RegLan,
}

impl Sort {
    pub fn bv_width(self) -> Option<u32> {
        match self {
            Sort::BitVec(w) => Some(w),
            _ => None,
        }
    }

    pub fn is_bv(self) -> bool {
        matches!(self, Sort::BitVec(_))
    }
}

impl std::fmt::Display for Sort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Sort::Bool => write!(f, "Bool"),
            Sort::BitVec(w) => write!(f, "(_ BitVec {w})"),
            Sort::Float(e, s) => write!(f, "(_ FloatingPoint {e} {s})"),
            Sort::RoundingMode => write!(f, "RoundingMode"),
            Sort::Int => write!(f, "Int"),
            Sort::Str => write!(f, "String"),
            Sort::RegLan => write!(f, "RegLan"),
        }
    }
}
