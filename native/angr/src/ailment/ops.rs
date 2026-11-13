//! Classification of AIL operator names.
//!
//! Integer and floating-point operations are distinct ops: the floating-point counterpart of an op
//! carries an `F` suffix (`Add` / `AddF`, `CmpEQ` / `CmpEQF`, `Neg` / `NegF`). Lane-wise vector
//! ops put their `V` suffix last (`AddV` / `AddFV`). Ops that only exist on floating-point values
//! ([`FP_ONLY_OPS`]) keep their plain name.
//!
//! `CmpF` (the VEX three-way comparison, `Iop_CmpF64`) is the one exception to the suffix rule: it
//! yields an integer condition code that flag arithmetic is done on, and it is not a
//! floating-point op.

/// Ops that are floating-point by nature and have no integer counterpart, so they carry no `F`.
const FP_ONLY_OPS: &[&str] = &[
    "Atan2", "CmpUN", "Cos", "Exp2", "Log2", "PRem", "PRem1", "Scale", "SignBit", "Sin", "Sqrt",
    "Tan",
];

/// Ops whose name ends in `F` without being a floating-point op.
const INT_OPS_ENDING_IN_F: &[&str] = &["CmpF"];

/// Whether `op` names a floating-point operation.
pub fn is_float_op(op: &str) -> bool {
    // a lane-wise vector op is named after its scalar op
    let base = match op.strip_suffix('V') {
        Some(base) if !base.is_empty() => base,
        _ => op,
    };
    (base.ends_with('F') && !INT_OPS_ENDING_IN_F.contains(&base)) || FP_ONLY_OPS.contains(&base)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn float_ops_are_told_from_integer_ops() {
        for op in ["Add", "CmpEQ", "Neg", "AddV", "Max", "Round", "V", "CmpF"] {
            assert!(!is_float_op(op), "{op}");
        }
        for op in [
            "AddF", "CmpEQF", "NegF", "AddFV", "MaxF", "Sqrt", "SqrtV", "CmpUN", "CmpUNV",
            "SignBit",
        ] {
            assert!(is_float_op(op), "{op}");
        }
    }
}
