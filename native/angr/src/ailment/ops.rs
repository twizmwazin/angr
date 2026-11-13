//! Naming rules for AIL operator names.
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

/// Split a lane-wise vector op name into its scalar name and the `V` suffix (empty if scalar).
fn split_vector(op: &str) -> (&str, &str) {
    match op.strip_suffix('V') {
        Some(base) if !base.is_empty() => (base, "V"),
        _ => (op, ""),
    }
}

/// Whether `op` names a floating-point operation.
pub fn is_float_op(op: &str) -> bool {
    let (base, _) = split_vector(op);
    (base.ends_with('F') && !INT_OPS_ENDING_IN_F.contains(&base)) || FP_ONLY_OPS.contains(&base)
}

/// The floating-point counterpart of `op`; a no-op for ops that are already floating-point.
pub fn float_op(op: &str) -> String {
    let (base, vector) = split_vector(op);
    if is_float_op(op) || INT_OPS_ENDING_IN_F.contains(&base) {
        return op.to_string();
    }
    format!("{base}F{vector}")
}

/// The integer counterpart of `op`; a no-op for integer ops and for floating-point-only ops.
pub fn int_op(op: &str) -> String {
    let (base, vector) = split_vector(op);
    match base.strip_suffix('F') {
        Some(int_base) if !int_base.is_empty() && is_float_op(op) => format!("{int_base}{vector}"),
        _ => op.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn float_and_int_names_round_trip() {
        for (int, float) in [
            ("Add", "AddF"),
            ("CmpEQ", "CmpEQF"),
            ("Neg", "NegF"),
            ("AddV", "AddFV"),
            ("Max", "MaxF"),
        ] {
            assert!(!is_float_op(int));
            assert!(is_float_op(float));
            assert_eq!(float_op(int), float);
            assert_eq!(float_op(float), float);
            assert_eq!(int_op(float), int);
            assert_eq!(int_op(int), int);
        }
    }

    #[test]
    fn fp_only_ops_keep_their_name() {
        for op in ["Sqrt", "SqrtV", "CmpUN", "CmpUNV", "SignBit"] {
            assert!(is_float_op(op));
            assert_eq!(float_op(op), op);
            assert_eq!(int_op(op), op);
        }
        assert!(!is_float_op("V"));
        assert!(!is_float_op("Round"));
    }

    #[test]
    fn cmpf_is_an_integer_op() {
        assert!(!is_float_op("CmpF"));
        assert_eq!(float_op("CmpF"), "CmpF");
        assert_eq!(int_op("CmpF"), "CmpF");
    }
}
