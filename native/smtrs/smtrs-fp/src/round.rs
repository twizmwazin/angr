//! Rounding: the single place where IEEE-754's five modes, subnormal
//! gradual underflow, and overflow-to-infinity are decided.
//!
//! Every arithmetic operation produces an exact (or exactly-truncated with a
//! sticky bit) result in a wider working format, then hands it here. Keeping
//! one rounder means the modes are implemented once and every operation
//! inherits them.

use crate::unpacked::{make_inf, make_zero, Format, Unpacked, B};
use smtrs_core::TermId;

/// Rounding modes, matching `Op::RmConst` encodings.
pub const RNE: u8 = 0;
pub const RNA: u8 = 1;
pub const RTP: u8 = 2;
pub const RTN: u8 = 3;
// RTZ is the fall-through case of the rounder — "never increment" — so nothing
// tests for it by name. Kept so the encoding of `Op::RmConst` is spelled out in
// full here rather than in four fifths.
#[allow(dead_code)]
pub const RTZ: u8 = 4;

/// A value to be rounded: sign, unbiased exponent (signed, `exp_width`), and
/// a significand of `sig.len()` bits whose leading bit is the integer part
/// (i.e. value = sig * 2^(exp - (width-1))), plus a sticky bit recording
/// whether anything nonzero was already discarded below.
pub struct Rounding {
    pub sign: TermId,
    pub exp: TermId,
    pub sig: TermId,
    pub sticky: TermId,
}

/// Is the rounding-mode term equal to `mode`? Rounding modes are always
/// literals here (symbolic modes are rejected during lowering), so this folds
/// to a constant — which in turn constant-folds every branch of the rounder
/// that belongs to a different mode, leaving only the selected mode's logic.
fn rm_is(b: &mut B, rm: TermId, mode: u8) -> TermId {
    match b.pool.op(rm) {
        smtrs_core::Op::RmConst(m) => {
            if m == mode {
                b.tt()
            } else {
                b.ff()
            }
        }
        _ => {
            let m = b.pool.rm(mode);
            b.eq(rm, m)
        }
    }
}

/// Should a truncated result be incremented, given the mode, the sign, and
/// the guard/sticky/lsb of the discarded part? Shared by the main rounder and
/// by `fp.roundToIntegral`, which rounds at a fixed exponent rather than a
/// fixed precision.
pub fn should_increment(
    b: &mut B,
    rm: TermId,
    sign: TermId,
    guard: TermId,
    sticky: TermId,
    lsb: TermId,
) -> TermId {
    let is_rne = rm_is(b, rm, RNE);
    let is_rna = rm_is(b, rm, RNA);
    let is_rtp = rm_is(b, rm, RTP);
    let is_rtn = rm_is(b, rm, RTN);
    let inexact = b.or(&[guard, sticky]);
    let rne_inc = {
        let tie_break = b.or(&[sticky, lsb]);
        b.and(&[guard, tie_break])
    };
    let not_sign = b.not(sign);
    let rtp_inc = b.and(&[inexact, not_sign]);
    let rtn_inc = b.and(&[inexact, sign]);
    let a = b.and(&[is_rne, rne_inc]);
    let c = b.and(&[is_rna, guard]);
    let d = b.and(&[is_rtp, rtp_inc]);
    let e = b.and(&[is_rtn, rtn_inc]);
    b.or(&[a, c, d, e])
}

/// Round `r` into `fmt`, producing a packed-ready unpacked value.
///
/// `r.sig` must be normalized so its top bit is 1 whenever the value is
/// nonzero; callers arrange this (arithmetic normalizes before calling).
pub fn round(b: &mut B, fmt: Format, rm: TermId, r: &Rounding) -> Unpacked {
    let ew = fmt.exp_width();
    let sw = b.width(r.sig);
    let target = fmt.sb;
    debug_assert!(sw > target, "rounder needs extra precision bits");

    // ---- gradual underflow: if exp < min_normal_exp, shift right ----
    let min_exp = b.bv_signed(ew, fmt.min_normal_exp());
    let below = b.slt(r.exp, min_exp);
    let shift_amt = b.sub(min_exp, r.exp); // > 0 when below
                                           // Cap the shift so an enormous underflow saturates instead of wrapping.
    let cap = b.bv(ew, sw as u64);
    let capped = b.ult(shift_amt, cap);
    let eff_shift = b.ite(capped, shift_amt, cap);
    let shift_sig = b.resize(eff_shift, sw);
    // Sticky must capture bits shifted out: nonzero iff (sig << (sw - shift))
    // has any bit set, i.e. sig has a set bit below `shift`.
    let shifted = b.lshr(r.sig, shift_sig);
    let back = b.shl(shifted, shift_sig);
    let lost = {
        let x = b.mk(smtrs_core::Op::BvXor, &[r.sig, back]);
        let z = b.is_zero_bv(x);
        b.not(z)
    };
    let sub_sticky = b.and(&[below, lost]);
    let sig = b.ite(below, shifted, r.sig);
    let exp = b.ite(below, min_exp, r.exp);
    let sticky = b.or(&[r.sticky, sub_sticky]);

    // ---- split into kept / guard / rest ----
    let extra = sw - target; // bits below the target precision
    let kept = b.extract(sig, sw - 1, extra); // `target` bits
    let guard = b.extract(sig, extra - 1, extra - 1);
    let guard_set = b.bv1_to_bool(guard);
    let rest_sticky = if extra >= 2 {
        let rest = b.extract(sig, extra - 2, 0);
        let z = b.is_zero_bv(rest);
        b.not(z)
    } else {
        b.ff()
    };
    let sticky = b.or(&[sticky, rest_sticky]);
    let lsb = b.extract(kept, 0, 0);
    let lsb_set = b.bv1_to_bool(lsb);
    let inexact = b.or(&[guard_set, sticky]);

    // ---- decide whether to increment ----
    let is_rne = rm_is(b, rm, RNE);
    let is_rna = rm_is(b, rm, RNA);
    let is_rtp = rm_is(b, rm, RTP);
    let is_rtn = rm_is(b, rm, RTN);
    // RTZ never increments.

    // RNE: increment if guard && (sticky || lsb)  [ties to even]
    let rne_inc = {
        let tie_break = b.or(&[sticky, lsb_set]);
        b.and(&[guard_set, tie_break])
    };
    // RNA: increment if guard  [ties away from zero]
    let rna_inc = guard_set;
    // RTP: increment if inexact and positive; RTN: if inexact and negative.
    let not_sign = b.not(r.sign);
    let rtp_inc = b.and(&[inexact, not_sign]);
    let rtn_inc = b.and(&[inexact, r.sign]);

    let inc = {
        let a = b.and(&[is_rne, rne_inc]);
        let c = b.and(&[is_rna, rna_inc]);
        let d = b.and(&[is_rtp, rtp_inc]);
        let e = b.and(&[is_rtn, rtn_inc]);
        b.or(&[a, c, d, e])
    };

    // Increment with one extra bit of headroom to catch the carry that turns
    // 1.111..1 into 10.000..0 (which bumps the exponent).
    let kept_ext = b.zext(kept, 1);
    let one = b.bv(target + 1, 1);
    let zero_ext = b.zeros(target + 1);
    let addend = b.ite(inc, one, zero_ext);
    let summed = b.add(kept_ext, addend);
    let carry = b.extract(summed, target, target);
    let carried = b.bv1_to_bool(carry);
    // On carry the significand becomes 1.0 and the exponent grows by one.
    let sig_no_carry = b.extract(summed, target - 1, 0);
    let sig_carry = {
        let top = b.bv(1, 1);
        let rest = b.zeros(target - 1);
        b.concat(&[top, rest])
    };
    let final_sig = b.ite(carried, sig_carry, sig_no_carry);
    let one_e = b.bv(ew, 1);
    let bumped = b.add(exp, one_e);
    let final_exp = b.ite(carried, bumped, exp);

    // A subnormal that rounded up to the normal minimum is simply normal
    // again; `pack` derives the field layout from the exponent, so nothing
    // special is needed here.

    // ---- zero / overflow (decided before renormalization) ----
    let result_zero = b.is_zero_bv(final_sig);
    let max_exp = b.bv(ew, fmt.max_normal_exp() as u64);
    let overflow = b.slt(max_exp, final_exp);
    // Overflow goes to infinity except where the mode rounds toward zero /
    // toward the opposite infinity, which cap at the largest finite value.
    let to_inf = {
        let near = b.or(&[is_rne, is_rna]);
        let up_pos = b.and(&[is_rtp, not_sign]);
        let down_neg = b.and(&[is_rtn, r.sign]);
        b.or(&[near, up_pos, down_neg])
    };
    let max_finite_sig = b.ones(target);
    let max_finite_exp = max_exp;

    let inf_val = make_inf(b, fmt, r.sign);
    let zero_val = make_zero(b, fmt, r.sign);

    // Restore the representation invariant: every finite non-zero value keeps
    // its leading significand bit set, with the exponent free to fall below
    // the normal minimum for subnormals. Gradual underflow above produced a
    // denormalized significand, so renormalize it here — otherwise the same
    // value could be represented two ways and compare unequal.
    let renorm_shift = b.clz(final_sig);
    let renorm_sig = b.shl(final_sig, renorm_shift);
    let renorm_exp = {
        let s = b.resize(renorm_shift, ew);
        b.sub(final_exp, s)
    };
    let final_sig = renorm_sig;
    let final_exp = renorm_exp;

    let ff = b.ff();
    let normal = Unpacked {
        fmt,
        nan: ff,
        inf: ff,
        zero: ff,
        sign: r.sign,
        exp: final_exp,
        sig: final_sig,
    };
    let max_finite = Unpacked {
        fmt,
        nan: ff,
        inf: ff,
        zero: ff,
        sign: r.sign,
        exp: max_finite_exp,
        sig: max_finite_sig,
    };

    let over = crate::unpacked::ite_unpacked(b, to_inf, &inf_val, &max_finite);
    let res = crate::unpacked::ite_unpacked(b, overflow, &over, &normal);
    crate::unpacked::ite_unpacked(b, result_zero, &zero_val, &res)
}
