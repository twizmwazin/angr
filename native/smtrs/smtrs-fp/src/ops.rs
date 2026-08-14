//! Arithmetic, comparison and conversion circuits over `Unpacked` values.

use crate::round::{round, Rounding};
use crate::unpacked::{ite_unpacked, make_inf, make_nan, make_zero, Format, Unpacked, B};
use smtrs_core::{Op, TermId};

/// `fp.abs` / `fp.neg` only touch the sign (and leave NaN alone as a value —
/// SMT-LIB's NaN has no observable sign).
pub fn abs(b: &mut B, x: &Unpacked) -> Unpacked {
    let f = b.ff();
    Unpacked { sign: f, ..*x }
}

pub fn neg(b: &mut B, x: &Unpacked) -> Unpacked {
    let s = b.not(x.sign);
    Unpacked { sign: s, ..*x }
}

/// Ordered comparison `x < y` (false whenever either side is NaN).
pub fn lt(b: &mut B, x: &Unpacked, y: &Unpacked) -> TermId {
    let either_nan = b.or(&[x.nan, y.nan]);
    let both_zero = b.and(&[x.zero, y.zero]); // +0 == -0

    // Magnitude ordering for finite non-zero values.
    let ew = b.width(x.exp);
    let exp_lt = b.slt(x.exp, y.exp);
    let exp_eq = b.eq(x.exp, y.exp);
    let sig_lt = b.ult(x.sig, y.sig);
    let mag_lt_finite = {
        let tail = b.and(&[exp_eq, sig_lt]);
        b.or(&[exp_lt, tail])
    };
    let _ = ew;

    // Extend magnitude comparison over zero/infinity: order by class first.
    // rank: zero < finite < inf (by magnitude).
    let x_inf = x.inf;
    let y_inf = y.inf;
    let x_zero = x.zero;
    let y_zero = y.zero;
    let mag_lt = {
        // |x| < |y| cases:
        //  x zero and y not zero (y finite or inf)
        let a = {
            let ynz = b.not(y_zero);
            b.and(&[x_zero, ynz])
        };
        //  y inf and x not inf (and x not zero, covered by a)
        let c = {
            let xni = b.not(x_inf);
            let xnz = b.not(x_zero);
            b.and(&[y_inf, xni, xnz])
        };
        //  both finite non-zero: compare exponent/significand
        let d = {
            let xf = x.is_finite_nonzero(b);
            let yf = y.is_finite_nonzero(b);
            b.and(&[xf, yf, mag_lt_finite])
        };
        b.or(&[a, c, d])
    };
    let mag_eq = {
        let both_inf = b.and(&[x_inf, y_inf]);
        let both_fin = {
            let xf = x.is_finite_nonzero(b);
            let yf = y.is_finite_nonzero(b);
            let ee = b.eq(x.exp, y.exp);
            let se = b.eq(x.sig, y.sig);
            b.and(&[xf, yf, ee, se])
        };
        b.or(&[both_zero, both_inf, both_fin])
    };

    // Signed comparison: negative < positive; within a sign, magnitude order
    // (reversed for negatives).
    let neg_pos = {
        let np = b.not(y.sign);
        let nbz = b.not(both_zero);
        b.and(&[x.sign, np, nbz])
    };
    let same_sign = {
        let x_xor_y = b.mk(Op::Xor, &[x.sign, y.sign]);
        b.not(x_xor_y)
    };
    let within = {
        let pos_case = {
            let ns = b.not(x.sign);
            b.and(&[ns, mag_lt])
        };
        let neg_case = {
            let gt = {
                let nlt = b.not(mag_lt);
                let neq = b.not(mag_eq);
                b.and(&[nlt, neq])
            };
            b.and(&[x.sign, gt])
        };
        let inner = b.or(&[pos_case, neg_case]);
        b.and(&[same_sign, inner])
    };
    let raw = b.or(&[neg_pos, within]);
    let not_nan = b.not(either_nan);
    b.and(&[not_nan, raw])
}

/// IEEE equality (`fp.eq`): NaN is unequal to everything, +0 == -0.
pub fn feq(b: &mut B, x: &Unpacked, y: &Unpacked) -> TermId {
    let either_nan = b.or(&[x.nan, y.nan]);
    let both_zero = b.and(&[x.zero, y.zero]);
    let both_inf = {
        let se = {
            let d = b.mk(Op::Xor, &[x.sign, y.sign]);
            b.not(d)
        };
        b.and(&[x.inf, y.inf, se])
    };
    let both_fin = {
        let xf = x.is_finite_nonzero(b);
        let yf = y.is_finite_nonzero(b);
        let se = {
            let d = b.mk(Op::Xor, &[x.sign, y.sign]);
            b.not(d)
        };
        let ee = b.eq(x.exp, y.exp);
        let sg = b.eq(x.sig, y.sig);
        b.and(&[xf, yf, se, ee, sg])
    };
    let eq = b.or(&[both_zero, both_inf, both_fin]);
    let nn = b.not(either_nan);
    b.and(&[nn, eq])
}

pub fn leq(b: &mut B, x: &Unpacked, y: &Unpacked) -> TermId {
    let l = lt(b, x, y);
    let e = feq(b, x, y);
    b.or(&[l, e])
}

/// Classification predicates.
pub fn is_normal(b: &mut B, x: &Unpacked) -> TermId {
    // Finite, non-zero, and exponent at or above the normal minimum.
    let fin = x.is_finite_nonzero(b);
    let ew = b.width(x.exp);
    let min = b.bv_signed(ew, x.fmt.min_normal_exp());
    let ge = b.sle(min, x.exp);
    b.and(&[fin, ge])
}

pub fn is_subnormal(b: &mut B, x: &Unpacked) -> TermId {
    let fin = x.is_finite_nonzero(b);
    let n = is_normal(b, x);
    let nn = b.not(n);
    b.and(&[fin, nn])
}

/// Addition. Both operands are aligned into a common wide significand, added
/// or subtracted by sign, renormalized, then rounded once.
pub fn add(b: &mut B, rm: TermId, x: &Unpacked, y: &Unpacked) -> Unpacked {
    let fmt = x.fmt;
    let ew = b.width(x.exp);
    let sw = fmt.sb;
    // Working significand width: 2 guard positions + room for the carry.
    let ww = sw + 3;

    // Align: the larger exponent wins; shift the smaller significand right.
    let x_bigger = {
        let gt = b.slt(y.exp, x.exp);
        let eq = b.eq(x.exp, y.exp);
        let sig_ge = b.ule(y.sig, x.sig);
        let tie = b.and(&[eq, sig_ge]);
        b.or(&[gt, tie])
    };
    let (hi, lo) = (
        ite_unpacked(b, x_bigger, x, y),
        ite_unpacked(b, x_bigger, y, x),
    );

    let exp_diff = b.sub(hi.exp, lo.exp);
    let two_w = b.bv(ww, 2);
    let hi_sig = {
        let s = b.zext_to(hi.sig, ww);
        b.shl(s, two_w)
    };
    let lo_sig_full = {
        let s = b.zext_to(lo.sig, ww);
        b.shl(s, two_w)
    };
    // Cap the alignment shift; anything beyond the working width is sticky.
    let cap = b.bv(ew, ww as u64);
    let small = b.ult(exp_diff, cap);
    let shift = b.ite(small, exp_diff, cap);
    let shift_w = b.resize(shift, ww);
    let lo_shifted = b.lshr(lo_sig_full, shift_w);
    let back = b.shl(lo_shifted, shift_w);
    let sticky_align = {
        let x2 = b.mk(Op::BvXor, &[lo_sig_full, back]);
        let z = b.is_zero_bv(x2);
        b.not(z)
    };

    let signs_differ = b.mk(Op::Xor, &[hi.sign, lo.sign]);
    let sum = b.add(hi_sig, lo_shifted);
    // Effective subtraction: bits that fell off the end during alignment
    // represent a quantity still to be subtracted, so borrow one ulp when any
    // were lost. Without this the result is one ulp too large whenever the
    // smaller operand had significant bits below the guard position.
    let borrow = {
        let one = b.bv(ww, 1);
        let zero = b.zeros(ww);
        b.ite(sticky_align, one, zero)
    };
    let diff_raw = b.sub(hi_sig, lo_shifted);
    let diff = b.sub(diff_raw, borrow);
    let magnitude = b.ite(signs_differ, diff, sum);

    // Renormalize: shift the leading one to the top of the working word.
    let shift_norm = b.clz(magnitude);
    let normalized = b.shl(magnitude, shift_norm);
    let exp_adj = {
        // Widening sb -> sb+3 bits while shifting left by 2 moves the leading
        // bit one place further from the top, so the exponent gains exactly
        // (ww - sb) - 2 == 1 under the `value = sig * 2^(exp-(width-1))`
        // convention. Renormalization then subtracts the leading-zero count.
        let one_e = b.bv(ew, 1);
        let base = b.add(hi.exp, one_e);
        let sn = b.resize(shift_norm, ew);
        b.sub(base, sn)
    };
    // After normalization the top bit is the integer bit; the value is
    // sig * 2^(exp - (ww-1)), and `round` expects exactly that convention.
    let exact_zero = b.is_zero_bv(magnitude);

    let r = Rounding {
        sign: hi.sign,
        exp: exp_adj,
        sig: normalized,
        sticky: sticky_align,
    };
    let rounded = round(b, fmt, rm, &r);

    // Exact cancellation gives +0 (or -0 under RTN, per IEEE).
    let is_rtn = match b.pool.op(rm) {
        Op::RmConst(m) => {
            if m == crate::round::RTN {
                b.tt()
            } else {
                b.ff()
            }
        }
        _ => {
            let m = b.pool.rm(crate::round::RTN);
            b.eq(rm, m)
        }
    };
    let zero_sign = is_rtn;
    let zero_val = make_zero(b, fmt, zero_sign);
    let res = ite_unpacked(b, exact_zero, &zero_val, &rounded);

    // Special cases: NaN, infinities, zeros.
    let nan_val = make_nan(b, fmt);
    let inf_x = make_inf(b, fmt, x.sign);
    let inf_y = make_inf(b, fmt, y.sign);
    let inf_opposite = {
        let d = b.mk(Op::Xor, &[x.sign, y.sign]);
        b.and(&[x.inf, y.inf, d])
    };
    let any_nan = b.or(&[x.nan, y.nan, inf_opposite]);

    // x zero: result is y (with sign rules for 0+0).
    let both_zero = b.and(&[x.zero, y.zero]);
    let both_zero_val = {
        let same = {
            let d = b.mk(Op::Xor, &[x.sign, y.sign]);
            b.not(d)
        };
        // Same-sign zeros keep the sign; opposite-sign zeros give +0 (RTN: -0).
        let s = b.ite(same, x.sign, zero_sign);
        make_zero(b, fmt, s)
    };

    let res = ite_unpacked(b, y.zero, x, &res);
    let res = ite_unpacked(b, x.zero, y, &res);
    let res = ite_unpacked(b, both_zero, &both_zero_val, &res);
    let res = ite_unpacked(b, y.inf, &inf_y, &res);
    let res = ite_unpacked(b, x.inf, &inf_x, &res);
    ite_unpacked(b, any_nan, &nan_val, &res)
}

pub fn sub(b: &mut B, rm: TermId, x: &Unpacked, y: &Unpacked) -> Unpacked {
    let ny = neg(b, y);
    add(b, rm, x, &ny)
}

/// Multiplication: exponents add, significands multiply into a double-width
/// product which is renormalized and rounded.
pub fn mul(b: &mut B, rm: TermId, x: &Unpacked, y: &Unpacked) -> Unpacked {
    let fmt = x.fmt;
    let ew = b.width(x.exp);
    let sw = fmt.sb;
    let pw = 2 * sw;

    let xs = b.zext_to(x.sig, pw);
    let ys = b.zext_to(y.sig, pw);
    let product = b.mul(xs, ys);
    // Both inputs are in [1,2), so the product is in [1,4): its leading one
    // sits at bit 2*sw-1 or 2*sw-2.
    let top = b.extract(product, pw - 1, pw - 1);
    let top_set = b.bv1_to_bool(top);
    let one_p = b.bv(pw, 1);
    let shifted = b.shl(product, one_p);
    let normalized = b.ite(top_set, product, shifted);

    let exp_sum = b.add(x.exp, y.exp);
    let one_e = b.bv(ew, 1);
    let zero_e = b.zeros(ew);
    let adj = b.ite(top_set, one_e, zero_e);
    let exp = b.add(exp_sum, adj);

    let sign = b.mk(Op::Xor, &[x.sign, y.sign]);
    let ff = b.ff();
    let r = Rounding {
        sign,
        exp,
        sig: normalized,
        sticky: ff,
    };
    let rounded = round(b, fmt, rm, &r);

    // Specials: 0*inf = NaN; else zero if either zero; inf if either inf.
    let nan_val = make_nan(b, fmt);
    let zero_val = make_zero(b, fmt, sign);
    let inf_val = make_inf(b, fmt, sign);
    let zero_times_inf = {
        let a = b.and(&[x.zero, y.inf]);
        let c = b.and(&[x.inf, y.zero]);
        b.or(&[a, c])
    };
    let any_nan = b.or(&[x.nan, y.nan, zero_times_inf]);
    let any_zero = b.or(&[x.zero, y.zero]);
    let any_inf = b.or(&[x.inf, y.inf]);

    let res = ite_unpacked(b, any_zero, &zero_val, &rounded);
    let res = ite_unpacked(b, any_inf, &inf_val, &res);
    ite_unpacked(b, any_nan, &nan_val, &res)
}

/// Division by restoring long division on the significands.
pub fn div(b: &mut B, rm: TermId, x: &Unpacked, y: &Unpacked) -> Unpacked {
    let fmt = x.fmt;
    let ew = b.width(x.exp);
    let sw = fmt.sb;
    // Compute sw+3 quotient bits: integer bit, sw-1 fraction bits, guard,
    // round, and a sticky derived from the final remainder.
    let qw = sw + 3;
    let width = sw + qw + 1;

    let num = {
        let n = b.zext_to(x.sig, width);
        let sh = b.bv(width, qw as u64);
        b.shl(n, sh)
    };
    let den = b.zext_to(y.sig, width);
    let quot = b.mk(Op::BvUdiv, &[num, den]);
    let rem = b.mk(Op::BvUrem, &[num, den]);
    let rem_nonzero = {
        let z = b.is_zero_bv(rem);
        b.not(z)
    };
    let q = b.extract(quot, qw, 0); // qw+1 bits
                                    // x.sig/y.sig is in (1/2, 2): the leading one is at bit qw or qw-1.
    let top = b.extract(q, qw, qw);
    let top_set = b.bv1_to_bool(top);
    let one_q = b.bv(qw + 1, 1);
    let q_shifted = b.shl(q, one_q);
    let normalized = b.ite(top_set, q, q_shifted);

    let exp_diff = b.sub(x.exp, y.exp);
    let zero_e = b.zeros(ew);
    let one_e = b.bv(ew, 1);
    let minus_one_e = b.neg(one_e);
    let adj = b.ite(top_set, zero_e, minus_one_e);
    let exp = b.add(exp_diff, adj);

    let sign = b.mk(Op::Xor, &[x.sign, y.sign]);
    let r = Rounding {
        sign,
        exp,
        sig: normalized,
        sticky: rem_nonzero,
    };
    let rounded = round(b, fmt, rm, &r);

    // Specials: 0/0 and inf/inf are NaN; x/0 is inf; x/inf is zero.
    let nan_val = make_nan(b, fmt);
    let zero_val = make_zero(b, fmt, sign);
    let inf_val = make_inf(b, fmt, sign);
    let zero_zero = b.and(&[x.zero, y.zero]);
    let inf_inf = b.and(&[x.inf, y.inf]);
    let any_nan = b.or(&[x.nan, y.nan, zero_zero, inf_inf]);
    let to_inf = b.or(&[x.inf, y.zero]);
    let to_zero = b.or(&[x.zero, y.inf]);

    let res = ite_unpacked(b, to_zero, &zero_val, &rounded);
    let res = ite_unpacked(b, to_inf, &inf_val, &res);
    ite_unpacked(b, any_nan, &nan_val, &res)
}

/// Square root by restoring digit-by-digit extraction.
///
/// With `value = sig * 2^t` (t = exp - (sb-1)), write t = 2q + p so that
/// `sqrt(value) = sqrt(sig * 2^p) * 2^q` with an integral q. The integer
/// square root of `sig * 2^p` scaled up by `2^(2k)` then gives k extra
/// fractional bits, which the rounder consumes as guard/round/sticky.
pub fn sqrt(b: &mut B, rm: TermId, x: &Unpacked) -> Unpacked {
    let fmt = x.fmt;
    let ew = b.width(x.exp);
    let sb = fmt.sb;
    let k = sb + 3;
    let n = 2 * (sb + k + 2); // radicand width; root gets n/2 bits
    let rw = n / 2;

    // t = exp - (sb - 1); p = t mod 2 (two's-complement low bit works for
    // negative t as well), q = (t - p) / 2 via arithmetic shift.
    let sb_minus_1 = b.bv(ew, (sb - 1) as u64);
    let t = b.sub(x.exp, sb_minus_1);
    let p_bit = b.extract(t, 0, 0);
    let p_set = b.bv1_to_bool(p_bit);
    let one_e = b.bv(ew, 1);
    let q = b.mk(Op::BvAshr, &[t, one_e]); // floor(t/2); t = 2q + p

    // radicand = sig * 2^p * 2^(2k)
    let sig_n = b.zext_to(x.sig, n);
    let shift_even = b.bv(n, (2 * k) as u64);
    let shift_odd = b.bv(n, (2 * k + 1) as u64);
    let shift = b.ite(p_set, shift_odd, shift_even);
    let radicand = b.shl(sig_n, shift);

    // Restoring integer square root over `rw` digit steps.
    let mut root = b.zeros(n);
    let mut remainder = b.zeros(n);
    let two_n = b.bv(n, 2);
    let one_n = b.bv(n, 1);
    let zero_n = b.zeros(n);
    let mask3 = b.bv(n, 3);
    for i in (0..rw).rev() {
        let sh = b.bv(n, (2 * i) as u64);
        let brought = b.lshr(radicand, sh);
        let top2 = b.bvand(brought, mask3);
        let r2 = b.shl(remainder, two_n);
        remainder = b.bvor(r2, top2);
        let rs = b.shl(root, two_n);
        let trial = b.bvor(rs, one_n);
        let fits = b.ule(trial, remainder);
        let reduced = b.sub(remainder, trial);
        remainder = b.ite(fits, reduced, remainder);
        let root_shifted = b.shl(root, one_n);
        let bit = b.ite(fits, one_n, zero_n);
        root = b.bvor(root_shifted, bit);
    }
    let inexact = {
        let z = b.is_zero_bv(remainder);
        b.not(z)
    };

    // root ~= sqrt(sig * 2^p) * 2^k, held in `rw` bits. Normalize so the
    // leading one sits at the top, then convert to the rounder's convention:
    // value = root * 2^(q - k), i.e. exponent = q - k + (rw - 1) - clz.
    let root_r = b.extract(root, rw - 1, 0);
    let lz = b.clz(root_r);
    let normalized = b.shl(root_r, lz);
    let exp = {
        let k_e = b.bv(ew, k as u64);
        let base = b.sub(q, k_e);
        let top = b.bv(ew, (rw - 1) as u64);
        let with_top = b.add(base, top);
        let lz_e = b.resize(lz, ew);
        b.sub(with_top, lz_e)
    };

    let r = Rounding {
        sign: x.sign,
        exp,
        sig: normalized,
        sticky: inexact,
    };
    let rounded = round(b, fmt, rm, &r);

    // sqrt(-x) is NaN for x > 0; sqrt(±0) = ±0; sqrt(+inf) = +inf.
    let nan_val = make_nan(b, fmt);
    let neg_nonzero = {
        let nz = b.not(x.zero);
        let nn = b.not(x.nan);
        b.and(&[x.sign, nz, nn])
    };
    let any_nan = b.or(&[x.nan, neg_nonzero]);
    let pos_inf = {
        let np = b.not(x.sign);
        b.and(&[x.inf, np])
    };
    let inf_val = make_inf(b, fmt, x.sign);

    let res = ite_unpacked(b, x.zero, x, &rounded);
    let res = ite_unpacked(b, pos_inf, &inf_val, &res);
    ite_unpacked(b, any_nan, &nan_val, &res)
}

/// `fp.min` / `fp.max`. SMT-LIB leaves the ±0 case underspecified, and any
/// choice is conformant; this circuit returns the **second** operand there.
/// `lt` is a strict comparison, so on `+0` against `-0` it is false in both
/// directions, `pick_x` is false, and the `ite` below selects `y`.
pub fn min_max(b: &mut B, x: &Unpacked, y: &Unpacked, is_min: bool) -> Unpacked {
    let x_lt = lt(b, x, y);
    let pick_x = if is_min { x_lt } else { lt(b, y, x) };
    let chosen = ite_unpacked(b, pick_x, x, y);
    // NaN operands are ignored unless both are NaN.
    let res = ite_unpacked(b, y.nan, x, &chosen);
    let res = ite_unpacked(b, x.nan, y, &res);
    let both_nan = b.and(&[x.nan, y.nan]);
    let nan_val = make_nan(b, x.fmt);
    ite_unpacked(b, both_nan, &nan_val, &res)
}

/// Round to an integral value in the same format.
///
/// Unlike ordinary arithmetic this rounds at a *fixed exponent* (ulp = 1)
/// rather than a fixed precision, so it computes the integer directly and
/// renormalizes, sharing only the mode decision with the main rounder.
pub fn round_to_integral(b: &mut B, rm: TermId, x: &Unpacked) -> Unpacked {
    let fmt = x.fmt;
    let ew = b.width(x.exp);
    let sb = fmt.sb;
    let w = sb + 2;

    // Number of fractional bits: bit i of the significand has weight
    // 2^(exp-(sb-1)+i), so bits below index f = (sb-1) - exp are fractional.
    let sb_minus_1 = b.bv(ew, (sb - 1) as u64);
    let f = b.sub(sb_minus_1, x.exp);
    let zero_e = b.zeros(ew);
    let already_integral = b.sle(f, zero_e);
    // Clamp into [0, sb+1]; beyond that everything is fractional anyway.
    let max_f = b.bv(ew, (sb + 1) as u64);
    let f_hi = b.slt(max_f, f);
    let f_clamped = b.ite(f_hi, max_f, f);
    let f_pos = b.slt(zero_e, f_clamped);
    let fc = b.ite(f_pos, f_clamped, zero_e);

    let sig_w = b.zext_to(x.sig, w);
    let fc_w = b.resize(fc, w);
    let one_w = b.bv(w, 1);
    let integer_part = b.lshr(sig_w, fc_w);

    // guard = bit (fc-1); sticky = any bit strictly below that.
    let fc_minus_1 = b.sub(fc_w, one_w);
    let guard_shifted = b.lshr(sig_w, fc_minus_1);
    let guard_bit = b.extract(guard_shifted, 0, 0);
    let guard = b.bv1_to_bool(guard_bit);
    let below = {
        let kept = b.shl(guard_shifted, fc_minus_1);
        let diff = b.mk(Op::BvXor, &[sig_w, kept]);
        let z = b.is_zero_bv(diff);
        b.not(z)
    };
    let lsb_bit = b.extract(integer_part, 0, 0);
    let lsb = b.bv1_to_bool(lsb_bit);
    let inc = crate::round::should_increment(b, rm, x.sign, guard, below, lsb);
    let zero_w = b.zeros(w);
    let addend = b.ite(inc, one_w, zero_w);
    let n = b.add(integer_part, addend);

    // The result is exactly the integer `n`; renormalize it into the format.
    let n_zero = b.is_zero_bv(n);
    let lz = b.clz(n);
    let normalized = b.shl(n, lz);
    let new_sig = b.extract(normalized, w - 1, w - sb);
    let new_exp = {
        let top = b.bv(ew, (w - 1) as u64);
        let lz_e = b.resize(lz, ew);
        b.sub(top, lz_e)
    };
    let ff = b.ff();
    let integral = Unpacked {
        fmt,
        nan: ff,
        inf: ff,
        zero: ff,
        sign: x.sign,
        exp: new_exp,
        sig: new_sig,
    };
    let zero_val = make_zero(b, fmt, x.sign);
    let res = ite_unpacked(b, n_zero, &zero_val, &integral);

    // Specials and already-integral values pass through untouched.
    let res = ite_unpacked(b, already_integral, x, &res);
    let res = ite_unpacked(b, x.zero, x, &res);
    let res = ite_unpacked(b, x.inf, x, &res);
    ite_unpacked(b, x.nan, x, &res)
}

/// Align two (sign, exponent, significand) triples that already share the
/// working width `ww` and the convention `value = sig * 2^(exp - (ww-1))`,
/// add or subtract them by sign, renormalize, and return the result ready for
/// a single rounding.
///
/// Factored out so `fp.fma` can add the *exact* double-width product to the
/// addend without an intermediate rounding — which is the entire difference
/// between an FMA and a multiply followed by an add.
fn add_aligned(
    b: &mut B,
    ww: u32,
    ew: u32,
    a: (TermId, TermId, TermId),
    c: (TermId, TermId, TermId),
) -> (Rounding, TermId) {
    let (a_sign, a_exp, a_sig) = a;
    let (c_sign, c_exp, c_sig) = c;
    // Order by magnitude so the shift is always to the right.
    let a_bigger = {
        let gt = b.slt(c_exp, a_exp);
        let eq = b.eq(a_exp, c_exp);
        let ge = b.ule(c_sig, a_sig);
        let tie = b.and(&[eq, ge]);
        b.or(&[gt, tie])
    };
    let hi_sign = b.ite(a_bigger, a_sign, c_sign);
    let hi_exp = b.ite(a_bigger, a_exp, c_exp);
    let hi_sig = b.ite(a_bigger, a_sig, c_sig);
    let lo_sign = b.ite(a_bigger, c_sign, a_sign);
    let lo_exp = b.ite(a_bigger, c_exp, a_exp);
    let lo_sig = b.ite(a_bigger, c_sig, a_sig);

    let exp_diff = b.sub(hi_exp, lo_exp);
    let cap = b.bv(ew, ww as u64);
    let small = b.ult(exp_diff, cap);
    let shift = b.ite(small, exp_diff, cap);
    let shift_w = b.resize(shift, ww);
    let lo_shifted = b.lshr(lo_sig, shift_w);
    let back = b.shl(lo_shifted, shift_w);
    let sticky = {
        let d = b.mk(Op::BvXor, &[lo_sig, back]);
        let z = b.is_zero_bv(d);
        b.not(z)
    };

    let signs_differ = b.mk(Op::Xor, &[hi_sign, lo_sign]);
    let sum = b.add(hi_sig, lo_shifted);
    // Effective subtraction borrows one ulp for whatever the alignment lost.
    let one_w = b.bv(ww, 1);
    let zero_w = b.zeros(ww);
    let borrow = b.ite(sticky, one_w, zero_w);
    let diff_raw = b.sub(hi_sig, lo_shifted);
    let diff = b.sub(diff_raw, borrow);
    let magnitude = b.ite(signs_differ, diff, sum);

    let shift_norm = b.clz(magnitude);
    let normalized = b.shl(magnitude, shift_norm);
    let exp = {
        let sn = b.resize(shift_norm, ew);
        b.sub(hi_exp, sn)
    };
    let exact_zero = b.is_zero_bv(magnitude);
    (
        Rounding {
            sign: hi_sign,
            exp,
            sig: normalized,
            sticky,
        },
        exact_zero,
    )
}

/// Fused multiply-add: `round(x*y + z)` with the product kept exact, so the
/// result is rounded exactly once. The product is computed at double
/// significand width and the addend is injected at the same width, which is
/// what makes this different from `add(mul(x, y), z)`.
pub fn fma(b: &mut B, rm: TermId, x: &Unpacked, y: &Unpacked, z: &Unpacked) -> Unpacked {
    let fmt = x.fmt;
    let ew = b.width(x.exp);
    let sb = fmt.sb;
    // Working width: the exact product needs 2*sb bits, plus guard/round room.
    let ww = 2 * sb + 4;

    // Exact product. With `value = sig * 2^(exp-(width-1))`, placing the raw
    // 2*sb-bit product at the top of `ww` bits gives exponent x.exp+y.exp+1.
    let xs = b.zext_to(x.sig, ww);
    let ys = b.zext_to(y.sig, ww);
    let raw = b.mul(xs, ys);
    let place = b.bv(ww, (ww - 2 * sb) as u64);
    let p_placed = b.shl(raw, place);
    let p_exp_raw = {
        let sum = b.add(x.exp, y.exp);
        let one = b.bv(ew, 1);
        b.add(sum, one)
    };
    // Both significands lie in [2^(sb-1), 2^sb), so their product's leading
    // bit falls at one of two positions. Normalize it, or the exponent-first
    // magnitude comparison below would compare unlike representations.
    let p_norm = b.clz(p_placed);
    let p_top = b.shl(p_placed, p_norm);
    let p_exp_top = {
        let n = b.resize(p_norm, ew);
        b.sub(p_exp_raw, n)
    };
    // Keep one spare bit above the leading one so the addition below cannot
    // carry out of the working word. Shifting right by one and bumping the
    // exponent preserves the value exactly, because the product occupies only
    // the top 2*sb bits of a (2*sb+4)-bit word.
    let one_w = b.bv(ww, 1);
    let one_e = b.bv(ew, 1);
    let p_sig = b.lshr(p_top, one_w);
    let p_exp = b.add(p_exp_top, one_e);
    let p_sign = b.mk(Op::Xor, &[x.sign, y.sign]);

    // Addend at the same width: exponent is unchanged by the placement.
    let z_sig = {
        let s = b.zext_to(z.sig, ww);
        let sh = b.bv(ww, (ww - sb - 1) as u64);
        b.shl(s, sh)
    };
    let z_exp = b.add(z.exp, one_e);

    let (r, exact_zero) = add_aligned(b, ww, ew, (p_sign, p_exp, p_sig), (z.sign, z_exp, z_sig));
    let rounded = round(b, fmt, rm, &r);
    // A zero addend carries a meaningless stored exponent, so it must not
    // reach the magnitude comparison inside `add_aligned` — otherwise
    // `tiny_product + (-0.0)` picks the zero as the larger operand and the
    // result inherits its sign. Round the product on its own instead.
    let ff0 = b.ff();
    // `round` expects the leading significand bit at the top of the word, so
    // use the pre-headroom form here rather than the shifted one.
    let prod_only = round(
        b,
        fmt,
        rm,
        &Rounding {
            sign: p_sign,
            exp: p_exp_top,
            sig: p_top,
            sticky: ff0,
        },
    );

    // Exact cancellation yields +0 (-0 under RTN), as for plain addition.
    let is_rtn = match b.pool.op(rm) {
        Op::RmConst(m) => {
            if m == crate::round::RTN {
                b.tt()
            } else {
                b.ff()
            }
        }
        _ => {
            let m = b.pool.rm(crate::round::RTN);
            b.eq(rm, m)
        }
    };
    let zero_val = make_zero(b, fmt, is_rtn);
    let res = ite_unpacked(b, exact_zero, &zero_val, &rounded);

    // Specials. The product's own special cases come first, then the addend's:
    // NaN anywhere, 0*inf, and inf + (-inf) all give NaN.
    let nan_val = make_nan(b, fmt);
    let p_zero = b.or(&[x.zero, y.zero]);
    let p_inf = b.or(&[x.inf, y.inf]);
    let zero_times_inf = {
        let a1 = b.and(&[x.zero, y.inf]);
        let a2 = b.and(&[x.inf, y.zero]);
        b.or(&[a1, a2])
    };
    let inf_minus_inf = {
        let d = b.mk(Op::Xor, &[p_sign, z.sign]);
        b.and(&[p_inf, z.inf, d])
    };
    let any_nan = b.or(&[x.nan, y.nan, z.nan, zero_times_inf, inf_minus_inf]);

    let p_inf_val = make_inf(b, fmt, p_sign);
    let z_inf_val = make_inf(b, fmt, z.sign);
    // Product zero: result is the addend (with 0+0 sign rules).
    let both_zero = b.and(&[p_zero, z.zero]);
    let both_zero_val = {
        let same = {
            let d = b.mk(Op::Xor, &[p_sign, z.sign]);
            b.not(d)
        };
        let sgn = b.ite(same, p_sign, is_rtn);
        make_zero(b, fmt, sgn)
    };
    let p_zero_val = *z;

    let res = ite_unpacked(b, z.zero, &prod_only, &res);
    let res = ite_unpacked(b, p_zero, &p_zero_val, &res);
    let res = ite_unpacked(b, both_zero, &both_zero_val, &res);
    let res = ite_unpacked(b, z.inf, &z_inf_val, &res);
    let res = ite_unpacked(b, p_inf, &p_inf_val, &res);
    ite_unpacked(b, any_nan, &nan_val, &res)
}

/// Reduction stages we are willing to build for a symbolic `fp.rem`. One
/// stage per unit of exponent gap, so this admits Float16 (40) and Float32
/// (277) and rejects Float64 (2098), whose circuit would run to roughly a
/// million gates on a serial carry chain. Constant operands never get here —
/// `rem` evaluates those directly.
const REM_MAX_STAGES: u32 = 320;

/// `fp.rem`: IEEE-754 `remainder`, `x - y*n` with `n` the integer nearest
/// `x/y`, ties to even. Exact — the result is always representable.
///
/// The reduction runs on `A = X*2^(d+1)` against `B = 2Y` (see
/// `concrete::rem` for why that framing makes both sides integral), one
/// shift-subtract stage per unit of exponent gap `d = ex-ey`. Only the
/// running remainder is kept, so each stage is `sb+2` bits wide rather than
/// growing with the gap; the quotient is discarded except for its last bit,
/// which is its parity and therefore settles ties.
///
/// Returns `None` when the format's exponent range needs more stages than we
/// are prepared to build.
pub fn rem(b: &mut B, x: &Unpacked, y: &Unpacked) -> Option<Unpacked> {
    let fmt = x.fmt;
    let ew = b.width(x.exp);
    let sb = fmt.sb;
    let w = sb + 2;
    let stages = u32::try_from(fmt.exp_span()).ok()? + 1;
    if stages > REM_MAX_STAGES {
        return None;
    }

    let one_e = b.bv(ew, 1);
    let zero_e = b.zeros(ew);
    let d = b.sub(x.exp, y.exp);
    let e = b.add(d, one_e);
    // e < 0 means |x| < |y|/2, so the nearest multiple of y is zero and the
    // remainder is x itself. Clamping keeps the stage predicates well-behaved.
    let e_below = b.slt(e, zero_e);
    let cap = b.bv(ew, stages as u64);
    let e_above = b.slt(cap, e);
    let e_capped = b.ite(e_above, cap, e);
    let e_eff = b.ite(e_below, zero_e, e_capped);

    let one_w = b.bv(w, 1);
    let bb = {
        let yw = b.zext_to(y.sig, w);
        b.shl(yw, one_w)
    };
    // X < 2^sb <= 2Y = B, so the initial remainder is X and the quotient so
    // far is zero.
    let mut r = b.zext_to(x.sig, w);
    let mut q_lsb = b.ff();
    for i in 1..=stages {
        let iv = b.bv(ew, i as u64);
        let active = b.sle(iv, e_eff);
        let doubled = b.shl(r, one_w);
        let fits = b.ule(bb, doubled);
        let reduced = b.sub(doubled, bb);
        let stepped = b.ite(fits, reduced, doubled);
        r = b.ite(active, stepped, r);
        q_lsb = b.ite(active, fits, q_lsb);
    }

    // n = q, or q+1 when what is left exceeds half of |y|. On an exact tie
    // the even n wins, which means rounding up exactly when q is odd.
    let two_r = b.shl(r, one_w);
    let over = b.ult(bb, two_r);
    let tie = {
        let exact = b.eq(two_r, bb);
        b.and(&[exact, q_lsb])
    };
    let inc = b.or(&[over, tie]);
    let flipped = b.sub(bb, r);
    let mu = b.ite(inc, flipped, r);

    // |mu| <= B/2 = Y < 2^sb, measured in units of 2^(ey-sb): normalizing it
    // into the top `sb` bits of the `sb+2`-bit word puts the exponent at
    // ey + 1 - clz.
    let lz = b.clz(mu);
    let normalized = b.shl(mu, lz);
    let sig = b.extract(normalized, w - 1, w - sb);
    let exp = {
        let base = b.add(y.exp, one_e);
        let lz_e = b.resize(lz, ew);
        b.sub(base, lz_e)
    };
    let sign = b.mk(Op::Xor, &[x.sign, inc]);
    let ff = b.ff();
    let finite = Unpacked {
        fmt,
        nan: ff,
        inf: ff,
        zero: ff,
        sign,
        exp,
        sig,
    };

    // An exact multiple gives zero with the sign of x (mu can only vanish
    // when `inc` is false, so `sign` would agree, but say it outright).
    let mu_zero = b.is_zero_bv(mu);
    let zero_val = make_zero(b, fmt, x.sign);
    let res = ite_unpacked(b, mu_zero, &zero_val, &finite);

    // Specials: x itself when y is infinite, when x is zero, or when the
    // quotient rounds to zero; NaN when x is infinite or y is zero.
    let res = ite_unpacked(b, e_below, x, &res);
    let res = ite_unpacked(b, x.zero, x, &res);
    let res = ite_unpacked(b, y.inf, x, &res);
    let nan_val = make_nan(b, fmt);
    let any_nan = b.or(&[x.nan, y.nan, x.inf, y.zero]);
    Some(ite_unpacked(b, any_nan, &nan_val, &res))
}

/// Convert from a signed or unsigned bit-vector.
pub fn from_int_bv(b: &mut B, fmt: Format, rm: TermId, bv: TermId, signed: bool) -> Unpacked {
    let w = b.width(bv);
    let sign = if signed {
        let top = b.extract(bv, w - 1, w - 1);
        b.bv1_to_bool(top)
    } else {
        b.ff()
    };
    let magnitude = if signed {
        let n = b.neg(bv);
        b.ite(sign, n, bv)
    } else {
        bv
    };
    let is_zero = b.is_zero_bv(magnitude);

    // Normalize the magnitude into a significand of width max(w, sb+3).
    let ww = w.max(fmt.sb + 3);
    let wide = b.zext_to(magnitude, ww);
    let shift = b.clz(wide);
    let normalized = b.shl(wide, shift);
    let ew = fmt.exp_width();
    // value = magnitude = normalized * 2^(-(ww-1)) * 2^(ww-1-shift)
    let exp = {
        let base = b.bv(ew, (ww - 1) as u64);
        let s = b.resize(shift, ew);
        b.sub(base, s)
    };
    let ff = b.ff();
    let r = Rounding {
        sign,
        exp,
        sig: normalized,
        sticky: ff,
    };
    let rounded = round(b, fmt, rm, &r);
    let zero_val = make_zero(b, fmt, sign);
    ite_unpacked(b, is_zero, &zero_val, &rounded)
}

/// Convert to a signed/unsigned bit-vector of `m` bits, rounding per `rm`.
///
/// SMT-LIB leaves NaN and out-of-range results unspecified. NaN and infinity
/// produce zero; a *finite* out-of-range value produces the low `m` bits of
/// the truncation, not zero — see the `bad` mux at the end, which tests only
/// `nan` and `inf`.
pub fn to_int_bv(b: &mut B, rm: TermId, x: &Unpacked, m: u32, signed: bool) -> TermId {
    let fmt = x.fmt;
    // Round to integral first, then extract the integer value.
    let ri = round_to_integral(b, rm, x);
    let sw = fmt.sb;
    let ew = b.width(ri.exp);
    let out_w = m.max(sw) + 2;

    let sig = b.zext_to(ri.sig, out_w);
    // value = sig * 2^(exp - (sw-1))
    let shift_left = {
        let s = b.bv(ew, (sw - 1) as u64);
        b.sub(ri.exp, s)
    };
    let zero_e = b.zeros(ew);
    let neg_shift = b.slt(shift_left, zero_e);
    let left_amt = b.resize(shift_left, out_w);
    let right_amt = {
        let n = b.neg(shift_left);
        b.resize(n, out_w)
    };
    let l = b.shl(sig, left_amt);
    let r = b.lshr(sig, right_amt);
    let magnitude = b.ite(neg_shift, r, l);
    let value = if signed {
        let n = b.neg(magnitude);
        b.ite(ri.sign, n, magnitude)
    } else {
        magnitude
    };
    let truncated = b.extract(value, m - 1, 0);
    let zero_out = b.zeros(m);
    let bad = b.or(&[x.nan, x.inf]);
    b.ite(bad, zero_out, truncated)
}
