//! Concrete floating-point values, and the operations that are only tractable
//! on them.
//!
//! Most FP operators are cheap enough to word-blast unconditionally, so the
//! circuit *is* the semantics and constants fall out of the bit-blaster. One
//! is not: `fp.rem` is exact, and reducing `x` modulo `y` takes one
//! shift-subtract stage per unit of exponent difference — up to 2098 of them
//! for a double. That is fine to *evaluate*, and hopeless to *encode*.
//!
//! So this module carries a Rust-side mirror of `Unpacked` and evaluates
//! `fp.rem` on it with arbitrary-width integer arithmetic. `ops::rem` uses it
//! whenever both operands are constant and falls back to the circuit
//! otherwise.

use crate::unpacked::{make_inf, make_nan, make_zero, Format, Unpacked, B};
use smtrs_core::{BvConst, Op, TermId, TermPool};

/// A floating-point value known at lowering time. `Finite` uses the same
/// convention as `Unpacked`: `value = (-1)^sign * sig * 2^(exp - (sb-1))`
/// with the leading bit of `sig` set, so subnormals carry an exponent below
/// the format minimum rather than a denormalized significand.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Concrete {
    Nan,
    Inf(bool),
    Zero(bool),
    Finite { sign: bool, exp: i64, sig: BvConst },
}

fn as_bool(pool: &TermPool, t: TermId) -> Option<bool> {
    match pool.op(t) {
        Op::True => Some(true),
        Op::False => Some(false),
        _ => None,
    }
}

/// Read a two's-complement `BvConst` as an `i64` (None if it does not fit).
fn signed(c: &BvConst) -> Option<i64> {
    if c.sign_bit() {
        c.neg()
            .as_u64()
            .and_then(|v| i64::try_from(v).ok())
            .map(|v| -v)
    } else {
        c.as_u64().and_then(|v| i64::try_from(v).ok())
    }
}

/// Index of the highest set bit plus one (0 for zero).
fn bit_len(c: &BvConst) -> u32 {
    (0..c.width())
        .rev()
        .find(|&i| c.bit(i))
        .map_or(0, |i| i + 1)
}

/// Recover the concrete value behind an `Unpacked`, if every field is a
/// literal. The class flags are mutually exclusive by construction, so the
/// first one that holds decides.
pub fn of_unpacked(pool: &TermPool, u: &Unpacked) -> Option<Concrete> {
    let nan = as_bool(pool, u.nan)?;
    let inf = as_bool(pool, u.inf)?;
    let zero = as_bool(pool, u.zero)?;
    let sign = as_bool(pool, u.sign)?;
    if nan {
        return Some(Concrete::Nan);
    }
    if inf {
        return Some(Concrete::Inf(sign));
    }
    if zero {
        return Some(Concrete::Zero(sign));
    }
    let exp = signed(pool.as_bv_const(u.exp)?)?;
    let sig = pool.as_bv_const(u.sig)?.clone();
    Some(Concrete::Finite { sign, exp, sig })
}

/// Build the `Unpacked` form of a concrete value; all fields are literals.
pub fn to_unpacked(b: &mut B, fmt: Format, c: &Concrete) -> Unpacked {
    match c {
        Concrete::Nan => make_nan(b, fmt),
        Concrete::Inf(s) => {
            let s = if *s { b.tt() } else { b.ff() };
            make_inf(b, fmt, s)
        }
        Concrete::Zero(s) => {
            let s = if *s { b.tt() } else { b.ff() };
            make_zero(b, fmt, s)
        }
        Concrete::Finite { sign, exp, sig } => {
            let ff = b.ff();
            let sign = if *sign { b.tt() } else { ff };
            let exp = b.bv_signed(fmt.exp_width(), *exp);
            let sig = b.pool.bv(sig.clone());
            Unpacked {
                fmt,
                nan: ff,
                inf: ff,
                zero: ff,
                sign,
                exp,
                sig,
            }
        }
    }
}

/// Decode an IEEE interchange bit pattern, mirroring `unpacked::unpack`
/// (including its renormalization of subnormals).
pub fn decode(fmt: Format, bits: &BvConst) -> Concrete {
    let total = fmt.total_width();
    debug_assert_eq!(bits.width(), total);
    let sign = bits.bit(total - 1);
    let biased = bits.extract(total - 2, fmt.sb - 1);
    let frac = bits.extract(fmt.sb - 2, 0);
    if biased.is_ones() {
        return if frac.is_zero() {
            Concrete::Inf(sign)
        } else {
            Concrete::Nan
        };
    }
    let widen = |f: &BvConst| BvConst::from_bits(fmt.sb, |i| f.width() > i && f.bit(i));
    if biased.is_zero() {
        if frac.is_zero() {
            return Concrete::Zero(sign);
        }
        // Subnormal: value = frac * 2^(1-bias-(sb-1)); shift the leading one
        // up to the top and drop the exponent to match.
        let k = bit_len(&frac);
        let sig = widen(&frac).shl_small(fmt.sb - k);
        let exp = fmt.min_normal_exp() - (fmt.sb - k) as i64;
        return Concrete::Finite { sign, exp, sig };
    }
    let sig = BvConst::from_bits(fmt.sb, |i| i == fmt.sb - 1 || frac.bit(i));
    let exp = biased.as_u64().expect("exponent field fits in u64") as i64 - fmt.bias();
    Concrete::Finite { sign, exp, sig }
}

/// IEEE-754 `remainder`: `x - y*n` with `n` the integer nearest `x/y`, ties to
/// even. The result is always exact.
///
/// Writing `|x| = X*2^(ex-sb+1)` and `|y| = Y*2^(ey-sb+1)`, and taking
/// `A = X*2^(d+1)`, `B = 2Y` with `d = ex-ey`, we have `A/B = |x|/|y|` with
/// both sides integral as soon as `d >= -1`; `d <= -2` means `|x| < |y|/2`
/// and `n = 0`. One integer division then gives the quotient (whose parity
/// settles ties) and the remainder, and `x - y*n` is `R` or `R - B` measured
/// in units of `2^(ey-sb)`.
///
/// `None` for an exponent gap wider than the format permits, which nothing
/// `decode` produces can reach. It is there so the working width is bounded
/// by the format rather than by whatever an exponent field happens to say.
pub fn rem(fmt: Format, x: &Concrete, y: &Concrete) -> Option<Concrete> {
    use Concrete::*;
    let (sx, ex, gx, ey, gy) = match (x, y) {
        (Nan, _) | (_, Nan) | (Inf(_), _) | (_, Zero(_)) => return Some(Nan),
        // y infinite (x finite, possibly zero) and x zero both give x back.
        (_, Inf(_)) | (Zero(_), _) => return Some(x.clone()),
        (
            Finite {
                sign,
                exp: ex,
                sig: gx,
            },
            Finite {
                exp: ey, sig: gy, ..
            },
        ) => (*sign, *ex, gx, *ey, gy),
    };

    let sb = fmt.sb;
    let e = ex - ey + 1;
    if e < 0 {
        return Some(x.clone()); // |x| < |y|/2: nearest multiple of y is zero.
    }
    if e > fmt.exp_span() + 1 {
        return None;
    }
    let e = e as u32;
    let w = sb + e + 2;
    let a = gx.zero_extend(w - sb).shl_small(e);
    let bb = gy.zero_extend(w - sb).shl_small(1);
    let (q, r) = a.udivrem(&bb);

    // n = q, or q+1 when the leftover exceeds half of |y| (ties: pick the
    // even n, i.e. round up exactly when q is odd).
    let two_r = r.shl_small(1);
    let inc = bb.ult(&two_r) || (two_r == bb && q.bit(0));
    let mu = if inc { bb.sub(&r) } else { r };
    if mu.is_zero() {
        // An exact multiple: IEEE gives zero with the sign of x.
        return Some(Zero(sx));
    }
    // |mu| <= B/2 = Y < 2^sb, so the magnitude always fits the significand.
    let k = bit_len(&mu);
    debug_assert!(k <= sb);
    Some(Finite {
        sign: sx ^ inc,
        exp: (ey - sb as i64) + k as i64 - 1,
        sig: mu.extract(sb - 1, 0).shl_small(sb - k),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const F64: Format = Format { eb: 11, sb: 53 };
    const F16: Format = Format { eb: 5, sb: 11 };

    fn bits(fmt: Format, v: u64) -> BvConst {
        BvConst::from_u64(fmt.total_width(), v)
    }

    fn rem_bits(fmt: Format, x: u64, y: u64) -> Concrete {
        rem(
            fmt,
            &decode(fmt, &bits(fmt, x)),
            &decode(fmt, &bits(fmt, y)),
        )
        .expect("in-range operands")
    }

    fn as_f64(c: &Concrete) -> f64 {
        match c {
            Concrete::Zero(s) => {
                if *s {
                    -0.0
                } else {
                    0.0
                }
            }
            Concrete::Finite { sign, exp, sig } => {
                let m = sig.as_u64().unwrap() as f64;
                let v = m * (*exp as f64 - 52.0).exp2();
                if *sign {
                    -v
                } else {
                    v
                }
            }
            other => panic!("not finite: {other:?}"),
        }
    }

    #[test]
    fn specials() {
        // NaN propagates; x infinite or y zero is NaN; y infinite returns x.
        let nan = bits(F64, 0x7ff8_0000_0000_0000);
        let inf = bits(F64, 0x7ff0_0000_0000_0000);
        let one = bits(F64, 0x3ff0_0000_0000_0000);
        let d = |c: &BvConst| decode(F64, c);
        assert_eq!(rem(F64, &d(&nan), &d(&one)), Some(Concrete::Nan));
        assert_eq!(rem(F64, &d(&one), &d(&nan)), Some(Concrete::Nan));
        assert_eq!(rem(F64, &d(&inf), &d(&one)), Some(Concrete::Nan));
        assert_eq!(rem(F64, &d(&one), &d(&bits(F64, 0))), Some(Concrete::Nan));
        assert_eq!(rem(F64, &d(&one), &d(&inf)), Some(d(&one)));
        // Sign of a zero result follows x, not y.
        assert_eq!(
            rem_bits(F64, 0x4010_0000_0000_0000, 0x3ff0_0000_0000_0000),
            Concrete::Zero(false)
        );
        assert_eq!(
            rem_bits(F64, 0xc010_0000_0000_0000, 0x3ff0_0000_0000_0000),
            Concrete::Zero(true)
        );
    }

    #[test]
    fn round_to_nearest_even_quotient() {
        // 5 rem 2: x/y = 2.5, a tie; n = 2 (even), so the result is +1.
        assert_eq!(
            as_f64(&rem_bits(F64, 0x4014_0000_0000_0000, 0x4000_0000_0000_0000)),
            1.0
        );
        // 7 rem 2: x/y = 3.5, a tie; n = 4 (even), so the result is -1.
        assert_eq!(
            as_f64(&rem_bits(F64, 0x401c_0000_0000_0000, 0x4000_0000_0000_0000)),
            -1.0
        );
        // 3 rem 2: x/y = 1.5, a tie; n = 2, giving -1.
        assert_eq!(
            as_f64(&rem_bits(F64, 0x4008_0000_0000_0000, 0x4000_0000_0000_0000)),
            -1.0
        );
        // 1 rem 2: x/y = 0.5, a tie; n = 0, so the result is x itself.
        assert_eq!(
            as_f64(&rem_bits(F64, 0x3ff0_0000_0000_0000, 0x4000_0000_0000_0000)),
            1.0
        );
    }

    #[test]
    fn huge_exponent_gap() {
        // The case a staged circuit cannot reach: 2^1000 rem 3.0. With
        // 2^1000 = 3*k + 1 (1000 is even, so 2^1000 = 4^500 = 1 mod 3), the
        // remainder is exactly 1.
        let x = 0x3e70_0000_0000_0000u64 + (1000u64 << 52); // 2^1000
        assert_eq!(as_f64(&rem_bits(F64, x, 0x4008_0000_0000_0000)), 1.0);
        // 2^1001 = 2 mod 3, and 2 > 3/2, so it rounds up to -1.
        let x = x + (1u64 << 52);
        assert_eq!(as_f64(&rem_bits(F64, x, 0x4008_0000_0000_0000)), -1.0);
        // The smallest subnormal double against the largest finite one.
        let tiny = 1u64;
        let huge = 0x7fef_ffff_ffff_ffffu64;
        assert_eq!(rem_bits(F64, tiny, huge), decode(F64, &bits(F64, tiny)));
        // ... and the other way round: max_double rem min_subnormal is exact,
        // and max_double is an exact multiple of 2^-1074.
        assert_eq!(rem_bits(F64, huge, tiny), Concrete::Zero(false));
    }

    #[test]
    fn subnormal_results_stay_canonical() {
        // 3 rem 2 in units of the smallest subnormal: the quotient is exactly
        // 1.5, a tie, so n = 2 and the result is -1 unit -- subnormal, and
        // negative even though both operands are positive. It must come back
        // renormalized (leading bit set, exponent below the format minimum).
        let got = rem_bits(F16, 3, 2);
        let want = decode(F16, &bits(F16, 0x8001));
        assert_eq!(got, want);
        match got {
            Concrete::Finite { exp, ref sig, .. } => {
                assert!(sig.bit(F16.sb - 1), "significand must be normalized");
                assert!(exp < F16.min_normal_exp());
            }
            _ => panic!("expected a finite result"),
        }
    }
}
