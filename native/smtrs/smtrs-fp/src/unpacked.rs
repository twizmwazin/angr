//! Unpacked floating-point values built out of BV terms.
//!
//! Following SymFPU: a float is carried as explicit class flags plus a sign,
//! an *unbiased* signed exponent, and a significand with an explicit leading
//! one. Keeping values unpacked between operations means pack/unpack (and
//! subnormal renormalization) happens only at the boundaries, and every
//! arithmetic circuit sees a uniform normalized form.
//!
//! All fields are ordinary BV/Bool terms in the shared `TermPool`, so the
//! existing rewriter, AIG blaster and CDCL engine handle FP with no changes:
//! constant-folding an FP operation falls out of constant-folding its circuit.

use smtrs_core::{BvConst, Op, TermId, TermPool};

/// Builder helpers over the term pool (all panic on sort errors, which would
/// be construction bugs in this crate rather than user input).
pub struct B<'a> {
    pub pool: &'a mut TermPool,
}

impl B<'_> {
    pub fn mk(&mut self, op: Op, args: &[TermId]) -> TermId {
        self.pool
            .mk(op, args)
            .expect("fp lowering built an ill-sorted term")
    }

    pub fn tt(&self) -> TermId {
        self.pool.true_term
    }

    pub fn ff(&self) -> TermId {
        self.pool.false_term
    }

    pub fn not(&mut self, a: TermId) -> TermId {
        self.mk(Op::Not, &[a])
    }

    pub fn and(&mut self, args: &[TermId]) -> TermId {
        match args.len() {
            0 => self.tt(),
            1 => args[0],
            _ => self.mk(Op::And, args),
        }
    }

    pub fn or(&mut self, args: &[TermId]) -> TermId {
        match args.len() {
            0 => self.ff(),
            1 => args[0],
            _ => self.mk(Op::Or, args),
        }
    }

    pub fn ite(&mut self, c: TermId, t: TermId, e: TermId) -> TermId {
        if t == e {
            return t;
        }
        self.mk(Op::Ite, &[c, t, e])
    }

    pub fn eq(&mut self, a: TermId, b: TermId) -> TermId {
        self.mk(Op::Eq, &[a, b])
    }

    pub fn bv(&mut self, width: u32, value: u64) -> TermId {
        self.pool.bv_u64(width, value)
    }

    /// A two's-complement literal of a signed value. `unsigned_abs` rather
    /// than `-v`, so `i64::MIN` is not an overflow.
    pub fn bv_signed(&mut self, width: u32, v: i64) -> TermId {
        let c = BvConst::from_u64(width, v.unsigned_abs());
        let c = if v < 0 { c.neg() } else { c };
        self.pool.bv(c)
    }

    pub fn zeros(&mut self, width: u32) -> TermId {
        self.pool.bv(BvConst::zero(width))
    }

    pub fn ones(&mut self, width: u32) -> TermId {
        self.pool.bv(BvConst::ones(width))
    }

    pub fn width(&self, t: TermId) -> u32 {
        self.pool.width(t)
    }

    pub fn extract(&mut self, t: TermId, hi: u32, lo: u32) -> TermId {
        self.mk(Op::Extract { hi, lo }, &[t])
    }

    pub fn concat(&mut self, args: &[TermId]) -> TermId {
        if args.len() == 1 {
            return args[0];
        }
        self.mk(Op::Concat, args)
    }

    pub fn zext(&mut self, t: TermId, extra: u32) -> TermId {
        if extra == 0 {
            return t;
        }
        self.mk(Op::ZeroExtend(extra), &[t])
    }

    pub fn sext(&mut self, t: TermId, extra: u32) -> TermId {
        if extra == 0 {
            return t;
        }
        self.mk(Op::SignExtend(extra), &[t])
    }

    /// Zero/sign-extend to exactly `width` bits (no-op if already there).
    pub fn zext_to(&mut self, t: TermId, width: u32) -> TermId {
        let w = self.width(t);
        assert!(w <= width, "zext_to narrowing");
        self.zext(t, width - w)
    }

    /// Resize to exactly `width` bits, zero-extending or truncating. Used
    /// where a quantity's natural width (e.g. a shift distance derived from a
    /// significand) and the width it must be applied at differ by format.
    pub fn resize(&mut self, t: TermId, width: u32) -> TermId {
        let w = self.width(t);
        match w.cmp(&width) {
            std::cmp::Ordering::Equal => t,
            std::cmp::Ordering::Less => self.zext(t, width - w),
            std::cmp::Ordering::Greater => self.extract(t, width - 1, 0),
        }
    }

    pub fn sext_to(&mut self, t: TermId, width: u32) -> TermId {
        let w = self.width(t);
        assert!(w <= width, "sext_to narrowing");
        self.sext(t, width - w)
    }

    pub fn add(&mut self, a: TermId, b: TermId) -> TermId {
        self.mk(Op::BvAdd, &[a, b])
    }

    pub fn sub(&mut self, a: TermId, b: TermId) -> TermId {
        self.mk(Op::BvSub, &[a, b])
    }

    pub fn mul(&mut self, a: TermId, b: TermId) -> TermId {
        self.mk(Op::BvMul, &[a, b])
    }

    pub fn neg(&mut self, a: TermId) -> TermId {
        self.mk(Op::BvNeg, &[a])
    }

    pub fn bvand(&mut self, a: TermId, b: TermId) -> TermId {
        self.mk(Op::BvAnd, &[a, b])
    }

    pub fn bvor(&mut self, a: TermId, b: TermId) -> TermId {
        self.mk(Op::BvOr, &[a, b])
    }

    pub fn shl(&mut self, a: TermId, b: TermId) -> TermId {
        self.mk(Op::BvShl, &[a, b])
    }

    pub fn lshr(&mut self, a: TermId, b: TermId) -> TermId {
        self.mk(Op::BvLshr, &[a, b])
    }

    pub fn ult(&mut self, a: TermId, b: TermId) -> TermId {
        self.mk(Op::BvUlt, &[a, b])
    }

    pub fn ule(&mut self, a: TermId, b: TermId) -> TermId {
        self.mk(Op::BvUle, &[a, b])
    }

    pub fn slt(&mut self, a: TermId, b: TermId) -> TermId {
        self.mk(Op::BvSlt, &[a, b])
    }

    pub fn sle(&mut self, a: TermId, b: TermId) -> TermId {
        self.mk(Op::BvSle, &[a, b])
    }

    pub fn is_zero_bv(&mut self, a: TermId) -> TermId {
        let z = self.zeros(self.width(a));
        self.eq(a, z)
    }

    pub fn is_all_ones(&mut self, a: TermId) -> TermId {
        let o = self.ones(self.width(a));
        self.eq(a, o)
    }

    /// Bool -> 1-bit BV.
    pub fn bool_to_bv1(&mut self, b: TermId) -> TermId {
        let one = self.bv(1, 1);
        let zero = self.bv(1, 0);
        self.ite(b, one, zero)
    }

    /// 1-bit BV -> Bool.
    pub fn bv1_to_bool(&mut self, t: TermId) -> TermId {
        let one = self.bv(1, 1);
        self.eq(t, one)
    }

    /// Count leading zeros of `t` as a BV of the same width (used to
    /// renormalize subnormals and post-subtraction cancellation).
    pub fn clz(&mut self, t: TermId) -> TermId {
        // Binary-search mux tree, not the old linear chain of full-width
        // adders (w sequential w-bit additions: ~w^2 gates at ripple depth,
        // which for the f64 adder's 56-bit working word dominated every
        // FP operation's encoding). Here: is the top half zero? That is the
        // count's next-most-significant bit; then recurse into whichever half
        // holds the leading one. Linear gates, logarithmic depth, and the
        // count assembles by concatenation — no adders at all.
        //
        // The recursion's invariant is a non-zero word (each selected half
        // then really contains the leading one, so every level's sub-count
        // stays below its half width and the concatenation is exact). Padding
        // the *low* end with ones up to a power of two establishes it for
        // free: ones below `t` add no leading zeros, and an all-zero `t`
        // stops the count exactly at the pad boundary, i.e. at w.
        let w = self.width(t);
        let wp = (w + 1).next_power_of_two().max(2);
        let ones = {
            let z = self.zeros(wp - w);
            self.mk(Op::BvNot, &[z])
        };
        let padded = self.mk(Op::Concat, &[t, ones]);
        let cnt = self.clz_nonzero(padded);
        self.resize(cnt, w)
    }

    /// Leading-zero count of a power-of-two-width, provably non-zero word,
    /// in `log2(width)` bits. See [`Self::clz`].
    fn clz_nonzero(&mut self, t: TermId) -> TermId {
        let w = self.width(t);
        debug_assert!(w.is_power_of_two() && w >= 2);
        let hi = self.extract(t, w - 1, w / 2);
        if w == 2 {
            // One bit left: the count is 1 exactly when the top bit is 0.
            let one = self.bv(1, 1);
            return self.mk(Op::BvXor, &[hi, one]);
        }
        let lo = self.extract(t, w / 2 - 1, 0);
        let hi_zero = self.is_zero_bv(hi);
        let sel = self.ite(hi_zero, lo, hi);
        let rest = self.clz_nonzero(sel);
        let one = self.bv(1, 1);
        let zero = self.bv(1, 0);
        let top = self.ite(hi_zero, one, zero);
        self.mk(Op::Concat, &[top, rest])
    }
}

/// The IEEE-754 interchange format: `eb` exponent bits, `sb` significand bits
/// *including* the hidden bit (SMT-LIB's `(_ FloatingPoint eb sb)`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Format {
    pub eb: u32,
    pub sb: u32,
}

impl Format {
    pub fn total_width(&self) -> u32 {
        self.eb + self.sb
    }

    pub fn bias(&self) -> i64 {
        (1i64 << (self.eb - 1)) - 1
    }

    /// Smallest/largest unbiased exponents of *normal* numbers.
    pub fn min_normal_exp(&self) -> i64 {
        1 - self.bias()
    }

    pub fn max_normal_exp(&self) -> i64 {
        self.bias()
    }

    /// Lowest exponent an `Unpacked` can carry: the smallest subnormal, after
    /// the renormalization `unpack` applies to it.
    pub fn min_unpacked_exp(&self) -> i64 {
        self.min_normal_exp() - (self.sb as i64 - 1)
    }

    /// Widest possible gap between two exponents in this format. `fp.rem`
    /// needs one reduction stage per unit of gap, so this is what decides
    /// whether it can be encoded as a circuit at all.
    pub fn exp_span(&self) -> i64 {
        self.max_normal_exp() - self.min_unpacked_exp()
    }

    /// Working width for exponents: wide enough that products and the
    /// subnormal shift distance cannot overflow.
    pub fn exp_width(&self) -> u32 {
        self.eb + self.sb.next_power_of_two().trailing_zeros() + 4
    }
}

/// A floating-point value in unpacked form. `exp` is a signed (two's
/// complement) unbiased exponent of width `Format::exp_width`; `sig` has an
/// explicit leading one at its top bit for all non-special values.
#[derive(Clone, Copy)]
pub struct Unpacked {
    pub fmt: Format,
    /// Class flags (Bool terms). Exactly one of nan/inf/zero may hold.
    pub nan: TermId,
    pub inf: TermId,
    pub zero: TermId,
    /// Sign (Bool term): true = negative.
    pub sign: TermId,
    pub exp: TermId,
    pub sig: TermId,
}

impl Unpacked {
    /// Is this a "real" (finite, non-zero) value?
    pub fn is_finite_nonzero(&self, b: &mut B) -> TermId {
        let specials = b.or(&[self.nan, self.inf, self.zero]);
        b.not(specials)
    }
}

/// Build the canonical NaN of a format.
pub fn make_nan(b: &mut B, fmt: Format) -> Unpacked {
    let t = b.tt();
    let f = b.ff();
    let exp = b.zeros(fmt.exp_width());
    let sig = b.zeros(fmt.sb);
    Unpacked {
        fmt,
        nan: t,
        inf: f,
        zero: f,
        sign: f,
        exp,
        sig,
    }
}

pub fn make_inf(b: &mut B, fmt: Format, sign: TermId) -> Unpacked {
    let t = b.tt();
    let f = b.ff();
    let exp = b.zeros(fmt.exp_width());
    let sig = b.zeros(fmt.sb);
    Unpacked {
        fmt,
        nan: f,
        inf: t,
        zero: f,
        sign,
        exp,
        sig,
    }
}

pub fn make_zero(b: &mut B, fmt: Format, sign: TermId) -> Unpacked {
    let t = b.tt();
    let f = b.ff();
    let exp = b.zeros(fmt.exp_width());
    let sig = b.zeros(fmt.sb);
    Unpacked {
        fmt,
        nan: f,
        inf: f,
        zero: t,
        sign,
        exp,
        sig,
    }
}

/// Select between two unpacked values.
pub fn ite_unpacked(b: &mut B, c: TermId, x: &Unpacked, y: &Unpacked) -> Unpacked {
    debug_assert_eq!(x.fmt, y.fmt);
    Unpacked {
        fmt: x.fmt,
        nan: b.ite(c, x.nan, y.nan),
        inf: b.ite(c, x.inf, y.inf),
        zero: b.ite(c, x.zero, y.zero),
        sign: b.ite(c, x.sign, y.sign),
        exp: b.ite(c, x.exp, y.exp),
        sig: b.ite(c, x.sig, y.sig),
    }
}

/// Unpack an IEEE bit pattern (width `eb + sb`) into the working form.
pub fn unpack(b: &mut B, fmt: Format, bits: TermId) -> Unpacked {
    let total = fmt.total_width();
    debug_assert_eq!(b.width(bits), total);
    let sign_bit = b.extract(bits, total - 1, total - 1);
    let sign = b.bv1_to_bool(sign_bit);
    let biased_exp = b.extract(bits, total - 2, fmt.sb - 1);
    let sig_field = b.extract(bits, fmt.sb - 2, 0); // sb-1 bits

    let exp_all_ones = b.is_all_ones(biased_exp);
    let exp_zero = b.is_zero_bv(biased_exp);
    let sig_zero = b.is_zero_bv(sig_field);

    let nan = {
        let nz = b.not(sig_zero);
        b.and(&[exp_all_ones, nz])
    };
    let inf = b.and(&[exp_all_ones, sig_zero]);
    let zero = b.and(&[exp_zero, sig_zero]);
    let subnormal = {
        let nz = b.not(sig_zero);
        b.and(&[exp_zero, nz])
    };

    let ew = fmt.exp_width();
    // Normal: exponent = biased - bias, significand = 1 . field
    let normal_exp = {
        let e = b.zext_to(biased_exp, ew);
        let bias = b.bv(ew, fmt.bias() as u64);
        b.sub(e, bias)
    };
    let one_bit = b.bv(1, 1);
    let normal_sig = b.concat(&[one_bit, sig_field]);

    // Subnormal: value is 0.field * 2^(1-bias); renormalize by shifting the
    // leading one up to the top, decrementing the exponent accordingly.
    let zero_bit = b.bv(1, 0);
    let sub_sig_raw = b.concat(&[zero_bit, sig_field]); // sb bits, leading 0
    let shift = b.clz(sub_sig_raw); // >= 1 for subnormals
    let sub_sig = b.shl(sub_sig_raw, shift);
    let sub_exp = {
        let base = b.bv_signed(ew, fmt.min_normal_exp()); // 1 - bias (two's compl.)
        let sh = b.resize(shift, ew);
        b.sub(base, sh)
    };

    let exp = b.ite(subnormal, sub_exp, normal_exp);
    let sig = b.ite(subnormal, sub_sig, normal_sig);
    Unpacked {
        fmt,
        nan,
        inf,
        zero,
        sign,
        exp,
        sig,
    }
}

/// Pack a *rounded* unpacked value back into an IEEE bit pattern. The input
/// must already be representable: exponent in range and significand rounded
/// to `sb` bits (this is what `round::round` produces).
pub fn pack(b: &mut B, x: &Unpacked) -> TermId {
    let fmt = x.fmt;
    let ew = fmt.exp_width();
    let sign_bit = b.bool_to_bv1(x.sign);

    // Finite path. Two kinds of value can arrive here: one straight from the
    // rounder, which has already applied gradual underflow (subnormals come
    // with their leading bit cleared and exponent pinned at the minimum), and
    // one straight from `unpack`, where subnormals were *renormalized* (leading
    // bit set, exponent below the minimum). Both are handled by shifting by
    // `1 - biased` whenever the encoding is not a normal one.
    let bias = b.bv(ew, fmt.bias() as u64);
    let biased = b.add(x.exp, bias);
    let lead = b.extract(x.sig, fmt.sb - 1, fmt.sb - 1);
    let lead_set = b.bv1_to_bool(lead);
    let one = b.bv(ew, 1);
    let in_normal_range = b.sle(one, biased);
    let is_normal = b.and(&[lead_set, in_normal_range]);

    let shift = b.sub(one, biased);
    let shift_sig = b.resize(shift, fmt.sb);
    let denormalized = b.lshr(x.sig, shift_sig);

    let exp_field_normal = b.extract(biased, fmt.eb - 1, 0);
    let exp_field_sub = b.zeros(fmt.eb);
    let exp_field = b.ite(is_normal, exp_field_normal, exp_field_sub);

    let sig_norm = b.extract(x.sig, fmt.sb - 2, 0);
    let sig_sub = b.extract(denormalized, fmt.sb - 2, 0);
    let sig_field = b.ite(is_normal, sig_norm, sig_sub);

    let finite = b.concat(&[sign_bit, exp_field, sig_field]);

    // Specials override.
    let ones_exp = b.ones(fmt.eb);
    let zero_sig = b.zeros(fmt.sb - 1);
    let inf_bits = b.concat(&[sign_bit, ones_exp, zero_sig]);
    let zero_bits = {
        let ze = b.zeros(fmt.eb);
        b.concat(&[sign_bit, ze, zero_sig])
    };
    // Canonical quiet NaN: sign 0, exponent all ones, MSB of trailing field 1.
    let nan_bits = {
        let s = b.bv(1, 0);
        let e = b.ones(fmt.eb);
        let top = b.bv(1, 1);
        let rest = b.zeros(fmt.sb - 2);
        b.concat(&[s, e, top, rest])
    };

    let r = b.ite(x.zero, zero_bits, finite);
    let r = b.ite(x.inf, inf_bits, r);
    b.ite(x.nan, nan_bits, r)
}

#[cfg(test)]
mod clz_tests {
    use super::*;
    use smtrs_core::{TermPool, eval};

    /// Exhaustive against the arithmetic definition, across widths that cover
    /// the padding cases (already power-of-two, one below, odd) and every
    /// value including zero — where the count must be exactly the width.
    #[test]
    fn clz_matches_reference_exhaustively() {
        for w in 1..=11u32 {
            let mut pool = TermPool::new();
            let mut b = B { pool: &mut pool };
            for v in 0..(1u64 << w) {
                let t = b.bv(w, v);
                let c = b.clz(t);
                let vals = eval(b.pool, &[c], &Default::default()).expect("constant clz");
                let got = vals[0].as_bv().and_then(|c| c.as_u64()).expect("bv");
                let expected = if v == 0 {
                    u64::from(w)
                } else {
                    u64::from(w) - (64 - u64::from(v.leading_zeros()))
                };
                assert_eq!(got, expected, "clz({v:#b}) at width {w}");
            }
        }
    }
}
