//! Arbitrary-width bit-vector constants with SMT-LIB semantics.
//!
//! Little-endian u64 limbs; bits above `width` in the top limb are always zero
//! (the canonical form all constructors and operations maintain). This type is
//! both the constant representation in the term DAG and the value domain of
//! the model evaluator, so the operations here define our ground-truth
//! semantics for every BV operator.

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct BvConst {
    width: u32,
    limbs: Box<[u64]>,
}

fn limb_count(width: u32) -> usize {
    (width as usize).div_ceil(64)
}

impl BvConst {
    pub fn zero(width: u32) -> Self {
        assert!(width > 0, "zero-width bit-vector");
        BvConst {
            width,
            limbs: vec![0; limb_count(width)].into(),
        }
    }

    pub fn ones(width: u32) -> Self {
        let mut c = Self::zero(width);
        for l in c.limbs.iter_mut() {
            *l = u64::MAX;
        }
        c.normalize();
        c
    }

    pub fn from_u64(width: u32, value: u64) -> Self {
        let mut c = Self::zero(width);
        c.limbs[0] = value;
        c.normalize();
        c
    }

    /// Parse a decimal string (e.g. from `(_ bv123 32)`), reducing mod 2^width.
    pub fn from_decimal(width: u32, digits: &str) -> Option<Self> {
        // `(_ bvN w)` takes its width from the input, so validate it here as
        // `from_binary_str` and `from_hex_str` already do — `zero` asserts.
        if width == 0 || width > crate::pool::MAX_BV_WIDTH {
            return None;
        }
        let mut c = Self::zero(width);
        for b in digits.bytes() {
            let d = (b as char).to_digit(10)?;
            c = c.checked_scale_add(10, d as u64);
        }
        Some(c)
    }

    /// value * scale + add, reduced mod 2^width.
    fn checked_scale_add(&self, scale: u64, add: u64) -> Self {
        let mut out = Self::zero(self.width);
        let mut carry: u128 = add as u128;
        for (i, &l) in self.limbs.iter().enumerate() {
            let v = l as u128 * scale as u128 + carry;
            out.limbs[i] = v as u64;
            carry = v >> 64;
        }
        out.normalize();
        out
    }

    /// Build from a per-bit predicate (bit 0 = LSB).
    pub fn from_bits(width: u32, mut bit: impl FnMut(u32) -> bool) -> Self {
        let mut c = Self::zero(width);
        for i in 0..width {
            if bit(i) {
                c.limbs[i as usize / 64] |= 1u64 << (i % 64);
            }
        }
        c
    }

    /// Parse `#b...` binary literal (without the `#b` prefix).
    pub fn from_binary_str(bits: &str) -> Option<Self> {
        let width = u32::try_from(bits.len()).ok()?;
        if width == 0 {
            return None;
        }
        let mut c = Self::zero(width);
        for (i, b) in bits.bytes().rev().enumerate() {
            match b {
                b'0' => {}
                b'1' => c.limbs[i / 64] |= 1u64 << (i % 64),
                _ => return None,
            }
        }
        Some(c)
    }

    /// Parse `#x...` hex literal (without the `#x` prefix).
    pub fn from_hex_str(hex: &str) -> Option<Self> {
        let width = u32::try_from(hex.len()).ok()?.checked_mul(4)?;
        if width == 0 {
            return None;
        }
        let mut c = Self::zero(width);
        for (i, b) in hex.bytes().rev().enumerate() {
            let d = (b as char).to_digit(16)? as u64;
            let bit = i * 4;
            c.limbs[bit / 64] |= d << (bit % 64);
            // A nibble can straddle a limb boundary only when 64 % 4 != 0 — it can't.
        }
        Some(c)
    }

    pub fn width(&self) -> u32 {
        self.width
    }

    pub fn limbs(&self) -> &[u64] {
        &self.limbs
    }

    pub fn bit(&self, i: u32) -> bool {
        debug_assert!(i < self.width);
        (self.limbs[i as usize / 64] >> (i % 64)) & 1 == 1
    }

    pub fn is_zero(&self) -> bool {
        self.limbs.iter().all(|&l| l == 0)
    }

    pub fn is_ones(&self) -> bool {
        *self == Self::ones(self.width)
    }

    pub fn is_one(&self) -> bool {
        self.limbs[0] == 1 && self.limbs[1..].iter().all(|&l| l == 0)
    }

    /// Value as u64 if it fits.
    pub fn as_u64(&self) -> Option<u64> {
        if self.limbs[1..].iter().all(|&l| l == 0) {
            Some(self.limbs[0])
        } else {
            None
        }
    }

    pub fn sign_bit(&self) -> bool {
        self.bit(self.width - 1)
    }

    fn normalize(&mut self) {
        let rem = self.width % 64;
        if rem != 0 {
            let last = self.limbs.len() - 1;
            self.limbs[last] &= (1u64 << rem) - 1;
        }
    }

    // ---- arithmetic ----

    pub fn add(&self, rhs: &Self) -> Self {
        debug_assert_eq!(self.width, rhs.width);
        let mut out = Self::zero(self.width);
        let mut carry = 0u64;
        for i in 0..self.limbs.len() {
            let (s1, c1) = self.limbs[i].overflowing_add(rhs.limbs[i]);
            let (s2, c2) = s1.overflowing_add(carry);
            out.limbs[i] = s2;
            carry = (c1 as u64) + (c2 as u64);
        }
        out.normalize();
        out
    }

    pub fn neg(&self) -> Self {
        self.not().add(&Self::from_u64(self.width, 1))
    }

    pub fn sub(&self, rhs: &Self) -> Self {
        self.add(&rhs.neg())
    }

    pub fn mul(&self, rhs: &Self) -> Self {
        debug_assert_eq!(self.width, rhs.width);
        let n = self.limbs.len();
        let mut acc = vec![0u64; n];
        for i in 0..n {
            if self.limbs[i] == 0 {
                continue;
            }
            let mut carry: u128 = 0;
            for j in 0..n - i {
                let v = self.limbs[i] as u128 * rhs.limbs[j] as u128 + acc[i + j] as u128 + carry;
                acc[i + j] = v as u64;
                carry = v >> 64;
            }
        }
        let mut out = BvConst {
            width: self.width,
            limbs: acc.into(),
        };
        out.normalize();
        out
    }

    /// (quotient, remainder) of unsigned division; SMT-LIB total semantics for
    /// division by zero: udiv -> all ones, urem -> dividend.
    pub fn udivrem(&self, rhs: &Self) -> (Self, Self) {
        debug_assert_eq!(self.width, rhs.width);
        if rhs.is_zero() {
            return (Self::ones(self.width), self.clone());
        }
        if let (Some(a), Some(b)) = (self.as_u64(), rhs.as_u64()) {
            return (
                Self::from_u64(self.width, a / b),
                Self::from_u64(self.width, a % b),
            );
        }
        // Bit-serial restoring division for multi-limb values.
        let mut quot = Self::zero(self.width);
        let mut rem = Self::zero(self.width);
        for i in (0..self.width).rev() {
            rem = rem.shl_small(1);
            if self.bit(i) {
                rem.limbs[0] |= 1;
            }
            if rem.uge(rhs) {
                rem = rem.sub(rhs);
                quot.limbs[i as usize / 64] |= 1u64 << (i % 64);
            }
        }
        (quot, rem)
    }

    pub fn udiv(&self, rhs: &Self) -> Self {
        self.udivrem(rhs).0
    }

    pub fn urem(&self, rhs: &Self) -> Self {
        self.udivrem(rhs).1
    }

    /// SMT-LIB bvsdiv (round toward zero), defined via unsigned division on
    /// magnitudes; division by zero follows from bvudiv's totalization:
    /// non-negative / 0 = -1, negative / 0 = 1.
    pub fn sdiv(&self, rhs: &Self) -> Self {
        let (na, nb) = (self.sign_bit(), rhs.sign_bit());
        let a = if na { self.neg() } else { self.clone() };
        let b = if nb { rhs.neg() } else { rhs.clone() };
        let q = a.udiv(&b);
        if na != nb {
            q.neg()
        } else {
            q
        }
    }

    /// SMT-LIB bvsrem: remainder with sign of the dividend. x srem 0 = x.
    pub fn srem(&self, rhs: &Self) -> Self {
        let (na, nb) = (self.sign_bit(), rhs.sign_bit());
        let a = if na { self.neg() } else { self.clone() };
        let b = if nb { rhs.neg() } else { rhs.clone() };
        let r = a.urem(&b);
        if na {
            r.neg()
        } else {
            r
        }
    }

    /// SMT-LIB bvsmod: remainder with sign of the divisor. x smod 0 = x.
    pub fn smod(&self, rhs: &Self) -> Self {
        if rhs.is_zero() {
            return self.clone();
        }
        let r = self.srem(rhs);
        if r.is_zero() || r.sign_bit() == rhs.sign_bit() {
            r
        } else {
            r.add(rhs)
        }
    }

    // ---- bitwise ----

    pub fn not(&self) -> Self {
        let mut out = self.clone();
        for l in out.limbs.iter_mut() {
            *l = !*l;
        }
        out.normalize();
        out
    }

    pub fn and(&self, rhs: &Self) -> Self {
        self.zip(rhs, |a, b| a & b)
    }

    pub fn or(&self, rhs: &Self) -> Self {
        self.zip(rhs, |a, b| a | b)
    }

    pub fn xor(&self, rhs: &Self) -> Self {
        self.zip(rhs, |a, b| a ^ b)
    }

    fn zip(&self, rhs: &Self, f: impl Fn(u64, u64) -> u64) -> Self {
        debug_assert_eq!(self.width, rhs.width);
        let mut out = self.clone();
        for (o, &r) in out.limbs.iter_mut().zip(rhs.limbs.iter()) {
            *o = f(*o, r);
        }
        out.normalize();
        out
    }

    // ---- shifts (symbolic amount: rhs is a BvConst of the same width) ----

    fn shift_amount(&self, rhs: &Self) -> Option<u32> {
        // Amount >= width means the shift saturates; report None.
        match rhs.as_u64() {
            Some(v) if v < self.width as u64 => Some(v as u32),
            _ => None,
        }
    }

    pub fn shl(&self, rhs: &Self) -> Self {
        match self.shift_amount(rhs) {
            Some(n) => self.shl_small(n),
            None => Self::zero(self.width),
        }
    }

    pub fn lshr(&self, rhs: &Self) -> Self {
        match self.shift_amount(rhs) {
            Some(n) => self.lshr_small(n),
            None => Self::zero(self.width),
        }
    }

    pub fn ashr(&self, rhs: &Self) -> Self {
        let sign = self.sign_bit();
        match self.shift_amount(rhs) {
            Some(n) => {
                let mut out = self.lshr_small(n);
                if sign && n > 0 {
                    // Fill the top n bits with ones.
                    for i in self.width - n..self.width {
                        out.limbs[i as usize / 64] |= 1u64 << (i % 64);
                    }
                }
                out
            }
            None => {
                if sign {
                    Self::ones(self.width)
                } else {
                    Self::zero(self.width)
                }
            }
        }
    }

    pub fn shl_small(&self, n: u32) -> Self {
        debug_assert!(n <= self.width);
        let mut out = Self::zero(self.width);
        let limb_shift = (n / 64) as usize;
        let bit_shift = n % 64;
        for i in (limb_shift..self.limbs.len()).rev() {
            let mut v = self.limbs[i - limb_shift] << bit_shift;
            if bit_shift > 0 && i > limb_shift {
                v |= self.limbs[i - limb_shift - 1] >> (64 - bit_shift);
            }
            out.limbs[i] = v;
        }
        out.normalize();
        out
    }

    pub fn lshr_small(&self, n: u32) -> Self {
        debug_assert!(n <= self.width);
        let mut out = Self::zero(self.width);
        let limb_shift = (n / 64) as usize;
        let bit_shift = n % 64;
        for i in 0..self.limbs.len() - limb_shift {
            let mut v = self.limbs[i + limb_shift] >> bit_shift;
            if bit_shift > 0 && i + limb_shift + 1 < self.limbs.len() {
                v |= self.limbs[i + limb_shift + 1] << (64 - bit_shift);
            }
            out.limbs[i] = v;
        }
        out
    }

    pub fn rotate_left(&self, n: u32) -> Self {
        let n = n % self.width;
        if n == 0 {
            return self.clone();
        }
        self.shl_small(n).or(&self.lshr_small(self.width - n))
    }

    pub fn rotate_right(&self, n: u32) -> Self {
        self.rotate_left(self.width - n % self.width)
    }

    // ---- structural ----

    /// self is the high part: `concat self rhs`.
    pub fn concat(&self, rhs: &Self) -> Self {
        let width = self.width + rhs.width;
        let mut out = Self::zero(width);
        out.limbs[..rhs.limbs.len()].copy_from_slice(&rhs.limbs);
        // OR in self shifted left by rhs.width.
        let limb_shift = (rhs.width / 64) as usize;
        let bit_shift = rhs.width % 64;
        for (i, &l) in self.limbs.iter().enumerate() {
            out.limbs[i + limb_shift] |= l << bit_shift;
            if bit_shift > 0 && l >> (64 - bit_shift) != 0 {
                out.limbs[i + limb_shift + 1] |= l >> (64 - bit_shift);
            }
        }
        out.normalize();
        out
    }

    pub fn extract(&self, hi: u32, lo: u32) -> Self {
        debug_assert!(hi >= lo && hi < self.width);
        let width = hi - lo + 1;
        let shifted = self.lshr_small(lo);
        let mut out = Self::zero(width);
        let n = out.limbs.len();
        out.limbs[..n].copy_from_slice(&shifted.limbs[..n]);
        out.normalize();
        out
    }

    pub fn zero_extend(&self, extra: u32) -> Self {
        let mut out = Self::zero(self.width + extra);
        out.limbs[..self.limbs.len()].copy_from_slice(&self.limbs);
        out
    }

    pub fn sign_extend(&self, extra: u32) -> Self {
        let mut out = self.zero_extend(extra);
        if self.sign_bit() {
            for i in self.width..self.width + extra {
                out.limbs[i as usize / 64] |= 1u64 << (i % 64);
            }
        }
        out
    }

    pub fn repeat(&self, times: u32) -> Self {
        let mut out = self.clone();
        for _ in 1..times {
            out = out.concat(self);
        }
        out
    }

    // ---- comparisons ----

    pub fn ult(&self, rhs: &Self) -> bool {
        debug_assert_eq!(self.width, rhs.width);
        for i in (0..self.limbs.len()).rev() {
            if self.limbs[i] != rhs.limbs[i] {
                return self.limbs[i] < rhs.limbs[i];
            }
        }
        false
    }

    pub fn ule(&self, rhs: &Self) -> bool {
        !rhs.ult(self)
    }

    pub fn uge(&self, rhs: &Self) -> bool {
        !self.ult(rhs)
    }

    pub fn slt(&self, rhs: &Self) -> bool {
        match (self.sign_bit(), rhs.sign_bit()) {
            (true, false) => true,
            (false, true) => false,
            _ => self.ult(rhs),
        }
    }

    pub fn sle(&self, rhs: &Self) -> bool {
        !rhs.slt(self)
    }

    /// Render as `#b...` binary literal.
    pub fn to_binary_string(&self) -> String {
        let mut s = String::with_capacity(self.width as usize + 2);
        s.push_str("#b");
        for i in (0..self.width).rev() {
            s.push(if self.bit(i) { '1' } else { '0' });
        }
        s
    }
}

impl std::fmt::Display for BvConst {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_binary_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bv(width: u32, v: u64) -> BvConst {
        BvConst::from_u64(width, v)
    }

    #[test]
    fn parse_and_print() {
        let c = BvConst::from_binary_str("1011").unwrap();
        assert_eq!(c.width(), 4);
        assert_eq!(c.as_u64(), Some(11));
        assert_eq!(c.to_binary_string(), "#b1011");
        let h = BvConst::from_hex_str("deadBEEF").unwrap();
        assert_eq!(h.width(), 32);
        assert_eq!(h.as_u64(), Some(0xdead_beef));
        let d = BvConst::from_decimal(8, "300").unwrap();
        assert_eq!(d.as_u64(), Some(300 % 256));
    }

    #[test]
    fn arithmetic_wraps() {
        assert_eq!(bv(8, 200).add(&bv(8, 100)).as_u64(), Some(44));
        assert_eq!(bv(8, 3).sub(&bv(8, 5)).as_u64(), Some(254));
        assert_eq!(bv(8, 16).mul(&bv(8, 17)).as_u64(), Some(16));
        assert_eq!(bv(8, 0).neg().as_u64(), Some(0));
        assert_eq!(bv(8, 1).neg().as_u64(), Some(255));
    }

    #[test]
    fn division_semantics() {
        // Division by zero: udiv -> all ones, urem -> dividend.
        assert_eq!(bv(8, 7).udiv(&bv(8, 0)).as_u64(), Some(255));
        assert_eq!(bv(8, 7).urem(&bv(8, 0)).as_u64(), Some(7));
        // Signed: -7 sdiv 2 = -3 (round toward zero), -7 srem 2 = -1.
        let m7 = bv(8, 7).neg();
        assert_eq!(m7.sdiv(&bv(8, 2)), bv(8, 3).neg());
        assert_eq!(m7.srem(&bv(8, 2)), bv(8, 1).neg());
        // smod takes divisor's sign: -7 smod 2 = 1.
        assert_eq!(m7.smod(&bv(8, 2)).as_u64(), Some(1));
        // sdiv by zero: non-negative -> -1, negative -> 1.
        assert_eq!(bv(8, 5).sdiv(&bv(8, 0)).as_u64(), Some(255));
        assert_eq!(m7.sdiv(&bv(8, 0)).as_u64(), Some(1));
        // INT_MIN / -1 wraps to INT_MIN.
        let int_min = bv(8, 0x80);
        assert_eq!(int_min.sdiv(&bv(8, 1).neg()), int_min);
    }

    #[test]
    fn multilimb_division() {
        let a = BvConst::from_hex_str("ffffffffffffffffffffffffffffffff").unwrap(); // 2^128-1
        let b = BvConst::from_u64(128, 3);
        let (q, r) = a.udivrem(&b);
        assert_eq!(r.as_u64(), Some(0));
        assert_eq!(q.mul(&b), a);
    }

    #[test]
    fn shifts() {
        assert_eq!(bv(8, 0b1101).shl(&bv(8, 2)).as_u64(), Some(0b110100));
        assert_eq!(bv(8, 0b1101).lshr(&bv(8, 2)).as_u64(), Some(0b11));
        assert_eq!(bv(8, 0x84).ashr(&bv(8, 2)).as_u64(), Some(0xe1));
        // Shift >= width saturates.
        assert_eq!(bv(8, 0xff).shl(&bv(8, 8)).as_u64(), Some(0));
        assert_eq!(bv(8, 0x80).ashr(&bv(8, 200)).as_u64(), Some(0xff));
        // Multi-limb shifts.
        let x = BvConst::from_u64(128, 1);
        assert_eq!(
            x.shl(&BvConst::from_u64(128, 100))
                .extract(100, 100)
                .as_u64(),
            Some(1)
        );
    }

    #[test]
    fn structural() {
        let hi = bv(4, 0b1010);
        let lo = bv(8, 0xff);
        let c = hi.concat(&lo);
        assert_eq!(c.width(), 12);
        assert_eq!(c.as_u64(), Some(0xaff));
        assert_eq!(c.extract(11, 8), hi);
        assert_eq!(c.extract(7, 0), lo);
        assert_eq!(bv(4, 0b1010).sign_extend(4).as_u64(), Some(0xfa));
        assert_eq!(bv(4, 0b1010).zero_extend(4).as_u64(), Some(0x0a));
        assert_eq!(bv(4, 0b0110).rotate_left(1).as_u64(), Some(0b1100));
        assert_eq!(bv(4, 0b0110).rotate_right(1).as_u64(), Some(0b0011));
        assert_eq!(bv(2, 0b10).repeat(3).as_u64(), Some(0b101010));
        // Concat across limb boundaries.
        let a = BvConst::from_u64(60, u64::MAX >> 4);
        let b = BvConst::from_u64(60, 0);
        let cc = a.concat(&b);
        assert_eq!(cc.width(), 120);
        assert_eq!(cc.extract(119, 60), a);
    }

    #[test]
    fn comparisons() {
        assert!(bv(8, 3).ult(&bv(8, 200)));
        assert!(bv(8, 200).slt(&bv(8, 3))); // 200 is negative as i8
        assert!(bv(8, 3).sle(&bv(8, 3)));
        let a = BvConst::from_hex_str("00000000000000010000000000000000").unwrap();
        let b = BvConst::from_hex_str("00000000000000000000000000000001").unwrap();
        assert!(b.ult(&a));
    }
}
