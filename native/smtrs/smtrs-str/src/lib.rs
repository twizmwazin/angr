//! smtrs-str: strings by bounded-length reduction to bit-vectors.
//!
//! A string is represented as a length plus a fixed array of character slots,
//! all ordinary BV terms, so the existing pipeline solves string constraints
//! with no further changes. Regular expressions are compiled to an NFA
//! (Thompson construction) whose acceptance over the bounded string is encoded
//! as a per-position state vector.
//!
//! **Soundness under bounding.** The encoding only explores strings up to
//! `max_len`, so `sat` is always backed by a real model, while `unsat` in
//! general only means "no model of bounded length". [`bounds`] decides when the
//! bound provably excludes nothing — see its module docs for the argument —
//! and `lower` reports that decision as [`Lowered::unsat_trustworthy`], so the
//! solver can pass a real `unsat` through instead of conceding `unknown`.
//!
//! **When no bound exists.** [`length`] is the other way to a real `unsat`: it
//! throws the characters away entirely and reasons about how *long* the strings
//! are, which needs no bound because it never has to represent a string. It is
//! an over-approximation, so it only ever answers `unsat`, and the solver
//! consults it only on paths already headed for `unknown`.

mod analysis;
pub mod bounds;
pub mod length;
mod regex;

use rustc_hash::FxHashMap;
use smtrs_core::{BvConst, Op, Sort, SymbolId, TermId, TermPool};

/// Character slots per string. Strings longer than this are not explored.
pub const DEFAULT_MAX_LEN: u32 = 16;

/// Bound a problem may always be raised to, whatever it costs (see
/// [`required_bound`]). Encoding cost grows quadratically in the slot count —
/// `str.++` builds an `ite` chain per output slot — so past here the raise has
/// to be earned; see [`affordable_bound`].
pub const MAX_AUTO_LEN: u32 = 64;

/// Ceiling on the earned raise. Regex membership is linear in the slot count,
/// so a regex-only problem could in principle go much higher, but the *string*
/// variables it constrains cost `max_len` character variables each and the
/// benefit tails off fast: the long-literal benchmarks that convert here need
/// 65-256 slots, and nothing measured beyond that converted before it timed
/// out.
pub const HARD_MAX_LEN: u32 = 256;

/// Slot-work the quadratic constructs may spend between them, in units of
/// `max_len` slots squared. Calibrated so that a problem with a handful of
/// concatenations still reaches a 150-200 slot bound, while the
/// concatenation-heavy families (thousands of joins, tens of gigabytes at 256
/// slots) stay exactly where they are today.
const QUADRATIC_SLOT_BUDGET: u64 = 250_000;

/// Bits used for lengths and integer results (str.len, str.indexof, ...).
const INT_BITS: u32 = 16;
const INT_MASK: u64 = (1u64 << INT_BITS) - 1;
const CHAR_BITS: u32 = 8;

/// Integers are `INT_BITS` wide and compared signed (`str.indexof` and
/// `str.to_int` both return -1), so the representable numeric range is
/// `-2^(INT_BITS-1) ..= INT_MAX`.
const INT_MAX: u64 = (1u64 << (INT_BITS - 1)) - 1;

/// Width used *inside* decimal decoding only. One `acc*10 + digit` step is
/// applied to an accumulator already constrained to `INT_MAX`, so the widest
/// intermediate is `10*INT_MAX + 9` — three bits past `INT_BITS`, and this is
/// five. Nothing outside [`decode_decimal`] ever sees this width.
const DEC_BITS: u32 = INT_BITS + 5;

pub struct Config {
    pub max_len: u32,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            max_len: DEFAULT_MAX_LEN,
        }
    }
}

#[derive(Debug)]
pub enum LowerError {
    Unsupported(String),
}

impl std::fmt::Display for LowerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LowerError::Unsupported(s) => write!(f, "strings: {s}"),
        }
    }
}

/// A bounded string: `len` characters of `chars` are live; slots at or beyond
/// `len` are pinned to zero so that equal strings have equal encodings.
#[derive(Clone)]
pub struct BoundedStr {
    pub len: TermId,
    pub chars: Vec<TermId>,
}

pub struct Lowered {
    pub roots: Vec<TermId>,
    /// Side conditions (slot canonicalization) to assert alongside the roots.
    pub side: Vec<TermId>,
    /// True when `unsat` under this encoding implies real unsatisfiability.
    /// False whenever any string could have been longer than the bound.
    pub unsat_trustworthy: bool,
}

struct B<'a> {
    pool: &'a mut TermPool,
    cfg: Config,
}

impl B<'_> {
    fn mk(&mut self, op: Op, args: &[TermId]) -> TermId {
        self.pool
            .mk(op, args)
            .expect("string lowering built an ill-sorted term")
    }
    fn tt(&self) -> TermId {
        self.pool.true_term
    }
    fn ff(&self) -> TermId {
        self.pool.false_term
    }
    fn not(&mut self, a: TermId) -> TermId {
        self.mk(Op::Not, &[a])
    }
    fn and(&mut self, args: &[TermId]) -> TermId {
        match args.len() {
            0 => self.tt(),
            1 => args[0],
            _ => self.mk(Op::And, args),
        }
    }
    fn or(&mut self, args: &[TermId]) -> TermId {
        match args.len() {
            0 => self.ff(),
            1 => args[0],
            _ => self.mk(Op::Or, args),
        }
    }
    fn ite(&mut self, c: TermId, t: TermId, e: TermId) -> TermId {
        if t == e {
            return t;
        }
        self.mk(Op::Ite, &[c, t, e])
    }
    fn eq(&mut self, a: TermId, b: TermId) -> TermId {
        self.mk(Op::Eq, &[a, b])
    }
    fn int(&mut self, v: u64) -> TermId {
        self.pool.bv_u64(INT_BITS, v)
    }
    fn ch(&mut self, v: u64) -> TermId {
        self.pool.bv_u64(CHAR_BITS, v)
    }
    fn add(&mut self, a: TermId, b: TermId) -> TermId {
        self.mk(Op::BvAdd, &[a, b])
    }
    fn sub(&mut self, a: TermId, b: TermId) -> TermId {
        self.mk(Op::BvSub, &[a, b])
    }
    fn ule(&mut self, a: TermId, b: TermId) -> TermId {
        self.mk(Op::BvUle, &[a, b])
    }
    fn ult(&mut self, a: TermId, b: TermId) -> TermId {
        self.mk(Op::BvUlt, &[a, b])
    }

    // ---- constant-folding wrappers ----
    //
    // `TermPool::mk` interns but does not evaluate, and the `str.replace`
    // encodings below multiply out to O(max_len^2) index comparisons whose
    // operands are usually *both* literals (a literal `t`/`t'` makes every
    // length concrete). Folding here collapses those to `true`/`false` before
    // they reach the term graph, which is the difference between a few hundred
    // nodes and a few hundred thousand.

    fn const_val(&self, t: TermId) -> Option<u64> {
        self.pool.as_bv_const(t).and_then(|c| c.as_u64())
    }
    /// The length of `s`, when it is statically known (`s` is a literal).
    fn const_len(&self, s: &BoundedStr) -> Option<u64> {
        self.const_val(s.len)
    }
    fn boolc(&mut self, v: bool) -> TermId {
        if v {
            self.tt()
        } else {
            self.ff()
        }
    }
    fn not_f(&mut self, a: TermId) -> TermId {
        let (tt, ff) = (self.tt(), self.ff());
        if a == tt {
            ff
        } else if a == ff {
            tt
        } else {
            self.not(a)
        }
    }
    fn and_f(&mut self, args: &[TermId]) -> TermId {
        let (tt, ff) = (self.tt(), self.ff());
        let mut keep = Vec::with_capacity(args.len());
        for &a in args {
            if a == ff {
                return ff;
            }
            if a != tt && !keep.contains(&a) {
                keep.push(a);
            }
        }
        self.and(&keep)
    }
    fn or_f(&mut self, args: &[TermId]) -> TermId {
        let (tt, ff) = (self.tt(), self.ff());
        let mut keep = Vec::with_capacity(args.len());
        for &a in args {
            if a == tt {
                return tt;
            }
            if a != ff && !keep.contains(&a) {
                keep.push(a);
            }
        }
        self.or(&keep)
    }
    fn ite_f(&mut self, c: TermId, t: TermId, e: TermId) -> TermId {
        if c == self.tt() {
            t
        } else if c == self.ff() {
            e
        } else {
            self.ite(c, t, e)
        }
    }
    fn eq_f(&mut self, a: TermId, b: TermId) -> TermId {
        if a == b {
            return self.tt();
        }
        match (self.const_val(a), self.const_val(b)) {
            (Some(x), Some(y)) => self.boolc(x == y),
            _ => self.eq(a, b),
        }
    }
    fn ult_f(&mut self, a: TermId, b: TermId) -> TermId {
        match (self.const_val(a), self.const_val(b)) {
            (Some(x), Some(y)) => self.boolc(x < y),
            _ => self.ult(a, b),
        }
    }
    fn ule_f(&mut self, a: TermId, b: TermId) -> TermId {
        match (self.const_val(a), self.const_val(b)) {
            (Some(x), Some(y)) => self.boolc(x <= y),
            _ => self.ule(a, b),
        }
    }
    fn add_f(&mut self, a: TermId, b: TermId) -> TermId {
        match (self.const_val(a), self.const_val(b)) {
            (Some(x), Some(y)) => self.int(x.wrapping_add(y) & INT_MASK),
            _ => self.add(a, b),
        }
    }
    fn sub_f(&mut self, a: TermId, b: TermId) -> TermId {
        match (self.const_val(a), self.const_val(b)) {
            (Some(x), Some(y)) => self.int(x.wrapping_sub(y) & INT_MASK),
            _ => self.sub(a, b),
        }
    }

    // ---- bit-vector bridge ----
    //
    // Bit-vector clients (clarirs/claripy) speak of string lengths and
    // positions as 64-bit bit-vectors, not Int. `bv2nat`/`(_ int2bv w)` carry
    // values across that boundary. The string world's integers are INT_BITS
    // wide and every real position is at most HARD_MAX_LEN, so `bv2nat` clamps
    // anything above INT_MAX to INT_MAX — an offset past every representable
    // string behaves like any other out-of-range offset.

    /// The unsigned value of a bit-vector as a string-world integer, clamping
    /// values above INT_MAX to INT_MAX.
    fn bv2nat(&mut self, x: TermId) -> Result<TermId, LowerError> {
        let Some(w) = self.pool.sort(x).bv_width() else {
            return Err(LowerError::Unsupported(
                "bv2nat expects a bit-vector operand".into(),
            ));
        };
        Ok(if let Some(v) = self.const_val(x) {
            self.int(v.min(INT_MAX))
        } else if w < INT_BITS {
            // Widths below INT_BITS cannot exceed INT_MAX (2^(INT_BITS-1)-1).
            self.mk(Op::ZeroExtend(INT_BITS - w), &[x])
        } else {
            let max_wide = self.pool.bv(BvConst::from_u64(w, INT_MAX));
            let in_range = self.ule(x, max_wide);
            let narrow = if w == INT_BITS {
                x
            } else {
                self.mk(
                    Op::Extract {
                        hi: INT_BITS - 1,
                        lo: 0,
                    },
                    &[x],
                )
            };
            let max_int = self.int(INT_MAX);
            self.ite(in_range, narrow, max_int)
        })
    }

    /// A string-world integer as a `w`-bit bit-vector, `(_ int2bv w)`:
    /// the value mod 2^w. String-world integers are INT_BITS-wide signed
    /// (`str.indexof` returns -1), so widening is sign extension.
    fn int2bv(&mut self, n: TermId, w: u32) -> Result<TermId, LowerError> {
        if w == 0 {
            return Err(LowerError::Unsupported("int2bv to width 0".into()));
        }
        Ok(match w.cmp(&INT_BITS) {
            std::cmp::Ordering::Greater => self.mk(Op::SignExtend(w - INT_BITS), &[n]),
            std::cmp::Ordering::Equal => n,
            std::cmp::Ordering::Less => self.mk(Op::Extract { hi: w - 1, lo: 0 }, &[n]),
        })
    }

    fn literal(&mut self, bytes: &[u8]) -> Result<BoundedStr, LowerError> {
        let n = bytes.len();
        if n > self.cfg.max_len as usize {
            // Truncating a literal would silently change the problem.
            return Err(LowerError::Unsupported(format!(
                "string literal longer than the {}-character bound",
                self.cfg.max_len
            )));
        }
        let len = self.int(n as u64);
        let mut chars = Vec::with_capacity(self.cfg.max_len as usize);
        for i in 0..self.cfg.max_len as usize {
            let v = bytes.get(i).map_or(0, |&b| b as u64);
            let c = self.ch(v);
            chars.push(c);
        }
        Ok(BoundedStr { len, chars })
    }

    /// A symbolic string: fresh length and character variables, with the
    /// canonicalization side conditions the caller must assert.
    fn fresh(&mut self, name: &str, side: &mut Vec<TermId>) -> BoundedStr {
        let len_sym = self
            .pool
            .fresh_symbol(format!("{name}!len"), Sort::BitVec(INT_BITS));
        let len = self.pool.var(len_sym);
        let bound = self.int(self.cfg.max_len as u64);
        let in_bound = self.ule(len, bound);
        side.push(in_bound);
        let mut chars = Vec::with_capacity(self.cfg.max_len as usize);
        for i in 0..self.cfg.max_len {
            let sym = self
                .pool
                .fresh_symbol(format!("{name}!c{i}"), Sort::BitVec(CHAR_BITS));
            let c = self.pool.var(sym);
            // Slots past the end are pinned to zero so equal strings encode
            // identically (and so `=` is just a componentwise comparison).
            let idx = self.int(i as u64);
            let live = self.ult(idx, len);
            let zero = self.ch(0);
            let is_zero = self.eq(c, zero);
            let pinned = self.or(&[live, is_zero]);
            side.push(pinned);
            chars.push(c);
        }
        BoundedStr { len, chars }
    }

    fn concat(&mut self, xs: &[BoundedStr], side: &mut Vec<TermId>) -> BoundedStr {
        let mut acc = xs[0].clone();
        for y in &xs[1..] {
            acc = self.concat2(&acc, y, side);
        }
        acc
    }

    fn concat2(&mut self, x: &BoundedStr, y: &BoundedStr, side: &mut Vec<TermId>) -> BoundedStr {
        let max = self.cfg.max_len as usize;
        let len = self.add(x.len, y.len);
        // Only `max` character slots exist, so a longer concatenation would be
        // compared on its prefix alone — which would let a model satisfy the
        // encoding without satisfying the original constraint. Restricting the
        // length keeps every `sat` answer backed by a real string; the cost is
        // that `unsat` becomes "unsat within the bound" (reported as unknown).
        let bound = self.int(self.cfg.max_len as u64);
        let fits = self.ule(len, bound);
        side.push(fits);
        let mut chars = Vec::with_capacity(max);
        for i in 0..max {
            // result[i] = i < x.len ? x[i] : y[i - x.len]
            let idx = self.int(i as u64);
            let from_x = self.ult(idx, x.len);
            let mut pick = x.chars[i];
            // y index j = i - x.len, selected by comparing against each j.
            let mut y_char = self.ch(0);
            for (j, &yc) in y.chars.iter().enumerate().take(i + 1) {
                let jj = self.int(j as u64);
                let want = self.add(jj, x.len);
                let matches = self.eq(want, idx);
                y_char = self.ite(matches, yc, y_char);
            }
            pick = self.ite(from_x, pick, y_char);
            chars.push(pick);
        }
        BoundedStr { len, chars }
    }

    /// Componentwise equality (valid because unused slots are pinned to zero).
    fn str_eq(&mut self, x: &BoundedStr, y: &BoundedStr) -> TermId {
        let mut conj = vec![self.eq(x.len, y.len)];
        for i in 0..self.cfg.max_len as usize {
            let e = self.eq(x.chars[i], y.chars[i]);
            conj.push(e);
        }
        self.and(&conj)
    }

    /// `y` occurs in `x` starting exactly at position `p`.
    fn matches_at(&mut self, x: &BoundedStr, y: &BoundedStr, p: usize) -> TermId {
        let max = self.cfg.max_len as usize;
        let mut conj = Vec::new();
        // p + |y| <= |x|
        let pp = self.int(p as u64);
        let end = self.add(pp, y.len);
        let fits = self.ule(end, x.len);
        conj.push(fits);
        for (j, &yc) in y.chars.iter().enumerate() {
            if p + j >= max {
                // Beyond the slot array: only consistent if y ends first.
                let jj = self.int(j as u64);
                let short = self.ule(y.len, jj);
                conj.push(short);
                continue;
            }
            let jj = self.int(j as u64);
            let live = self.ult(jj, y.len);
            let same = self.eq(x.chars[p + j], yc);
            let not_live = self.not(live);
            let implied = self.or(&[not_live, same]);
            conj.push(implied);
        }
        self.and(&conj)
    }

    fn contains(&mut self, x: &BoundedStr, y: &BoundedStr) -> TermId {
        let max = self.cfg.max_len as usize;
        let mut disj = Vec::new();
        // `p == max` is a real start position: the empty needle occurs just
        // past the end of a string that fills every slot.
        for p in 0..=max {
            let m = self.matches_at(x, y, p);
            disj.push(m);
        }
        self.or(&disj)
    }

    fn prefix_of(&mut self, y: &BoundedStr, x: &BoundedStr) -> TermId {
        self.matches_at(x, y, 0)
    }

    fn suffix_of(&mut self, y: &BoundedStr, x: &BoundedStr) -> TermId {
        let max = self.cfg.max_len as usize;
        let mut disj = Vec::new();
        for p in 0..=max {
            let m = self.matches_at(x, y, p);
            // suffix: p + |y| == |x|
            let pp = self.int(p as u64);
            let end = self.add(pp, y.len);
            let exact = self.eq(end, x.len);
            let both = self.and(&[m, exact]);
            disj.push(both);
        }
        self.or(&disj)
    }

    /// First index at which `y` occurs at or after `from`, or -1.
    fn index_of(&mut self, x: &BoundedStr, y: &BoundedStr, from: TermId) -> TermId {
        let max = self.cfg.max_len as usize;
        let minus_one = {
            let one = self.int(1);
            self.mk(Op::BvNeg, &[one])
        };
        let mut result = minus_one;
        // Scan downwards so earlier positions take precedence.
        for p in (0..=max).rev() {
            let pp = self.int(p as u64);
            let after = self.ule(from, pp);
            let m = self.matches_at(x, y, p);
            let hit = self.and(&[after, m]);
            result = self.ite(hit, pp, result);
        }
        result
    }

    /// Like [`matches_at`](Self::matches_at), but specialised when `|y|` is
    /// statically known — which is the case whenever `y` is a literal, the
    /// shape `str.replace` almost always appears in. Only the first `|y|`
    /// character comparisons survive, and positions that cannot fit `y` inside
    /// the slot array are rejected outright.
    fn matches_at_known(&mut self, x: &BoundedStr, y: &BoundedStr, p: usize) -> TermId {
        let max = self.cfg.max_len as usize;
        let Some(k) = self.const_len(y).map(|k| k as usize) else {
            return self.matches_at(x, y, p);
        };
        if p + k > max {
            // A match needs p + |y| <= |x| <= max_len, so this cannot happen.
            return self.ff();
        }
        let end = self.int((p + k) as u64);
        let fits = self.ule_f(end, x.len);
        let mut conj = vec![fits];
        for j in 0..k {
            let same = self.eq_f(x.chars[p + j], y.chars[j]);
            conj.push(same);
        }
        self.and_f(&conj)
    }

    /// SMT-LIB `(str.replace x t r)`: the leftmost occurrence of `t` in `x` is
    /// replaced by `r`; if `t` does not occur, the result is `x`.
    ///
    /// The empty `t` needs no special case. It matches at position 0, so the
    /// general formula below rebuilds `x[0..0] ++ r ++ x[0..]`, which is
    /// exactly the standard's `r ++ x`.
    fn replace(
        &mut self,
        x: &BoundedStr,
        t: &BoundedStr,
        r: &BoundedStr,
        side: &mut Vec<TermId>,
    ) -> BoundedStr {
        let max = self.cfg.max_len as usize;

        // sel[p]: the leftmost occurrence of `t` starts at p. `none`: `t` does
        // not occur at all. These are mutually exclusive and exhaustive.
        let mut sel = Vec::with_capacity(max);
        let mut none = self.tt();
        for p in 0..max {
            let m = self.matches_at_known(x, t, p);
            let first = self.and_f(&[none, m]);
            sel.push(first);
            let miss = self.not_f(m);
            none = self.and_f(&[none, miss]);
        }

        let grown = {
            let cut = self.sub_f(x.len, t.len);
            self.add_f(cut, r.len)
        };
        let len = self.ite_f(none, x.len, grown);
        // `r` may be longer than `t`, so the result can outgrow the slot
        // array. Truncating would let a model satisfy the encoding without
        // satisfying the original constraint, so — exactly as in `concat2` —
        // the over-long case is excluded instead, at the cost of `unsat`
        // meaning only "unsat within the bound".
        let bound = self.int(max as u64);
        let fits = self.ule_f(grown, bound);
        let ok = self.or_f(&[none, fits]);
        side.push(ok);
        // Excluding the over-long case removes models, so an `unsat` under it
        // is not trustworthy. [`bounds::analyze`] gives `str.replace` no length
        // bound, which blocks completeness for the whole problem — that is what
        // makes this sound. Teaching the analysis a bound for `str.replace`
        // without also accounting for this exclusion would admit a wrong
        // `unsat`.

        // tail[i] = x[i + |t| - |r|]: the source character that lands at output
        // position i when i falls past the replacement. Independent of the
        // match position, so it is built once per output slot.
        let mut tail = Vec::with_capacity(max);
        for i in 0..max {
            let ii = self.int(i as u64);
            let want = self.add_f(ii, t.len);
            let mut c = self.ch(0);
            for (j, &xc) in x.chars.iter().enumerate() {
                let jj = self.int(j as u64);
                let shifted = self.add_f(jj, r.len);
                let hit = self.eq_f(shifted, want);
                c = self.ite_f(hit, xc, c);
            }
            tail.push(c);
        }

        // out[i] = i < p ? x[i] : (i - p < |r| ? r[i - p] : tail[i]), for the
        // selected p; x[i] when there is no match. Positions p > i leave x[i]
        // untouched, so the chain only runs down to 0 from i.
        let mut chars = Vec::with_capacity(max);
        for (i, &tail_i) in tail.iter().enumerate() {
            let mut c = x.chars[i];
            for p in (0..=i).rev() {
                let d = i - p;
                let dd = self.int(d as u64);
                let in_repl = self.ult_f(dd, r.len);
                let pick = self.ite_f(in_repl, r.chars[d], tail_i);
                c = self.ite_f(sel[p], pick, c);
            }
            chars.push(c);
        }
        BoundedStr { len, chars }
    }

    /// SMT-LIB `(str.replace_all x t r)`: every non-overlapping occurrence of
    /// `t`, scanning left to right, is replaced by `r`.
    ///
    /// An empty `t` leaves `x` unchanged — the opposite convention from
    /// `str.replace`, so it gets an explicit guard rather than falling out of
    /// the general encoding (which would happily replace at every position).
    fn replace_all(
        &mut self,
        x: &BoundedStr,
        t: &BoundedStr,
        r: &BoundedStr,
        side: &mut Vec<TermId>,
    ) -> BoundedStr {
        let klen = self.const_len(t);
        if klen == Some(0) {
            return x.clone();
        }
        if klen == Some(1) && self.const_len(r) == Some(1) {
            return self.replace_all_pointwise(x, t.chars[0], r.chars[0]);
        }
        self.replace_all_general(x, t, r, side)
    }

    fn replace_all_general(
        &mut self,
        x: &BoundedStr,
        t: &BoundedStr,
        r: &BoundedStr,
        side: &mut Vec<TermId>,
    ) -> BoundedStr {
        let max = self.cfg.max_len as usize;
        let klen = self.const_len(t);
        let zero = self.int(0);
        let t_empty = self.eq_f(t.len, zero);

        // The greedy scan as a recurrence over positions: `sel[p]` is "the scan
        // takes a match at p", which holds when `t` occurs at p and p is not
        // already covered by a match taken earlier (`cov[p]`). `cov` is what
        // makes the occurrences non-overlapping: `str.replace_all` of "aa" in
        // "aaa" takes position 0 and then skips position 1.
        let mut sel: Vec<TermId> = Vec::with_capacity(max);
        let mut cov: Vec<TermId> = Vec::with_capacity(max);
        for p in 0..max {
            let m = self.matches_at_known(x, t, p);
            // A match at q covers p when q < p < q + |t|.
            let lo = match klen {
                Some(k) => p.saturating_sub(k as usize - 1),
                None => 0,
            };
            let mut inside = Vec::with_capacity(p - lo);
            for (q, &sel_q) in sel.iter().enumerate().take(p).skip(lo) {
                let c = if klen.is_some() {
                    sel_q // q >= p - |t| + 1 already implies q + |t| > p
                } else {
                    let pp = self.int(p as u64);
                    let qq = self.int(q as u64);
                    let end = self.add_f(qq, t.len);
                    let within = self.ult_f(pp, end);
                    self.and_f(&[sel[q], within])
                };
                inside.push(c);
            }
            let covered = self.or_f(&inside);
            let free = self.not_f(covered);
            let taken = self.and_f(&[m, free]);
            sel.push(taken);
            cov.push(covered);
        }

        // out_at[p] = how many output characters `x[0..p]` produces. A taken
        // match emits |r|, a covered position emits nothing, and any other live
        // position emits its own character.
        let one = self.int(1);
        let mut out_at: Vec<TermId> = Vec::with_capacity(max + 1);
        let mut acc = zero;
        out_at.push(acc);
        for p in 0..max {
            let pp = self.int(p as u64);
            let live = self.ult_f(pp, x.len);
            let copied = self.ite_f(live, one, zero);
            let unmatched = self.ite_f(cov[p], zero, copied);
            let delta = self.ite_f(sel[p], r.len, unmatched);
            acc = self.add_f(acc, delta);
            out_at.push(acc);
        }
        let out_len = acc;
        let bound = self.int(max as u64);
        let fits = self.ule_f(out_len, bound);
        let ok = self.or_f(&[t_empty, fits]);
        side.push(ok);
        // As in `replace`: this exclusion removes models, and soundness rests
        // on `bounds::analyze` deriving no length for `str.replace_all`.

        // Each source position owns a contiguous, disjoint span of the output,
        // so the guards below fire for at most one (p, j) per output slot and
        // their order does not matter. Slots past the end see no guard at all
        // and stay zero, which is the pinning the rest of the encoding expects.
        let rlen = self.const_len(r);
        let mut chars = Vec::with_capacity(max);
        for o in 0..max {
            let oo = self.int(o as u64);
            let mut c = self.ch(0);
            for p in 0..max {
                let pp = self.int(p as u64);
                let live = self.ult_f(pp, x.len);
                let unmatched = self.not_f(sel[p]);
                let free = self.not_f(cov[p]);
                let here = self.eq_f(out_at[p], oo);
                let copied = self.and_f(&[live, unmatched, free, here]);
                c = self.ite_f(copied, x.chars[p], c);
                let jmax = match rlen {
                    Some(rl) => (rl as usize).min(o + 1),
                    None => o + 1,
                }
                .min(max);
                for (j, &rc) in r.chars.iter().enumerate().take(jmax) {
                    let jj = self.int(j as u64);
                    let dest = self.add_f(out_at[p], jj);
                    let hit = self.eq_f(dest, oo);
                    let mut conj = vec![sel[p], hit];
                    if rlen.is_none() {
                        let in_repl = self.ult_f(jj, r.len);
                        conj.push(in_repl);
                    }
                    let emit = self.and_f(&conj);
                    c = self.ite_f(emit, rc, c);
                }
            }
            chars.push(c);
        }

        // Empty `t`: the result is `x` untouched.
        let len = self.ite_f(t_empty, x.len, out_len);
        let mut out = Vec::with_capacity(max);
        for (i, &ci) in chars.iter().enumerate() {
            let c = self.ite_f(t_empty, x.chars[i], ci);
            out.push(c);
        }
        BoundedStr { len, chars: out }
    }

    /// `str.replace_all` when both the pattern and the replacement are single
    /// characters: the result is a pointwise character map, `O(max_len)` gates
    /// instead of the general encoding's `O(max_len^2)` index arithmetic.
    ///
    /// This is not an approximation, it is the general encoding evaluated by
    /// hand at `|t| = |r| = 1`. There, `cov[p]` is empty (a one-character match
    /// covers only its own position), so `sel[p]` is just "position p is live
    /// and holds `t`"; every live position emits exactly one character, so
    /// `out_at[p] = p` and the output length is `|x|`. The general code's
    /// `out_len <= max_len` side condition therefore holds vacuously and is
    /// dropped — which is also why [`bounds::analyze`] may derive a length here
    /// when it may not for the general case: nothing is excluded.
    ///
    /// The liveness guard matters: slots at or past `|x|` are pinned to zero and
    /// the rest of the encoding relies on that, so a pattern of `\u{0}` must not
    /// rewrite them.
    fn replace_all_pointwise(&mut self, x: &BoundedStr, tc: TermId, rc: TermId) -> BoundedStr {
        let max = self.cfg.max_len as usize;
        let mut chars = Vec::with_capacity(max);
        for i in 0..max {
            let ii = self.int(i as u64);
            let live = self.ult_f(ii, x.len);
            let same = self.eq_f(x.chars[i], tc);
            let hit = self.and_f(&[live, same]);
            let c = self.ite_f(hit, rc, x.chars[i]);
            chars.push(c);
        }
        BoundedStr { len: x.len, chars }
    }

    fn substr(&mut self, x: &BoundedStr, start: TermId, count: TermId) -> BoundedStr {
        let max = self.cfg.max_len as usize;
        // SMT-LIB: out of range start or non-positive count gives "".
        let in_range = self.ult(start, x.len);
        let avail = self.sub(x.len, start);
        let clipped = self.ule(count, avail);
        let len_raw = self.ite(clipped, count, avail);
        let zero = self.int(0);
        let len = self.ite(in_range, len_raw, zero);
        let mut chars = Vec::with_capacity(max);
        for i in 0..max {
            let ii = self.int(i as u64);
            let src = self.add(start, ii);
            let mut c = self.ch(0);
            for (j, &xc) in x.chars.iter().enumerate() {
                let jj = self.int(j as u64);
                let matches = self.eq(src, jj);
                c = self.ite(matches, xc, c);
            }
            let live = self.ult(ii, len);
            let zero_c = self.ch(0);
            let pick = self.ite(live, c, zero_c);
            chars.push(pick);
        }
        BoundedStr { len, chars }
    }

    fn dec(&mut self, v: u64) -> TermId {
        self.pool.bv_u64(DEC_BITS, v)
    }

    /// Decimal decoding shared by `str.to_int` and `str.from_int`.
    ///
    /// Returns `(is_num, value, no_overflow)`:
    ///   * `is_num` — `s` is non-empty and every live character is `0`-`9`,
    ///     which is exactly the SMT-LIB condition for `str.to_int` to be a
    ///     value rather than -1;
    ///   * `value` — the decimal value in `DEC_BITS` bits, meaningful only
    ///     when both other flags hold;
    ///   * `no_overflow` — the value and every prefix of it stay within
    ///     `INT_MAX`.
    ///
    /// The accumulator is constrained to `INT_MAX` after *every* step, which
    /// is what makes the `DEC_BITS` arithmetic wrap-free: entering a step with
    /// `acc <= INT_MAX` bounds `acc*10 + 9` well inside `DEC_BITS`. Without
    /// that per-step check a long digit string could wrap around to a small
    /// value and pass a final range test while denoting something else.
    fn decode_decimal(&mut self, s: &BoundedStr) -> (TermId, TermId, TermId) {
        let max = self.cfg.max_len as usize;
        let mut digit_ok = Vec::with_capacity(max + 1);
        let mut fits = Vec::with_capacity(max);
        let mut acc = self.dec(0);
        let ten = self.dec(10);
        let cap = self.dec(INT_MAX);
        for i in 0..max {
            let ii = self.int(i as u64);
            let live = self.ult(ii, s.len);
            let not_live = self.not(live);
            let c = s.chars[i];
            let lo = self.ch(b'0' as u64);
            let hi = self.ch(b'9' as u64);
            let ge = self.ule(lo, c);
            let le = self.ule(c, hi);
            let is_digit = self.and(&[ge, le]);
            digit_ok.push(self.or(&[not_live, is_digit]));

            let wide = self.mk(Op::ZeroExtend(DEC_BITS - CHAR_BITS), &[c]);
            let zero_ch = self.dec(b'0' as u64);
            let value = self.sub(wide, zero_ch);
            let scaled = self.mk(Op::BvMul, &[acc, ten]);
            let stepped = self.add(scaled, value);
            acc = self.ite(live, stepped, acc);
            let within = self.ule(acc, cap);
            fits.push(self.or(&[not_live, within]));
        }
        let zero = self.int(0);
        let nonempty = self.ult(zero, s.len);
        digit_ok.push(nonempty);
        let is_num = self.and(&digit_ok);
        let no_overflow = self.and(&fits);
        (is_num, acc, no_overflow)
    }

    /// `(str.to_int s)`: the value of a non-empty all-digit `s`, else -1.
    ///
    /// Values above `INT_MAX` are not representable at `INT_BITS`, so rather
    /// than wrapping (which would answer a *different* problem) the encoding
    /// asserts that a digit string never denotes one. That only ever removes
    /// models, so every `sat` stays backed by a real string.
    ///
    /// Removing models is exactly what makes an `unsat` untrustworthy, so
    /// [`bounds::analyze`] blocks completeness whenever a `str.to_int` operand
    /// is long enough to overflow. Keep the two in step: relaxing this
    /// restriction without relaxing that blocker would admit a wrong `unsat`.
    fn str_to_int(&mut self, s: &BoundedStr, side: &mut Vec<TermId>) -> TermId {
        let (is_num, acc, no_overflow) = self.decode_decimal(s);
        let not_num = self.not(is_num);
        let restriction = self.or(&[not_num, no_overflow]);
        side.push(restriction);
        let narrowed = self.mk(
            Op::Extract {
                hi: INT_BITS - 1,
                lo: 0,
            },
            &[acc],
        );
        let minus_one = {
            let one = self.int(1);
            self.mk(Op::BvNeg, &[one])
        };
        self.ite(is_num, narrowed, minus_one)
    }

    /// `(str.from_int n)`: the decimal numeral for `n >= 0`, else `""`.
    ///
    /// Encoded relationally — a fresh bounded string pinned by `decode_decimal`
    /// to have `n`'s value — which avoids building a division circuit and
    /// reuses the digit machinery exactly. `n` is an `INT_BITS` signed value so
    /// it needs at most 5 digits, well inside any bound we run with.
    fn str_from_int(&mut self, n: TermId, side: &mut Vec<TermId>) -> BoundedStr {
        let out = self.fresh("from_int", side);
        let (is_num, acc, no_overflow) = self.decode_decimal(&out);
        let zero = self.int(0);
        let nonneg = self.mk(Op::BvSle, &[zero, n]);
        let wide_n = self.mk(Op::ZeroExtend(DEC_BITS - INT_BITS), &[n]);
        let same = self.eq(acc, wide_n);
        // The canonical numeral has no leading zero, except for "0" itself.
        let one = self.int(1);
        let single = self.eq(out.len, one);
        let digit_zero = self.ch(b'0' as u64);
        let leads_nonzero = {
            let e = self.eq(out.chars[0], digit_zero);
            self.not(e)
        };
        let canonical = self.or(&[single, leads_nonzero]);
        let positive_case = self.and(&[is_num, no_overflow, same, canonical]);
        let empty_case = self.eq(out.len, zero);
        let spec = self.ite(nonneg, positive_case, empty_case);
        side.push(spec);
        out
    }
}

/// Does this term set use any string or regex construct?
///
/// Note this tests only the `Str` and `RegLan` sorts, not `Int`: a problem
/// whose only non-BV content is Int arithmetic is not routed through the
/// string lowering, even though `lower_node` does handle Int operators once
/// it is running (they arrive as length and index arithmetic).
pub fn contains_strings(pool: &TermPool, roots: &[TermId]) -> bool {
    let mut found = false;
    pool.post_order(roots, |pool, t| {
        if matches!(pool.sort(t), Sort::Str | Sort::RegLan) {
            found = true;
        }
    });
    found
}

enum Val {
    Str(BoundedStr),
    Term(TermId),
}

/// The smallest bound that can represent every string literal in `roots`.
///
/// A literal cannot be truncated without changing the problem, so a bound
/// below the longest literal makes lowering fail outright. Raising the bound to
/// meet it turns those refusals into real attempts, and — because the bound is
/// only ever raised, never for a problem whose literals already fit — it cannot
/// slow down anything that works today.
pub fn required_bound(pool: &TermPool, roots: &[TermId]) -> u32 {
    survey(pool, roots).0
}

/// `(longest literal, number of quadratic-cost operator applications)`.
///
/// The second number is what the bound has to be paid for out of: `str.++`,
/// `str.substr` and the search operators each emit work proportional to
/// `max_len` for each of `max_len` slots or start positions, while literals,
/// equality and regex membership are only linear. An n-ary `str.++` is folded
/// pairwise, so it counts once per join.
fn survey(pool: &TermPool, roots: &[TermId]) -> (u32, u64) {
    let mut need = 0u32;
    let mut quadratic = 0u64;
    pool.post_order(roots, |pool, t| match pool.op(t) {
        Op::Var(sym) => {
            if pool.symbol(sym).sort == Sort::Str {
                if let Some(bytes) = literal_bytes(&pool.symbol(sym).name) {
                    need = need.max(bytes.len() as u32);
                }
            }
        }
        Op::Other { name, .. } => {
            let n = pool.args(t).len() as u64;
            quadratic += match pool.symbol(name).name.as_str() {
                "str.++" => n.saturating_sub(1),
                "str.substr" | "str.at" | "str.contains" | "str.suffixof" | "str.indexof"
                | "str.replace" | "str.replace_all" | "str.replace_re" | "str.replace_re_all"
                | "str.update" => 1,
                _ => 0,
            };
        }
        _ => {}
    });
    (need, quadratic)
}

/// The largest bound this problem can be encoded at without the quadratic
/// constructs exploding.
///
/// A problem with no concatenation or search — a pile of `str.in_re` over one
/// variable, say — costs only `O(max_len)` per operator and can happily run at
/// [`HARD_MAX_LEN`], which is what lets long-literal regex benchmarks be
/// attempted at all. A problem with thousands of concatenations cannot, and
/// stays at [`MAX_AUTO_LEN`]. The floor at `MAX_AUTO_LEN` means this only ever
/// *raises* the bound, so no problem that is solved today can be slowed down.
fn affordable_bound(quadratic: u64) -> u32 {
    if quadratic == 0 {
        return HARD_MAX_LEN;
    }
    let slots = (QUADRATIC_SLOT_BUDGET / quadratic) as f64;
    (slots.sqrt() as u32).clamp(MAX_AUTO_LEN, HARD_MAX_LEN)
}

/// Lower all string constructs in `roots` to BV/Bool terms.
pub fn lower(
    pool: &mut TermPool,
    roots: &[TermId],
    mut cfg: Config,
) -> Result<Lowered, LowerError> {
    // The automata are built once and handed to both the analysis and the
    // lowering: `re.comp`/`re.diff` determinize, which is far too expensive to
    // repeat.
    let nfas = regex::build_all(pool, roots)?;
    let analysis = bounds::analyze(pool, roots, &nfas);

    // Two independent things set the slot count, and they compose. `survey`
    // reports the longest literal (a hard floor — truncating one would change
    // the problem) and how much quadratic-cost work the problem does, which
    // `affordable_bound` turns into a ceiling the problem has to earn. The
    // completeness analysis then asks for exactly the slots it needs to prove
    // the bound excludes nothing: raising buys a real `unsat`, lowering shrinks
    // every `str.++` ite chain. The earned ceiling still applies — past it the
    // circuit is not worth building and the answer stays `unknown`.
    let (need, quadratic) = survey(pool, roots);
    let ceiling = affordable_bound(quadratic);
    cfg.max_len = cfg.max_len.max(need.min(ceiling));
    if analysis.blocker.is_none() {
        if let Some(n) = analysis.needed_len {
            cfg.max_len = n.max(need).max(1).min(ceiling.max(cfg.max_len));
        }
    }
    let unsat_trustworthy = analysis.complete_at(cfg.max_len);
    if std::env::var_os("SMTRS_DEBUG").is_some() {
        eprintln!(
            "; bounded strings: max_len={} needed={:?} ceiling={ceiling} \
             unsat_trustworthy={unsat_trustworthy} ({})",
            cfg.max_len,
            analysis.needed_len,
            analysis.blocker.as_deref().unwrap_or("complete")
        );
    }

    let mut b = B { pool, cfg };
    let mut side: Vec<TermId> = Vec::new();
    let mut cache: FxHashMap<TermId, Val> = FxHashMap::default();
    let mut order: Vec<TermId> = Vec::new();
    b.pool.post_order(roots, |_, t| order.push(t));

    for t in order {
        let op = b.pool.op(t);
        let sort = b.pool.sort(t);
        let args: Vec<TermId> = b.pool.args(t).to_vec();
        let node = Node {
            id: t,
            op,
            sort,
            args: &args,
        };
        let v = lower_node(&mut b, node, &cache, &nfas, &mut side)?;
        cache.insert(t, v);
    }

    let out: Result<Vec<TermId>, LowerError> = roots
        .iter()
        .map(|r| match &cache[r] {
            Val::Term(t) => Ok(*t),
            _ => Err(LowerError::Unsupported("non-Bool assertion".into())),
        })
        .collect();
    Ok(Lowered {
        roots: out?,
        side,
        unsat_trustworthy,
    })
}

fn name_of(pool: &TermPool, sym: SymbolId) -> String {
    pool.symbol(sym).name.clone()
}

/// Read a `\u` escape from `chars`, which must be positioned on the `u`.
/// Returns the code point with `chars` advanced past the whole escape, or
/// `None` with `chars` left exactly where it was.
///
/// SMT-LIB 2.6 leaves a *malformed* `\u` run as ordinary characters, so the
/// two readers below have to agree, character for character, on which runs are
/// escapes. They decided separately and disagreed in two ways, each of which
/// makes a literal's length a lie and so turns into a wrong `unsat`:
///
/// * `u32::from_str_radix` is not a validity test — it accepts a leading `+`.
///   Both readers used it as one, so `"\u+041"` parsed as `A`: a six-character
///   literal read as one. Every digit is now checked explicitly.
/// * Only `literal_char_len` required the un-braced form to carry all four hex
///   digits; `literal_bytes` accepted `"\u12"` at the end of a literal as the
///   single byte `0x12` while the other counted four characters.
fn read_unicode_escape(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> Option<u32> {
    let mut look = chars.clone();
    look.next(); // the `u`
    let hex: String = if look.peek() == Some(&'{') {
        look.next();
        let mut hex = String::new();
        let mut closed = false;
        for h in look.by_ref() {
            if h == '}' {
                closed = true;
                break;
            }
            hex.push(h);
        }
        if !closed {
            return None;
        }
        hex
    } else {
        let hex: String = look.by_ref().take(4).collect();
        if hex.chars().count() != 4 {
            return None;
        }
        hex
    };
    if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let cp = u32::from_str_radix(&hex, 16).ok()?;
    *chars = look;
    Some(cp)
}

/// String literals arrive from the parser as variables named `str!"..."`.
fn literal_bytes(name: &str) -> Option<Vec<u8>> {
    let inner = name.strip_prefix("str!\"")?.strip_suffix('"')?;
    // SMT-LIB escapes: "" is a quote; \u{..} is a code point.
    let mut out = Vec::new();
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '"' && chars.peek() == Some(&'"') {
            chars.next();
            out.push(b'"');
        } else if c == '\\' && chars.peek() == Some(&'u') {
            match read_unicode_escape(&mut chars) {
                Some(cp) if cp > 0xff => return None, // outside our byte alphabet
                Some(cp) => out.push(cp as u8),
                // Not an escape after all: the backslash is an ordinary
                // character, and the run behind it is re-read as ordinary
                // characters by the following iterations.
                None => out.push(b'\\'),
            }
        } else if (c as u32) <= 0xff {
            out.push(c as u8);
        } else {
            return None;
        }
    }
    Some(out)
}

/// Number of *characters* in a string literal, for the length reasoning in
/// [`length`]. Unlike [`literal_bytes`] this succeeds on literals holding
/// characters above `0xff`: how long such a string is remains perfectly well
/// defined even though the bounded encoding cannot represent its contents.
fn literal_char_len(name: &str) -> Option<usize> {
    let inner = name.strip_prefix("str!\"")?.strip_suffix('"')?;
    let mut n = 0usize;
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '"' && chars.peek() == Some(&'"') {
            chars.next();
        } else if c == '\\' && chars.peek() == Some(&'u') {
            // `\u` is an escape only when what follows is actually hex. A
            // well-formed one is consumed whole and counts as the single
            // character below; a malformed run leaves `chars` untouched, so
            // only the backslash is counted here and the rest falls through to
            // later iterations as the ordinary characters SMT-LIB says they
            // are. Counting a malformed run as one character would be a false
            // fact about every model, which the length abstraction turns into
            // a wrong `unsat` -- so the decision is made in one place, shared
            // with `literal_bytes`, rather than twice.
            let _ = read_unicode_escape(&mut chars);
        }
        n += 1;
    }
    Some(n)
}

/// Integer literals arrive as variables named `int!N`.
fn int_literal(name: &str) -> Option<u64> {
    name.strip_prefix("int!")?.parse().ok()
}

fn get_str(cache: &FxHashMap<TermId, Val>, t: TermId) -> Result<&BoundedStr, LowerError> {
    match cache.get(&t) {
        Some(Val::Str(s)) => Ok(s),
        _ => Err(LowerError::Unsupported("expected a string operand".into())),
    }
}

fn get_term(cache: &FxHashMap<TermId, Val>, t: TermId) -> Result<TermId, LowerError> {
    match cache.get(&t) {
        Some(Val::Term(x)) => Ok(*x),
        _ => Err(LowerError::Unsupported("expected a scalar operand".into())),
    }
}

/// The one term being lowered, with everything the pool says about it.
struct Node<'a> {
    id: TermId,
    op: Op,
    sort: Sort,
    args: &'a [TermId],
}

fn lower_node(
    b: &mut B,
    node: Node,
    cache: &FxHashMap<TermId, Val>,
    nfas: &FxHashMap<TermId, regex::Nfa>,
    side: &mut Vec<TermId>,
) -> Result<Val, LowerError> {
    let Node {
        id: term,
        op,
        sort,
        args,
    } = node;
    // Regex constructs were compiled to automata up front (see `lower`); a
    // RegLan node carries no BV value of its own.
    if sort == Sort::RegLan {
        return Ok(Val::Term(term));
    }

    // Leaves.
    if let Op::Var(sym) = op {
        let name = name_of(b.pool, sym);
        return Ok(match sort {
            Sort::Str => {
                if let Some(bytes) = literal_bytes(&name) {
                    Val::Str(b.literal(&bytes)?)
                } else {
                    Val::Str(b.fresh(&name, side))
                }
            }
            Sort::Int => {
                if let Some(v) = int_literal(&name) {
                    Val::Term(b.int(v))
                } else {
                    let s = b
                        .pool
                        .fresh_symbol(format!("{name}!int"), Sort::BitVec(INT_BITS));
                    Val::Term(b.pool.var(s))
                }
            }
            _ => Val::Term(term),
        });
    }

    let is_str_op = |name: &str| -> bool { name.starts_with("str.") };

    match op {
        Op::Other { name, index0, .. } => {
            let opname = name_of(b.pool, name);
            match opname.as_str() {
                // Bit-vector bridge (see the helpers on `B`): these are the
                // only heads whose operands/results cross between the Int
                // world of the string theory and plain bit-vectors.
                "bv2nat" => {
                    let x = get_term(cache, args[0])?;
                    Ok(Val::Term(b.bv2nat(x)?))
                }
                "int2bv" => {
                    let n = get_term(cache, args[0])?;
                    Ok(Val::Term(b.int2bv(n, index0)?))
                }
                "str.++" => {
                    let parts: Result<Vec<BoundedStr>, LowerError> =
                        args.iter().map(|&a| get_str(cache, a).cloned()).collect();
                    Ok(Val::Str(b.concat(&parts?, side)))
                }
                "str.len" => {
                    let s = get_str(cache, args[0])?.clone();
                    Ok(Val::Term(s.len))
                }
                "str.at" => {
                    let s = get_str(cache, args[0])?.clone();
                    let i = get_term(cache, args[1])?;
                    let one = b.int(1);
                    Ok(Val::Str(b.substr(&s, i, one)))
                }
                "str.substr" => {
                    let s = get_str(cache, args[0])?.clone();
                    let start = get_term(cache, args[1])?;
                    let count = get_term(cache, args[2])?;
                    Ok(Val::Str(b.substr(&s, start, count)))
                }
                "str.contains" => {
                    let x = get_str(cache, args[0])?.clone();
                    let y = get_str(cache, args[1])?.clone();
                    Ok(Val::Term(b.contains(&x, &y)))
                }
                "str.prefixof" => {
                    let y = get_str(cache, args[0])?.clone();
                    let x = get_str(cache, args[1])?.clone();
                    Ok(Val::Term(b.prefix_of(&y, &x)))
                }
                "str.suffixof" => {
                    let y = get_str(cache, args[0])?.clone();
                    let x = get_str(cache, args[1])?.clone();
                    Ok(Val::Term(b.suffix_of(&y, &x)))
                }
                "str.replace" | "str.replace_all" => {
                    let x = get_str(cache, args[0])?.clone();
                    let t = get_str(cache, args[1])?.clone();
                    let r = get_str(cache, args[2])?.clone();
                    Ok(Val::Str(if opname == "str.replace" {
                        b.replace(&x, &t, &r, side)
                    } else {
                        b.replace_all(&x, &t, &r, side)
                    }))
                }
                "str.indexof" => {
                    let x = get_str(cache, args[0])?.clone();
                    let y = get_str(cache, args[1])?.clone();
                    let from = get_term(cache, args[2])?;
                    Ok(Val::Term(b.index_of(&x, &y, from)))
                }
                "str.to_int" | "str.to.int" => {
                    let s = get_str(cache, args[0])?.clone();
                    Ok(Val::Term(b.str_to_int(&s, side)))
                }
                "str.from_int" | "int.to.str" => {
                    let n = get_term(cache, args[0])?;
                    Ok(Val::Str(b.str_from_int(n, side)))
                }
                "str.in_re" => {
                    let s = get_str(cache, args[0])?.clone();
                    let nfa = match nfas.get(&args[1]) {
                        Some(n) => n.clone(),
                        None => return Err(LowerError::Unsupported("expected a regex".into())),
                    };
                    Ok(Val::Term(regex::accepts(b.pool, &nfa, &s, b.cfg.max_len)))
                }
                // Integer arithmetic over lengths/indices.
                "+" | "-" | "*" | "int-neg" | "<" | "<=" | ">" | ">=" => {
                    let ts: Result<Vec<TermId>, LowerError> =
                        args.iter().map(|&a| get_term(cache, a)).collect();
                    let ts = ts?;
                    Ok(Val::Term(match opname.as_str() {
                        "+" => ts[1..].iter().fold(ts[0], |acc, &x| b.add(acc, x)),
                        "-" => ts[1..].iter().fold(ts[0], |acc, &x| b.sub(acc, x)),
                        "*" => ts[1..]
                            .iter()
                            .fold(ts[0], |acc, &x| b.mk(Op::BvMul, &[acc, x])),
                        "int-neg" => b.mk(Op::BvNeg, &[ts[0]]),
                        // The comparisons are :chainable, so `(< a b c)` means
                        // `a < b and b < c` — encoding only the first pair
                        // drops a conjunct and produces `sat` where the answer
                        // is `unsat`. Lengths and indices are non-negative, but
                        // indexof returns -1, so compare signed.
                        rel => {
                            let mut conj = Vec::with_capacity(ts.len() - 1);
                            for w in ts.windows(2) {
                                let (x, y) = (w[0], w[1]);
                                conj.push(match rel {
                                    "<" => b.mk(Op::BvSlt, &[x, y]),
                                    "<=" => b.mk(Op::BvSle, &[x, y]),
                                    ">" => b.mk(Op::BvSlt, &[y, x]),
                                    _ => b.mk(Op::BvSle, &[y, x]),
                                });
                            }
                            b.and(&conj)
                        }
                    }))
                }
                other if is_str_op(other) => {
                    Err(LowerError::Unsupported(format!("operator {other}")))
                }
                other => Err(LowerError::Unsupported(format!("operator {other}"))),
            }
        }
        Op::Eq | Op::Distinct => {
            // String equality is componentwise; scalars rebuild normally.
            if matches!(cache.get(&args[0]), Some(Val::Str(_))) {
                let strs: Result<Vec<BoundedStr>, LowerError> =
                    args.iter().map(|&a| get_str(cache, a).cloned()).collect();
                let strs = strs?;
                let mut conj = Vec::new();
                for i in 0..strs.len() {
                    for j in i + 1..strs.len() {
                        let e = b.str_eq(&strs[i], &strs[j]);
                        conj.push(if op == Op::Eq { e } else { b.not(e) });
                    }
                }
                return Ok(Val::Term(b.and(&conj)));
            }
            let ts: Result<Vec<TermId>, LowerError> =
                args.iter().map(|&a| get_term(cache, a)).collect();
            Ok(Val::Term(b.mk(op, &ts?)))
        }
        Op::Ite if sort == Sort::Str => {
            let c = get_term(cache, args[0])?;
            let x = get_str(cache, args[1])?.clone();
            let y = get_str(cache, args[2])?.clone();
            let len = b.ite(c, x.len, y.len);
            let chars = (0..b.cfg.max_len as usize)
                .map(|i| b.ite(c, x.chars[i], y.chars[i]))
                .collect();
            Ok(Val::Str(BoundedStr { len, chars }))
        }
        _ => {
            let ts: Result<Vec<TermId>, LowerError> =
                args.iter().map(|&a| get_term(cache, a)).collect();
            Ok(Val::Term(b.mk(op, &ts?)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smtrs_core::{eval, Value};

    /// Evaluate `str.to_int` on a concrete string, together with the side
    /// conditions it asked for. Everything is constant, so ground evaluation
    /// pins the semantics down without any SAT solving.
    fn to_int_of(text: &str, max_len: u32) -> (i64, bool) {
        let mut pool = TermPool::new();
        let mut b = B {
            pool: &mut pool,
            cfg: Config { max_len },
        };
        let s = b.literal(text.as_bytes()).expect("literal fits the bound");
        let mut side = Vec::new();
        let t = b.str_to_int(&s, &mut side);
        let model = Default::default();
        let vals = eval(&pool, &side, &model).expect("side conditions evaluate");
        let side_ok = vals.iter().all(|v| v == &Value::Bool(true));
        let v = eval(&pool, &[t], &model).expect("result evaluates");
        let raw = v[0].as_bv().expect("bit-vector result").as_u64().unwrap();
        // Integers are compared signed in this encoding, so read them back the
        // same way.
        let signed = raw as i64
            - if raw >> (INT_BITS - 1) == 1 {
                1i64 << INT_BITS
            } else {
                0
            };
        (signed, side_ok)
    }

    /// Ground-evaluate a `str.replace_all` encoding on concrete operands and
    /// read the result back as a Rust string.
    fn eval_replace_all(x: &str, t: &str, r: &str, max_len: u32, general: bool) -> String {
        let mut pool = TermPool::new();
        let mut b = B {
            pool: &mut pool,
            cfg: Config { max_len },
        };
        let xs = b.literal(x.as_bytes()).expect("x fits");
        let ts = b.literal(t.as_bytes()).expect("t fits");
        let rs = b.literal(r.as_bytes()).expect("r fits");
        let mut side = Vec::new();
        let out = if general {
            b.replace_all_general(&xs, &ts, &rs, &mut side)
        } else {
            b.replace_all(&xs, &ts, &rs, &mut side)
        };
        let model = Default::default();
        let ok = eval(&pool, &side, &model)
            .expect("side conditions evaluate")
            .iter()
            .all(|v| v == &Value::Bool(true));
        assert!(ok, "side conditions rejected a representable replace_all");
        let len = eval(&pool, &[out.len], &model).expect("len")[0]
            .as_bv()
            .expect("bv len")
            .as_u64()
            .unwrap() as usize;
        let bytes: Vec<u8> = out.chars[..len]
            .iter()
            .map(|&c| {
                eval(&pool, &[c], &model).expect("char")[0]
                    .as_bv()
                    .expect("bv char")
                    .as_u64()
                    .unwrap() as u8
            })
            .collect();
        String::from_utf8(bytes).expect("ascii result")
    }

    /// The single-character fast path is a specialisation, not an
    /// approximation: it has to agree with the general encoding *and* with the
    /// SMT-LIB semantics on every input, including ones where the pattern
    /// occurs at the very end, not at all, or as a run.
    #[test]
    fn pointwise_replace_all_agrees_with_the_general_encoding() {
        for (x, t, r) in [
            ("", "a", "b"),
            ("a", "a", "b"),
            ("a", "z", "b"),
            ("aaa", "a", "b"),
            ("banana", "a", "X"),
            ("banana", "n", "n"),
            ("abcabc", "c", "a"),
            ("xyz", "z", "x"),
            ("aXa", "X", "a"),
        ] {
            let want = x.replace(t, r);
            let fast = eval_replace_all(x, t, r, 12, false);
            let slow = eval_replace_all(x, t, r, 12, true);
            assert_eq!(fast, want, "fast path on ({x:?}, {t:?}, {r:?})");
            assert_eq!(slow, want, "general path on ({x:?}, {t:?}, {r:?})");
        }
    }

    /// A pattern of `\u{0}` must not rewrite the dead slots past the end of the
    /// string, which the rest of the encoding requires to stay zero.
    #[test]
    fn pointwise_replace_all_leaves_dead_slots_pinned() {
        let mut pool = TermPool::new();
        let mut b = B {
            pool: &mut pool,
            cfg: Config { max_len: 8 },
        };
        let xs = b.literal(b"ab").expect("x fits");
        let nul = b.ch(0);
        let z = b.ch(b'Z' as u64);
        let out = b.replace_all_pointwise(&xs, nul, z);
        let model = Default::default();
        for (i, &c) in out.chars.iter().enumerate().skip(2) {
            let v = eval(&pool, &[c], &model).expect("char")[0]
                .as_bv()
                .expect("bv")
                .as_u64()
                .unwrap();
            assert_eq!(v, 0, "slot {i} past the end was not left pinned to zero");
        }
    }

    #[test]
    fn to_int_matches_the_smtlib_definition() {
        for (text, want) in [
            ("123", 123),
            ("", -1),
            ("12a", -1),
            ("+7", -1),
            ("-7", -1),
            ("007", 7),
            ("0", 0),
            ("a", -1),
            (" 1", -1),
            ("1 ", -1),
        ] {
            let (got, ok) = to_int_of(text, 16);
            assert!(
                ok,
                "side conditions rejected {text:?}, which is representable"
            );
            assert_eq!(got, want, "str.to_int {text:?}");
        }
    }

    /// The overflow policy at its boundary: `INT_MAX` is answered exactly, and
    /// anything above it is excluded by a side condition rather than wrapped
    /// onto a wrong value.
    #[test]
    fn to_int_excludes_rather_than_wraps_above_int_max() {
        assert_eq!(to_int_of("32767", 16), (32767, true));
        for text in ["32768", "65536", "99999", "1234567890"] {
            let (_, ok) = to_int_of(text, 16);
            assert!(!ok, "{text:?} overflows INT_BITS but was not excluded");
        }
        // Non-digit strings are never restricted, however long: their value is
        // -1 regardless, so excluding them would lose real models.
        assert_eq!(to_int_of("99999x", 16), (-1, true));
    }

    /// A digit string long enough to wrap the internal accumulator several
    /// times over must still be excluded, not silently mapped onto some small
    /// value that happens to satisfy a range check.
    /// The budget may only ever *raise* the bound, and more quadratic work may
    /// only ever lower what it buys. Both are what make the raise safe for
    /// problems that already solve.
    #[test]
    fn the_earned_bound_stays_between_the_floor_and_the_ceiling() {
        assert_eq!(affordable_bound(0), HARD_MAX_LEN);
        let mut prev = HARD_MAX_LEN;
        for quadratic in 1..5000u64 {
            let b = affordable_bound(quadratic);
            assert!(b <= prev, "bound grew at {quadratic} quadratic operators");
            assert!(
                (MAX_AUTO_LEN..=HARD_MAX_LEN).contains(&b),
                "{b} out of range"
            );
            prev = b;
        }
        assert_eq!(affordable_bound(u64::MAX), MAX_AUTO_LEN);
    }

    #[test]
    fn to_int_rejects_astronomically_long_digit_strings() {
        let long = "1".repeat(40);
        let (_, ok) = to_int_of(&long, 64);
        assert!(!ok, "a 40-digit number was not excluded");
    }
}

#[cfg(test)]
mod escape_len_tests {
    /// `\u` forms an escape only when what follows is actually hex. SMT-LIB
    /// 2.6 leaves `\`, `u`, ... as ordinary characters otherwise, so counting
    /// the run as one character is a *false fact about every model* -- and the
    /// length abstraction turns false facts into wrong `unsat` answers.
    #[test]
    fn invalid_unicode_escapes_count_literally() {
        let n = |s: &str| super::literal_char_len(&format!("str!\"{s}\"")).unwrap();
        assert_eq!(n("\\u0041"), 1, "a valid 4-digit escape is one character");
        assert_eq!(n("\\u{41}"), 1, "a valid braced escape is one character");
        assert_eq!(n("\\uzzzz"), 6, "not hex, so six ordinary characters");
        assert_eq!(n("\\u12"), 4, "too short to be an escape");
        assert_eq!(n("\\u{zz}"), 6, "braced but not hex");
        assert_eq!(n("abc"), 3);
        // `u32::from_str_radix` accepts a leading sign, so these parsed as
        // code points and a six-character literal was counted as one.
        assert_eq!(n("\\u+041"), 6, "a sign is not a hex digit");
        assert_eq!(n("\\u{+41}"), 7, "nor inside braces");
        assert_eq!(n("\\u-041"), 6);
        assert_eq!(n("\\u{"), 3, "an unterminated brace is not an escape");
    }

    /// The two readers of a string literal must agree, character for
    /// character, on which `\u` runs are escapes: `literal_char_len` states
    /// how long the literal is and `literal_bytes` says what is in it, so a
    /// disagreement is a false fact about every model. They used to decide
    /// separately, and split on a leading `+` and on a short un-braced run.
    #[test]
    fn the_two_literal_readers_agree_on_every_escape() {
        for s in [
            "\\u0041",
            "\\u{41}",
            "\\uzzzz",
            "\\u12",
            "\\u{zz}",
            "\\u+041",
            "\\u{+41}",
            "\\u-041",
            "\\u{",
            "\\u",
            "a\\u0041b",
            "\\u0041\\u12",
            "abc",
            "",
        ] {
            let name = format!("str!\"{s}\"");
            let chars = super::literal_char_len(&name).expect("length is always defined");
            let bytes = super::literal_bytes(&name)
                .unwrap_or_else(|| panic!("{s:?} is representable in the byte alphabet"));
            assert_eq!(
                bytes.len(),
                chars,
                "{s:?}: literal_bytes gives {} bytes, literal_char_len says {chars} characters",
                bytes.len()
            );
        }
    }
}
