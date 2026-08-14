//! smtrs-bitblast: bit-blasting of Bool+BV terms into an AIG.
//!
//! Terms encode into an And-Inverter Graph (smtrs-aig) with structural
//! hashing and constant folding; CNF is emitted per asserted cone. Constant
//! operand bits now propagate through every circuit for free (an adder with
//! a constant operand collapses into wiring), and identical subcircuits are
//! shared regardless of how they were built.
//!
//! Expects rewritten terms: `Implies`, `BvUgt/Uge/Sgt/Sge`, `BvNand/Nor/Xnor`,
//! `BvComp`, `ZeroExtend`, `SignExtend`, `RotateLeft/Right`, `Repeat` are
//! normalized away by smtrs-rewrite. Encoders for those ops therefore panic:
//! reaching one is a pipeline bug, not user error.
//!
//! Bit order convention: `Vec<AigLit>` is LSB-first.

use rustc_hash::FxHashMap;
use smtrs_aig::{Aig, AigLit, FALSE, TRUE};
use smtrs_core::{Op, PollTick, TermId, TermPool};
use smtrs_sat::SatBackend;

#[derive(Clone)]
pub struct BitBlaster {
    pub aig: Aig,
    bool_map: FxHashMap<TermId, AigLit>,
    bv_map: FxHashMap<TermId, Vec<AigLit>>,
    /// (dividend, divisor) -> (quotient, remainder) so udiv/urem pairs share
    /// one divider circuit.
    div_cache: FxHashMap<(TermId, TermId), (Vec<AigLit>, Vec<AigLit>)>,
    /// Cooperative interrupt. Encoding a multi-million-node term is not
    /// bounded by the SAT budget, so the flag has to be observed here too.
    terminate: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// Sticky: set once the interrupt has been seen. From that point every
    /// encoder returns placeholder literals so the recursion unwinds, and the
    /// caller must discard the whole encoding (see `interrupted`).
    interrupted: bool,
    poll_tick: PollTick,
}

impl Default for BitBlaster {
    fn default() -> Self {
        Self::new()
    }
}

impl BitBlaster {
    pub fn new() -> Self {
        BitBlaster {
            aig: Aig::new(),
            bool_map: FxHashMap::default(),
            bv_map: FxHashMap::default(),
            div_cache: FxHashMap::default(),
            terminate: None,
            interrupted: false,
            poll_tick: PollTick::new(),
        }
    }

    /// Install the cooperative interrupt observed while encoding. The AIG
    /// gets it too: CNF emission is a separate, equally long traversal.
    pub fn set_terminate(&mut self, flag: std::sync::Arc<std::sync::atomic::AtomicBool>) {
        self.aig.set_terminate(flag.clone());
        self.terminate = Some(flag);
    }

    /// Drop the interrupt and the sticky record of having seen it (see
    /// `Rewriter::clear_terminate`).
    pub fn clear_terminate(&mut self) {
        self.aig.clear_terminate();
        self.terminate = None;
        self.interrupted = false;
    }

    /// True once encoding was cut short. The AIG and any CNF emitted from it
    /// are then **incomplete**, not merely unsimplified: subterms were
    /// replaced by placeholder constants. Neither `sat` nor `unsat` may be
    /// reported from such an encoding — the caller must answer `unknown` and
    /// throw the engine away.
    pub fn interrupted(&self) -> bool {
        self.interrupted || self.aig.interrupted()
    }

    /// One atomic load per `POLL_PERIOD` encoded nodes: bounded response time
    /// without a measurable cost next to the AIG hashing each node performs.
    #[inline]
    fn check_terminate(&mut self) -> bool {
        if self.interrupted {
            return true;
        }
        if !self.poll_tick.due() {
            return false;
        }
        if let Some(f) = &self.terminate {
            if f.load(std::sync::atomic::Ordering::Relaxed) {
                self.interrupted = true;
            }
        }
        self.interrupted
    }

    /// Blast and assert a Bool term, emitting new CNF into `sat`.
    pub fn assert_true<B: SatBackend>(&mut self, pool: &TermPool, t: TermId, sat: &mut B) {
        let out = self.blast_bool(pool, t);
        if self.interrupted {
            return;
        }
        self.aig.assert_true(sat, out);
    }

    pub fn bv_bits(&self, t: TermId) -> Option<&Vec<AigLit>> {
        self.bv_map.get(&t)
    }

    pub fn bool_lit(&self, t: TermId) -> Option<AigLit> {
        self.bool_map.get(&t).copied()
    }

    // ---- circuit helpers over the AIG ----

    /// Full adder: (sum, carry_out).
    fn full_adder(&mut self, a: AigLit, b: AigLit, cin: AigLit) -> (AigLit, AigLit) {
        let ab = self.aig.xor(a, b);
        let sum = self.aig.xor(ab, cin);
        let and1 = self.aig.and(a, b);
        let and2 = self.aig.and(cin, ab);
        let carry = self.aig.or(and1, and2);
        (sum, carry)
    }

    fn adder(&mut self, a: &[AigLit], b: &[AigLit], mut carry: AigLit) -> (Vec<AigLit>, AigLit) {
        debug_assert_eq!(a.len(), b.len());
        let mut sum = Vec::with_capacity(a.len());
        for i in 0..a.len() {
            let (s, c) = self.full_adder(a[i], b[i], carry);
            sum.push(s);
            carry = c;
        }
        (sum, carry)
    }

    fn negate_bits(&mut self, a: &[AigLit]) -> Vec<AigLit> {
        let inv: Vec<AigLit> = a.iter().map(|&l| !l).collect();
        let zeros = vec![FALSE; a.len()];
        let (sum, _) = self.adder(&inv, &zeros, TRUE);
        sum
    }

    /// Unsigned a < b (borrow of a - b).
    fn ult(&mut self, a: &[AigLit], b: &[AigLit]) -> AigLit {
        let inv: Vec<AigLit> = b.iter().map(|&l| !l).collect();
        let (_, carry) = self.adder(a, &inv, TRUE);
        !carry
    }

    fn slt(&mut self, a: &[AigLit], b: &[AigLit]) -> AigLit {
        let w = a.len();
        let (sa, sb) = (a[w - 1], b[w - 1]);
        let ult = self.ult(a, b);
        let neg_pos = self.aig.and(sa, !sb);
        let x = self.aig.xor(sa, sb);
        let same_and_ult = self.aig.and(!x, ult);
        self.aig.or(neg_pos, same_and_ult)
    }

    fn eq_bits(&mut self, a: &[AigLit], b: &[AigLit]) -> AigLit {
        let xnors: Vec<AigLit> = (0..a.len())
            .map(|i| {
                let x = self.aig.xor(a[i], b[i]);
                !x
            })
            .collect();
        self.aig.and_many(&xnors)
    }

    fn is_zero(&mut self, a: &[AigLit]) -> AigLit {
        let inv: Vec<AigLit> = a.iter().map(|&l| !l).collect();
        self.aig.and_many(&inv)
    }

    fn mux_bits(&mut self, c: AigLit, a: &[AigLit], b: &[AigLit]) -> Vec<AigLit> {
        (0..a.len()).map(|i| self.aig.mux(c, a[i], b[i])).collect()
    }

    /// Restoring-division circuit computing floor(a/b) and a mod b for b != 0
    /// (b == 0 handled by callers via mux). The working remainder needs w+1
    /// bits: after the shift-in step it can be up to 2b-1, which overflows w
    /// bits whenever b's top bit is set.
    fn divider(&mut self, a: &[AigLit], b: &[AigLit]) -> (Vec<AigLit>, Vec<AigLit>) {
        let w = a.len();
        let mut rem: Vec<AigLit> = vec![FALSE; w];
        let mut quot: Vec<AigLit> = vec![FALSE; w];
        let mut b_ext: Vec<AigLit> = b.to_vec();
        b_ext.push(FALSE);
        let negb_ext = self.negate_bits(&b_ext);
        for i in (0..w).rev() {
            let mut rem_ext = Vec::with_capacity(w + 1);
            rem_ext.push(a[i]);
            rem_ext.extend_from_slice(&rem);
            let ult = self.ult(&rem_ext, &b_ext);
            let geq = !ult;
            let (diff, _) = self.adder(&rem_ext, &negb_ext, FALSE);
            let sel = self.mux_bits(geq, &diff, &rem_ext);
            rem = sel[..w].to_vec();
            quot[i] = geq;
        }
        (quot, rem)
    }

    fn udivrem(&mut self, pool: &TermPool, ta: TermId, tb: TermId) -> (Vec<AigLit>, Vec<AigLit>) {
        if let Some(cached) = self.div_cache.get(&(ta, tb)) {
            return cached.clone();
        }
        let a = self.blast_bv(pool, ta);
        let b = self.blast_bv(pool, tb);
        let (q, r) = self.divider_total(&a, &b, &a);
        self.div_cache.insert((ta, tb), (q.clone(), r.clone()));
        (q, r)
    }

    /// divider + division-by-zero mux (quotient -> ones, remainder -> `rem0`).
    fn divider_total(
        &mut self,
        a: &[AigLit],
        b: &[AigLit],
        rem0: &[AigLit],
    ) -> (Vec<AigLit>, Vec<AigLit>) {
        let (q, r) = self.divider(a, b);
        let bz = self.is_zero(b);
        let ones = vec![TRUE; a.len()];
        let q = self.mux_bits(bz, &ones, &q);
        let r = self.mux_bits(bz, rem0, &r);
        (q, r)
    }

    /// abs via sign mux; returns (abs_bits, sign_lit).
    fn abs(&mut self, a: &[AigLit]) -> (Vec<AigLit>, AigLit) {
        let sign = a[a.len() - 1];
        let neg = self.negate_bits(a);
        (self.mux_bits(sign, &neg, a), sign)
    }

    // ---- term encoders ----

    pub fn blast_bool(&mut self, pool: &TermPool, t: TermId) -> AigLit {
        if let Some(&l) = self.bool_map.get(&t) {
            return l;
        }
        if self.check_terminate() {
            // Placeholder, deliberately not cached: the encoding is being
            // abandoned, and a poisoned map must not outlive this call.
            return FALSE;
        }
        let args: Vec<TermId> = pool.args(t).to_vec();
        let l = match pool.op(t) {
            Op::True => TRUE,
            Op::False => FALSE,
            Op::Var(_) => self.aig.input(),
            Op::Not => {
                let a = self.blast_bool(pool, args[0]);
                !a
            }
            Op::And => {
                let ls: Vec<AigLit> = args.iter().map(|&a| self.blast_bool(pool, a)).collect();
                self.aig.and_many(&ls)
            }
            Op::Or => {
                let ls: Vec<AigLit> = args.iter().map(|&a| self.blast_bool(pool, a)).collect();
                self.aig.or_many(&ls)
            }
            Op::Xor => {
                let ls: Vec<AigLit> = args.iter().map(|&a| self.blast_bool(pool, a)).collect();
                ls[1..].iter().fold(ls[0], |acc, &l| self.aig.xor(acc, l))
            }
            Op::Eq => {
                if pool.sort(args[0]) == smtrs_core::Sort::Bool {
                    let ls: Vec<AigLit> = args.iter().map(|&a| self.blast_bool(pool, a)).collect();
                    let pairs: Vec<AigLit> = ls
                        .windows(2)
                        .map(|w| {
                            let x = self.aig.xor(w[0], w[1]);
                            !x
                        })
                        .collect();
                    self.aig.and_many(&pairs)
                } else {
                    let bvs: Vec<Vec<AigLit>> =
                        args.iter().map(|&a| self.blast_bv(pool, a)).collect();
                    let pairs: Vec<AigLit> =
                        bvs.windows(2).map(|w| self.eq_bits(&w[0], &w[1])).collect();
                    self.aig.and_many(&pairs)
                }
            }
            Op::Distinct => {
                if pool.sort(args[0]) == smtrs_core::Sort::Bool {
                    let a = self.blast_bool(pool, args[0]);
                    let b = self.blast_bool(pool, args[1]);
                    self.aig.xor(a, b)
                } else {
                    let bvs: Vec<Vec<AigLit>> =
                        args.iter().map(|&a| self.blast_bv(pool, a)).collect();
                    let mut neqs = Vec::new();
                    for i in 0..bvs.len() {
                        for j in i + 1..bvs.len() {
                            let eq = self.eq_bits(&bvs[i], &bvs[j]);
                            neqs.push(!eq);
                        }
                    }
                    self.aig.and_many(&neqs)
                }
            }
            Op::Ite => {
                let c = self.blast_bool(pool, args[0]);
                let a = self.blast_bool(pool, args[1]);
                let b = self.blast_bool(pool, args[2]);
                self.aig.mux(c, a, b)
            }
            Op::BvUlt => {
                let a = self.blast_bv(pool, args[0]);
                let b = self.blast_bv(pool, args[1]);
                self.ult(&a, &b)
            }
            Op::BvUle => {
                let a = self.blast_bv(pool, args[0]);
                let b = self.blast_bv(pool, args[1]);
                let ult = self.ult(&b, &a);
                !ult
            }
            Op::BvSlt => {
                let a = self.blast_bv(pool, args[0]);
                let b = self.blast_bv(pool, args[1]);
                self.slt(&a, &b)
            }
            Op::BvSle => {
                let a = self.blast_bv(pool, args[0]);
                let b = self.blast_bv(pool, args[1]);
                let slt = self.slt(&b, &a);
                !slt
            }
            op => panic!("blast_bool: unexpected op {op:?} (missing rewrite?)"),
        };
        self.bool_map.insert(t, l);
        l
    }

    pub fn blast_bv(&mut self, pool: &TermPool, t: TermId) -> Vec<AigLit> {
        if let Some(bits) = self.bv_map.get(&t) {
            return bits.clone();
        }
        if self.check_terminate() {
            // Right-width placeholder so the callers' width invariants hold
            // while the recursion unwinds; not cached (see `blast_bool`).
            return vec![FALSE; pool.width(t) as usize];
        }
        let args: Vec<TermId> = pool.args(t).to_vec();
        let bits: Vec<AigLit> = match pool.op(t) {
            Op::BvConst(id) => {
                let c = pool.bv_const(id).clone();
                (0..c.width())
                    .map(|i| if c.bit(i) { TRUE } else { FALSE })
                    .collect()
            }
            Op::Var(_) => {
                let w = pool.width(t);
                (0..w).map(|_| self.aig.input()).collect()
            }
            Op::BvNot => {
                let a = self.blast_bv(pool, args[0]);
                a.iter().map(|&l| !l).collect()
            }
            Op::BvNeg => {
                let a = self.blast_bv(pool, args[0]);
                self.negate_bits(&a)
            }
            Op::BvAdd => {
                let mut acc = self.blast_bv(pool, args[0]);
                for &next in &args[1..] {
                    let b = self.blast_bv(pool, next);
                    let (sum, _) = self.adder(&acc, &b, FALSE);
                    acc = sum;
                }
                acc
            }
            Op::BvSub => {
                let a = self.blast_bv(pool, args[0]);
                let b = self.blast_bv(pool, args[1]);
                let inv: Vec<AigLit> = b.iter().map(|&l| !l).collect();
                let (sum, _) = self.adder(&a, &inv, TRUE);
                sum
            }
            Op::BvMul => {
                let mut acc = self.blast_bv(pool, args[0]);
                for &next in &args[1..] {
                    let b = self.blast_bv(pool, next);
                    acc = self.multiplier(&acc, &b);
                }
                acc
            }
            Op::BvUdiv => self.udivrem(pool, args[0], args[1]).0,
            Op::BvUrem => self.udivrem(pool, args[0], args[1]).1,
            Op::BvSdiv => {
                let a = self.blast_bv(pool, args[0]);
                let b = self.blast_bv(pool, args[1]);
                let (aa, sa) = self.abs(&a);
                let (ab, sb) = self.abs(&b);
                let (q, _) = self.divider_total(&aa, &ab, &aa);
                let opposite = self.aig.xor(sa, sb);
                let negq = self.negate_bits(&q);
                self.mux_bits(opposite, &negq, &q)
            }
            Op::BvSrem => {
                let a = self.blast_bv(pool, args[0]);
                let b = self.blast_bv(pool, args[1]);
                let (aa, sa) = self.abs(&a);
                let (ab, _) = self.abs(&b);
                let (_, r) = self.divider_total(&aa, &ab, &aa);
                let negr = self.negate_bits(&r);
                self.mux_bits(sa, &negr, &r)
            }
            Op::BvSmod => {
                // Mirror BvConst::smod: b == 0 -> a; else r = srem(a, b);
                // r == 0 or sign(r) == sign(b) -> r; else r + b.
                let a = self.blast_bv(pool, args[0]);
                let b = self.blast_bv(pool, args[1]);
                let (aa, sa) = self.abs(&a);
                let (ab, _) = self.abs(&b);
                let (_, ur) = self.divider_total(&aa, &ab, &aa);
                let negur = self.negate_bits(&ur);
                let r = self.mux_bits(sa, &negur, &ur);
                let w = a.len();
                let rz = self.is_zero(&r);
                let x = self.aig.xor(r[w - 1], b[w - 1]);
                let keep = self.aig.or(rz, !x);
                let (rb, _) = self.adder(&r, &b, FALSE);
                let adjusted = self.mux_bits(keep, &r, &rb);
                let bz = self.is_zero(&b);
                self.mux_bits(bz, &a, &adjusted)
            }
            Op::BvAnd | Op::BvOr | Op::BvXor => {
                let op = pool.op(t);
                let bvs: Vec<Vec<AigLit>> = args.iter().map(|&a| self.blast_bv(pool, a)).collect();
                let w = bvs[0].len();
                (0..w)
                    .map(|i| {
                        let ls: Vec<AigLit> = bvs.iter().map(|b| b[i]).collect();
                        match op {
                            Op::BvAnd => self.aig.and_many(&ls),
                            Op::BvOr => self.aig.or_many(&ls),
                            _ => ls[1..].iter().fold(ls[0], |acc, &l| self.aig.xor(acc, l)),
                        }
                    })
                    .collect()
            }
            Op::BvShl => self.shifter(pool, args[0], args[1], ShiftKind::Left),
            Op::BvLshr => self.shifter(pool, args[0], args[1], ShiftKind::LogicalRight),
            Op::BvAshr => self.shifter(pool, args[0], args[1], ShiftKind::ArithRight),
            Op::Concat => {
                let mut bits = Vec::with_capacity(pool.width(t) as usize);
                for &a in args.iter().rev() {
                    bits.extend(self.blast_bv(pool, a));
                }
                bits
            }
            Op::Extract { hi, lo } => {
                let a = self.blast_bv(pool, args[0]);
                a[lo as usize..=hi as usize].to_vec()
            }
            Op::Ite => {
                let c = self.blast_bool(pool, args[0]);
                let a = self.blast_bv(pool, args[1]);
                let b = self.blast_bv(pool, args[2]);
                self.mux_bits(c, &a, &b)
            }
            op => panic!("blast_bv: unexpected op {op:?} (missing rewrite?)"),
        };
        self.bv_map.insert(t, bits.clone());
        bits
    }

    /// One constant operand turns the product into a fixed sum of shifted
    /// copies, and how many copies is a property of *how the constant is
    /// written*, not of its value — so it is worth recoding. Constness is read
    /// off the blasted bits rather than the term, which catches constants that
    /// only became constant during encoding and needs no operand reordering.
    fn multiplier(&mut self, a: &[AigLit], b: &[AigLit]) -> Vec<AigLit> {
        match (all_const(a), all_const(b)) {
            (Some(c), _) => self.const_multiplier(b, &c),
            (_, Some(c)) => self.const_multiplier(a, &c),
            _ => self.array_multiplier(a, b),
        }
    }

    /// `x * c` for a constant `c`: a fixed sum of shifted, optionally negated
    /// copies of `x`, one row per nonzero digit of `c`.
    ///
    /// How many rows that is depends on *how the constant is written*, not on
    /// its value. Straight binary spends a row per set bit, so `x * 0x3F`
    /// costs six additions; the non-adjacent form writes the same constant as
    /// `2^6 - 1` and costs one subtraction. NAF is never longer than binary
    /// and averages `w/3` digits against `w/2`, but it is not uniformly
    /// cheaper here — a negative digit in the lowest row turns free wiring
    /// into a full negation, which is why `x * 3` is better off as
    /// `(x<<1) + x` than as `(x<<2) - x`. So both encodings are costed and the
    /// cheaper one is built; this is a weak improvement on every constant
    /// rather than a trade.
    ///
    /// Each row adds into `acc[shift..]` only, exactly as the array
    /// multiplier does: the bits below the shift are already final, and the
    /// carry (or borrow) out of the top is dropped, which is the truncation
    /// mod `2^w` the semantics call for.
    fn const_multiplier(&mut self, x: &[AigLit], c: &[bool]) -> Vec<AigLit> {
        let w = x.len();
        let binary: Vec<(usize, bool)> = (0..w).filter(|&i| c[i]).map(|i| (i, false)).collect();
        let signed: Vec<(usize, bool)> = naf(c).into_iter().filter(|&(s, _)| s < w).collect();
        let rows = if row_cost(&signed, w) < row_cost(&binary, w) {
            signed
        } else {
            binary
        };

        let Some(&(s0, neg0)) = rows.first() else {
            return vec![FALSE; w];
        };
        // First row: wire `x << s0`, negated in place when its digit is -1.
        let mut acc: Vec<AigLit> = (0..w)
            .map(|i| if i >= s0 { x[i - s0] } else { FALSE })
            .collect();
        if neg0 {
            acc = self.negate_bits(&acc);
        }
        for &(s, neg) in &rows[1..] {
            let src = &x[..w - s];
            let addend: Vec<AigLit> = if neg {
                src.iter().map(|&l| !l).collect()
            } else {
                src.to_vec()
            };
            let carry_in = if neg { TRUE } else { FALSE };
            let upper: Vec<AigLit> = acc[s..].to_vec();
            let (sum, _) = self.adder(&upper, &addend, carry_in);
            acc.truncate(s);
            acc.extend(sum);
        }
        acc
    }

    /// Shift-and-add array multiplier: one row per bit of `b`, each added into
    /// the accumulator's surviving suffix.
    ///
    /// The row-by-row ripple is worth more than its gate count suggests.
    /// Because row `j` only ever touches `acc[j..]`, "the high half of an
    /// operand is zero" propagates into "the high product bits are zero" by
    /// unit propagation alone — no case split. A carry-save tree computes the
    /// same function with fewer gates and destroys that, which is why the
    /// Dadda-tree rewrite was rejected.
    fn array_multiplier(&mut self, a: &[AigLit], b: &[AigLit]) -> Vec<AigLit> {
        let w = a.len();
        let mut acc: Vec<AigLit> = a.iter().map(|&l| self.aig.and(l, b[0])).collect();
        for j in 1..w {
            let pp: Vec<AigLit> = a[..w - j].iter().map(|&l| self.aig.and(l, b[j])).collect();
            let upper: Vec<AigLit> = acc[j..].to_vec();
            let (sum, _) = self.adder(&upper, &pp, FALSE);
            acc.truncate(j);
            acc.extend(sum);
        }
        acc
    }

    fn shifter(
        &mut self,
        pool: &TermPool,
        ta: TermId,
        tamount: TermId,
        kind: ShiftKind,
    ) -> Vec<AigLit> {
        let a = self.blast_bv(pool, ta);
        let amt = self.blast_bv(pool, tamount);
        let w = a.len();
        let fill_top = match kind {
            ShiftKind::ArithRight => a[w - 1],
            _ => FALSE,
        };
        let stages = (0..32).take_while(|&j| (1u64 << j) < w as u64).count();
        let mut cur = a;
        for (j, &amt_bit) in amt.iter().enumerate().take(stages) {
            let sh = 1usize << j;
            let shifted: Vec<AigLit> = match kind {
                ShiftKind::Left => (0..w)
                    .map(|i| if i >= sh { cur[i - sh] } else { FALSE })
                    .collect(),
                _ => (0..w)
                    .map(|i| if i + sh < w { cur[i + sh] } else { fill_top })
                    .collect(),
            };
            cur = self.mux_bits(amt_bit, &shifted, &cur);
        }
        let high_bits: Vec<AigLit> = amt[stages..].to_vec();
        if high_bits.is_empty() {
            return cur;
        }
        let sat = self.aig.or_many(&high_bits);
        let sat_val = vec![fill_top; w];
        self.mux_bits(sat, &sat_val, &cur)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ShiftKind {
    Left,
    LogicalRight,
    ArithRight,
}

/// The bit pattern of a fully constant operand, LSB-first, or `None` if any
/// bit is a real gate.
fn all_const(bits: &[AigLit]) -> Option<Vec<bool>> {
    bits.iter()
        .map(|&l| {
            if l == TRUE {
                Some(true)
            } else if l == FALSE {
                Some(false)
            } else {
                None
            }
        })
        .collect()
}

/// Full-adder count for a row list at width `w`. The first row is free when
/// positive (it is wiring) and a full negation when negative; every later row
/// is an add or subtract over the `w - shift` bits above it.
fn row_cost(rows: &[(usize, bool)], w: usize) -> usize {
    let Some(&(s0, neg0)) = rows.first() else {
        return 0;
    };
    let first = if neg0 { w - s0 } else { 0 };
    first + rows[1..].iter().map(|&(s, _)| w - s).sum::<usize>()
}

/// Non-adjacent form of an unsigned constant given LSB-first: the rows
/// `(shift, negative)` whose signed sum is the constant.
///
/// The standard right-to-left construction: at an odd residue, choose the
/// digit in `{-1, +1}` that makes the next quotient even, which is what forces
/// nonzero digits apart and minimises how many there are. Digits at shift `w`
/// or beyond are dropped by the caller — they are multiples of `2^w`, and the
/// product is taken mod `2^w` anyway (this is exactly what turns `x * (2^w-1)`
/// into a single negation).
#[allow(clippy::needless_range_loop)]
fn naf(c: &[bool]) -> Vec<(usize, bool)> {
    let w = c.len();
    // Two guard limbs: the carry can propagate one position past the top.
    let mut d: Vec<u8> = c.iter().map(|&b| b as u8).collect();
    d.push(0);
    d.push(0);
    let mut out = Vec::new();
    for i in 0..w + 1 {
        if d[i] == 0 {
            continue;
        }
        // d[i] == 1 here; the digit is +1 unless the next bit is also set, in
        // which case -1 and a carry into position i+1 is shorter.
        let negative = d[i + 1] == 1;
        out.push((i, negative));
        d[i] = 0;
        if negative {
            let mut j = i + 1;
            while j < d.len() && d[j] == 1 {
                d[j] = 0;
                j += 1;
            }
            if j < d.len() {
                d[j] = 1;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use smtrs_core::Sort;
    use smtrs_sat::{BatsatBackend, SatResult};

    fn bits(width: u32, value: u128) -> Vec<bool> {
        (0..width).map(|i| (value >> i) & 1 == 1).collect()
    }

    /// The recoding has to denote the same number mod `2^w` — that is the
    /// whole correctness obligation for `naf` itself.
    fn value_of(rows: &[(usize, bool)], width: u32) -> u128 {
        let modulus = 1i128 << width;
        let mut acc = 0i128;
        for &(s, neg) in rows {
            let term = 1i128 << s;
            acc += if neg { -term } else { term };
        }
        acc.rem_euclid(modulus) as u128
    }

    #[test]
    fn naf_denotes_the_constant() {
        for width in [1u32, 2, 4, 7, 8] {
            for v in 0..(1u128 << width) {
                let rows = naf(&bits(width, v));
                assert_eq!(value_of(&rows, width), v, "width {width} value {v}");
            }
        }
    }

    #[test]
    fn naf_digits_are_non_adjacent_and_no_longer_than_binary() {
        for width in [8u32, 12] {
            for v in 0..(1u128 << width) {
                let rows = naf(&bits(width, v));
                for pair in rows.windows(2) {
                    assert!(pair[1].0 > pair[0].0 + 1, "adjacent digits for {v}");
                }
                let popcount = v.count_ones() as usize;
                assert!(rows.len() <= popcount, "NAF longer than binary for {v}");
            }
        }
    }

    #[test]
    fn naf_collapses_all_ones_to_one_negation() {
        // 0xFF as an 8-bit constant is -1: a single negated row at shift 0
        // plus a row at shift 8, which the caller drops.
        let rows = naf(&bits(8, 0xFF));
        assert_eq!(rows, vec![(0, true), (8, false)]);
    }

    /// Encode `x * c` through the blaster, then read the product back out of
    /// a SAT model for each `x`. This is the property that matters: whichever
    /// recoding `const_multiplier` costs cheaper, the circuit it builds must
    /// compute exact multiplication mod 2^w.
    fn check_const_multiplier(width: u32, c: u64, xs: &[u64]) {
        let mask = if width == 64 {
            u64::MAX
        } else {
            (1u64 << width) - 1
        };
        let mut pool = TermPool::new();
        let sym = pool.fresh_symbol("x", Sort::BitVec(width));
        let x = pool.var(sym);
        let cterm = pool.bv_u64(width, c & mask);
        let t = pool.mk(Op::BvMul, &[x, cterm]).unwrap();

        let mut bb = BitBlaster::new();
        let mut sat = BatsatBackend::new();
        let prod = bb.blast_bv(&pool, t);
        let xb = bb.blast_bv(&pool, x);
        assert_eq!(prod.len(), width as usize);
        let xlits: Vec<_> = xb.iter().map(|&b| bb.aig.emit(&mut sat, b)).collect();
        for &b in &prod {
            bb.aig.emit(&mut sat, b);
        }

        for &xv in xs {
            let xv = xv & mask;
            let assumptions: Vec<_> = (0..width as usize)
                .map(|i| {
                    if (xv >> i) & 1 == 1 {
                        xlits[i]
                    } else {
                        !xlits[i]
                    }
                })
                .collect();
            assert_eq!(
                sat.solve(&assumptions),
                SatResult::Sat,
                "w={width} c={c:#x}"
            );
            let mut got: u64 = 0;
            for (i, &p) in prod.iter().enumerate().take(width as usize) {
                if bb.aig.value(&sat, p).expect("emitted") {
                    got |= 1 << i;
                }
            }
            let want = xv.wrapping_mul(c) & mask;
            assert_eq!(got, want, "w={width} x={xv:#x} c={c:#x}");
        }
    }

    #[test]
    fn const_multiplier_matches_exact_multiplication() {
        for width in [1u32, 2, 3, 5, 8, 16, 32] {
            let mask = ((1u128 << width) - 1) as u64;
            let mut consts: Vec<u64> = vec![
                0,
                1,
                2,
                3,
                5,
                7,
                0x3f,
                0x55,
                0xaa,
                mask,     // -1
                mask - 1, // -2
                mask - 2, // -3
            ];
            // Every power of two and every all-ones mask at this width: the
            // two families the recoding is supposed to collapse.
            for k in 0..width {
                consts.push(1u64 << k);
                consts.push(((1u128 << (k + 1)) - 1) as u64);
            }
            consts.sort_unstable();
            consts.dedup();

            let xs: Vec<u64> = vec![0, 1, 2, 3, 0x5a, mask, mask >> 1, 0x12345678];
            for c in consts {
                check_const_multiplier(width, c, &xs);
            }
        }
    }

    /// Exhaustive at a small width: every constant against every `x`.
    #[test]
    fn const_multiplier_is_exhaustively_exact_at_width_5() {
        let xs: Vec<u64> = (0..32).collect();
        for c in 0..32u64 {
            check_const_multiplier(5, c, &xs);
        }
    }
}
