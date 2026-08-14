//! Rewrite-soundness checking support.
//!
//! For a rewrite `t -> r`, emits an SMT-LIB query asserting `t != r`. If a
//! reference solver reports `unsat`, the rewrite is sound for that instance.
//! The test suite (and CI, when a reference solver is on PATH) runs every
//! rule's representative instances through this at several widths.

use smtrs_core::{Op, Sort, TermId, TermPool};

/// Collect the free variables of `roots` (deterministic order of first visit).
pub fn free_vars(pool: &TermPool, roots: &[TermId]) -> Vec<(String, Sort)> {
    let mut vars: Vec<(String, Sort)> = Vec::new();
    pool.post_order(roots, |pool, t| {
        if let Op::Var(sym) = pool.op(t) {
            let s = pool.symbol(sym);
            if !vars.iter().any(|(n, _)| *n == s.name) {
                vars.push((s.name.clone(), s.sort));
            }
        }
    });
    vars
}

/// SMT-LIB query that is unsat iff `a` and `b` are equivalent.
pub fn equiv_query(pool: &TermPool, a: TermId, b: TermId) -> String {
    let mut out = String::new();
    out.push_str("(set-logic QF_BV)\n");
    for (name, sort) in free_vars(pool, &[a, b]) {
        out.push_str(&format!("(declare-const {name} {sort})\n"));
    }
    out.push_str(&format!(
        "(assert (distinct {} {}))\n(check-sat)\n",
        pool.display(a),
        pool.display(b)
    ));
    out
}

/// Terms exercising linear normalization (coefficient collection and
/// constant distribution) and the disjoint-`or` rule, at width `w`.
/// Returns the seed terms themselves.
pub fn linear_and_or_seeds(pool: &mut TermPool, w: u32) -> Vec<TermId> {
    let xs = pool.fresh_symbol("x", Sort::BitVec(w));
    let ys = pool.fresh_symbol("y", Sort::BitVec(w));
    let zs = pool.fresh_symbol("z", Sort::BitVec(w));
    let (x, y, z) = (pool.var(xs), pool.var(ys), pool.var(zs));
    let mut out: Vec<TermId> = Vec::new();

    // Constants that stay in range at every width, including w = 1.
    let m = |v: u64| if w >= 64 { v } else { v % (1u64 << w) };
    let k2 = pool.bv_u64(w, m(2));
    let k3 = pool.bv_u64(w, m(3));
    let k4 = pool.bv_u64(w, m(4));
    let k5 = pool.bv_u64(w, m(5));
    let ones = pool.bv(smtrs_core::BvConst::ones(w));

    // --- linear normalization: distribution through a coefficient.
    // x + 2*y + (-2)*(y + 4)  ==  x - 8   (a ring identity at every width)
    let neg2 = pool.mk(Op::BvNeg, &[k2]).unwrap();
    let yp4 = pool.mk(Op::BvAdd, &[y, k4]).unwrap();
    let m2y = pool.mk(Op::BvMul, &[k2, y]).unwrap();
    let mn2yp4 = pool.mk(Op::BvMul, &[neg2, yp4]).unwrap();
    out.push(pool.mk(Op::BvAdd, &[m2y, mn2yp4, x]).unwrap());

    // -(x + y) + x + 3*(y + z) - 3*z
    let xy = pool.mk(Op::BvAdd, &[x, y]).unwrap();
    let nxy = pool.mk(Op::BvNeg, &[xy]).unwrap();
    let yz = pool.mk(Op::BvAdd, &[y, z]).unwrap();
    let m3yz = pool.mk(Op::BvMul, &[k3, yz]).unwrap();
    let m3z = pool.mk(Op::BvMul, &[k3, z]).unwrap();
    let nm3z = pool.mk(Op::BvNeg, &[m3z]).unwrap();
    out.push(pool.mk(Op::BvAdd, &[nxy, x, m3yz, nm3z]).unwrap());

    // A shared sum appearing both scaled and unscaled (needs `Full` mode).
    let s = pool.mk(Op::BvAdd, &[x, k5]).unwrap();
    let ns = pool.mk(Op::BvNeg, &[s]).unwrap();
    out.push(pool.mk(Op::BvAdd, &[s, ns, s, y]).unwrap());

    // bvsub under a coefficient.
    let sub = pool.mk(Op::BvSub, &[x, yp4]).unwrap();
    let m5sub = pool.mk(Op::BvMul, &[k5, sub]).unwrap();
    let m5y = pool.mk(Op::BvMul, &[k5, y]).unwrap();
    out.push(pool.mk(Op::BvAdd, &[m5sub, m5y]).unwrap());

    // 3 * (2*(x - 1) + y): nested coefficients.
    let x1 = pool.mk(Op::BvAdd, &[x, ones]).unwrap();
    let m2x1 = pool.mk(Op::BvMul, &[k2, x1]).unwrap();
    let inner = pool.mk(Op::BvAdd, &[m2x1, y]).unwrap();
    out.push(pool.mk(Op::BvMul, &[k3, inner]).unwrap());

    // The same shapes under equality and comparison, where the normalized
    // form goes on to feed constant cancellation and concat splitting.
    for a in out.clone() {
        out.push(pool.mk(Op::Eq, &[a, x]).unwrap());
        out.push(pool.mk(Op::BvUle, &[a, y]).unwrap());
    }

    // --- pulling a common factor out of a sum, and the not/neg interchange
    // that turns `~(-x)` into the sum-with-constant the factoring can use.
    let xx = pool.mk(Op::BvMul, &[x, x]).unwrap();
    let xy2 = pool.mk(Op::BvMul, &[x, y]).unwrap();
    let xz2 = pool.mk(Op::BvMul, &[x, z]).unwrap();
    let xyz = pool.mk(Op::BvMul, &[x, y, z]).unwrap();
    out.push(pool.mk(Op::BvAdd, &[xx, xy2]).unwrap());
    out.push(pool.mk(Op::BvAdd, &[xy2, xz2]).unwrap());
    out.push(pool.mk(Op::BvAdd, &[xy2, xz2, xyz]).unwrap());
    out.push(pool.mk(Op::BvAdd, &[xy2, x]).unwrap());
    let nxy2 = pool.mk(Op::BvNeg, &[xy2]).unwrap();
    out.push(pool.mk(Op::BvAdd, &[xx, nxy2]).unwrap());
    let nx = pool.mk(Op::BvNeg, &[x]).unwrap();
    out.push(pool.mk(Op::BvAdd, &[xy2, nx]).unwrap());
    let k3xy = pool.mk(Op::BvMul, &[k3, x, y]).unwrap();
    out.push(pool.mk(Op::BvAdd, &[k3xy, xz2]).unwrap());
    out.push(pool.mk(Op::BvAdd, &[k3xy, x]).unwrap());
    // Negative cases: no common factor, and a constant summand.
    out.push(pool.mk(Op::BvAdd, &[xy2, z]).unwrap());
    out.push(pool.mk(Op::BvAdd, &[xy2, k3]).unwrap());
    let negx = pool.mk(Op::BvNeg, &[x]).unwrap();
    let notnegx = pool.mk(Op::BvNot, &[negx]).unwrap();
    out.push(notnegx);
    let notx = pool.mk(Op::BvNot, &[x]).unwrap();
    out.push(pool.mk(Op::BvNeg, &[notx]).unwrap());
    out.push(pool.mk(Op::BvMul, &[y, notnegx]).unwrap());

    // --- shifting a term by its own value. These rest on `x < 2^x`, which
    // holds at every width, but the boundary between "shifts within the
    // width" and "saturates" moves with the width, so sweep them all.
    let shlxx = pool.mk(Op::BvShl, &[x, x]).unwrap();
    out.push(pool.mk(Op::BvAdd, &[x, shlxx]).unwrap());
    out.push(pool.mk(Op::BvAdd, &[shlxx, x]).unwrap());
    // The negative case: `y + (x << x)` carries like any other sum.
    out.push(pool.mk(Op::BvAdd, &[y, shlxx]).unwrap());
    let shlxy = pool.mk(Op::BvShl, &[x, y]).unwrap();
    out.push(pool.mk(Op::BvAdd, &[x, shlxy]).unwrap());
    for op in [Op::BvShl, Op::BvLshr, Op::BvAshr] {
        out.push(pool.mk(op, &[x, x]).unwrap());
        let nx = pool.mk(Op::BvNot, &[x]).unwrap();
        out.push(pool.mk(op, &[nx, x]).unwrap());
        // The negative cases: the rules must decline when the shifted term is
        // not the shift amount, or is only nearly so.
        out.push(pool.mk(op, &[x, y]).unwrap());
        let ny = pool.mk(Op::BvNot, &[y]).unwrap();
        out.push(pool.mk(op, &[ny, x]).unwrap());
        let negx = pool.mk(Op::BvNeg, &[x]).unwrap();
        out.push(pool.mk(op, &[negx, x]).unwrap());
    }

    // --- disjoint or: half-word assembly at this width.
    if w >= 2 {
        let h = w / 2;
        let shift = pool.bv_u64(w, h as u64);
        let zhi = pool.bv(smtrs_core::BvConst::zero(w - h));
        let zlo = pool.bv(smtrs_core::BvConst::zero(h));
        let lo_mask = pool.bv(smtrs_core::BvConst::ones(h).zero_extend(w - h));

        // (x << h) | zero_extend(y[h-1:0])
        let hi = pool.mk(Op::BvShl, &[x, shift]).unwrap();
        let lo_bits = pool.mk(Op::Extract { hi: h - 1, lo: 0 }, &[y]).unwrap();
        let lo = pool.mk(Op::ZeroExtend(w - h), &[lo_bits]).unwrap();
        out.push(pool.mk(Op::BvOr, &[hi, lo]).unwrap());

        // The same, built from concats.
        let top = pool
            .mk(
                Op::Extract {
                    hi: w - h - 1,
                    lo: 0,
                },
                &[z],
            )
            .unwrap();
        let a = pool.mk(Op::Concat, &[zhi, lo_bits]).unwrap();
        let b = pool.mk(Op::Concat, &[top, zlo]).unwrap();
        out.push(pool.mk(Op::BvOr, &[a, b]).unwrap());

        // Overlapping operands: the rule must decline. Checked anyway.
        out.push(pool.mk(Op::BvOr, &[a, x]).unwrap());

        // (x >> h) | (y << h): disjoint the other way round.
        let sr = pool.mk(Op::BvLshr, &[x, shift]).unwrap();
        let sl = pool.mk(Op::BvShl, &[y, shift]).unwrap();
        out.push(pool.mk(Op::BvOr, &[sr, sl]).unwrap());

        // An `and`-masked operand: the mask analysis must see through it.
        let masked = pool.mk(Op::BvAnd, &[x, lo_mask]).unwrap();
        out.push(pool.mk(Op::BvOr, &[masked, b]).unwrap());

        // Nested assembly plus a comparison and an equality over it.
        let asm = pool.mk(Op::BvOr, &[hi, lo]).unwrap();
        out.push(pool.mk(Op::Eq, &[asm, k5]).unwrap());
        out.push(pool.mk(Op::BvUle, &[asm, z]).unwrap());
        out.push(pool.mk(Op::BvSle, &[asm, z]).unwrap());

        // --- the same assembly written with `+` and with `xor`. Disjoint
        // operands generate no carry, so both equal the `or`; if the mask
        // analysis over-claimed a zero bit these would differ from it, and
        // the enumeration/z3 check below is what says they do not.
        out.push(pool.mk(Op::BvAdd, &[hi, lo]).unwrap());
        out.push(pool.mk(Op::BvXor, &[hi, lo]).unwrap());
        out.push(pool.mk(Op::BvAdd, &[a, b]).unwrap());
        // Operands that overlap in exactly one bit: the rule must decline,
        // and the wrong answer here is the *cheaper* one (a concat rather
        // than an adder), so nothing but the check stands in its way.
        out.push(pool.mk(Op::BvAdd, &[lo, lo]).unwrap());
        out.push(pool.mk(Op::BvAdd, &[hi, x]).unwrap());
        out.push(pool.mk(Op::BvXor, &[a, x]).unwrap());
    }

    // Shapes that exist to exercise the mask analysis's newer cases. Each is
    // a sum whose disjointness is only visible if the mask of one operand is
    // narrower than its width.
    if w >= 4 {
        let h = w / 2;
        let zlow = pool.mk(Op::Extract { hi: h - 1, lo: 0 }, &[y]).unwrap();
        let zext_low = pool.mk(Op::ZeroExtend(w - h), &[zlow]).unwrap();

        // A sum of two h-bit values needs h+1 bits, never more: the magnitude
        // bound, not the bitwise union, is what proves the top bits zero.
        let zlow2 = pool.mk(Op::Extract { hi: h - 1, lo: 0 }, &[z]).unwrap();
        let zext_low2 = pool.mk(Op::ZeroExtend(w - h), &[zlow2]).unwrap();
        let narrow_sum = pool.mk(Op::BvAdd, &[zext_low, zext_low2]).unwrap();
        // Not `bv_u64(w, 1 << (w - 1))`: this sweep runs to w = 65, where that
        // shift overflows `u64` — a debug panic, and in release a silent mask
        // to `1 << 0`, which degrades the seed to a multiply-by-one and makes
        // the whole width look verified when nothing was checked. Bit w-1 of a
        // multi-limb vector has to be built as one.
        let top_bit = pool.bv(smtrs_core::BvConst::zero(w).not().shl_small(w - 1));
        let top = pool.mk(Op::BvMul, &[top_bit, x]).unwrap();
        out.push(pool.mk(Op::BvAdd, &[top, narrow_sum]).unwrap());
        out.push(pool.mk(Op::BvOr, &[top, narrow_sum]).unwrap());

        // Multiplication by 2^k is a shift, so the product's live range moves
        // up by k and can clear the way for a disjoint low operand.
        let two = pool.bv_u64(w, 2);
        let scaled = pool.mk(Op::BvMul, &[two, zext_low]).unwrap();
        let bit0 = pool.mk(Op::Extract { hi: 0, lo: 0 }, &[z]).unwrap();
        let bit0w = pool.mk(Op::ZeroExtend(w - 1), &[bit0]).unwrap();
        out.push(pool.mk(Op::BvAdd, &[scaled, bit0w]).unwrap());

        // Sign extension of a value whose own top bit is provably 0 is zero
        // extension; of one that is not, nothing is known.
        let narrow = pool.mk(Op::Extract { hi: h - 2, lo: 0 }, &[y]).unwrap();
        let padded = pool.mk(Op::ZeroExtend(1), &[narrow]).unwrap();
        let sext = pool.mk(Op::SignExtend(w - h), &[padded]).unwrap();
        let shift_h = pool.bv_u64(w, h as u64);
        let hi_half = pool.mk(Op::BvShl, &[x, shift_h]).unwrap();
        out.push(pool.mk(Op::BvAdd, &[hi_half, sext]).unwrap());
        // The un-padded version really can be negative: must not be treated
        // as disjoint from anything.
        let sext_wide = pool.mk(Op::SignExtend(w - h), &[zlow]).unwrap();
        out.push(pool.mk(Op::BvAdd, &[hi_half, sext_wide]).unwrap());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Rewriter;
    use smtrs_core::TermPool;
    use std::io::Write as _;
    use std::process::{Command, Stdio};

    fn z3_available() -> bool {
        Command::new("z3")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn check_unsat_with_z3(query: &str) -> bool {
        let mut child = Command::new("z3")
            .args(["-in", "-smt2"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn z3");
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(query.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        String::from_utf8_lossy(&out.stdout).trim() == "unsat"
    }

    /// Random-ish term generator over the supported BV/Bool ops, then checks
    /// rewrite soundness against Z3. Deterministic seed: reproducible.
    #[test]
    fn rewrites_sound_vs_z3() {
        if !z3_available() {
            eprintln!("z3 not on PATH; skipping rewrite soundness test");
            return;
        }
        for width in [1u32, 3, 8, 32, 64, 65] {
            let mut pool = TermPool::new();
            let xs = pool.fresh_symbol("x", Sort::BitVec(width));
            let ys = pool.fresh_symbol("y", Sort::BitVec(width));
            let x = pool.var(xs);
            let y = pool.var(ys);
            let c1 = pool.bv_u64(width, 1);
            let c3 = pool.bv_u64(width, 3 % (1u64 << width.min(63))); // in range for w=1
            let mut terms = vec![x, y, c1, c3];

            // Build a deterministic pile of candidate terms exercising rules.
            fn push(t: Option<TermId>, terms: &mut Vec<TermId>) {
                if let Some(t) = t {
                    terms.push(t);
                }
            }
            let binops = [
                Op::BvAdd,
                Op::BvSub,
                Op::BvMul,
                Op::BvUdiv,
                Op::BvUrem,
                Op::BvSdiv,
                Op::BvSrem,
                Op::BvSmod,
                Op::BvAnd,
                Op::BvOr,
                Op::BvXor,
                Op::BvNand,
                Op::BvNor,
                Op::BvXnor,
                Op::BvShl,
                Op::BvLshr,
                Op::BvAshr,
            ];
            let seeds = terms.clone();
            for (i, &op) in binops.iter().enumerate() {
                let a = seeds[i % seeds.len()];
                let b = seeds[(i + 1) % seeds.len()];
                push(pool.mk(op, &[a, b]).ok(), &mut terms);
                push(pool.mk(op, &[a, a]).ok(), &mut terms);
            }
            for &op in &[Op::BvNeg, Op::BvNot] {
                push(pool.mk(op, &[x]).ok(), &mut terms);
                let nested = pool.mk(op, &[x]).unwrap();
                push(pool.mk(op, &[nested]).ok(), &mut terms);
            }
            if width >= 4 {
                let e1 = pool
                    .mk(
                        Op::Extract {
                            hi: width - 1,
                            lo: 1,
                        },
                        &[x],
                    )
                    .ok();
                push(e1, &mut terms);
                let cc = pool.mk(Op::Concat, &[x, y]).unwrap();
                let e2 = pool
                    .mk(
                        Op::Extract {
                            hi: width + 1,
                            lo: width - 2,
                        },
                        &[cc],
                    )
                    .ok();
                push(e2, &mut terms);
            }
            for &op in &[
                Op::ZeroExtend(3),
                Op::SignExtend(3),
                Op::RotateLeft(1),
                Op::RotateRight(2),
                Op::Repeat(2),
            ] {
                push(pool.mk(op, &[x]).ok(), &mut terms);
            }
            let cmps = [
                Op::BvUlt,
                Op::BvUle,
                Op::BvUgt,
                Op::BvUge,
                Op::BvSlt,
                Op::BvSle,
                Op::BvSgt,
                Op::BvSge,
                Op::BvComp,
            ];
            for (i, &op) in cmps.iter().enumerate() {
                let a = seeds[i % seeds.len()];
                push(
                    pool.mk(op, &[a, seeds[(i + 3) % seeds.len()]]).ok(),
                    &mut terms,
                );
            }
            // Bool layer.
            let p1 = pool.mk(Op::BvUlt, &[x, y]).unwrap();
            let p2 = pool.mk(Op::Eq, &[x, c3]).unwrap();
            let np1 = pool.mk(Op::Not, &[p1]).unwrap();
            for t in [
                pool.mk(Op::And, &[p1, np1]).unwrap(),
                pool.mk(Op::Or, &[p1, np1]).unwrap(),
                pool.mk(Op::Xor, &[p1, p2]).unwrap(),
                pool.mk(Op::Implies, &[p1, p2]).unwrap(),
                pool.mk(Op::Ite, &[p1, x, y]).unwrap(),
                pool.mk(Op::Distinct, &[x, y, c1]).unwrap(),
                pool.mk(Op::Eq, &[p1, pool.false_term]).unwrap(),
            ] {
                terms.push(t);
            }

            let mut rw = Rewriter::new();
            let mut checked = 0;
            for &t in &terms {
                let r = rw.rewrite(&mut pool, t);
                if r == t {
                    continue;
                }
                let q = equiv_query(&pool, t, r);
                assert!(
                    check_unsat_with_z3(&q),
                    "UNSOUND rewrite at width {width}:\n  {}\n  -> {}\nquery:\n{q}",
                    pool.display(t),
                    pool.display(r)
                );
                checked += 1;
            }
            assert!(
                checked > 10,
                "expected many rewrites to fire at width {width}"
            );
        }
    }

    /// SMT-LIB query that is unsat iff `t` is valid.
    fn valid_query(pool: &TermPool, t: TermId) -> String {
        let mut out = String::from("(set-logic QF_BV)\n");
        for (name, sort) in free_vars(pool, &[t]) {
            out.push_str(&format!("(declare-const {name} {sort})\n"));
        }
        out.push_str(&format!(
            "(assert (not {}))\n(check-sat)\n",
            pool.display(t)
        ));
        out
    }

    /// Every rewrite the new linear-normalization and disjoint-`or` rules
    /// perform must preserve meaning at *every* width, so this sweeps 1..=65
    /// rather than the sampled widths the general test uses.
    #[test]
    fn linear_and_disjoint_or_sound_vs_z3() {
        if !z3_available() {
            eprintln!("z3 not on PATH; skipping");
            return;
        }
        let mut fired = 0;
        for width in 1u32..=65 {
            let mut pool = TermPool::new();
            let seeds = super::linear_and_or_seeds(&mut pool, width);
            let mut rw = Rewriter::new();
            for t in seeds {
                let r = rw.rewrite(&mut pool, t);
                if r == t {
                    continue;
                }
                fired += 1;
                let q = equiv_query(&pool, t, r);
                assert!(
                    check_unsat_with_z3(&q),
                    "UNSOUND rewrite at width {width}:\n  {}\n  -> {}\nquery:\n{q}",
                    pool.display(t),
                    pool.display(r)
                );
            }
        }
        assert!(
            fired > 200,
            "expected the new rules to fire widely, got {fired}"
        );
    }

    /// The zero-bit analysis behind `or-disjoint-concat` is the one place the
    /// rule's soundness is not syntactic: it claims certain bits of a term are
    /// always 0. Check that claim directly — `t & ~mask` must be identically 0.
    #[test]
    fn nonzero_mask_never_overclaims() {
        if !z3_available() {
            eprintln!("z3 not on PATH; skipping");
            return;
        }
        let mut checked = 0;
        for width in 1u32..=65 {
            let mut pool = TermPool::new();
            // Reuse the same term pile; every subterm gets its mask checked.
            let seeds = super::linear_and_or_seeds(&mut pool, width);
            let mut subterms: Vec<TermId> = Vec::new();
            pool.post_order(&seeds, |pool, t| {
                if pool.sort(t).is_bv() {
                    subterms.push(t);
                }
            });
            for t in subterms {
                let mask = crate::nonzero_mask(&pool, t);
                if mask == smtrs_core::BvConst::ones(pool.width(t)) {
                    continue; // claims nothing
                }
                let mt = pool.bv(mask);
                let nmask = pool.mk(Op::BvNot, &[mt]).unwrap();
                let anded = pool.mk(Op::BvAnd, &[t, nmask]).unwrap();
                let zero = pool.bv(smtrs_core::BvConst::zero(pool.width(t)));
                let claim = pool.mk(Op::Eq, &[anded, zero]).unwrap();
                let q = valid_query(&pool, claim);
                assert!(
                    check_unsat_with_z3(&q),
                    "nonzero_mask over-claims zero bits at width {width} for {}\nquery:\n{q}",
                    pool.display(t)
                );
                checked += 1;
            }
        }
        assert!(
            checked > 100,
            "expected many masks to claim something, got {checked}"
        );
    }
}
