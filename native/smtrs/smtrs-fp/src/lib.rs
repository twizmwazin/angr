//! smtrs-fp: floating point by word-blasting to bit-vectors.
//!
//! FP terms are lowered into BV/Bool terms in the same `TermPool` before the
//! solver's normal pipeline runs, so the rewriter, AIG bit-blaster and CDCL
//! engine need no FP awareness at all. This is the SymFPU approach that both
//! cvc5 and Bitwuzla use, implemented natively over our term DAG.
//!
//! `lower` walks the assertion set bottom-up. FP-sorted subterms become
//! `Unpacked` values (class flags + sign + exponent + significand, all BV
//! terms); Bool- and BV-sorted results (predicates, `fp.to_ieee_bv`,
//! `fp.to_ubv`) come back as ordinary terms that replace the original node.

mod concrete;
mod ops;
mod round;
mod unpacked;

use rustc_hash::FxHashMap;
use smtrs_core::{BvConst, Op, Sort, TermId, TermPool};
use unpacked::{Format, Unpacked, B};

pub use unpacked::Format as FpFormat;

/// Result of lowering a single term.
#[derive(Clone, Copy)]
enum Lowered {
    /// The term keeps its sort and is replaced by this (Bool/BV) term.
    Term(TermId),
    /// The term was FP-sorted and is represented by these components.
    Fp(Unpacked),
    /// Rounding mode terms pass through unchanged.
    Rm(TermId),
}

#[derive(Debug)]
pub enum LowerError {
    /// An FP construct we do not implement (the solver answers `unknown`).
    Unsupported(&'static str),
}

impl std::fmt::Display for LowerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LowerError::Unsupported(s) => write!(f, "floating point: {s}"),
        }
    }
}

fn fmt_of(sort: Sort) -> Format {
    match sort {
        Sort::Float(eb, sb) => Format { eb, sb },
        _ => unreachable!("fmt_of on non-float sort"),
    }
}

/// Does this term set contain any floating-point operator?
pub fn contains_fp(pool: &TermPool, roots: &[TermId]) -> bool {
    let mut found = false;
    pool.post_order(roots, |pool, t| {
        if pool.op(t).is_fp() || matches!(pool.sort(t), Sort::Float(..) | Sort::RoundingMode) {
            found = true;
        }
    });
    found
}

/// Constant floating-point values recovered before lowering.
///
/// Only populated when the problem uses `fp.rem`, which — unlike every other
/// operator here — cannot be encoded as a circuit for a double (see
/// `concrete`) and so depends on seeing its operands as values. Leaving the
/// map empty otherwise means no other benchmark's circuit changes shape.
#[derive(Default)]
struct ConstEnv {
    /// Are we folding literal FP terms at all?
    fold: bool,
    /// Float-sorted variables pinned to a literal by a top-level equality.
    vars: FxHashMap<TermId, BvConst>,
}

/// The IEEE bit pattern of a float-sorted term, if it is a literal.
fn fp_literal_bits(pool: &TermPool, t: TermId) -> Option<BvConst> {
    let Sort::Float(eb, sb) = pool.sort(t) else {
        return None;
    };
    let total = eb + sb;
    let args = pool.args(t);
    match pool.op(t) {
        Op::FpFromBits => {
            let s = pool.as_bv_const(args[0])?;
            let e = pool.as_bv_const(args[1])?;
            let f = pool.as_bv_const(args[2])?;
            Some(BvConst::from_bits(total, |i| {
                if i == total - 1 {
                    s.bit(0)
                } else if i >= sb - 1 {
                    e.bit(i - (sb - 1))
                } else {
                    f.bit(i)
                }
            }))
        }
        Op::FpFromIeeeBv { .. } => pool.as_bv_const(args[0]).cloned(),
        // Any quiet NaN denotes the same value; use the canonical one.
        Op::FpNan => Some(BvConst::from_bits(total, |i| i >= sb - 2 && i < total - 1)),
        Op::FpInf(neg) => Some(BvConst::from_bits(total, |i| {
            (i >= sb - 1 && i < total - 1) || (neg && i == total - 1)
        })),
        Op::FpZero(neg) => Some(BvConst::from_bits(total, |i| neg && i == total - 1)),
        _ => None,
    }
}

/// Collect float variables that a top-level equality pins to a literal.
///
/// Substituting a variable for a value it is asserted equal to is sound, and
/// the equality itself stays asserted (it just becomes trivially true).
fn const_env(pool: &TermPool, roots: &[TermId]) -> ConstEnv {
    // Escape hatch for differential testing: with folding off, a constant
    // `fp.rem` takes the same reduction circuit a symbolic one would, so the
    // two implementations of the operator can be run against each other.
    if std::env::var_os("SMTRS_FP_NO_CONST_FOLD").is_some() {
        return ConstEnv::default();
    }
    let mut fold = false;
    pool.post_order(roots, |pool, t| {
        if pool.op(t) == Op::FpRem {
            fold = true;
        }
    });
    let mut env = ConstEnv {
        fold,
        vars: FxHashMap::default(),
    };
    if !fold {
        return env;
    }
    for &r in roots {
        let args = pool.args(r);
        if pool.op(r) != Op::Eq || args.len() != 2 {
            continue;
        }
        // `mk` sorts commutative operands, so either side may hold the value.
        for (v, k) in [(args[0], args[1]), (args[1], args[0])] {
            if matches!(pool.op(v), Op::Var(_)) {
                if let Some(bits) = fp_literal_bits(pool, k) {
                    env.vars.insert(v, bits);
                }
            }
        }
    }
    env
}

/// Lower every FP construct in `roots` to BV/Bool terms. Returns the rewritten
/// roots (same length, same order).
pub fn lower(pool: &mut TermPool, roots: &[TermId]) -> Result<Vec<TermId>, LowerError> {
    let mut cache: FxHashMap<TermId, Lowered> = FxHashMap::default();
    let mut order: Vec<TermId> = Vec::new();
    pool.post_order(roots, |_, t| order.push(t));
    let consts = const_env(pool, roots);

    for t in order {
        let op = pool.op(t);
        let sort = pool.sort(t);
        let args: Vec<TermId> = pool.args(t).to_vec();
        let lowered_args: Vec<Lowered> = args.iter().map(|a| cache[a]).collect();
        let mut b = B { pool };
        let result =
            lower_node(&mut b, t, op, sort, &args, &lowered_args, &consts).map_err(|e| {
                if std::env::var_os("SMTRS_DEBUG").is_some() {
                    eprintln!("; fp: failed on op {op:?} sort {sort:?}: {e}");
                }
                e
            })?;
        cache.insert(t, result);
    }

    roots
        .iter()
        .map(|r| match cache[r] {
            Lowered::Term(t) => Ok(t),
            Lowered::Fp(_) => Err(LowerError::Unsupported("float-sorted assertion")),
            Lowered::Rm(t) => Ok(t),
        })
        .collect()
}

fn as_fp(l: &Lowered) -> Result<Unpacked, LowerError> {
    match l {
        Lowered::Fp(u) => Ok(*u),
        _ => Err(LowerError::Unsupported("expected a float operand")),
    }
}

fn as_term(l: &Lowered) -> Result<TermId, LowerError> {
    match l {
        Lowered::Term(t) | Lowered::Rm(t) => Ok(*t),
        Lowered::Fp(_) => Err(LowerError::Unsupported("unexpected float operand")),
    }
}

/// `fp.rem`, evaluated when both operands are known and encoded otherwise.
fn rem_value(b: &mut B, x: &Unpacked, y: &Unpacked) -> Result<Unpacked, LowerError> {
    let known = concrete::of_unpacked(b.pool, x).zip(concrete::of_unpacked(b.pool, y));
    if let Some(r) = known.and_then(|(cx, cy)| concrete::rem(x.fmt, &cx, &cy)) {
        return Ok(concrete::to_unpacked(b, x.fmt, &r));
    }
    ops::rem(b, x, y).ok_or(LowerError::Unsupported(
        "fp.rem with symbolic operands in a format this wide",
    ))
}

fn lower_node(
    b: &mut B,
    term: TermId,
    op: Op,
    sort: Sort,
    orig_args: &[TermId],
    args: &[Lowered],
    consts: &ConstEnv,
) -> Result<Lowered, LowerError> {
    // Non-FP operators: rebuild with lowered children (children only change
    // when they contained FP, e.g. `(= (fp.to_ieee_bv x) y)`).
    if !op.is_fp() {
        return match sort {
            Sort::Float(..) => {
                // A float-sorted variable or ite: variables become a fresh
                // IEEE bit-vector that we unpack; ites select componentwise.
                match op {
                    Op::Var(sym) => {
                        let fmt = fmt_of(sort);
                        if let Some(bits) = consts.vars.get(&term) {
                            let c = concrete::decode(fmt, bits);
                            return Ok(Lowered::Fp(concrete::to_unpacked(b, fmt, &c)));
                        }
                        let name = b.pool.symbol(sym).name.clone();
                        let bv_sym = b
                            .pool
                            .fresh_symbol(format!("{name}!ieee"), Sort::BitVec(fmt.total_width()));
                        let bits = b.pool.var(bv_sym);
                        Ok(Lowered::Fp(unpacked::unpack(b, fmt, bits)))
                    }
                    Op::Ite => {
                        let c = as_term(&args[0])?;
                        let x = as_fp(&args[1])?;
                        let y = as_fp(&args[2])?;
                        Ok(Lowered::Fp(unpacked::ite_unpacked(b, c, &x, &y)))
                    }
                    _ => Err(LowerError::Unsupported("unsupported float-sorted term")),
                }
            }
            // A symbolic rounding mode would need the rounder to branch on a
            // variable; the corpus (and angr) only ever use literals.
            Sort::RoundingMode => Err(LowerError::Unsupported("symbolic rounding mode")),
            _ => {
                // Bool/BV term: equality over floats needs FP semantics.
                if matches!(op, Op::Eq | Op::Distinct)
                    && matches!(args.first(), Some(Lowered::Fp(_)))
                {
                    let vals: Result<Vec<Unpacked>, LowerError> = args.iter().map(as_fp).collect();
                    let vals = vals?;
                    // SMT-LIB `=` on floats is *structural* (identical values),
                    // unlike fp.eq: NaN = NaN holds, +0 = -0 does not.
                    let mut conj = Vec::new();
                    for w in vals.windows(2) {
                        conj.push(structural_eq(b, &w[0], &w[1]));
                    }
                    let all = b.and(&conj);
                    return Ok(Lowered::Term(if op == Op::Eq {
                        all
                    } else {
                        // distinct over floats: pairwise not-equal.
                        let mut ne = Vec::new();
                        for i in 0..vals.len() {
                            for j in i + 1..vals.len() {
                                let e = structural_eq(b, &vals[i], &vals[j]);
                                let n = b.not(e);
                                ne.push(n);
                            }
                        }
                        b.and(&ne)
                    }));
                }
                let new_args: Result<Vec<TermId>, LowerError> = args.iter().map(as_term).collect();
                let new_args = new_args?;
                if new_args == orig_args {
                    // Nothing below changed: reuse the original node.
                    let t = b
                        .pool
                        .mk(op, &new_args)
                        .map_err(|_| LowerError::Unsupported("rebuild failed"))?;
                    Ok(Lowered::Term(t))
                } else {
                    let t = b
                        .pool
                        .mk(op, &new_args)
                        .map_err(|_| LowerError::Unsupported("rebuild failed"))?;
                    Ok(Lowered::Term(t))
                }
            }
        };
    }

    // A literal FP term, when `fp.rem` needs values rather than circuits.
    if consts.fold {
        if let Some(bits) = fp_literal_bits(b.pool, term) {
            let fmt = fmt_of(sort);
            let c = concrete::decode(fmt, &bits);
            return Ok(Lowered::Fp(concrete::to_unpacked(b, fmt, &c)));
        }
    }

    // FP operators.
    Ok(match op {
        // Rounding-mode literals are leaves: the rounder compares against
        // them directly, so they pass through untouched.
        Op::RmConst(_) => Lowered::Rm(term),
        Op::FpFromBits => {
            let sign = as_term(&args[0])?;
            let exp = as_term(&args[1])?;
            let sig = as_term(&args[2])?;
            let bits = b.concat(&[sign, exp, sig]);
            let fmt = fmt_of(sort);
            Lowered::Fp(unpacked::unpack(b, fmt, bits))
        }
        Op::FpNan => Lowered::Fp(unpacked::make_nan(b, fmt_of(sort))),
        Op::FpInf(neg) => {
            let s = if neg { b.tt() } else { b.ff() };
            Lowered::Fp(unpacked::make_inf(b, fmt_of(sort), s))
        }
        Op::FpZero(neg) => {
            let s = if neg { b.tt() } else { b.ff() };
            Lowered::Fp(unpacked::make_zero(b, fmt_of(sort), s))
        }
        Op::FpAbs => Lowered::Fp(ops::abs(b, &as_fp(&args[0])?)),
        Op::FpNeg => Lowered::Fp(ops::neg(b, &as_fp(&args[0])?)),
        Op::FpAdd => {
            let rm = as_term(&args[0])?;
            Lowered::Fp(ops::add(b, rm, &as_fp(&args[1])?, &as_fp(&args[2])?))
        }
        Op::FpSub => {
            let rm = as_term(&args[0])?;
            Lowered::Fp(ops::sub(b, rm, &as_fp(&args[1])?, &as_fp(&args[2])?))
        }
        Op::FpMul => {
            let rm = as_term(&args[0])?;
            Lowered::Fp(ops::mul(b, rm, &as_fp(&args[1])?, &as_fp(&args[2])?))
        }
        Op::FpDiv => {
            let rm = as_term(&args[0])?;
            Lowered::Fp(ops::div(b, rm, &as_fp(&args[1])?, &as_fp(&args[2])?))
        }
        Op::FpSqrt => {
            let rm = as_term(&args[0])?;
            Lowered::Fp(ops::sqrt(b, rm, &as_fp(&args[1])?))
        }
        Op::FpRoundToIntegral => {
            let rm = as_term(&args[0])?;
            Lowered::Fp(ops::round_to_integral(b, rm, &as_fp(&args[1])?))
        }
        Op::FpMin => Lowered::Fp(ops::min_max(b, &as_fp(&args[0])?, &as_fp(&args[1])?, true)),
        Op::FpMax => Lowered::Fp(ops::min_max(b, &as_fp(&args[0])?, &as_fp(&args[1])?, false)),
        Op::FpFma => {
            let rm = as_term(&args[0])?;
            Lowered::Fp(ops::fma(
                b,
                rm,
                &as_fp(&args[1])?,
                &as_fp(&args[2])?,
                &as_fp(&args[3])?,
            ))
        }
        Op::FpRem => Lowered::Fp(rem_value(b, &as_fp(&args[0])?, &as_fp(&args[1])?)?),
        Op::FpLt => Lowered::Term(ops::lt(b, &as_fp(&args[0])?, &as_fp(&args[1])?)),
        Op::FpGt => Lowered::Term(ops::lt(b, &as_fp(&args[1])?, &as_fp(&args[0])?)),
        Op::FpLeq => Lowered::Term(ops::leq(b, &as_fp(&args[0])?, &as_fp(&args[1])?)),
        Op::FpGeq => Lowered::Term(ops::leq(b, &as_fp(&args[1])?, &as_fp(&args[0])?)),
        Op::FpEq => {
            let mut conj = Vec::new();
            for w in args.windows(2) {
                let x = as_fp(&w[0])?;
                let y = as_fp(&w[1])?;
                conj.push(ops::feq(b, &x, &y));
            }
            Lowered::Term(b.and(&conj))
        }
        Op::FpIsNan => Lowered::Term(as_fp(&args[0])?.nan),
        Op::FpIsInfinite => Lowered::Term(as_fp(&args[0])?.inf),
        Op::FpIsZero => Lowered::Term(as_fp(&args[0])?.zero),
        Op::FpIsNormal => Lowered::Term(ops::is_normal(b, &as_fp(&args[0])?)),
        Op::FpIsSubnormal => Lowered::Term(ops::is_subnormal(b, &as_fp(&args[0])?)),
        Op::FpIsNegative => {
            let x = as_fp(&args[0])?;
            let nn = b.not(x.nan);
            Lowered::Term(b.and(&[nn, x.sign]))
        }
        Op::FpIsPositive => {
            let x = as_fp(&args[0])?;
            let nn = b.not(x.nan);
            let ns = b.not(x.sign);
            Lowered::Term(b.and(&[nn, ns]))
        }
        Op::FpFromIeeeBv { eb, sb } => {
            let bits = as_term(&args[0])?;
            Lowered::Fp(unpacked::unpack(b, Format { eb, sb }, bits))
        }
        Op::FpToFp { eb, sb } => {
            let rm = as_term(&args[0])?;
            let x = as_fp(&args[1])?;
            let target = Format { eb, sb };
            Lowered::Fp(convert_format(b, rm, &x, target))
        }
        Op::FpFromSignedBv { eb, sb } => {
            let rm = as_term(&args[0])?;
            let bv = as_term(&args[1])?;
            Lowered::Fp(ops::from_int_bv(b, Format { eb, sb }, rm, bv, true))
        }
        Op::FpFromUnsignedBv { eb, sb } => {
            let rm = as_term(&args[0])?;
            let bv = as_term(&args[1])?;
            Lowered::Fp(ops::from_int_bv(b, Format { eb, sb }, rm, bv, false))
        }
        Op::FpToIeeeBv => Lowered::Term(unpacked::pack(b, &as_fp(&args[0])?)),
        Op::FpToUbv(m) => {
            let rm = as_term(&args[0])?;
            Lowered::Term(ops::to_int_bv(b, rm, &as_fp(&args[1])?, m, false))
        }
        Op::FpToSbv(m) => {
            let rm = as_term(&args[0])?;
            Lowered::Term(ops::to_int_bv(b, rm, &as_fp(&args[1])?, m, true))
        }
        _ => return Err(LowerError::Unsupported("unhandled float operator")),
    })
}

/// SMT-LIB `=` on floats: identical values (all NaNs equal; +0 != -0).
fn structural_eq(b: &mut B, x: &Unpacked, y: &Unpacked) -> TermId {
    let both_nan = b.and(&[x.nan, y.nan]);
    let sign_eq = {
        let d = b.mk(Op::Xor, &[x.sign, y.sign]);
        b.not(d)
    };
    let both_zero = {
        let z = b.and(&[x.zero, y.zero]);
        b.and(&[z, sign_eq])
    };
    let both_inf = b.and(&[x.inf, y.inf, sign_eq]);
    let both_fin = {
        let xf = x.is_finite_nonzero(b);
        let yf = y.is_finite_nonzero(b);
        let ee = b.eq(x.exp, y.exp);
        let se = b.eq(x.sig, y.sig);
        b.and(&[xf, yf, sign_eq, ee, se])
    };
    b.or(&[both_nan, both_zero, both_inf, both_fin])
}

/// FP-to-FP conversion: re-round the significand into the target format.
fn convert_format(b: &mut B, rm: TermId, x: &Unpacked, target: Format) -> Unpacked {
    if x.fmt == target {
        return *x;
    }
    let src_sw = x.fmt.sb;
    let dst_sw = target.sb;
    // Present the significand with at least 3 extra bits so the rounder has
    // guard/round/sticky room even when widening.
    let ww = src_sw.max(dst_sw + 3);
    let sig = {
        let s = b.zext_to(x.sig, ww);
        let sh = b.bv(ww, (ww - src_sw) as u64);
        b.shl(s, sh)
    };
    let ew = target.exp_width();
    let exp = {
        let w = b.width(x.exp);
        if w >= ew {
            b.extract(x.exp, ew - 1, 0)
        } else {
            b.sext_to(x.exp, ew)
        }
    };
    let ff = b.ff();
    let r = round::Rounding {
        sign: x.sign,
        exp,
        sig,
        sticky: ff,
    };
    let rounded = round::round(b, target, rm, &r);
    let nan_val = unpacked::make_nan(b, target);
    let inf_val = unpacked::make_inf(b, target, x.sign);
    let zero_val = unpacked::make_zero(b, target, x.sign);
    let res = unpacked::ite_unpacked(b, x.zero, &zero_val, &rounded);
    let res = unpacked::ite_unpacked(b, x.inf, &inf_val, &res);
    unpacked::ite_unpacked(b, x.nan, &nan_val, &res)
}
