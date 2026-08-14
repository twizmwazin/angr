//! Conversion between clarirs ASTs and smtrs terms.
//!
//! `to_term` lowers a clarirs [`AstRef`] into the thread-local
//! [`smtrs_core::TermPool`], mirroring the op-for-op translation the Z3
//! backend performed in `astext.rs`. The reverse direction never converts
//! whole terms: solver results come back as concrete [`Value`]s (or raw
//! [`BvConst`]s) and are rebuilt as clarirs constants directly.
//!
//! Strings and their positions cross the Int boundary through the `bv2nat` /
//! `(_ int2bv 64)` bridge that `smtrs-str` lowers (clarirs speaks of string
//! lengths and offsets as 64-bit bit-vectors, SMT-LIB strings as
//! unbounded Ints). String literals use the smtrs parser's `str!"..."`
//! variable-name convention; characters above `0xff` are rejected here rather
//! than silently becoming free variables in the bounded byte encoding.

use crate::{PoolState, sort_err};
use clarirs_core::prelude::*;
use smallvec::SmallVec;
use smtrs_core::{BvConst, Op, Sort, TermId, Value};

/// Rounding-mode literal codes: 0=RNE 1=RNA 2=RTP 3=RTN 4=RTZ.
fn rm_code(rm: &FPRM) -> u8 {
    match rm {
        FPRM::NearestTiesToEven => 0,
        FPRM::NearestTiesToAway => 1,
        FPRM::TowardPositive => 2,
        FPRM::TowardNegative => 3,
        FPRM::TowardZero => 4,
    }
}

pub(crate) fn bitvec_to_bvconst(bv: &BitVec) -> BvConst {
    let digits: Vec<u64> = bv.to_biguint().iter_u64_digits().collect();
    BvConst::from_bits(bv.len(), |i| {
        digits
            .get((i / 64) as usize)
            .is_some_and(|w| (w >> (i % 64)) & 1 == 1)
    })
}

pub(crate) fn bvconst_to_bitvec(c: &BvConst) -> Result<BitVec, ClarirsError> {
    BitVec::new(SmallVec::from_slice(c.limbs()), c.width())
        .map_err(|e| ClarirsError::ConversionError(format!("{e:?}")))
}

/// A model value as a clarirs constant of the sort `ty` says the evaluated
/// expression has. Floats arrive as their IEEE bit patterns.
pub(crate) fn value_to_ast<'c>(
    ctx: &'c Context<'c>,
    value: &Value,
    ty: &AstType,
) -> Result<AstRef<'c>, ClarirsError> {
    match (value, ty) {
        (Value::Bool(b), AstType::Bool) => ctx.boolv(*b),
        (Value::Bv(c), AstType::BitVec(_)) => ctx.bvv(bvconst_to_bitvec(c)?),
        (Value::Bv(c), AstType::Float(_)) => {
            ctx.fpv(Float::try_from_ieee_bits(&bvconst_to_bitvec(c)?)?)
        }
        (Value::Bv(c), AstType::Bool) => ctx.boolv(!c.is_zero()),
        _ => Err(ClarirsError::ConversionError(format!(
            "model value {value:?} does not fit sort {ty:?}"
        ))),
    }
}

/// The `str!"..."` symbol name encoding a string literal, in the syntax
/// `smtrs-str`'s `literal_bytes` decodes: `""` for a quote, `\u{..}` for
/// anything outside printable ASCII. Characters above `0xff` do not exist in
/// the bounded byte alphabet; reject them loudly (the lowering would treat
/// the whole literal as a fresh unconstrained variable, which is far worse).
fn string_literal_name(s: &str) -> Result<String, ClarirsError> {
    let mut out = String::from("str!\"");
    for ch in s.chars() {
        let c = ch as u32;
        if c > 0xff {
            return Err(ClarirsError::UnsupportedOperation(format!(
                "string literal contains character U+{c:04X}, outside the smtrs byte alphabet"
            )));
        }
        if ch == '"' {
            out.push_str("\"\"");
        } else if (0x20..0x7f).contains(&c) && ch != '\\' {
            out.push(ch);
        } else {
            out.push_str(&format!("\\u{{{c:x}}}"));
        }
    }
    out.push('"');
    Ok(out)
}

impl PoolState {
    fn mk(&mut self, op: Op, args: &[TermId]) -> Result<TermId, ClarirsError> {
        self.pool.mk(op, args).map_err(sort_err)
    }

    /// An `int!N` literal of the string world.
    fn int_lit(&mut self, n: u64) -> TermId {
        let sym = self.symbol(&format!("int!{n}"), Sort::Int);
        // Literal symbols need no model value; take it back out of declared.
        if self.declared.last() == Some(&sym) {
            self.declared.pop();
        }
        self.pool.var(sym)
    }

    /// A string-op application (`Op::Other`), e.g. `str.len`.
    fn str_app(
        &mut self,
        name: &'static str,
        args: &[TermId],
        sort: Sort,
    ) -> Result<TermId, ClarirsError> {
        let head = self.head(name);
        Ok(self.pool.other(head, 0, 0, args, sort))
    }

    /// `bv2nat`: a bit-vector as a string-world integer (clamped by the
    /// lowering to the representable position range).
    fn bv2nat(&mut self, t: TermId) -> Result<TermId, ClarirsError> {
        let head = self.head("bv2nat");
        Ok(self.pool.other(head, 0, 0, &[t], Sort::Int))
    }

    /// `(_ int2bv 64)`: a string-world integer as the 64-bit bit-vector
    /// clarirs expects lengths and indices in.
    fn int2bv64(&mut self, t: TermId) -> Result<TermId, ClarirsError> {
        let head = self.head("int2bv");
        Ok(self.pool.other(head, 64, 0, &[t], Sort::BitVec(64)))
    }

    fn rm(&mut self, rm: &FPRM) -> TermId {
        self.pool.rm(rm_code(rm))
    }

    /// Fold clarirs's >= 1-ary And/Or/Xor/Add/Mul into smtrs's >= 2-ary ones.
    fn nary(&mut self, op: Op, args: &[TermId]) -> Result<TermId, ClarirsError> {
        match args.len() {
            0 => Err(ClarirsError::InvalidArguments(
                "n-ary operation requires at least one operand".to_string(),
            )),
            1 => Ok(args[0]),
            _ => self.mk(op, args),
        }
    }
}

/// Whether any node of `expr` is float- or string-sorted. Such expressions
/// cannot be evaluated against a model directly (models carry only Bool and
/// bit-vector values, and the FP/string content is theory-lowered away before
/// solving), so the solver binds them to an auxiliary bit-vector or string
/// variable instead.
pub(crate) fn needs_aux(expr: &AstRef) -> bool {
    matches!(expr.ast_type(), AstType::Float(_) | AstType::String)
        || expr.child_iter().any(|c| needs_aux(&c))
}

/// Convert a clarirs AST into the thread-local term pool, reusing every
/// already-converted node. Iterative so pathological AST depth cannot
/// overflow the stack.
pub(crate) fn to_term(ast: &AstRef, st: &mut PoolState) -> Result<TermId, ClarirsError> {
    enum Frame<'c> {
        Enter(AstRef<'c>),
        Exit(AstRef<'c>),
    }
    let mut stack = vec![Frame::Enter(ast.clone())];
    while let Some(frame) = stack.pop() {
        match frame {
            Frame::Enter(a) => {
                if st.terms.contains_key(&a.hash()) {
                    continue;
                }
                stack.push(Frame::Exit(a.clone()));
                for c in a.child_iter() {
                    stack.push(Frame::Enter(c));
                }
            }
            Frame::Exit(a) => {
                if st.terms.contains_key(&a.hash()) {
                    continue;
                }
                let t = convert_node(&a, st)?;
                st.terms.insert(a.hash(), t);
            }
        }
    }
    Ok(st.terms[&ast.hash()])
}

/// Build the smtrs term for one node whose children are already converted.
fn convert_node(ast: &AstRef, st: &mut PoolState) -> Result<TermId, ClarirsError> {
    let child = |st: &PoolState, i: usize| -> Result<TermId, ClarirsError> {
        let c = ast
            .op()
            .get_child(i)
            .ok_or(ClarirsError::MissingChild(i))?;
        st.terms
            .get(&c.hash())
            .copied()
            .ok_or(ClarirsError::MissingChild(i))
    };
    let children = |st: &PoolState| -> Result<Vec<TermId>, ClarirsError> {
        (0..ast.op().num_children()).map(|i| child(st, i)).collect()
    };

    Ok(match ast.op() {
        // Polymorphic boolean/bitvector operations.
        AstOp::Not(..) => {
            let op = if ast.ast_type().is_bool() {
                Op::Not
            } else {
                Op::BvNot
            };
            let a = child(st, 0)?;
            st.mk(op, &[a])?
        }
        AstOp::And(..) => {
            let args = children(st)?;
            let op = if ast.ast_type().is_bool() {
                Op::And
            } else {
                Op::BvAnd
            };
            st.nary(op, &args)?
        }
        AstOp::Or(..) => {
            let args = children(st)?;
            let op = if ast.ast_type().is_bool() {
                Op::Or
            } else {
                Op::BvOr
            };
            st.nary(op, &args)?
        }
        AstOp::Xor(..) => {
            let args = children(st)?;
            let op = if ast.ast_type().is_bool() {
                Op::Xor
            } else {
                Op::BvXor
            };
            st.nary(op, &args)?
        }
        AstOp::ITE(..) => {
            let args = children(st)?;
            st.mk(Op::Ite, &args)?
        }

        // Boolean leaves.
        AstOp::BoolS(name) => {
            let sym = st.symbol(name.as_str(), Sort::Bool);
            st.pool.var(sym)
        }
        AstOp::BoolV(b) => st.pool.bool_const(*b),

        // Equality (any sort): floats use IEEE fp.eq, everything else is
        // structural. Neq is the negation of the same, exactly as the Z3
        // backend emitted not(fp.eq)/distinct.
        AstOp::Eq(a, _) => {
            let args = children(st)?;
            if a.ast_type().is_float() {
                st.mk(Op::FpEq, &args)?
            } else {
                st.mk(Op::Eq, &args)?
            }
        }
        AstOp::Neq(a, _) => {
            let args = children(st)?;
            let eq = if a.ast_type().is_float() {
                st.mk(Op::FpEq, &args)?
            } else {
                st.mk(Op::Eq, &args)?
            };
            st.mk(Op::Not, &[eq])?
        }
        AstOp::ULT(..) => {
            let args = children(st)?;
            st.mk(Op::BvUlt, &args)?
        }
        AstOp::ULE(..) => {
            let args = children(st)?;
            st.mk(Op::BvUle, &args)?
        }
        AstOp::UGT(..) => {
            let args = children(st)?;
            st.mk(Op::BvUgt, &args)?
        }
        AstOp::UGE(..) => {
            let args = children(st)?;
            st.mk(Op::BvUge, &args)?
        }
        AstOp::SLT(..) => {
            let args = children(st)?;
            st.mk(Op::BvSlt, &args)?
        }
        AstOp::SLE(..) => {
            let args = children(st)?;
            st.mk(Op::BvSle, &args)?
        }
        AstOp::SGT(..) => {
            let args = children(st)?;
            st.mk(Op::BvSgt, &args)?
        }
        AstOp::SGE(..) => {
            let args = children(st)?;
            st.mk(Op::BvSge, &args)?
        }

        // Float comparisons and predicates.
        AstOp::FpLt(..) => {
            let args = children(st)?;
            st.mk(Op::FpLt, &args)?
        }
        AstOp::FpLeq(..) => {
            let args = children(st)?;
            st.mk(Op::FpLeq, &args)?
        }
        AstOp::FpGt(..) => {
            let args = children(st)?;
            st.mk(Op::FpGt, &args)?
        }
        AstOp::FpGeq(..) => {
            let args = children(st)?;
            st.mk(Op::FpGeq, &args)?
        }
        AstOp::FpIsNan(..) => {
            let a = child(st, 0)?;
            st.mk(Op::FpIsNan, &[a])?
        }
        AstOp::FpIsInf(..) => {
            let a = child(st, 0)?;
            st.mk(Op::FpIsInfinite, &[a])?
        }

        // String predicates.
        AstOp::StrContains(..) => {
            let args = children(st)?;
            st.str_app("str.contains", &args, Sort::Bool)?
        }
        AstOp::StrPrefixOf(..) => {
            let args = children(st)?;
            st.str_app("str.prefixof", &args, Sort::Bool)?
        }
        AstOp::StrSuffixOf(..) => {
            let args = children(st)?;
            st.str_app("str.suffixof", &args, Sort::Bool)?
        }
        AstOp::StrIsDigit(..) => {
            // str.to_int is -1 on anything that is not a non-empty digit
            // string, so "all digits" is to_int >= 0 with a non-empty length
            // (the same encoding the Z3 backend used).
            let a = child(st, 0)?;
            let to_int = st.str_app("str.to_int", &[a], Sort::Int)?;
            let len = st.str_app("str.len", &[a], Sort::Int)?;
            let zero = st.int_lit(0);
            let non_negative = st.str_app(">=", &[to_int, zero], Sort::Bool)?;
            let non_empty = st.str_app(">", &[len, zero], Sort::Bool)?;
            st.mk(Op::And, &[non_negative, non_empty])?
        }

        // Bitvector leaves and operations.
        AstOp::BVS(name, w) => {
            let sym = st.symbol(name.as_str(), Sort::BitVec(*w));
            st.pool.var(sym)
        }
        AstOp::BVV(bv) => {
            let c = bitvec_to_bvconst(bv);
            st.pool.bv(c)
        }
        AstOp::Neg(..) => {
            let a = child(st, 0)?;
            st.mk(Op::BvNeg, &[a])?
        }
        AstOp::Add(..) => {
            let args = children(st)?;
            st.nary(Op::BvAdd, &args)?
        }
        AstOp::Sub(..) => {
            let args = children(st)?;
            st.mk(Op::BvSub, &args)?
        }
        AstOp::Mul(..) => {
            let args = children(st)?;
            st.nary(Op::BvMul, &args)?
        }
        AstOp::UDiv(..) => {
            let args = children(st)?;
            st.mk(Op::BvUdiv, &args)?
        }
        AstOp::SDiv(..) => {
            let args = children(st)?;
            st.mk(Op::BvSdiv, &args)?
        }
        AstOp::URem(..) => {
            let args = children(st)?;
            st.mk(Op::BvUrem, &args)?
        }
        AstOp::SRem(..) => {
            let args = children(st)?;
            st.mk(Op::BvSrem, &args)?
        }
        AstOp::ShL(..) => {
            let args = children(st)?;
            st.mk(Op::BvShl, &args)?
        }
        AstOp::LShR(..) => {
            let args = children(st)?;
            st.mk(Op::BvLshr, &args)?
        }
        AstOp::AShR(..) => {
            let args = children(st)?;
            st.mk(Op::BvAshr, &args)?
        }
        AstOp::RotateLeft(a, b) | AstOp::RotateRight(a, b) => {
            let left = matches!(ast.op(), AstOp::RotateLeft(..));
            let w = a.size();
            let x = child(st, 0)?;
            if let AstOp::BVV(amount) = b.op() {
                // Constant rotate: smtrs's indexed rotate, amount mod width.
                let n = (amount.to_biguint() % w).to_u64_digits().first().copied()
                    .unwrap_or(0) as u32;
                let op = if left {
                    Op::RotateLeft(n)
                } else {
                    Op::RotateRight(n)
                };
                st.mk(op, &[x])?
            } else {
                // Symbolic rotate (Z3's ext_rotate): with s = amount mod w,
                // rotl(x, s) = (x << s) | (x >> (w - s)); a shift by >= w is
                // zero, so the s = 0 case degenerates correctly. rotr mirrors.
                let s_raw = child(st, 1)?;
                let w_const = st.pool.bv(BvConst::from_u64(w, u64::from(w)));
                let s = st.mk(Op::BvUrem, &[s_raw, w_const])?;
                let w_minus_s = st.mk(Op::BvSub, &[w_const, s])?;
                let (near, far) = if left {
                    (Op::BvShl, Op::BvLshr)
                } else {
                    (Op::BvLshr, Op::BvShl)
                };
                let hi = st.mk(near, &[x, s])?;
                let lo = st.mk(far, &[x, w_minus_s])?;
                st.mk(Op::BvOr, &[hi, lo])?
            }
        }
        AstOp::ZeroExt(_, i) => {
            let a = child(st, 0)?;
            if *i == 0 {
                a
            } else {
                st.mk(Op::ZeroExtend(*i), &[a])?
            }
        }
        AstOp::SignExt(_, i) => {
            let a = child(st, 0)?;
            if *i == 0 {
                a
            } else {
                st.mk(Op::SignExtend(*i), &[a])?
            }
        }
        AstOp::Extract(a, high, low) => {
            if high >= &a.size() || low > high {
                return Err(ClarirsError::ConversionError(
                    "invalid extract bounds".to_string(),
                ));
            }
            let x = child(st, 0)?;
            st.mk(
                Op::Extract {
                    hi: *high,
                    lo: *low,
                },
                &[x],
            )?
        }
        AstOp::Concat(..) => {
            // SMT-LIB concat: first operand is the most significant, the same
            // order clarirs uses.
            let args = children(st)?;
            st.nary(Op::Concat, &args)?
        }
        AstOp::ByteReverse(a) => {
            let size = a.size();
            if size == 0 || size % 8 != 0 {
                return Err(ClarirsError::ConversionError(
                    "reverse only supports bitvectors with size multiple of 8".to_string(),
                ));
            }
            let x = child(st, 0)?;
            // The original low byte becomes the most significant operand.
            let mut bytes = Vec::with_capacity((size / 8) as usize);
            for i in 0..size / 8 {
                let lo = i * 8;
                bytes.push(st.mk(Op::Extract { hi: lo + 7, lo }, &[x])?);
            }
            st.nary(Op::Concat, &bytes)?
        }
        AstOp::FpToIEEEBV(..) => {
            let a = child(st, 0)?;
            st.mk(Op::FpToIeeeBv, &[a])?
        }
        AstOp::FpToUBV(_, size, rm) => {
            let r = st.rm(rm);
            let a = child(st, 0)?;
            st.mk(Op::FpToUbv(*size), &[r, a])?
        }
        AstOp::FpToSBV(_, size, rm) => {
            let r = st.rm(rm);
            let a = child(st, 0)?;
            st.mk(Op::FpToSbv(*size), &[r, a])?
        }

        // String-valued bitvector operations, across the Int bridge.
        AstOp::StrLen(..) => {
            let s = child(st, 0)?;
            let len = st.str_app("str.len", &[s], Sort::Int)?;
            st.int2bv64(len)?
        }
        AstOp::StrIndexOf(..) => {
            let h = child(st, 0)?;
            let n = child(st, 1)?;
            let off_bv = child(st, 2)?;
            let off = st.bv2nat(off_bv)?;
            let idx = st.str_app("str.indexof", &[h, n, off], Sort::Int)?;
            st.int2bv64(idx)?
        }
        AstOp::StrToBV(..) => {
            let s = child(st, 0)?;
            let v = st.str_app("str.to_int", &[s], Sort::Int)?;
            st.int2bv64(v)?
        }

        AstOp::Union(..) | AstOp::Intersection(..) | AstOp::Widen(..) => {
            return Err(ClarirsError::ConversionError(
                "vsa types are not currently supported in the smtrs backend".to_string(),
            ));
        }

        // Float leaves and operations.
        AstOp::FPS(name, fsort) => {
            let sym = st.symbol(
                name.as_str(),
                Sort::Float(fsort.exponent, fsort.mantissa + 1),
            );
            st.pool.var(sym)
        }
        AstOp::FPV(f) => {
            let bits = st.pool.bv(bitvec_to_bvconst(&f.to_ieee_bits()));
            let fsort = f.fsort();
            st.mk(
                Op::FpFromIeeeBv {
                    eb: fsort.exponent,
                    sb: fsort.mantissa + 1,
                },
                &[bits],
            )?
        }
        AstOp::FpNeg(..) => {
            let a = child(st, 0)?;
            st.mk(Op::FpNeg, &[a])?
        }
        AstOp::FpAbs(..) => {
            let a = child(st, 0)?;
            st.mk(Op::FpAbs, &[a])?
        }
        AstOp::FpAdd(_, _, rm) | AstOp::FpSub(_, _, rm) | AstOp::FpMul(_, _, rm)
        | AstOp::FpDiv(_, _, rm) => {
            let op = match ast.op() {
                AstOp::FpAdd(..) => Op::FpAdd,
                AstOp::FpSub(..) => Op::FpSub,
                AstOp::FpMul(..) => Op::FpMul,
                _ => Op::FpDiv,
            };
            let r = st.rm(rm);
            let a = child(st, 0)?;
            let b = child(st, 1)?;
            st.mk(op, &[r, a, b])?
        }
        AstOp::FpSqrt(_, rm) => {
            let r = st.rm(rm);
            let a = child(st, 0)?;
            st.mk(Op::FpSqrt, &[r, a])?
        }
        AstOp::FpToFp(_, fsort, rm) => {
            let r = st.rm(rm);
            let a = child(st, 0)?;
            st.mk(
                Op::FpToFp {
                    eb: fsort.exponent,
                    sb: fsort.mantissa + 1,
                },
                &[r, a],
            )?
        }
        AstOp::FpFP(..) => {
            let args = children(st)?;
            st.mk(Op::FpFromBits, &args)?
        }
        AstOp::BvToFp(_, fsort) => {
            let a = child(st, 0)?;
            st.mk(
                Op::FpFromIeeeBv {
                    eb: fsort.exponent,
                    sb: fsort.mantissa + 1,
                },
                &[a],
            )?
        }
        AstOp::BvToFpSigned(_, fsort, rm) | AstOp::BvToFpUnsigned(_, fsort, rm) => {
            let signed = matches!(ast.op(), AstOp::BvToFpSigned(..));
            let (eb, sb) = (fsort.exponent, fsort.mantissa + 1);
            let op = if signed {
                Op::FpFromSignedBv { eb, sb }
            } else {
                Op::FpFromUnsignedBv { eb, sb }
            };
            let r = st.rm(rm);
            let a = child(st, 0)?;
            st.mk(op, &[r, a])?
        }

        // String leaves and operations.
        AstOp::StringS(name) => {
            let sym = st.symbol(name.as_str(), Sort::Str);
            st.pool.var(sym)
        }
        AstOp::StringV(s) => {
            let lit = string_literal_name(s)?;
            // Literals are constants, not model variables; intern the symbol
            // without declaring it.
            let sym = st.symbol(&lit, Sort::Str);
            if st.declared.last() == Some(&sym) {
                st.declared.pop();
            }
            st.pool.var(sym)
        }
        AstOp::StrConcat(..) => {
            let args = children(st)?;
            st.str_app("str.++", &args, Sort::Str)?
        }
        AstOp::StrSubstr(..) => {
            let s = child(st, 0)?;
            let off_bv = child(st, 1)?;
            let len_bv = child(st, 2)?;
            let off = st.bv2nat(off_bv)?;
            let len = st.bv2nat(len_bv)?;
            st.str_app("str.substr", &[s, off, len], Sort::Str)?
        }
        AstOp::StrReplace(..) => {
            let args = children(st)?;
            st.str_app("str.replace", &args, Sort::Str)?
        }
        AstOp::BVToStr(..) => {
            let a = child(st, 0)?;
            let n = st.bv2nat(a)?;
            st.str_app("str.from_int", &[n], Sort::Str)?
        }
    })
}
