//! clarirs ASTs to smtrs terms, and smtrs model values back to clarirs ASTs.

use clarirs_core::prelude::*;
use num_bigint::BigUint;
use rustc_hash::FxHashMap;
use smallvec::SmallVec;
use smtrs_core::{BvConst, Op, Sort, SymbolId, TermId, TermPool, Value};

/// Converts ASTs into one shared [`TermPool`], memoising by AST hash.
///
/// The hash covers annotations, so an annotated and an unannotated copy of
/// the same expression are converted separately — to the same term, since
/// variables are keyed by name and sort rather than by AST hash.
pub(crate) struct Converter<'b> {
    pub pool: &'b mut TermPool,
    terms: &'b mut FxHashMap<u64, TermId>,
    vars: &'b mut FxHashMap<(InternedString, Sort), SymbolId>,
    /// Head symbols of string operators and string-literal leaves, by the
    /// name smtrs's string lowering matches on.
    names: &'b mut FxHashMap<String, SymbolId>,
}

/// What an evaluated term stands for, so its value can be handed back as an
/// AST of the sort the caller asked about.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Kind {
    Bool,
    BitVec,
    /// The term is the IEEE bit pattern of a float of this sort.
    Float(FSort),
    /// Strings are lowered to a length and a bounded character array; their
    /// value is read back from those derived symbols, not from a term.
    String,
}

/// Width of the bit-vectors clarirs uses for string lengths and indices.
const STR_INDEX_BITS: u32 = 64;

fn type_error(msg: impl Into<String>) -> ClarirsError {
    ClarirsError::TypeError(msg.into())
}

fn unsupported(msg: impl Into<String>) -> ClarirsError {
    ClarirsError::UnsupportedOperation(msg.into())
}

pub(crate) fn fsort_to_sort(fs: FSort) -> Sort {
    // smtrs significand widths include the hidden bit; clarirs mantissas do not.
    Sort::Float(fs.exponent, fs.mantissa + 1)
}

fn rm_code(rm: &FPRM) -> u8 {
    match rm {
        FPRM::NearestTiesToEven => 0,
        FPRM::NearestTiesToAway => 1,
        FPRM::TowardPositive => 2,
        FPRM::TowardNegative => 3,
        FPRM::TowardZero => 4,
    }
}

pub(crate) fn bvconst_of(bv: &BitVec) -> BvConst {
    let width = bv.len();
    if width <= 64 {
        return BvConst::from_u64(width, bv.to_u64().unwrap_or(0));
    }
    let digits = BigUint::from(bv).to_u64_digits();
    BvConst::from_limbs(width, &digits)
}

pub(crate) fn bitvec_of(c: &BvConst) -> BitVec {
    BitVec::new(SmallVec::from_slice(c.limbs()), c.width()).expect("BitVec::new is infallible")
}

impl<'b> Converter<'b> {
    pub(crate) fn new(
        pool: &'b mut TermPool,
        terms: &'b mut FxHashMap<u64, TermId>,
        vars: &'b mut FxHashMap<(InternedString, Sort), SymbolId>,
        names: &'b mut FxHashMap<String, SymbolId>,
    ) -> Self {
        Self {
            pool,
            terms,
            vars,
            names,
        }
    }

    /// The smtrs symbol standing for variable `name` of `sort`, if any
    /// query has mentioned it.
    pub(crate) fn existing_var(&self, name: &InternedString, sort: Sort) -> Option<SymbolId> {
        self.vars.get(&(name.clone(), sort)).copied()
    }

    /// A symbol smtrs's string lowering identifies by name: an operator head
    /// or a literal leaf.
    fn named(&mut self, name: &str, sort: Sort) -> SymbolId {
        if let Some(&s) = self.names.get(name) {
            return s;
        }
        let s = self.pool.fresh_symbol(name, sort);
        self.names.insert(name.to_string(), s);
        s
    }

    /// A string operator application, as the smtrs parser would build it.
    fn str_op(&mut self, name: &str, args: &[TermId], sort: Sort) -> TermId {
        let head = self.named(name, sort);
        self.pool.other(head, 0, 0, args, sort)
    }

    /// A string literal leaf. smtrs strings are byte strings whose code
    /// points are at most U+00FF; the literal syntax is SMT-LIB's, with
    /// `""` for a quote and `\u{..}` escapes.
    fn str_lit(&mut self, s: &str) -> Result<TermId, ClarirsError> {
        let mut name = String::from("str!\"");
        for c in s.chars() {
            let cp = u32::from(c);
            match c {
                '"' => name.push_str("\"\""),
                ' '..='~' if c != '\\' => name.push(c),
                _ if cp <= 0xff => name.push_str(&format!("\\u{{{cp:x}}}")),
                _ => {
                    return Err(unsupported(format!(
                        "the smtrs backend cannot represent U+{cp:04X} in a string"
                    )));
                }
            }
        }
        name.push('"');
        let sym = self.named(&name, Sort::Str);
        Ok(self.pool.var(sym))
    }

    /// A clarirs index (a bit-vector) as an smtrs `Int`.
    fn bv_to_int(&mut self, x: TermId) -> TermId {
        self.str_op("bv2int", &[x], Sort::Int)
    }

    /// An smtrs `Int` (a length or index) as clarirs's 64-bit vector.
    fn int_to_bv(&mut self, x: TermId) -> TermId {
        let head = self.named("int2bv", Sort::BitVec(STR_INDEX_BITS));
        self.pool
            .other(head, STR_INDEX_BITS, 0, &[x], Sort::BitVec(STR_INDEX_BITS))
    }

    fn mk(&mut self, op: Op, args: &[TermId]) -> Result<TermId, ClarirsError> {
        self.pool
            .mk(op, args)
            .map_err(|e| type_error(format!("smtrs rejected a term: {e}")))
    }

    fn var(&mut self, name: &InternedString, sort: Sort) -> TermId {
        let key = (name.clone(), sort);
        let sym = match self.vars.get(&key) {
            Some(&s) => s,
            None => {
                let s = self.pool.fresh_symbol(name.as_str(), sort);
                self.vars.insert(key, s);
                s
            }
        };
        self.pool.var(sym)
    }

    /// The term for `ast`, converting whatever part of it is not yet known.
    pub(crate) fn term<'c>(&mut self, ast: &AstRef<'c>) -> Result<TermId, ClarirsError> {
        if let Some(&t) = self.terms.get(&ast.hash()) {
            return Ok(t);
        }
        let _t = crate::stats::CONVERT.enter();
        // Explicit stack: angr builds ASTs thousands of nodes deep.
        let mut stack: Vec<(AstRef<'c>, usize)> = vec![(ast.clone(), 0)];
        while let Some((node, next_child)) = stack.last_mut() {
            let n = node.op().num_children();
            if *next_child < n {
                let child = node.get_child(*next_child).expect("index in range");
                *next_child += 1;
                if !self.terms.contains_key(&child.hash()) {
                    stack.push((child, 0));
                }
                continue;
            }
            let node = node.clone();
            stack.pop();
            if self.terms.contains_key(&node.hash()) {
                continue; // a shared subterm converted via another path
            }
            let t = self.build(&node)?;
            self.terms.insert(node.hash(), t);
        }
        Ok(self.terms[&ast.hash()])
    }

    fn child_term(&self, node: &AstRef<'_>, i: usize) -> TermId {
        let child = node.get_child(i).expect("child index in range");
        self.terms[&child.hash()]
    }

    fn child_terms(&self, node: &AstRef<'_>) -> Vec<TermId> {
        (0..node.op().num_children())
            .map(|i| self.child_term(node, i))
            .collect()
    }

    /// One node whose children are all converted.
    fn build(&mut self, node: &AstRef<'_>) -> Result<TermId, ClarirsError> {
        let a = |this: &Self| this.child_term(node, 0);
        let b = |this: &Self| this.child_term(node, 1);
        let is_bool = node.ast_type().is_bool();
        Ok(match node.op() {
            // Leaves
            AstOp::BoolS(name) => self.var(name, Sort::Bool),
            AstOp::BoolV(v) => self.pool.bool_const(*v),
            AstOp::BVS(name, width) => self.var(name, Sort::BitVec(*width)),
            AstOp::BVV(bv) => self.pool.bv(bvconst_of(bv)),
            AstOp::FPS(name, fsort) => self.var(name, fsort_to_sort(*fsort)),
            AstOp::FPV(f) => {
                let fs = f.fsort();
                let bits = self.pool.bv(bvconst_of(&f.to_ieee_bits()));
                self.mk(
                    Op::FpFromIeeeBv {
                        eb: fs.exponent,
                        sb: fs.mantissa + 1,
                    },
                    &[bits],
                )?
            }
            AstOp::StringS(name) => self.var(name, Sort::Str),
            AstOp::StringV(s) => self.str_lit(s)?,

            // Polymorphic Bool/BV
            AstOp::Not(_) => {
                let x = a(self);
                self.mk(if is_bool { Op::Not } else { Op::BvNot }, &[x])?
            }
            AstOp::And(_) => self.nary(node, if is_bool { Op::And } else { Op::BvAnd })?,
            AstOp::Or(_) => self.nary(node, if is_bool { Op::Or } else { Op::BvOr })?,
            AstOp::Xor(_) => self.nary(node, if is_bool { Op::Xor } else { Op::BvXor })?,
            AstOp::ITE(..) => {
                let args = self.child_terms(node);
                self.mk(Op::Ite, &args)?
            }

            // Equality: IEEE on floats, structural otherwise
            AstOp::Eq(l, _) => {
                let (x, y) = (a(self), b(self));
                if l.ast_type().is_float() {
                    self.mk(Op::FpEq, &[x, y])?
                } else {
                    self.mk(Op::Eq, &[x, y])?
                }
            }
            AstOp::Neq(l, _) => {
                let (x, y) = (a(self), b(self));
                if l.ast_type().is_float() {
                    let eq = self.mk(Op::FpEq, &[x, y])?;
                    self.mk(Op::Not, &[eq])?
                } else {
                    self.mk(Op::Distinct, &[x, y])?
                }
            }

            // BV comparisons
            AstOp::ULT(..) => self.binary(node, Op::BvUlt)?,
            AstOp::ULE(..) => self.binary(node, Op::BvUle)?,
            AstOp::UGT(..) => self.binary(node, Op::BvUgt)?,
            AstOp::UGE(..) => self.binary(node, Op::BvUge)?,
            AstOp::SLT(..) => self.binary(node, Op::BvSlt)?,
            AstOp::SLE(..) => self.binary(node, Op::BvSle)?,
            AstOp::SGT(..) => self.binary(node, Op::BvSgt)?,
            AstOp::SGE(..) => self.binary(node, Op::BvSge)?,

            // BV arithmetic and bitwise
            AstOp::Neg(_) => {
                let x = a(self);
                self.mk(Op::BvNeg, &[x])?
            }
            AstOp::Add(_) => self.nary(node, Op::BvAdd)?,
            AstOp::Mul(_) => self.nary(node, Op::BvMul)?,
            AstOp::Sub(..) => self.binary(node, Op::BvSub)?,
            AstOp::UDiv(..) => self.binary(node, Op::BvUdiv)?,
            AstOp::SDiv(..) => self.binary(node, Op::BvSdiv)?,
            AstOp::URem(..) => self.binary(node, Op::BvUrem)?,
            AstOp::SRem(..) => self.binary(node, Op::BvSrem)?,
            AstOp::ShL(..) => self.binary(node, Op::BvShl)?,
            AstOp::LShR(..) => self.binary(node, Op::BvLshr)?,
            AstOp::AShR(..) => self.binary(node, Op::BvAshr)?,
            AstOp::RotateLeft(..) => {
                let (x, amt) = (a(self), b(self));
                self.rotate(x, amt, true)?
            }
            AstOp::RotateRight(..) => {
                let (x, amt) = (a(self), b(self));
                self.rotate(x, amt, false)?
            }
            AstOp::ZeroExt(_, n) => {
                let x = a(self);
                if *n == 0 {
                    x
                } else {
                    self.mk(Op::ZeroExtend(*n), &[x])?
                }
            }
            AstOp::SignExt(_, n) => {
                let x = a(self);
                if *n == 0 {
                    x
                } else {
                    self.mk(Op::SignExtend(*n), &[x])?
                }
            }
            AstOp::Extract(_, hi, lo) => {
                let x = a(self);
                self.mk(Op::Extract { hi: *hi, lo: *lo }, &[x])?
            }
            AstOp::Concat(_) => self.nary(node, Op::Concat)?,
            AstOp::ByteReverse(inner) => {
                let x = a(self);
                let size = inner.size();
                if size == 0 || !size.is_multiple_of(8) {
                    return Err(ClarirsError::ConversionError(
                        "reverse only supports bitvectors with size multiple of 8".to_string(),
                    ));
                }
                let bytes = size / 8;
                if bytes == 1 {
                    x
                } else {
                    // Most significant operand first: the lowest byte of the
                    // input leads the output.
                    let mut parts = Vec::with_capacity(bytes as usize);
                    for i in 0..bytes {
                        parts.push(self.mk(
                            Op::Extract {
                                hi: 8 * i + 7,
                                lo: 8 * i,
                            },
                            &[x],
                        )?);
                    }
                    self.mk(Op::Concat, &parts)?
                }
            }

            // Float <-> BV conversions
            AstOp::FpToIEEEBV(_) => {
                let x = a(self);
                self.mk(Op::FpToIeeeBv, &[x])?
            }
            AstOp::FpToUBV(_, size, rm) => {
                let (x, rm) = (a(self), self.pool.rm(rm_code(rm)));
                self.mk(Op::FpToUbv(*size), &[rm, x])?
            }
            AstOp::FpToSBV(_, size, rm) => {
                let (x, rm) = (a(self), self.pool.rm(rm_code(rm)));
                self.mk(Op::FpToSbv(*size), &[rm, x])?
            }
            AstOp::FpToFp(_, fsort, rm) => {
                let (x, rm) = (a(self), self.pool.rm(rm_code(rm)));
                self.mk(
                    Op::FpToFp {
                        eb: fsort.exponent,
                        sb: fsort.mantissa + 1,
                    },
                    &[rm, x],
                )?
            }
            AstOp::BvToFp(_, fsort) => {
                let x = a(self);
                self.mk(
                    Op::FpFromIeeeBv {
                        eb: fsort.exponent,
                        sb: fsort.mantissa + 1,
                    },
                    &[x],
                )?
            }
            AstOp::BvToFpSigned(_, fsort, rm) => {
                let (x, rm) = (a(self), self.pool.rm(rm_code(rm)));
                self.mk(
                    Op::FpFromSignedBv {
                        eb: fsort.exponent,
                        sb: fsort.mantissa + 1,
                    },
                    &[rm, x],
                )?
            }
            AstOp::BvToFpUnsigned(_, fsort, rm) => {
                let (x, rm) = (a(self), self.pool.rm(rm_code(rm)));
                self.mk(
                    Op::FpFromUnsignedBv {
                        eb: fsort.exponent,
                        sb: fsort.mantissa + 1,
                    },
                    &[rm, x],
                )?
            }
            AstOp::FpFP(..) => {
                let args = self.child_terms(node);
                self.mk(Op::FpFromBits, &args)?
            }

            // Float arithmetic and predicates
            AstOp::FpNeg(_) => {
                let x = a(self);
                self.mk(Op::FpNeg, &[x])?
            }
            AstOp::FpAbs(_) => {
                let x = a(self);
                self.mk(Op::FpAbs, &[x])?
            }
            AstOp::FpAdd(_, _, rm) => self.fp_binary(node, Op::FpAdd, rm)?,
            AstOp::FpSub(_, _, rm) => self.fp_binary(node, Op::FpSub, rm)?,
            AstOp::FpMul(_, _, rm) => self.fp_binary(node, Op::FpMul, rm)?,
            AstOp::FpDiv(_, _, rm) => self.fp_binary(node, Op::FpDiv, rm)?,
            AstOp::FpSqrt(_, rm) => {
                let (x, rm) = (a(self), self.pool.rm(rm_code(rm)));
                self.mk(Op::FpSqrt, &[rm, x])?
            }
            AstOp::FpLt(..) => self.binary(node, Op::FpLt)?,
            AstOp::FpLeq(..) => self.binary(node, Op::FpLeq)?,
            AstOp::FpGt(..) => self.binary(node, Op::FpGt)?,
            AstOp::FpGeq(..) => self.binary(node, Op::FpGeq)?,
            AstOp::FpIsNan(_) => {
                let x = a(self);
                self.mk(Op::FpIsNan, &[x])?
            }
            AstOp::FpIsInf(_) => {
                let x = a(self);
                self.mk(Op::FpIsInfinite, &[x])?
            }

            // Value-set (VSA) operations have no SMT meaning.
            AstOp::Union(..) | AstOp::Intersection(..) | AstOp::Widen(..) => {
                return Err(unsupported(
                    "VSA operations (Union/Intersection/Widen) cannot be solved by smtrs",
                ));
            }

            // Strings: the operator names and operand orders are SMT-LIB's,
            // which is what smtrs's string lowering reads. Lengths and
            // indices cross between clarirs's 64-bit vectors and smtrs's
            // `Int` through the `bv2int`/`int2bv` bridges.
            AstOp::StrContains(..) => {
                let (x, y) = (a(self), b(self));
                self.str_op("str.contains", &[x, y], Sort::Bool)
            }
            AstOp::StrPrefixOf(..) => {
                let (x, y) = (a(self), b(self));
                self.str_op("str.prefixof", &[x, y], Sort::Bool)
            }
            AstOp::StrSuffixOf(..) => {
                let (x, y) = (a(self), b(self));
                self.str_op("str.suffixof", &[x, y], Sort::Bool)
            }
            AstOp::StrIsDigit(_) => {
                // claripy's is_digit is Python's: non-empty and all digits,
                // which is exactly when `str.to_int` is not -1 (the same
                // reading the z3 backend used). SMT-LIB's own `str.is_digit`
                // means a single digit and is not what callers expect.
                let x = a(self);
                let n = self.str_op("str.to_int", &[x], Sort::Int);
                let zero_sym = self.named("int!0", Sort::Int);
                let zero = self.pool.var(zero_sym);
                self.str_op(">=", &[n, zero], Sort::Bool)
            }
            AstOp::StrLen(_) => {
                let x = a(self);
                let len = self.str_op("str.len", &[x], Sort::Int);
                self.int_to_bv(len)
            }
            AstOp::StrIndexOf(..) => {
                let (s, t, start) = (a(self), b(self), self.child_term(node, 2));
                let start = self.bv_to_int(start);
                let index = self.str_op("str.indexof", &[s, t, start], Sort::Int);
                self.int_to_bv(index)
            }
            AstOp::StrToBV(_) => {
                let x = a(self);
                let n = self.str_op("str.to_int", &[x], Sort::Int);
                self.int_to_bv(n)
            }
            AstOp::StrConcat(..) => {
                let (x, y) = (a(self), b(self));
                self.str_op("str.++", &[x, y], Sort::Str)
            }
            AstOp::StrSubstr(..) => {
                let (s, start, len) = (a(self), b(self), self.child_term(node, 2));
                let start = self.bv_to_int(start);
                let len = self.bv_to_int(len);
                self.str_op("str.substr", &[s, start, len], Sort::Str)
            }
            AstOp::StrReplace(..) => {
                let args = self.child_terms(node);
                self.str_op("str.replace", &args, Sort::Str)
            }
            AstOp::BVToStr(_) => {
                let x = a(self);
                let n = self.bv_to_int(x);
                self.str_op("str.from_int", &[n], Sort::Str)
            }
        })
    }

    fn nary(&mut self, node: &AstRef<'_>, op: Op) -> Result<TermId, ClarirsError> {
        let args = self.child_terms(node);
        if args.len() == 1 {
            return Ok(args[0]);
        }
        self.mk(op, &args)
    }

    fn binary(&mut self, node: &AstRef<'_>, op: Op) -> Result<TermId, ClarirsError> {
        let (x, y) = (self.child_term(node, 0), self.child_term(node, 1));
        self.mk(op, &[x, y])
    }

    fn fp_binary(&mut self, node: &AstRef<'_>, op: Op, rm: &FPRM) -> Result<TermId, ClarirsError> {
        let (x, y) = (self.child_term(node, 0), self.child_term(node, 1));
        let rm = self.pool.rm(rm_code(rm));
        self.mk(op, &[rm, x, y])
    }

    /// Rotation by a same-width amount, reduced modulo the width as
    /// `Z3_mk_ext_rotate_*` does. A literal amount uses smtrs's native
    /// indexed rotate; a symbolic one is two shifts and an or.
    fn rotate(&mut self, x: TermId, amt: TermId, left: bool) -> Result<TermId, ClarirsError> {
        let w = self.pool.width(x);
        if let Some(c) = self.pool.as_bv_const(amt) {
            let n = c
                .urem(&BvConst::from_u64(c.width(), u64::from(w)))
                .as_u64()
                .expect("a value below the width fits in a u64") as u32;
            let op = if left {
                Op::RotateLeft(n)
            } else {
                Op::RotateRight(n)
            };
            return self.mk(op, &[x]);
        }
        let width = self.pool.bv_u64(w, u64::from(w));
        let k = self.mk(Op::BvUrem, &[amt, width])?;
        let wk = self.mk(Op::BvSub, &[width, k])?;
        let (p, q) = if left {
            (self.mk(Op::BvShl, &[x, k])?, self.mk(Op::BvLshr, &[x, wk])?)
        } else {
            (self.mk(Op::BvLshr, &[x, k])?, self.mk(Op::BvShl, &[x, wk])?)
        };
        self.mk(Op::BvOr, &[p, q])
    }

    /// The term whose model value answers for `expr`, and how to read it.
    /// With `as_bitvec`, Bool expressions become a 1-bit vector, for the
    /// engine entry points that only take bit-vectors.
    pub(crate) fn query_term(
        &mut self,
        expr: &AstRef<'_>,
        as_bitvec: bool,
    ) -> Result<(TermId, Kind), ClarirsError> {
        let t = self.term(expr)?;
        match expr.ast_type() {
            AstType::Bool => {
                if as_bitvec {
                    let one = self.pool.bv_u64(1, 1);
                    let zero = self.pool.bv_u64(1, 0);
                    Ok((self.mk(Op::Ite, &[t, one, zero])?, Kind::Bool))
                } else {
                    Ok((t, Kind::Bool))
                }
            }
            AstType::BitVec(_) => Ok((t, Kind::BitVec)),
            AstType::Float(fsort) => Ok((self.mk(Op::FpToIeeeBv, &[t])?, Kind::Float(fsort))),
            AstType::String => Ok((t, Kind::String)),
        }
    }
}

/// The value of string variable `sym` in `model`: its length and that many
/// characters, read off the symbols the string lowering derived from it. A
/// variable the constraints never mentioned has none and reads as `""`.
pub(crate) fn string_value(
    pool: &TermPool,
    model: &FxHashMap<SymbolId, Value>,
    sym: SymbolId,
) -> String {
    let as_u64 = |s: Option<SymbolId>| -> Option<u64> { model.get(&s?)?.as_bv()?.as_u64() };
    let len = as_u64(pool.derived_symbol_of(sym, smtrs_str::LEN_TAG)).unwrap_or(0);
    let mut out = String::new();
    for i in 0..len {
        let Some(byte) = as_u64(pool.derived_symbol_of(sym, smtrs_str::CHAR_TAG_BASE + i as u32))
        else {
            break;
        };
        out.push(char::from(byte as u8));
    }
    out
}

/// A model value as an AST of the sort the query was about.
pub(crate) fn value_to_ast<'c>(
    ctx: &'c Context<'c>,
    value: &Value,
    kind: Kind,
) -> Result<AstRef<'c>, ClarirsError> {
    match (kind, value) {
        (Kind::Bool, Value::Bool(b)) => ctx.boolv(*b),
        (Kind::Bool, Value::Bv(c)) => ctx.boolv(c.bit(0)),
        (Kind::BitVec, Value::Bv(c)) => ctx.bvv(bitvec_of(c)),
        (Kind::Float(fsort), Value::Bv(c)) => {
            if c.width() != fsort.size() {
                return Err(ClarirsError::ConversionError(format!(
                    "smtrs returned {} bits for a {}-bit float",
                    c.width(),
                    fsort.size()
                )));
            }
            ctx.fpv(Float::try_from_ieee_bits(&bitvec_of(c))?)
        }
        (Kind::BitVec | Kind::Float(_), Value::Bool(_)) => Err(ClarirsError::ConversionError(
            "smtrs returned a Bool for a bit-vector query".to_string(),
        )),
        (Kind::String, _) => Err(ClarirsError::ConversionError(
            "a string value is read from the model, not from a term".to_string(),
        )),
    }
}

/// Does `ast` need no solver at all: a literal of its sort.
pub(crate) fn is_literal(ast: &AstRef<'_>) -> bool {
    matches!(
        ast.op(),
        AstOp::BoolV(_) | AstOp::BVV(_) | AstOp::FPV(_) | AstOp::StringV(_)
    )
}

/// Evaluate `roots` under `model`, completing it: a variable the model does
/// not assign (one the constraints never mention) reads as zero/false, as
/// Z3's model completion does.
pub(crate) fn eval_completed(
    pool: &TermPool,
    model: &FxHashMap<SymbolId, Value>,
    roots: &[TermId],
) -> Result<Vec<Value>, ClarirsError> {
    let mut cache: FxHashMap<TermId, Value> = FxHashMap::default();
    let mut error: Option<ClarirsError> = None;
    pool.post_order(roots, |pool, t| {
        if error.is_some() {
            return;
        }
        let op = pool.op(t);
        let value = match op {
            Op::True => Value::Bool(true),
            Op::False => Value::Bool(false),
            Op::BvConst(id) => Value::Bv(pool.bv_const(id).clone()),
            Op::Var(sym) => match model.get(&sym) {
                Some(v) => v.clone(),
                None => match pool.symbol(sym).sort {
                    Sort::Bool => Value::Bool(false),
                    Sort::BitVec(w) => Value::Bv(BvConst::zero(w)),
                    other => {
                        error = Some(unsupported(format!(
                            "no model value for a variable of sort {other}"
                        )));
                        return;
                    }
                },
            },
            _ => {
                let vals: Vec<Value> = pool.args(t).iter().map(|a| cache[a].clone()).collect();
                match smtrs_core::apply_op(op, &vals) {
                    Some(v) => v,
                    None => {
                        error = Some(unsupported(format!("cannot evaluate {op:?} under a model")));
                        return;
                    }
                }
            }
        };
        cache.insert(t, value);
    });
    if let Some(e) = error {
        return Err(e);
    }
    Ok(roots.iter().map(|r| cache[r].clone()).collect())
}
