use crate::pool::{BvConstId, SymbolId};

/// Term operators.
///
/// Bool and QF_BV are handled natively by the rewriter, bit-blaster and
/// evaluator. Floating point is word-blasted to BV by `smtrs-fp`, and strings
/// are reduced to bounded BV by `smtrs-str`, both *before* the rest of the
/// pipeline sees the term — so an `Op::Fp*` node never reaches the blaster.
/// Int appears only as the length/index arithmetic of the string reduction.
/// What is left unsupported (arrays, UF, quantifiers) becomes [`Op::Other`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Op {
    // Leaves.
    True,
    False,
    BvConst(BvConstId),
    /// Free constant (0-ary declared function).
    Var(SymbolId),

    // Core / Bool. And/Or/Xor/Eq/Distinct are n-ary.
    Not,
    Implies,
    And,
    Or,
    Xor,
    Eq,
    Distinct,
    Ite,

    // BV arithmetic. Add/Mul are n-ary (SMT-LIB left-assoc chains flattened).
    BvNeg,
    BvAdd,
    BvSub,
    BvMul,
    BvUdiv,
    BvUrem,
    BvSdiv,
    BvSrem,
    BvSmod,

    // Bitwise. And/Or/Xor n-ary.
    BvNot,
    BvAnd,
    BvOr,
    BvXor,
    BvNand,
    BvNor,
    BvXnor,
    /// bvcomp: 1-bit equality result.
    BvComp,

    // Shifts (second operand is a same-width BV).
    BvShl,
    BvLshr,
    BvAshr,

    // Structural. Concat is n-ary.
    Concat,
    Extract {
        hi: u32,
        lo: u32,
    },
    ZeroExtend(u32),
    SignExtend(u32),
    RotateLeft(u32),
    RotateRight(u32),
    Repeat(u32),

    // Comparisons.
    BvUlt,
    BvUle,
    BvUgt,
    BvUge,
    BvSlt,
    BvSle,
    BvSgt,
    BvSge,

    // ---- Floating point (IEEE-754). Formats carry (eb, sb) via the term's
    // sort; `sb` includes the hidden bit. Rounding-mode operands are terms of
    // sort RoundingMode (RmConst or a variable).
    /// Rounding mode literal: 0=RNE 1=RNA 2=RTP 3=RTN 4=RTZ.
    RmConst(u8),
    /// `(fp sign exp sig)` from three BV operands.
    FpFromBits,
    /// Special constants for the term's own sort.
    FpNan,
    FpInf(bool),
    FpZero(bool),
    FpAbs,
    FpNeg,
    /// Arithmetic; first operand is the rounding mode.
    FpAdd,
    FpSub,
    FpMul,
    FpDiv,
    FpSqrt,
    FpFma,
    FpRoundToIntegral,
    /// No rounding mode.
    FpRem,
    FpMin,
    FpMax,
    /// Predicates.
    FpLeq,
    FpLt,
    FpGeq,
    FpGt,
    FpEq,
    FpIsNormal,
    FpIsSubnormal,
    FpIsZero,
    FpIsInfinite,
    FpIsNan,
    FpIsNegative,
    FpIsPositive,
    /// Conversions. `to` carries the destination format for FP results.
    /// (_ to_fp eb sb) applied to a single BV = reinterpret IEEE bits.
    FpFromIeeeBv {
        eb: u32,
        sb: u32,
    },
    /// (_ to_fp eb sb) rm f — FP to FP.
    FpToFp {
        eb: u32,
        sb: u32,
    },
    /// (_ to_fp eb sb) rm bv — signed BV to FP.
    FpFromSignedBv {
        eb: u32,
        sb: u32,
    },
    /// (_ to_fp_unsigned eb sb) rm bv — unsigned BV to FP.
    FpFromUnsignedBv {
        eb: u32,
        sb: u32,
    },
    /// fp.to_ieee_bv: the packed bit pattern (NaN is nondeterministic in
    /// SMT-LIB; we produce the canonical quiet NaN).
    FpToIeeeBv,
    /// (_ fp.to_ubv m) rm f / (_ fp.to_sbv m) rm f.
    FpToUbv(u32),
    FpToSbv(u32),

    /// Any operator the core does not interpret: string and regex operators,
    /// Int arithmetic, and UF applications. `name` is the interned operator
    /// symbol; the node's sort is inferred by the parser's rule table.
    ///
    /// Reaching `check_sat` with an `Other` node makes the solver answer
    /// `unknown`, but most of them never get that far: `smtrs-str` lowers the
    /// string, regex and Int heads away first, and only what survives that is
    /// tested by `Solver::unsupported_reason`.
    ///
    /// Note that `TermPool::check` does **not** sort- or arity-check `Other`
    /// — it has no signature for heads it does not interpret — so the parser
    /// is the only place a malformed application of one is rejected. See
    /// `Parser::other_arity`.
    Other {
        name: SymbolId,
        index0: u32,
        index1: u32,
    },
}

impl Op {
    /// Operators whose operand order does not matter (used by hash-consing
    /// normalization: operands of commutative n-ary ops are sorted).
    pub fn is_commutative(self) -> bool {
        matches!(
            self,
            Op::And
                | Op::Or
                | Op::Xor
                | Op::Eq
                | Op::Distinct
                | Op::BvAdd
                | Op::BvMul
                | Op::BvAnd
                | Op::BvOr
                | Op::BvXor
                | Op::BvNand
                | Op::BvNor
                | Op::BvXnor
                | Op::BvComp
        )
    }

    /// Floating-point (or rounding-mode) operator: handled by lowering to BV
    /// in smtrs-fp before the rest of the pipeline runs.
    pub fn is_fp(self) -> bool {
        use Op::*;
        matches!(
            self,
            RmConst(_)
                | FpFromBits
                | FpNan
                | FpInf(_)
                | FpZero(_)
                | FpAbs
                | FpNeg
                | FpAdd
                | FpSub
                | FpMul
                | FpDiv
                | FpSqrt
                | FpFma
                | FpRoundToIntegral
                | FpRem
                | FpMin
                | FpMax
                | FpLeq
                | FpLt
                | FpGeq
                | FpGt
                | FpEq
                | FpIsNormal
                | FpIsSubnormal
                | FpIsZero
                | FpIsInfinite
                | FpIsNan
                | FpIsNegative
                | FpIsPositive
                | FpFromIeeeBv { .. }
                | FpToFp { .. }
                | FpFromSignedBv { .. }
                | FpFromUnsignedBv { .. }
                | FpToIeeeBv
                | FpToUbv(_)
                | FpToSbv(_)
        )
    }
}
