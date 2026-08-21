use std::collections::BTreeSet;

use num_bigint::BigUint;

use crate::ast::op::AstOp;
use crate::error::ClarirsError;
use crate::prelude::*;

pub trait AstFactory: Sized {
    // Required methods
    fn intern_string(&self, s: impl AsRef<str>) -> InternedString;

    /// Intern a fully-constructed node into its canonical shared handle.
    fn intern_ast(&self, node: AstNode) -> Result<AstRef, ClarirsError>;

    /// The context that owns the nodes this factory builds.
    fn context(&self) -> &Arc<Context>;

    // Provided methods

    /// The single node constructor entry point all `make_*` helpers delegate to.
    /// The node gets exactly `annotations`; relocatable annotations of children
    /// are NOT collected.
    fn make_ast_exact(
        &self,
        op: AstOp,
        annotations: BTreeSet<Annotation>,
    ) -> Result<AstRef, ClarirsError> {
        op.validate()?;
        self.intern_ast(AstNode::new(self.context().clone(), op, annotations))
    }

    /// Construct a node with `annotations` plus the relocatable annotations of
    /// the op's children, mirroring how operations propagate annotations.
    fn make_ast_annotated(
        &self,
        op: AstOp,
        mut annotations: BTreeSet<Annotation>,
    ) -> Result<AstRef, ClarirsError> {
        annotations.extend(
            op.child_iter()
                .flat_map(|c| c.annotations().clone())
                .filter(|a| a.relocatable()),
        );
        self.make_ast_exact(op, annotations)
    }

    fn make_ast(&self, op: AstOp) -> Result<AstRef, ClarirsError> {
        self.make_ast_annotated(op, BTreeSet::new())
    }

    fn bools<S: AsRef<str>>(&self, name: S) -> Result<AstRef, ClarirsError> {
        let interned = self.intern_string(name);
        self.make_ast(AstOp::BoolS(interned))
    }

    fn boolv(&self, value: bool) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::BoolV(value))
    }

    fn bvs<S: AsRef<str>>(&self, name: S, width: u32) -> Result<AstRef, ClarirsError> {
        let interned = self.intern_string(name);
        self.make_ast(AstOp::BVS(interned, width))
    }

    fn bvv(&self, value: BitVec) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::BVV(value))
    }

    fn fps<S: AsRef<str>, FS: Into<FSort>>(
        &self,
        name: S,
        sort: FS,
    ) -> Result<AstRef, ClarirsError> {
        let interned = self.intern_string(name);
        self.make_ast(AstOp::FPS(interned, sort.into()))
    }

    fn fpv<F: Into<Float>>(&self, value: F) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::FPV(value.into()))
    }

    fn strings<S: AsRef<str>>(&self, name: S) -> Result<AstRef, ClarirsError> {
        let interned = self.intern_string(name);
        self.make_ast(AstOp::StringS(interned))
    }

    fn stringv<S: Into<String>>(&self, value: S) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::StringV(value.into()))
    }

    /// Logical/bitwise negation. Requires a boolean or bitvector operand.
    fn not(&self, ast: impl IntoOwned<AstRef>) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::Not(ast.into_owned()))
    }

    fn and(&self, args: impl IntoIterator<Item = AstRef>) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::And(args.into_iter().collect()))
    }

    fn and2(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::And(vec![lhs.into_owned(), rhs.into_owned()]))
    }

    fn or(&self, args: impl IntoIterator<Item = AstRef>) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::Or(args.into_iter().collect()))
    }

    fn or2(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::Or(vec![lhs.into_owned(), rhs.into_owned()]))
    }

    fn xor(&self, args: impl IntoIterator<Item = AstRef>) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::Xor(args.into_iter().collect()))
    }

    fn xor2(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::Xor(vec![lhs.into_owned(), rhs.into_owned()]))
    }

    /// Equality over operands of any matching sort. For floats this has IEEE
    /// `fp.eq` semantics, otherwise it is structural.
    fn eq_(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::Eq(lhs.into_owned(), rhs.into_owned()))
    }

    fn neq(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::Neq(lhs.into_owned(), rhs.into_owned()))
    }

    fn neg(&self, ast: impl IntoOwned<AstRef>) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::Neg(ast.into_owned()))
    }

    fn add(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::Add(vec![lhs.into_owned(), rhs.into_owned()]))
    }

    fn add_many(&self, args: impl IntoIterator<Item = AstRef>) -> Result<AstRef, ClarirsError> {
        let args: Vec<AstRef> = args.into_iter().collect();
        self.make_ast(AstOp::Add(args))
    }

    fn mul(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::Mul(vec![lhs.into_owned(), rhs.into_owned()]))
    }

    fn mul_many(&self, args: impl IntoIterator<Item = AstRef>) -> Result<AstRef, ClarirsError> {
        let args: Vec<AstRef> = args.into_iter().collect();
        self.make_ast(AstOp::Mul(args))
    }

    fn sub(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::Sub(lhs.into_owned(), rhs.into_owned()))
    }

    fn udiv(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::UDiv(lhs.into_owned(), rhs.into_owned()))
    }

    fn sdiv(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::SDiv(lhs.into_owned(), rhs.into_owned()))
    }

    fn urem(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::URem(lhs.into_owned(), rhs.into_owned()))
    }

    fn srem(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::SRem(lhs.into_owned(), rhs.into_owned()))
    }

    fn shl(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::ShL(lhs.into_owned(), rhs.into_owned()))
    }

    fn ashr(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::AShR(lhs.into_owned(), rhs.into_owned()))
    }

    fn lshr(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::LShR(lhs.into_owned(), rhs.into_owned()))
    }

    fn rotate_left(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::RotateLeft(lhs.into_owned(), rhs.into_owned()))
    }

    fn rotate_right(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::RotateRight(lhs.into_owned(), rhs.into_owned()))
    }

    fn zero_ext(&self, lhs: impl IntoOwned<AstRef>, width: u32) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::ZeroExt(lhs.into_owned(), width))
    }

    fn sign_ext(&self, lhs: impl IntoOwned<AstRef>, width: u32) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::SignExt(lhs.into_owned(), width))
    }

    fn extract(
        &self,
        lhs: impl IntoOwned<AstRef>,
        high: u32,
        low: u32,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::Extract(lhs.into_owned(), high, low))
    }

    fn concat(&self, args: impl IntoIterator<Item = AstRef>) -> Result<AstRef, ClarirsError> {
        let args: Vec<AstRef> = args.into_iter().collect();
        if args.is_empty() {
            return Err(ClarirsError::InvalidArguments(
                "Concat requires at least one argument".to_string(),
            ));
        }
        self.make_ast(AstOp::Concat(args))
    }

    fn concat2(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.concat([lhs.into_owned(), rhs.into_owned()])
    }

    fn byte_reverse(&self, lhs: impl IntoOwned<AstRef>) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::ByteReverse(lhs.into_owned()))
    }

    fn ult(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::ULT(lhs.into_owned(), rhs.into_owned()))
    }

    fn ule(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::ULE(lhs.into_owned(), rhs.into_owned()))
    }

    fn ugt(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::UGT(lhs.into_owned(), rhs.into_owned()))
    }

    fn uge(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::UGE(lhs.into_owned(), rhs.into_owned()))
    }

    fn slt(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::SLT(lhs.into_owned(), rhs.into_owned()))
    }

    fn sle(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::SLE(lhs.into_owned(), rhs.into_owned()))
    }

    fn sgt(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::SGT(lhs.into_owned(), rhs.into_owned()))
    }

    fn sge(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::SGE(lhs.into_owned(), rhs.into_owned()))
    }

    fn fp_to_fp<RM: Into<FPRM>, FS: Into<FSort>>(
        &self,
        lhs: impl IntoOwned<AstRef>,
        sort: FS,
        rm: RM,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::FpToFp(lhs.into_owned(), sort.into(), rm.into()))
    }

    fn bv_to_fp<FS: Into<FSort>>(
        &self,
        lhs: impl IntoOwned<AstRef>,
        sort: FS,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::BvToFp(lhs.into_owned(), sort.into()))
    }

    fn fp_fp(
        &self,
        sign: impl IntoOwned<AstRef>,
        exponent: impl IntoOwned<AstRef>,
        significand: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::FpFP(
            sign.into_owned(),
            exponent.into_owned(),
            significand.into_owned(),
        ))
    }

    fn bv_to_fp_signed<RM: Into<FPRM>, FS: Into<FSort>>(
        &self,
        lhs: impl IntoOwned<AstRef>,
        sort: FS,
        rm: RM,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::BvToFpSigned(
            lhs.into_owned(),
            sort.into(),
            rm.into(),
        ))
    }

    fn bv_to_fp_unsigned<RM: Into<FPRM>, FS: Into<FSort>>(
        &self,
        lhs: impl IntoOwned<AstRef>,
        sort: FS,
        rm: RM,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::BvToFpUnsigned(
            lhs.into_owned(),
            sort.into(),
            rm.into(),
        ))
    }

    fn fp_to_ieeebv(&self, lhs: impl IntoOwned<AstRef>) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::FpToIEEEBV(lhs.into_owned()))
    }

    fn fp_to_ubv<RM: Into<FPRM>>(
        &self,
        lhs: impl IntoOwned<AstRef>,
        width: u32,
        rm: RM,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::FpToUBV(lhs.into_owned(), width, rm.into()))
    }

    fn fp_to_sbv<RM: Into<FPRM>>(
        &self,
        lhs: impl IntoOwned<AstRef>,
        width: u32,
        rm: RM,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::FpToSBV(lhs.into_owned(), width, rm.into()))
    }

    fn fp_neg(&self, lhs: impl IntoOwned<AstRef>) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::FpNeg(lhs.into_owned()))
    }

    fn fp_abs(&self, lhs: impl IntoOwned<AstRef>) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::FpAbs(lhs.into_owned()))
    }

    fn fp_add<RM: Into<FPRM>>(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
        rm: RM,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::FpAdd(lhs.into_owned(), rhs.into_owned(), rm.into()))
    }

    fn fp_sub<RM: Into<FPRM>>(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
        rm: RM,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::FpSub(lhs.into_owned(), rhs.into_owned(), rm.into()))
    }

    fn fp_mul<RM: Into<FPRM>>(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
        rm: RM,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::FpMul(lhs.into_owned(), rhs.into_owned(), rm.into()))
    }

    fn fp_div<RM: Into<FPRM>>(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
        rm: RM,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::FpDiv(lhs.into_owned(), rhs.into_owned(), rm.into()))
    }

    fn fp_sqrt<RM: Into<FPRM>>(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rm: RM,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::FpSqrt(lhs.into_owned(), rm.into()))
    }

    fn fp_eq(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::Eq(lhs.into_owned(), rhs.into_owned()))
    }

    fn fp_neq(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::Neq(lhs.into_owned(), rhs.into_owned()))
    }

    fn fp_lt(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::FpLt(lhs.into_owned(), rhs.into_owned()))
    }

    fn fp_leq(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::FpLeq(lhs.into_owned(), rhs.into_owned()))
    }

    fn fp_gt(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::FpGt(lhs.into_owned(), rhs.into_owned()))
    }

    fn fp_geq(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::FpGeq(lhs.into_owned(), rhs.into_owned()))
    }

    fn fp_is_nan(&self, lhs: impl IntoOwned<AstRef>) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::FpIsNan(lhs.into_owned()))
    }

    fn fp_is_inf(&self, lhs: impl IntoOwned<AstRef>) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::FpIsInf(lhs.into_owned()))
    }

    fn str_len(&self, lhs: impl IntoOwned<AstRef>) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::StrLen(lhs.into_owned()))
    }

    fn str_concat(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::StrConcat(lhs.into_owned(), rhs.into_owned()))
    }

    fn str_substr(
        &self,
        lhs: impl IntoOwned<AstRef>,
        start: impl IntoOwned<AstRef>,
        size: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::StrSubstr(
            lhs.into_owned(),
            start.into_owned(),
            size.into_owned(),
        ))
    }

    fn str_contains(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::StrContains(lhs.into_owned(), rhs.into_owned()))
    }

    fn str_index_of(
        &self,
        base: impl IntoOwned<AstRef>,
        substr: impl IntoOwned<AstRef>,
        offset: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::StrIndexOf(
            base.into_owned(),
            substr.into_owned(),
            offset.into_owned(),
        ))
    }

    fn str_replace(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
        start: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::StrReplace(
            lhs.into_owned(),
            rhs.into_owned(),
            start.into_owned(),
        ))
    }

    fn str_prefix_of(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::StrPrefixOf(lhs.into_owned(), rhs.into_owned()))
    }

    fn str_suffix_of(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::StrSuffixOf(lhs.into_owned(), rhs.into_owned()))
    }

    fn str_to_bv(&self, lhs: impl IntoOwned<AstRef>) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::StrToBV(lhs.into_owned()))
    }

    fn bv_to_str(&self, lhs: impl IntoOwned<AstRef>) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::BVToStr(lhs.into_owned()))
    }

    fn str_is_digit(&self, lhs: impl IntoOwned<AstRef>) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::StrIsDigit(lhs.into_owned()))
    }

    fn str_eq(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::Eq(lhs.into_owned(), rhs.into_owned()))
    }

    fn str_neq(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::Neq(lhs.into_owned(), rhs.into_owned()))
    }

    /// If-then-else. `then` and `else_` must have the same sort.
    /// If-then-else. The condition must be boolean and both branches must have
    /// the same sort.
    fn ite(
        &self,
        cond: impl IntoOwned<AstRef>,
        then: impl IntoOwned<AstRef>,
        else_: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::ITE(
            cond.into_owned(),
            then.into_owned(),
            else_.into_owned(),
        ))
    }

    fn annotate(
        &self,
        ast: impl IntoOwned<AstRef>,
        annotations: impl IntoIterator<Item = Annotation>,
    ) -> Result<AstRef, ClarirsError> {
        ast.into_owned().annotate(annotations)
    }

    // VSA methods

    fn si(
        &self,
        size: u32,
        stride: BigUint,
        lower_bound: BigUint,
        upper_bound: BigUint,
    ) -> Result<AstRef, ClarirsError> {
        let name = format!("SI{size}_{stride}_{lower_bound}_{upper_bound}");
        let interned = self.intern_string(name);
        self.make_ast_annotated(
            AstOp::BVS(interned, size),
            BTreeSet::from([Annotation::new(
                AnnotationType::StridedInterval {
                    stride,
                    lower_bound,
                    upper_bound,
                },
                false,
                false,
            )]),
        )
    }

    fn esi(&self, size: u32) -> Result<AstRef, ClarirsError> {
        let name = format!("ESI{size}");
        let interned = self.intern_string(name);
        self.make_ast_annotated(
            AstOp::BVS(interned, size),
            BTreeSet::from([Annotation::new(
                AnnotationType::EmptyStridedInterval,
                false,
                false,
            )]),
        )
    }

    fn union(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::Union(lhs.into_owned(), rhs.into_owned()))
    }

    fn intersection(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::Intersection(lhs.into_owned(), rhs.into_owned()))
    }

    fn widen(
        &self,
        lhs: impl IntoOwned<AstRef>,
        rhs: impl IntoOwned<AstRef>,
    ) -> Result<AstRef, ClarirsError> {
        self.make_ast(AstOp::Widen(lhs.into_owned(), rhs.into_owned()))
    }

    // Helper methods
    fn true_(&self) -> Result<AstRef, ClarirsError> {
        self.boolv(true)
    }

    fn false_(&self) -> Result<AstRef, ClarirsError> {
        self.boolv(false)
    }

    fn fpv_from_f64(&self, value: f64) -> Result<AstRef, ClarirsError> {
        self.fpv(Float::from(value))
    }
}
