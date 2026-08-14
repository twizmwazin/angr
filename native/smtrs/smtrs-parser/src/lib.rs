//! smtrs-parser: SMT-LIB 2.6 parsing into the smtrs-core term DAG.

mod lexer;
mod parser;

pub use parser::{parse_script, Command, ParseError, Parser, Script};

#[cfg(test)]
mod tests {
    use super::*;
    use smtrs_core::{Sort, TermPool};

    fn parse(input: &str) -> (TermPool, Script) {
        let mut pool = TermPool::new();
        let script = parse_script(input, &mut pool).unwrap();
        (pool, script)
    }

    #[test]
    fn simple_qfbv_script() {
        let (pool, script) = parse(
            r#"
            (set-info :status sat)
            (set-logic QF_BV)
            (declare-fun x () (_ BitVec 8))
            (declare-const y (_ BitVec 8))
            (assert (= (bvadd x y) #x2a))
            (assert (bvult x (_ bv100 8)))
            (check-sat)
            (exit)
            "#,
        );
        // SetStatus, SetLogic, Assert, Assert, CheckSat, Exit.
        assert_eq!(script.commands.len(), 6);
        match &script.commands[2] {
            Command::Assert(t, _) => assert_eq!(pool.sort(*t), Sort::Bool),
            c => panic!("expected assert, got {c:?}"),
        }
        match &script.commands[0] {
            Command::SetStatus(s) => assert_eq!(s, "sat"),
            c => panic!("expected status, got {c:?}"),
        }
    }

    #[test]
    fn let_shadowing_and_sharing() {
        let (pool, script) = parse(
            r#"
            (set-logic QF_BV)
            (declare-fun a () (_ BitVec 4))
            (assert (let ((b (bvadd a a))) (let ((b (bvmul b b))) (= b a))))
            (check-sat)
            "#,
        );
        match &script.commands[1] {
            Command::Assert(t, _) => {
                // (= (bvmul (bvadd a a) (bvadd a a)) a)
                assert_eq!(pool.display(*t), "(= a (bvmul (bvadd a a) (bvadd a a)))");
            }
            c => panic!("expected assert, got {c:?}"),
        }
    }

    #[test]
    fn define_fun_expansion() {
        let (pool, script) = parse(
            r#"
            (set-logic QF_BV)
            (declare-fun x () (_ BitVec 8))
            (define-fun double ((v (_ BitVec 8))) (_ BitVec 8) (bvadd v v))
            (assert (= (double x) #x00))
            (check-sat)
            "#,
        );
        match &script.commands[1] {
            Command::Assert(t, _) => {
                assert_eq!(pool.display(*t), "(= (bvadd x x) #b00000000)");
            }
            c => panic!("expected assert, got {c:?}"),
        }
    }

    #[test]
    fn indexed_ops_and_annotations() {
        let (pool, script) = parse(
            r#"
            (set-logic QF_BV)
            (declare-fun x () (_ BitVec 8))
            (assert (! (= ((_ extract 3 0) x) ((_ rotate_left 1) ((_ extract 7 4) x))) :named a0))
            (check-sat)
            "#,
        );
        assert_eq!(script.named.len(), 1);
        assert_eq!(script.named[0].0, "a0");
        match &script.commands[1] {
            Command::Assert(t, _) => assert_eq!(pool.sort(*t), Sort::Bool),
            c => panic!("expected assert, got {c:?}"),
        }
    }

    /// FP gets its own `Op` variants — it is *not* `Op::Other`, which is what
    /// this test used to be named for.
    #[test]
    fn fp_parses_to_native_ops() {
        let (pool, script) = parse(
            r#"
            (set-logic QF_FP)
            (declare-fun a () (_ FloatingPoint 8 24))
            (declare-fun b () Float32)
            (assert (fp.eq (fp.add RNE a b) a))
            (check-sat)
            "#,
        );
        assert_eq!(script.commands.len(), 3); // SetLogic, Assert, CheckSat.
        match &script.commands[1] {
            Command::Assert(t, _) => {
                assert_eq!(pool.op(*t), smtrs_core::Op::FpEq);
                assert!(!matches!(pool.op(*t), smtrs_core::Op::Other { .. }));
            }
            c => panic!("expected assert, got {c:?}"),
        }
    }

    // ---- malformed input is rejected, not panicked on ----
    //
    // Every case below aborted or hung the process before these guards
    // existed. `Op::Other` heads get no sort check in the pool, and widths,
    // FP formats, repetition counts and nesting depth all come straight from
    // the input, so the parser is where they have to be caught.

    fn rejects(input: &str) -> ParseError {
        let mut pool = TermPool::new();
        match parse_script(input, &mut pool) {
            Err(e) => e,
            Ok(_) => panic!("expected rejection of: {input}"),
        }
    }

    #[test]
    fn other_head_arity_is_checked() {
        // Each of these reached a positional `args[i]` in smtrs-str.
        for bad in [
            r#"(assert (str.contains "a"))"#,
            r#"(declare-const s String)(assert (= s (str.++)))"#,
            r#"(declare-const s String)(assert (= s (str.substr "abc" 1)))"#,
            r#"(assert (str.in_re "a" (re.range)))"#,
            r#"(assert (< 1))"#,
            r#"(assert (str.len))"#,
            r#"(assert (str.indexof "a" "b"))"#,
        ] {
            rejects(bad);
        }
        // A `declare-fun` that shadows a theory head goes down a different
        // path -- `apply` resolves the binding and builds `Op::Other` from it
        // directly -- and so bypassed the check above entirely. The resulting
        // term is indistinguishable from the theory's own, so the first of
        // these panicked `smtrs-str` at `args[1]` and the second was answered
        // `unsat` on a satisfiable formula, both from a well-formed script.
        for bad in [
            r#"(declare-fun str.contains (String) Bool)(declare-fun s () String)
               (assert (str.contains s))"#,
            r#"(declare-fun str.len (String String) Int)(declare-fun a () String)
               (assert (= (str.len a a) 4))"#,
            r#"(declare-fun str.substr (String Int) String)(declare-fun a () String)
               (assert (= (str.substr a 1) a))"#,
        ] {
            rejects(bad);
        }
        // A declared head that is not a theory symbol is unaffected.
        parse(
            r#"(declare-fun my.contains (String) Bool)(declare-fun s () String)
               (assert (my.contains s))(check-sat)"#,
        );
        // ...and the well-formed versions still parse.
        parse(r#"(assert (str.contains "ab" "a"))(check-sat)"#);
        parse(r#"(declare-const s String)(assert (= s (str.++ "a" "b" "c")))(check-sat)"#);
        // `-` is unary negation at one argument and n-ary below that.
        parse(r#"(declare-const s String)(assert (< (- (str.len s)) 3))(check-sat)"#);
        parse(r#"(declare-const s String)(assert (< (- (str.len s) 1 2) 3))(check-sat)"#);
    }

    #[test]
    fn oversized_widths_are_rejected() {
        for bad in [
            "(declare-const x (_ BitVec 4294967295))(assert (= (concat x x) (concat x x)))",
            "(declare-const x (_ BitVec 8))\
             (assert (= ((_ repeat 4000000000) x) ((_ repeat 4000000000) x)))",
            "(declare-const x (_ BitVec 8))(declare-const y (_ BitVec 8))\
             (assert (bvult ((_ zero_extend 2000000000) x) ((_ zero_extend 2000000000) y)))",
            "(assert (= (_ bv1 0) (_ bv1 0)))",
        ] {
            rejects(bad);
        }
        parse("(declare-const x (_ BitVec 64))(assert (= (concat x x) (concat x x)))(check-sat)");
    }

    #[test]
    fn degenerate_fp_formats_are_rejected() {
        for bad in [
            "(declare-const f (_ FloatingPoint 8 1))(assert (fp.isNaN f))",
            "(declare-const f (_ FloatingPoint 0 24))(assert (fp.isNaN f))",
            "(declare-const f (_ FloatingPoint 4294967295 4294967295))(assert (fp.isNaN f))",
            "(declare-const f Float32)\
             (assert (= ((_ fp.to_ubv 0) RNE f) ((_ fp.to_ubv 0) RNE f)))",
            // FP *literals* intern via `fp_const`, which never reaches
            // `TermPool::check`, so the parser is their only validation.
            "(assert (fp.isNaN (_ NaN 0 24)))",
            "(assert (fp.isInfinite (_ +oo 8 1)))",
        ] {
            rejects(bad);
        }
        parse("(assert (fp.isNaN (_ NaN 8 24)))(check-sat)");
        // The formats real benchmarks use, including the widest in the corpus.
        parse("(declare-const f (_ FloatingPoint 15 64))(assert (fp.isNaN f))(check-sat)");
        parse("(declare-const f Float64)(assert (fp.isNaN f))(check-sat)");
    }

    #[test]
    fn huge_regex_repetition_is_rejected() {
        rejects(r#"(assert (str.in_re "a" ((_ re.loop 4000000000 4000000000) (str.to_re "a"))))"#);
        parse(r#"(assert (str.in_re "aa" ((_ re.loop 1 4) (str.to_re "a"))))(check-sat)"#);
    }

    /// Nesting depth in the input is stack depth in the parser, and a stack
    /// overflow aborts the process rather than unwinding, so the CLI cannot
    /// contain it.
    ///
    /// Run on an explicit large stack because the limit is 100_000 frames
    /// deep and a default test thread gets 2 MiB — the same reason
    /// `smtrs-cli` spawns the pipeline on a 1 GiB thread. Depth is bounded
    /// here; the stack to reach that bound is still the caller's job.
    ///
    /// The 20_000 case is the regression guard that matters: the deepest term
    /// in the corpus is 17_100 parens, and a limit picked from a 400-file
    /// sample (which said 3_350) rejected four valid `sage/app7` benchmarks.
    #[test]
    fn deeply_nested_terms_are_rejected_not_overflowed() {
        std::thread::Builder::new()
            .stack_size(512 << 20)
            .spawn(|| {
                let n = 200_000;
                let deep = format!("(assert {}true{})", "(not ".repeat(n), ")".repeat(n));
                rejects(&deep);
                // Deeper than the deepest corpus term: must still parse.
                let ok = format!(
                    "(assert {}true{})(check-sat)",
                    "(not ".repeat(20_000),
                    ")".repeat(20_000)
                );
                parse(&ok);
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn arrays_unsupported() {
        let mut pool = TermPool::new();
        let r = parse_script(
            "(set-logic QF_ABV)(declare-const a (Array (_ BitVec 8) (_ BitVec 8)))",
            &mut pool,
        );
        assert!(matches!(r, Err(ParseError::Unsupported(_))));
    }
}
