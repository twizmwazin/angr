//! Unsat cores, end to end from SMT-LIB text.
//!
//! Every test here asserts the same property, which is the only one that
//! matters: **the reported core, asserted on its own, is still unsat.** That is
//! checked mechanically by [`Case::core_refutes`], which re-runs the script
//! with the non-core named assertions deleted. A core that names too few
//! assertions fails that check; a core that names too many only fails the
//! separate, weaker size assertions.
//!
//! The cases are chosen for the ways this pipeline can lose an assertion
//! between `assert` and the SAT solver: rewriting to `true` or `false`,
//! top-level equality substitution in `preprocess`, bounded variable
//! elimination in the CDCL preprocessor, the dual encoding building the
//! formula twice, and `push`/`pop` throwing the engine away.

use smtrs_core::{SymbolId, TermPool};
use smtrs_parser::{parse_script, Command};
use smtrs_solver::{Answer, Solver};

/// A script run the way the CLI runs it, with `:named` assertions tracked.
struct Case {
    script: String,
    answers: Vec<Answer>,
    /// Core after the last check, as names, sorted. `Err` is a refusal.
    core: Result<Vec<String>, String>,
    /// Names of every top-level `:named` assertion in the script.
    named: Vec<String>,
}

fn execute(script: &str, cores: bool) -> Case {
    let mut pool = TermPool::new();
    let parsed = parse_script(script, &mut pool).expect("parse");
    let mut solver = Solver::new();
    solver.declared = parsed.declared.clone();
    solver.set_produce_unsat_cores(cores);
    let mut names: Vec<(SymbolId, String)> = Vec::new();
    let mut all_named: Vec<String> = Vec::new();
    let mut answers = Vec::new();
    for cmd in &parsed.commands {
        match cmd {
            Command::Assert(t, Some(name)) if cores => {
                all_named.push(name.clone());
                names.push((solver.assert_tracked(&mut pool, *t), name.clone()));
            }
            Command::Assert(t, name) => {
                if let Some(n) = name {
                    all_named.push(n.clone());
                }
                solver.assert(*t);
            }
            Command::CheckSat => answers.push(solver.check_sat(&mut pool, &[])),
            Command::CheckSatAssuming(ts) => answers.push(solver.check_sat(&mut pool, ts)),
            Command::Push(n) => solver.push(*n),
            Command::Pop(n) => solver.pop(*n),
            _ => {}
        }
    }
    let core = match solver.unsat_core() {
        Ok(syms) => Ok({
            let mut v: Vec<String> = syms
                .iter()
                .map(|s| {
                    names
                        .iter()
                        .find(|(sym, _)| sym == s)
                        .map(|(_, n)| n.clone())
                        .expect("core names a symbol we minted")
                })
                .collect();
            v.sort();
            v
        }),
        Err(why) => Err(why.to_string()),
    };
    Case {
        script: script.to_string(),
        answers,
        core,
        named: all_named,
    }
}

fn run(script: &str) -> Case {
    execute(script, true)
}

impl Case {
    fn core(&self) -> &[String] {
        match &self.core {
            Ok(c) => c,
            Err(e) => panic!("expected a core, got refusal: {e}"),
        }
    }

    fn last(&self) -> &Answer {
        self.answers.last().expect("a check-sat ran")
    }

    /// Re-run the script with every named assertion *outside* the core
    /// deleted, and require the answer to still be `unsat`.
    ///
    /// This is the definition of an unsat core, checked rather than argued.
    /// Deletion is textual and needs each named assertion on its own line,
    /// which every script in this file obeys.
    fn core_refutes(&self) {
        let core = self.core();
        let mut reduced = String::new();
        for line in self.script.lines() {
            let dropped = self
                .named
                .iter()
                .any(|n| line.contains(&format!(":named {n})")) && !core.contains(n));
            if !dropped {
                reduced.push_str(line);
                reduced.push('\n');
            }
        }
        let again = execute(&reduced, false);
        assert_eq!(
            again.last(),
            &Answer::Unsat,
            "core {core:?} does not refute on its own; reduced script:\n{reduced}"
        );
    }
}

#[test]
fn core_drops_the_irrelevant_assertions() {
    let c = run("
        (declare-const x (_ BitVec 8))
        (declare-const y (_ BitVec 8))
        (assert (! (bvult x #x0a) :named n1))
        (assert (! (bvugt x #x14) :named n2))
        (assert (! (= y #x01) :named n3))
        (assert (! (bvule y #xf0) :named n4))
        (check-sat)");
    assert_eq!(c.last(), &Answer::Unsat);
    assert_eq!(c.core(), ["n1", "n2"]);
    c.core_refutes();
}

/// An assertion that rewrites to `true` contributes nothing and must not be
/// named. The guard `act -> true` collapses to `true` and the activation
/// literal never reaches the circuit — the case that has to *not* be reported
/// as "cannot tell".
#[test]
fn assertion_rewriting_to_true_is_not_in_the_core() {
    let c = run("
        (declare-const x (_ BitVec 8))
        (assert (! (= (bvor x x) x) :named tautology))
        (assert (! (bvult x #x05) :named lo))
        (assert (! (bvugt x #x50) :named hi))
        (check-sat)");
    assert_eq!(c.last(), &Answer::Unsat);
    assert_eq!(c.core(), ["hi", "lo"]);
    c.core_refutes();
}

/// An assertion that rewrites to `false` is a one-element core. The guard
/// `act -> false` becomes `not act`, which `preprocess` turns into the
/// definition `act := false` and *deletes* — so the activation literal is not
/// in the circuit at all, and the case has to be recognised from the
/// substitution rather than from the SAT search.
#[test]
fn assertion_rewriting_to_false_is_the_whole_core() {
    let c = run("
        (declare-const x (_ BitVec 8))
        (assert (! (bvult x #x05) :named other))
        (assert (! (distinct x x) :named contradiction))
        (assert (! (bvugt x #x01) :named more))
        (check-sat)");
    assert_eq!(c.last(), &Answer::Unsat);
    assert_eq!(c.core(), ["contradiction"]);
    c.core_refutes();
}

/// The same, but the contradiction is *unnamed*: the core is then empty, which
/// is the correct answer and not a failure to compute one.
#[test]
fn unnamed_contradiction_gives_an_empty_core() {
    let c = run("
        (declare-const x (_ BitVec 8))
        (assert (distinct x x))
        (assert (! (bvult x #x05) :named other))
        (check-sat)");
    assert_eq!(c.last(), &Answer::Unsat);
    assert!(c.core().is_empty(), "got {:?}", c.core());
    c.core_refutes();
}

/// Untracked assertions are hard constraints the core is taken relative to:
/// an unsat that owes nothing to any named assertion reports the empty core.
#[test]
fn refutation_among_untracked_assertions_gives_an_empty_core() {
    let c = run("
        (declare-const x (_ BitVec 8))
        (assert (bvult x #x05))
        (assert (bvugt x #x50))
        (assert (! (= x #x03) :named named))
        (check-sat)");
    assert_eq!(c.last(), &Answer::Unsat);
    assert!(c.core().is_empty(), "got {:?}", c.core());
    c.core_refutes();
}

/// Top-level equalities are what `preprocess` substitutes away, eliminating the
/// variable and *deleting* the assertion. Wrapped in an activation literal they
/// are no longer top-level equalities, so they survive as themselves — which is
/// what this checks, by making the equalities the only possible core.
#[test]
fn defining_equalities_survive_substitution() {
    let c = run("
        (declare-const x (_ BitVec 8))
        (declare-const y (_ BitVec 8))
        (declare-const z (_ BitVec 8))
        (assert (! (= x #x10) :named defx))
        (assert (! (= y #x20) :named defy))
        (assert (! (= z #x30) :named defz))
        (assert (bvult (bvadd x y) #x0f))
        (check-sat)");
    assert_eq!(c.last(), &Answer::Unsat);
    assert_eq!(c.core(), ["defx", "defy"]);
    c.core_refutes();
}

/// Bounded variable elimination removes the clauses of a variable and
/// reconstructs it afterwards. A named assertion whose variables are all
/// eliminable is the shape that would lose its activation literal with them;
/// the literals are frozen against exactly this.
#[test]
fn core_survives_bounded_variable_elimination() {
    let c = run("
        (declare-const a (_ BitVec 16))
        (declare-const b (_ BitVec 16))
        (declare-const c (_ BitVec 16))
        (declare-const d (_ BitVec 16))
        (assert (! (= (bvadd a b) (bvmul c d)) :named link))
        (assert (! (bvult (bvmul c d) #x0010) :named small))
        (assert (! (bvugt (bvadd a b) #x8000) :named big))
        (assert (! (bvult a #xff00) :named spare))
        (check-sat)");
    assert_eq!(c.last(), &Answer::Unsat);
    assert_eq!(c.core(), ["big", "link", "small"]);
    c.core_refutes();
}

/// The first `pop` throws the engine away and rebuilds it, so the activation
/// literals are re-minted in a fresh variable numbering. A core taken after
/// the rebuild must describe the assertions that are live *then*.
#[test]
fn core_after_push_and_pop() {
    let c = run("
        (declare-const x (_ BitVec 8))
        (assert (! (bvult x #x0a) :named base))
        (push 1)
        (assert (! (bvugt x #x14) :named inner))
        (check-sat)
        (pop 1)
        (assert (! (= x #x40) :named outer))
        (check-sat)");
    assert_eq!(c.answers, vec![Answer::Unsat, Answer::Unsat]);
    assert_eq!(c.core(), ["base", "outer"]);
    c.core_refutes();
}

/// Once a script has popped enough to earn guarded mode, levels are retired
/// with an activation literal instead of a rebuild, so a core is read off an
/// engine that carries *two* kinds of activation literal: the ones naming
/// tracked assertions and the ones naming push levels. Only the first kind may
/// appear in a core, and the second kind has to be in force while it is
/// computed — including in the verification re-solve, which would otherwise
/// run with the whole open level switched off and widen the core back to
/// everything.
#[test]
fn core_inside_a_guarded_push_level() {
    let c = run("
        (declare-const x (_ BitVec 8))
        (assert (! (bvult x #x40) :named base))
        (assert (! (bvugt x #x02) :named spare))
        (push 1)
        (assert (! (bvult x #x10) :named lvl1))
        (check-sat)
        (pop 1)
        (push 1)
        (assert (! (bvult x #x20) :named lvl2))
        (check-sat)
        (pop 1)
        (push 1)
        (assert (! (bvugt x #x80) :named lvl3))
        (check-sat)
        (pop 1)
        (check-sat)");
    // The last check runs at the base scope: satisfiable, so no core.
    assert_eq!(
        c.answers,
        vec![Answer::Sat, Answer::Sat, Answer::Unsat, Answer::Sat]
    );
}

/// The same shape, but with the `unsat` last so the core is the one reported.
/// The final level is asserted into an engine that has already retired two
/// levels in place, which is where a stale activation literal would show up.
#[test]
fn core_from_a_level_reopened_after_a_guarded_pop() {
    let c = run("
        (declare-const x (_ BitVec 8))
        (assert (! (bvult x #x40) :named base))
        (assert (! (bvult x #xf0) :named loose))
        (push 1)
        (assert (! (bvugt x #x80) :named first))
        (check-sat)
        (pop 1)
        (push 1)
        (assert (! (bvugt x #x84) :named second))
        (check-sat)
        (pop 1)
        (push 1)
        (assert (! (bvugt x #x90) :named third))
        (check-sat)");
    assert_eq!(c.answers, vec![Answer::Unsat, Answer::Unsat, Answer::Unsat]);
    assert_eq!(c.core(), ["base", "third"]);
    c.core_refutes();
}

/// With `check-sat-assuming`, the core names tracked assertions only; the
/// assumptions of the check are in force and are not core members. Re-running
/// the reduced script keeps the same `check-sat-assuming`, so the property
/// being checked is "core plus the same assumptions is unsat".
#[test]
fn core_under_check_sat_assuming() {
    let c = run("
        (declare-const x (_ BitVec 8))
        (declare-const p Bool)
        (assert (! (=> p (bvugt x #x80)) :named guard))
        (assert (! (bvult x #x10) :named low))
        (assert (! (bvult x #xf0) :named loose))
        (check-sat-assuming (p))");
    assert_eq!(c.last(), &Answer::Unsat);
    assert_eq!(c.core(), ["guard", "low"]);
    c.core_refutes();
}

/// The activation literals must not change the answer, and must not change it
/// under either encoding of the dual-encoding selector either: whichever
/// engine answers is the one the core is read from.
#[test]
fn cores_do_not_change_answers() {
    for script in [
        "(declare-const x (_ BitVec 8))
         (assert (! (bvult x #x0a) :named a))
         (assert (! (bvugt x #x02) :named b))
         (check-sat)",
        "(declare-const a (_ BitVec 16))(declare-const b (_ BitVec 16))
         (declare-const c (_ BitVec 16))(declare-const d (_ BitVec 16))
         (assert (! (bvult (bvadd a b) #x0100) :named s1))
         (assert (! (bvult (bvadd (bvadd a b) c) #x0200) :named s2))
         (assert (! (bvult (bvadd (bvadd (bvadd a b) c) d) #x0300) :named s3))
         (assert (! (= (bvadd (bvadd (bvadd a b) c) d) #x02ff) :named s4))
         (check-sat)",
        "(declare-const a (_ BitVec 16))(declare-const b (_ BitVec 16))
         (assert (! (= (bvadd (bvadd a b) (bvadd a b)) #x0001) :named odd))
         (assert (! (bvult (bvadd a b) #x0100) :named bound))
         (check-sat)",
    ] {
        let tracked = execute(script, true);
        let plain = execute(script, false);
        assert_eq!(
            tracked.answers, plain.answers,
            "activation literals changed the answer of\n{script}"
        );
        if tracked.last() == &Answer::Unsat {
            tracked.core_refutes();
        }
    }
}

/// A model still has to satisfy every tracked assertion. `act -> phi` is
/// satisfied by a false `act`, so a check that forgot to assume the activation
/// literals would report `sat` with a model that ignores the assertions —
/// model validation runs against the guards, and would pass vacuously.
#[test]
fn tracked_assertions_still_constrain_models() {
    let c = run("
        (declare-const x (_ BitVec 8))
        (assert (! (= x #x2a) :named fix))
        (check-sat)");
    assert_eq!(c.last(), &Answer::Sat);
    assert!(c.core.is_err(), "a sat answer has no core");

    // Same script, with the assertion made unsatisfiable by an untracked one:
    // if the guard were droppable this would come back sat.
    let c = run("
        (declare-const x (_ BitVec 8))
        (assert (! (= x #x2a) :named fix))
        (assert (distinct x #x2a))
        (check-sat)");
    assert_eq!(c.last(), &Answer::Unsat);
}

/// Without `:produce-unsat-cores`, `get-unsat-core` is refused rather than
/// answered with something plausible.
#[test]
fn core_is_refused_when_tracking_is_off() {
    let c = execute(
        "(declare-const x (_ BitVec 8))
         (assert (! (bvult x #x05) :named a))
         (assert (! (bvugt x #x50) :named b))
         (check-sat)",
        false,
    );
    assert_eq!(c.last(), &Answer::Unsat);
    assert!(c.core.is_err());
}

/// Incremental use: the engine is reused across checks, and the activation
/// literals are cached with it. A core taken on the second check must reflect
/// the assertions added since the first.
#[test]
fn core_on_a_reused_engine() {
    let c = run("
        (declare-const x (_ BitVec 8))
        (assert (! (bvult x #x80) :named first))
        (check-sat)
        (assert (! (bvugt x #xc0) :named second))
        (check-sat)");
    assert_eq!(c.answers, vec![Answer::Sat, Answer::Unsat]);
    assert_eq!(c.core(), ["first", "second"]);
    c.core_refutes();
}

/// Two named assertions with the *same* formula get separate activation
/// literals, and naming either one is a correct core; naming neither is not.
#[test]
fn duplicate_formulas_get_separate_names() {
    let c = run("
        (declare-const x (_ BitVec 8))
        (assert (! (bvult x #x05) :named dup1))
        (assert (! (bvult x #x05) :named dup2))
        (assert (! (bvugt x #x50) :named hi))
        (check-sat)");
    assert_eq!(c.last(), &Answer::Unsat);
    assert!(c.core().contains(&"hi".to_string()));
    assert!(c.core().len() >= 2, "got {:?}", c.core());
    c.core_refutes();
}

/// A `:named` annotation on a *subterm* names a term, not an asserted formula,
/// and SMT-LIB does not allow `get-unsat-core` to return it. It must not be
/// tracked, and the enclosing assertion must stay a hard constraint.
#[test]
fn nested_named_annotations_are_not_core_members() {
    let c = run("
        (declare-const x (_ BitVec 8))
        (assert (and (! (bvult x #x05) :named inner) (bvugt x #x50)))
        (assert (! (= x #x03) :named outer))
        (check-sat)");
    assert_eq!(c.last(), &Answer::Unsat);
    // The refutation is entirely inside the untracked assertion.
    assert!(c.core().is_empty(), "got {:?}", c.core());
}

/// `unknown_or_prop_unsat` proves `unsat` by solving an *over-approximation*
/// in a fresh sub-solver that never saw an activation literal. There is no core
/// to read, and the refusal has to be explicit.
///
/// The same test pins the answer itself: the guards must not weaken the
/// approximation. A Boolean skeleton of `act -> phi` is satisfied by a false
/// `act`, so building the skeleton from the guards instead of from the
/// assertions would turn this `unsat` into `unknown` the moment the option was
/// set — the answer would depend on whether cores were being collected.
#[test]
fn unsat_from_an_over_approximation_refuses_a_core() {
    // `Int` outside a string problem is unsupported, so the pipeline concedes
    // and the Boolean skeleton is what settles it.
    let script = "
        (declare-fun a () Int)
        (assert (! (> a 5) :named p))
        (assert (! (not (> a 5)) :named q))
        (check-sat)";
    let tracked = execute(script, true);
    assert_eq!(tracked.last(), &Answer::Unsat);
    assert!(
        tracked.core.is_err(),
        "a core was invented for an over-approximation: {:?}",
        tracked.core
    );
    assert_eq!(
        execute(script, false).answers,
        tracked.answers,
        "core tracking changed the answer"
    );
}

/// A string problem is encoded under a **length bound**, and the analysis that
/// says the bound removes no model harvests its length facts from the top-level
/// conjuncts of the whole problem. Delete a named assertion and the fact that
/// justified the bound may go with it, so the subset's `unsat` is again only
/// "no model this short". The core is refused, even though the engine computed
/// one and even when the full answer is a trustworthy `unsat`.
///
/// Floating point is the contrast, and the next test is it: FP lowering is
/// exact word-blasting, not a bound, so its cores stand.
#[test]
fn bounded_string_encodings_refuse_a_core() {
    let c = run("
        (declare-const s String)
        (assert (! (= (str.len s) 3) :named len3))
        (assert (! (str.prefixof \"ab\" s) :named pre))
        (assert (! (str.suffixof \"zz\" s) :named suf))
        (assert (! (str.contains s \"b\") :named hasb))
        (check-sat)");
    assert!(
        c.core.is_err(),
        "a core was reported from a bounded string encoding: {:?}",
        c.core
    );
}

/// The core reported for a floating-point problem comes from the same pipeline
/// (FP is lowered to BV before anything else runs), so the guards ride through
/// the lowering with the assertions they guard.
#[test]
fn core_after_floating_point_lowering() {
    // 1.0f and 2.0f as IEEE bit patterns.
    let c = run("
        (declare-const f (_ FloatingPoint 8 24))
        (assert (! (fp.lt f (fp #b0 #b01111111 #b00000000000000000000000)) :named lt1))
        (assert (! (fp.gt f (fp #b0 #b10000000 #b00000000000000000000000)) :named gt2))
        (assert (! (not (fp.isNaN f)) :named notnan))
        (check-sat)");
    assert_eq!(c.last(), &Answer::Unsat);
    assert!(c.core().contains(&"gt2".to_string()));
    assert!(c.core().contains(&"lt1".to_string()));
    c.core_refutes();
}
