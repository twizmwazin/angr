//! Incremental solving: `push`/`pop`, `check-sat-assuming`, and the property
//! that ties them together.
//!
//! The engine is *persistent* across checks — that is the entire point of
//! incremental mode, and it is also the entire risk. Assertions retired by a
//! `pop` must stop constraining, assumptions from one
//! `check-sat-assuming` must not survive into the next, and a model handed
//! back after a `pop` must satisfy the assertions that are still in scope
//! rather than the ones that were.
//!
//! Rather than test those one at a time with hand-picked scripts, most of the
//! file rests on a single differential property:
//!
//! > At every `check-sat`, the incremental solver must answer exactly what a
//! > **fresh** solver answers when given only the assertions currently in
//! > scope.
//!
//! A one-shot solve has no state to leak, so it is the oracle. Any way of
//! carrying information across a `pop` that should not have been carried —
//! a clause learnt under a retired assertion, a stale activation literal, a
//! phase saved from a scope that no longer exists — shows up as a disagreement.
//! [`assert_matches_oneshot`] is that check, and [`replay`] applies it to whole
//! scripts including real corpus files.
//!
//! This matters more than usual right now: incremental solving is the workload
//! angr actually generates (a long-lived solver answering many related queries)
//! and is under active optimization. An optimization that makes `pop` cheaper
//! by keeping more state is exactly the change this property catches.

use smtrs_core::{TermId, TermPool};
use smtrs_parser::{parse_script, Command};
use smtrs_solver::{Answer, Solver};

/// Answers, with `Unknown`'s message discarded so comparisons are meaningful.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum A {
    Sat,
    Unsat,
    Unknown,
}

fn norm(a: &Answer) -> A {
    match a {
        Answer::Sat => A::Sat,
        Answer::Unsat => A::Unsat,
        Answer::Unknown(_) => A::Unknown,
    }
}

/// Solve `roots` (plus `assuming`) on a solver that has never seen anything
/// else. This is the oracle: no persistent state, so nothing can leak into it.
fn oneshot(
    pool: &mut TermPool,
    declared: &[smtrs_core::SymbolId],
    roots: &[TermId],
    assuming: &[TermId],
) -> A {
    let mut s = Solver::new();
    s.declared = declared.to_vec();
    for &r in roots {
        s.assert(r);
    }
    norm(&s.check_sat(pool, assuming))
}

/// Replay an SMT-LIB script incrementally while mirroring the assertion stack,
/// and check every `check-sat` against a one-shot solve of what is in scope.
///
/// Returns the incremental answers. Panics with the offending check index on
/// the first disagreement.
fn replay(input: &str) -> Vec<A> {
    let mut pool = TermPool::new();
    let script = parse_script(input, &mut pool).expect("parse");
    let mut solver = Solver::new();
    solver.declared = script.declared.clone();

    // Mirror of the solver's own stack, so the oracle can be told exactly what
    // is in scope. Kept independently on purpose: reading it back out of the
    // solver would make the test agree with the implementation by construction.
    let mut in_scope: Vec<TermId> = Vec::new();
    let mut levels: Vec<usize> = Vec::new();
    let mut answers = Vec::new();
    let mut check = 0usize;

    for cmd in &script.commands {
        match cmd {
            Command::Assert(t, _) => {
                solver.assert(*t);
                in_scope.push(*t);
            }
            Command::Push(n) => {
                solver.push(*n);
                for _ in 0..*n {
                    levels.push(in_scope.len());
                }
            }
            Command::Pop(n) => {
                solver.pop(*n);
                for _ in 0..*n {
                    if let Some(len) = levels.pop() {
                        in_scope.truncate(len);
                    }
                }
            }
            Command::CheckSat | Command::CheckSatAssuming(_) => {
                let assuming: Vec<TermId> = match cmd {
                    Command::CheckSatAssuming(ts) => ts.clone(),
                    _ => Vec::new(),
                };
                let got = norm(&solver.check_sat(&mut pool, &assuming));
                let want = oneshot(&mut pool, &script.declared, &in_scope, &assuming);
                assert_eq!(
                    got,
                    want,
                    "check #{check}: incremental said {got:?}, a fresh solver on the \
                     same {} in-scope assertions said {want:?}",
                    in_scope.len()
                );
                answers.push(got);
                check += 1;
            }
            _ => {}
        }
    }
    answers
}

/// The same property for a script given as text, returning nothing — used when
/// the answers themselves are asserted separately.
fn assert_matches_oneshot(input: &str) {
    replay(input);
}

// ---------------------------------------------------------------------------
// Scoping semantics
// ---------------------------------------------------------------------------

#[test]
fn pop_retires_the_assertion_that_made_it_unsat() {
    let a = replay(
        "(declare-const x (_ BitVec 4))
         (assert (bvult x #x8))
         (check-sat)
         (push 1)
         (assert (bvugt x #x9))
         (check-sat)
         (pop 1)
         (check-sat)",
    );
    assert_eq!(a, vec![A::Sat, A::Unsat, A::Sat]);
}

#[test]
fn multi_level_push_and_a_single_multi_pop() {
    // `(pop 3)` must retire all three levels at once, not one.
    let a = replay(
        "(declare-const x (_ BitVec 8))
         (assert (bvult x #x80))
         (check-sat)
         (push 1) (assert (bvugt x #x10)) (check-sat)
         (push 1) (assert (bvugt x #x20)) (check-sat)
         (push 1) (assert (bvult x #x05)) (check-sat)
         (pop 3)
         (check-sat)",
    );
    assert_eq!(a, vec![A::Sat, A::Sat, A::Sat, A::Unsat, A::Sat]);
}

#[test]
fn push_n_greater_than_one_opens_n_levels() {
    // `(push 3)` then three single pops must land back at the base scope, not
    // underflow it.
    let a = replay(
        "(declare-const x (_ BitVec 8))
         (assert (bvult x #x80))
         (push 3)
         (assert (= x #xff))
         (check-sat)
         (pop 1) (pop 1) (pop 1)
         (check-sat)",
    );
    assert_eq!(a, vec![A::Unsat, A::Sat]);
}

#[test]
fn reasserting_after_a_pop_is_unsat_again() {
    // The retired constraint must be genuinely gone and genuinely restorable —
    // a cache keyed on the term alone could get this wrong in either direction.
    let a = replay(
        "(declare-const x (_ BitVec 4))
         (assert (bvult x #x8))
         (push 1) (assert (bvugt x #x9)) (check-sat)
         (pop 1) (check-sat)
         (push 1) (assert (bvugt x #x9)) (check-sat)
         (pop 1) (check-sat)",
    );
    assert_eq!(a, vec![A::Unsat, A::Sat, A::Unsat, A::Sat]);
}

#[test]
fn pop_to_an_empty_assertion_set() {
    let a = replay(
        "(declare-const x (_ BitVec 4))
         (push 1)
         (assert (and (bvult x #x2) (bvugt x #x8)))
         (check-sat)
         (pop 1)
         (check-sat)",
    );
    assert_eq!(a, vec![A::Unsat, A::Sat]);
}

#[test]
fn push_without_any_assertion_in_the_scope() {
    let a = replay(
        "(declare-const x (_ BitVec 4))
         (assert (bvult x #x8))
         (push 1)
         (check-sat)
         (pop 1)
         (check-sat)",
    );
    assert_eq!(a, vec![A::Sat, A::Sat]);
}

#[test]
fn unsat_at_the_base_scope_stays_unsat_through_push_and_pop() {
    // Nothing a scope does can rescue a contradiction below it.
    let a = replay(
        "(declare-const x (_ BitVec 4))
         (assert (bvult x #x2))
         (assert (bvugt x #x8))
         (check-sat)
         (push 1) (assert (bvult x #xf)) (check-sat) (pop 1)
         (check-sat)",
    );
    assert_eq!(a, vec![A::Unsat, A::Unsat, A::Unsat]);
}

// ---------------------------------------------------------------------------
// check-sat-assuming
// ---------------------------------------------------------------------------

#[test]
fn assumptions_do_not_survive_the_next_check() {
    let a = replay(
        "(declare-const p Bool)(declare-const x (_ BitVec 4))
         (assert (= p (bvult x #x2)))
         (check-sat-assuming (p (bvugt x #x0)))
         (check-sat-assuming ((not p) (bvult x #x1)))
         (check-sat)",
    );
    // The third check has no assumptions at all, so both earlier ones must be
    // gone — if either leaked, this would be unsat.
    assert_eq!(a, vec![A::Sat, A::Unsat, A::Sat]);
}

#[test]
fn contradictory_assumptions_do_not_poison_the_solver() {
    // An unsat-under-assumptions result must not become a permanent unsat.
    let a = replay(
        "(declare-const x (_ BitVec 8))
         (assert (bvult x #x10))
         (check-sat-assuming ((bvugt x #x20)))
         (check-sat)
         (check-sat-assuming ((bvult x #x05)))",
    );
    assert_eq!(a, vec![A::Unsat, A::Sat, A::Sat]);
}

#[test]
fn assumptions_interleaved_with_push_and_pop() {
    let a = replay(
        "(declare-const x (_ BitVec 8))
         (assert (bvult x #x40))
         (push 1)
         (assert (bvugt x #x10))
         (check-sat-assuming ((bvult x #x20)))
         (check-sat-assuming ((bvult x #x05)))
         (pop 1)
         (check-sat-assuming ((bvult x #x05)))",
    );
    // Under the pushed `x > 0x10`, assuming `x < 5` is unsat; after the pop it
    // is satisfiable again.
    assert_eq!(a, vec![A::Sat, A::Unsat, A::Sat]);
}

// ---------------------------------------------------------------------------
// Models
// ---------------------------------------------------------------------------

#[test]
fn the_model_after_a_pop_satisfies_only_what_is_still_in_scope() {
    // A model cached from the pushed scope would still satisfy `x > 0x30`;
    // the point is that the solver must produce one for the *current* scope,
    // and must actually re-derive it rather than hand back the old one.
    let mut pool = TermPool::new();
    let script = parse_script(
        "(declare-const x (_ BitVec 8))
         (assert (bvult x #x40))
         (push 1)
         (assert (bvugt x #x30))
         (check-sat)
         (pop 1)
         (assert (bvult x #x05))
         (check-sat)",
        &mut pool,
    )
    .expect("parse");

    let mut solver = Solver::new();
    solver.declared = script.declared.clone();
    let mut last = None;
    for cmd in &script.commands {
        match cmd {
            Command::Assert(t, _) => solver.assert(*t),
            Command::Push(n) => solver.push(*n),
            Command::Pop(n) => solver.pop(*n),
            Command::CheckSat => {
                last = Some(solver.check_sat(&mut pool, &[]));
            }
            _ => {}
        }
    }
    assert_eq!(norm(&last.expect("a check ran")), A::Sat);

    let model = solver.model().expect("sat check leaves a model");
    let x = script.declared[0];
    let v = model.get(&x).expect("x is in the model");
    // After the pop the constraints are `x < 0x40` and `x < 5`.
    let n: u64 = match v {
        smtrs_core::Value::Bv(bv) => bv.as_u64().expect("8-bit fits"),
        other => panic!("expected a bitvector value, got {other:?}"),
    };
    assert!(n < 5, "model must satisfy the in-scope bound, got x = {n}");
}

// ---------------------------------------------------------------------------
// Differential against one-shot, on shapes that stress the persistent engine
// ---------------------------------------------------------------------------

#[test]
fn deep_stack_of_alternating_sat_and_unsat_scopes() {
    let mut s = String::from("(declare-const x (_ BitVec 16))\n(assert (bvult x #x8000))\n");
    for i in 0..12 {
        s.push_str("(push 1)\n");
        // Alternate between a satisfiable narrowing and a contradiction.
        if i % 2 == 0 {
            s.push_str(&format!("(assert (bvugt x #x{:04x}))\n", i * 16));
        } else {
            s.push_str(&format!("(assert (bvult x #x{:04x}))\n", i));
        }
        s.push_str("(check-sat)\n");
    }
    for _ in 0..12 {
        s.push_str("(pop 1)\n(check-sat)\n");
    }
    // Every answer is checked against a fresh solve inside `replay`.
    let a = replay(&s);
    assert_eq!(a.len(), 24);
    assert_eq!(*a.last().unwrap(), A::Sat);
}

#[test]
fn many_checks_at_one_scope_are_stable() {
    // Repeated identical checks must not drift: the tenth answer is the first.
    let mut s = String::from("(declare-const x (_ BitVec 8))\n(assert (bvult x #x10))\n");
    for _ in 0..10 {
        s.push_str("(check-sat)\n");
    }
    let a = replay(&s);
    assert!(a.iter().all(|&r| r == A::Sat));
}

#[test]
fn push_pop_with_shared_structure_across_scopes() {
    // The scopes share a large common subterm, so the term DAG and any cached
    // encoding are reused across the pop. That reuse is what an optimization
    // will target, and this is the shape that catches it going wrong.
    assert_matches_oneshot(
        "(declare-const a (_ BitVec 16))
         (declare-const b (_ BitVec 16))
         (assert (bvult (bvadd (bvmul a b) (bvxor a b)) #x8000))
         (check-sat)
         (push 1)
         (assert (bvugt (bvadd (bvmul a b) (bvxor a b)) #x7000))
         (check-sat)
         (pop 1)
         (push 1)
         (assert (= (bvadd (bvmul a b) (bvxor a b)) #x0000))
         (check-sat)
         (pop 1)
         (check-sat)",
    );
}

#[test]
fn declarations_made_before_a_push_remain_usable_after_the_pop() {
    assert_matches_oneshot(
        "(declare-const x (_ BitVec 8))
         (declare-const y (_ BitVec 8))
         (assert (bvult x y))
         (push 1)
         (assert (= y #x00))
         (check-sat)
         (pop 1)
         (assert (bvugt y #x7f))
         (check-sat)",
    );
}

#[test]
fn a_level_that_asserts_false_dies_with_the_level() {
    // `false` inside a scope takes the short path that adds the unit `¬act`
    // rather than blasting anything, and nesting must retire the inner level
    // together with the outer one. The failure mode this catches is the
    // contradiction outliving its scope, which would make everything after
    // the pop unsat.
    let a = replay(
        "(declare-const x (_ BitVec 4))
         (assert (bvult x #x8))
         (push 1)
         (assert false)
         (check-sat)
         (push 1)
         (assert (= x #x1))
         (check-sat)
         (pop 2)
         (check-sat)
         (push 1) (assert (= x #x1)) (check-sat) (pop 1)
         (check-sat)",
    );
    assert_eq!(a, vec![A::Unsat, A::Unsat, A::Sat, A::Sat, A::Sat]);
}

// ---------------------------------------------------------------------------
// The engine actually survives the pop
// ---------------------------------------------------------------------------

/// Run a script, returning the answers, the rebuild count, and the largest SAT
/// variable count any check ran against.
fn run_counting(src: &str) -> (Vec<A>, u64, u32) {
    let mut pool = TermPool::new();
    let script = parse_script(src, &mut pool).expect("parse");
    let mut solver = Solver::new();
    solver.declared = script.declared.clone();
    let mut answers = Vec::new();
    let mut peak_vars = 0u32;
    for cmd in &script.commands {
        match cmd {
            Command::Assert(t, _) => solver.assert(*t),
            Command::Push(n) => solver.push(*n),
            Command::Pop(n) => solver.pop(*n),
            Command::CheckSat => {
                answers.push(norm(&solver.check_sat(&mut pool, &[])));
                peak_vars = peak_vars.max(solver.stats.sat_vars);
            }
            _ => {}
        }
    }
    (answers, solver.stats.rebuilds, peak_vars)
}

/// A base big enough that re-encoding it per query is the cost that matters.
/// Written as text so the scripts below stay readable.
fn wide_base() -> String {
    let mut s = String::new();
    for i in 0..8 {
        s.push_str(&format!("(declare-const v{i} (_ BitVec 32))\n"));
    }
    for i in 0..8 {
        let j = (i + 1) % 8;
        s.push_str(&format!(
            "(assert (bvult (bvadd (bvmul v{i} v{j}) (bvxor v{i} v{j})) #x7fffffff))\n"
        ));
    }
    s
}

/// The point of all of the above: a `pop` must not rebuild the engine.
///
/// `stats.rebuilds` counts checks that could not reuse the persistent engine
/// and re-ran the whole preprocess-and-blast pipeline. It is a pure count, so
/// unlike wall time it says the same thing on a loaded machine as on an idle
/// one — which is what makes it the number to assert on.
///
/// The BMC shape below (`push; assert; check-sat; pop`, repeated over a base
/// that dwarfs what each round adds) used to rebuild on *every* check, because
/// `pop` shortens the assertion list and the engine's reuse test is a prefix
/// test. Three is the whole budget now: the first check, and the two pops it
/// takes to earn guarded mode.
#[test]
fn the_bmc_shape_rebuilds_a_fixed_number_of_times_not_once_per_check() {
    let mut src = wide_base();
    for i in 0..20 {
        src.push_str(&format!(
            "(push 1)\n(assert (bvugt v0 #x{:08x}))\n(check-sat)\n(pop 1)\n",
            i * 0x100
        ));
    }
    let (answers, rebuilds, _) = run_counting(&src);
    assert_eq!(answers.len(), 20);
    assert!(answers.iter().all(|&a| a == A::Sat));
    assert_eq!(
        rebuilds, 3,
        "20 checks bracketed by push/pop cost {rebuilds} engine rebuilds; only \
         the first check and the two pops that earn guarded mode may"
    );
}

/// Retiring a level satisfies its clauses but does not delete them, so a long
/// script would otherwise carry every round it has ever run. The engine is
/// collected once the retired part outweighs the live one, which bounds the
/// formula each query faces at twice the live encoding however many rounds the
/// script does.
///
/// Without the collection this same script ends its 60th round against a
/// database several times the size of its first, and the growth has no limit.
#[test]
fn a_long_pop_loop_does_not_grow_the_formula_without_bound() {
    let mut src = String::from("(declare-const x (_ BitVec 16))\n(assert (bvult x #x8000))\n");
    for i in 0..60 {
        src.push_str(&format!(
            "(push 1)\n(assert (bvugt x #x{:04x}))\n(check-sat)\n(pop 1)\n",
            i * 0x10
        ));
    }
    let (answers, _, peak_vars) = run_counting(&src);
    assert_eq!(answers.len(), 60);
    assert!(answers.iter().all(|&a| a == A::Sat));

    // What one round costs, measured the same way.
    let mut one = String::from("(declare-const x (_ BitVec 16))\n(assert (bvult x #x8000))\n");
    one.push_str("(push 1)\n(assert (bvugt x #x0000))\n(check-sat)\n(pop 1)\n");
    let (_, _, one_round_vars) = run_counting(&one);

    assert!(
        peak_vars <= 2 * one_round_vars,
        "60 rounds peaked at {peak_vars} SAT variables against {one_round_vars} \
         for a single round; the retired levels are not being collected"
    );
}

/// A script that only ever grows still rebuilds exactly once — the guarded-level
/// machinery must not cost a rebuild to scripts that never pop, which is the
/// shape (`push` without `pop`) that made unconditional guarding a 6x loss.
#[test]
fn a_script_that_never_pops_rebuilds_once() {
    let mut pool = TermPool::new();
    let script = parse_script(
        "(declare-const x (_ BitVec 16))
         (assert (bvult x #x8000))
         (check-sat)
         (push 1) (assert (bvugt x #x0010)) (check-sat)
         (push 1) (assert (bvugt x #x0020)) (check-sat)
         (assert (bvugt x #x0030)) (check-sat)",
        &mut pool,
    )
    .expect("parse");
    let mut solver = Solver::new();
    solver.declared = script.declared.clone();
    for cmd in &script.commands {
        match cmd {
            Command::Assert(t, _) => solver.assert(*t),
            Command::Push(n) => solver.push(*n),
            Command::Pop(n) => solver.pop(*n),
            Command::CheckSat => {
                assert_eq!(norm(&solver.check_sat(&mut pool, &[])), A::Sat);
            }
            _ => {}
        }
    }
    assert_eq!(solver.stats.rebuilds, 1);
}

// ---------------------------------------------------------------------------
// Theory lowering across a pop
// ---------------------------------------------------------------------------
//
// These are the cases this file did not cover when it was written, and the gap
// was not academic: `pop` after a string lowering was a live wrong `sat` on
// main. The lowering replaces the assertion vector with one of a *different
// length* — rewritten roots followed by the encoding's own side constraints —
// while the level stack goes on indexing the old one, so a `pop` truncated to a
// stale index and deleted the side constraints while keeping the assertions
// that depend on them.
//
// The one-shot oracle catches this class for free; there simply was no string
// script pointed at it. Every theory whose lowering can change the assertion
// count needs a case here.

#[test]
fn string_lowering_survives_a_pop() {
    // The original reproducer. Both lengths in scope at the second check, so
    // it must be unsat; it answered sat, because `(= (str.len s) 3)`'s side
    // constraints were deleted by the pop and its lowered form was left
    // unconstrained.
    let a = replay(
        "(declare-const s String)
         (assert (= (str.len s) 3))
         (push 1)
         (assert (str.prefixof \"a\" s))
         (check-sat)
         (pop 1)
         (assert (= (str.len s) 5))
         (check-sat)",
    );
    assert_eq!(a, vec![A::Sat, A::Unsat]);
}

#[test]
fn string_constraint_inside_a_scope_is_retired_by_the_pop() {
    // The other direction: a contradiction introduced inside the scope must
    // stop constraining after the pop. A lowering that leaked its side
    // constraints forward would keep this unsat.
    let a = replay(
        "(declare-const s String)
         (assert (= (str.len s) 3))
         (push 1)
         (assert (= (str.len s) 5))
         (check-sat)
         (pop 1)
         (check-sat)",
    );
    assert_eq!(a, vec![A::Unsat, A::Sat]);
}

#[test]
fn repeated_string_push_pop_cycles_stay_consistent() {
    // Re-lowering has to be repeatable: each cycle must give the same answers,
    // and the base constraint must survive all of them.
    let a = replay(
        "(declare-const s String)
         (assert (str.prefixof \"ab\" s))
         (push 1) (assert (= (str.len s) 1)) (check-sat) (pop 1)
         (check-sat)
         (push 1) (assert (= (str.len s) 1)) (check-sat) (pop 1)
         (check-sat)",
    );
    assert_eq!(a, vec![A::Unsat, A::Sat, A::Unsat, A::Sat]);
}

/// Theory content asserted *after* a lowering, with no `push`/`pop` at all.
///
/// This is a third distinct wrong `sat`, found by the agent auditing the
/// `check_sat` prologue and originally recorded on its branch as an
/// `#[ignore]`d reproducer. Both lowerings replace `Solver::assertions` with
/// their lowered forms in place; assert more theory content afterwards and the
/// two never meet, because the earlier assertions now hold bit-vectors where
/// `s` (or `f`) used to be, while the new formula is lowered afresh into its
/// own encoding of the same variable.
///
/// Asserting both before the first check answers correctly, so this is
/// specific to incremental use — which is exactly why a one-shot oracle is the
/// right test and why nothing before this suite caught it.
#[test]
fn string_content_asserted_after_a_lowering_is_not_lost() {
    let a = replay(
        "(declare-const s String)
         (assert (= (str.len s) 3))
         (check-sat)
         (assert (= s \"abcd\"))
         (check-sat)",
    );
    assert_eq!(a, vec![A::Sat, A::Unsat]);
}

/// The floating-point half of the same defect. It survived the first fix: the
/// FP lowering preserves the assertion *count*, so `levels` stays valid and
/// `push`/`pop` were never wrong — but the terms still change identity, and
/// there was no `fp_lowered` flag for `undo_lowering` to act on.
#[test]
fn fp_content_asserted_after_a_lowering_is_not_lost() {
    let a = replay(
        "(declare-const f Float32)
         (declare-const g Float32)
         (assert (fp.lt f g))
         (check-sat)
         (assert (fp.lt g f))
         (check-sat)",
    );
    assert_eq!(a, vec![A::Sat, A::Unsat]);
}

/// Mixed theories across a lowering: BV first, then strings, then more BV.
#[test]
fn a_clean_prefix_does_not_hide_theory_content_asserted_later() {
    assert_matches_oneshot(
        "(declare-const x (_ BitVec 8))
         (declare-const s String)
         (assert (bvult x #x40))
         (check-sat)
         (assert (= (str.len s) 3))
         (check-sat)
         (assert (bvugt x #x30))
         (check-sat)",
    );
}

#[test]
fn fp_lowering_survives_a_pop() {
    // The FP lowering preserves the assertion count, so it was never affected
    // by the same defect — which is exactly why it is worth pinning, so a
    // future change that makes it append side constraints fails here.
    // #x3f800000 is 1.0f32, #x40000000 is 2.0f32.
    let a = replay(
        "(declare-const x (_ FloatingPoint 8 24))
         (assert (fp.lt x ((_ to_fp 8 24) #x3f800000)))
         (push 1)
         (assert (fp.gt x ((_ to_fp 8 24) #x40000000)))
         (check-sat)
         (pop 1)
         (check-sat)",
    );
    assert_eq!(a, vec![A::Unsat, A::Sat]);
}

// ---------------------------------------------------------------------------
// Real incremental corpus files
// ---------------------------------------------------------------------------

/// Replay a sample of the incremental corpus and hold every check to the
/// one-shot oracle.
///
/// Skipped when the corpus is absent — CI does not vendor it (mixed licences;
/// `scripts/fetch-corpus.sh` fetches it). The skip is announced on stderr so it
/// cannot pass silently as a green test.
#[test]
fn corpus_incremental_files_agree_with_one_shot() {
    let dir = std::path::Path::new("../../corpus/incremental/incremental/QF_BV");
    if !dir.exists() {
        eprintln!(
            "SMTRS-SKIP incremental corpus replay: {} absent (run scripts/fetch-corpus.sh)",
            dir.display()
        );
        return;
    }

    // Small files only: the oracle re-solves from scratch at every check, so
    // this is quadratic in script length by construction. Correctness coverage
    // comes from the number of push/pop shapes seen, not from instance size.
    let mut files: Vec<std::path::PathBuf> = walk(dir)
        .into_iter()
        .filter(|p| {
            p.extension().is_some_and(|e| e == "smt2")
                && std::fs::metadata(p)
                    .map(|m| m.len() < 24 * 1024)
                    .unwrap_or(false)
        })
        .collect();
    files.sort();

    if files.is_empty() {
        eprintln!("SMTRS-SKIP incremental corpus replay: no file under 24 KB found");
        return;
    }

    // Stride rather than take a prefix, so the sample spans subdirectories.
    // The default is what a routine `cargo test` can afford; a change to the
    // push/pop encoding wants a deeper sweep than that, and re-running this
    // same replay over hundreds of files is the cheapest way to get one —
    // hence the override rather than a second, near-identical test.
    let want: usize = std::env::var("SMTRS_INCREMENTAL_REPLAY_FILES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(12);
    let step = std::cmp::max(1, files.len() / want);
    let sample: Vec<_> = files.iter().step_by(step).take(want).collect();

    let mut checked = 0usize;
    for path in &sample {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(_) => continue,
        };
        // Parse failures are not this test's subject; the parser has its own.
        let mut probe = TermPool::new();
        if parse_script(&text, &mut probe).is_err() {
            continue;
        }
        replay(&text);
        checked += 1;
    }

    assert!(
        checked > 0,
        "no corpus file was successfully replayed out of {} sampled",
        sample.len()
    );
    eprintln!("incremental corpus replay: {checked} files agreed with one-shot at every check");
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.push(p);
            }
        }
    }
    out
}
