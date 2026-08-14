use super::*;

fn ivs_of(pool: &TermPool, roots: &[TermId]) -> Ivs {
    let nfas = crate::regex::build_all(pool, roots).unwrap_or_default();
    let re_lens = regex_lengths(pool, &nfas, roots);
    let mut order: Vec<TermId> = Vec::new();
    pool.post_order(roots, |_, t| order.push(t));
    let facts = top_level_facts(pool, roots);
    let mut ivs = Ivs {
        len: FxHashMap::default(),
        int: FxHashMap::default(),
        infeasible: false,
    };
    for _ in 0..6 {
        forward(pool, &order, &mut ivs);
        harvest(pool, &re_lens, &facts, &mut ivs);
        backward(pool, &order, &mut ivs);
    }
    ivs
}

/// Parse an SMT-LIB script and return the pool plus its assertions.
fn parse(src: &str) -> (TermPool, Vec<TermId>) {
    let mut pool = TermPool::new();
    let script = smtrs_parser::parse_script(src, &mut pool).expect("parse");
    let roots: Vec<TermId> = script
        .commands
        .iter()
        .filter_map(|c| match c {
            smtrs_parser::Command::Assert(t, _) => Some(*t),
            _ => None,
        })
        .collect();
    (pool, roots)
}

/// The term for a declared variable of the given name.
fn var(pool: &TermPool, roots: &[TermId], name: &str) -> TermId {
    let mut found = None;
    pool.post_order(roots, |p, t| {
        if matches!(p.op(t), Op::Var(s) if p.symbol(s).name == name) {
            found = Some(t);
        }
    });
    found.unwrap_or_else(|| panic!("variable {name} is not in the problem"))
}

/// The (last) term whose operator has the given name.
fn node(pool: &TermPool, roots: &[TermId], name: &str) -> TermId {
    let mut found = None;
    pool.post_order(roots, |p, t| {
        if op_name(p, t) == Some(name) {
            found = Some(t);
        }
    });
    found.unwrap_or_else(|| panic!("no {name} in the problem"))
}

#[test]
fn interval_of_a_concatenation_sums_its_parts() {
    let (pool, roots) = parse(
        "(declare-fun x () String)(declare-fun y () String)
         (assert (<= (str.len x) 4))(assert (= (str.len y) 3))
         (assert (distinct (str.++ x y) \"q\"))",
    );
    let ivs = ivs_of(&pool, &roots);
    // |x| is in [0,4] and |y| is exactly 3, so the join is in [3,7].
    let iv = ivs.l(node(&pool, &roots, "str.++"));
    assert_eq!((iv.lo, iv.hi), (Some(3), Some(7)));
}

#[test]
fn substr_length_is_exact_when_the_window_is_inside() {
    // |s| = 8, so (str.substr s 2 3) has exactly 3 characters.
    let (pool, roots) = parse(
        "(declare-fun s () String)(assert (= (str.len s) 8))
         (assert (distinct (str.substr s 2 3) \"q\"))",
    );
    let ivs = ivs_of(&pool, &roots);
    let iv = ivs.l(node(&pool, &roots, "str.substr"));
    assert_eq!((iv.lo, iv.hi), (Some(3), Some(3)));
}

#[test]
fn substr_past_the_end_is_empty_not_negative() {
    // |s| <= 2 but the window starts at 5: the result is empty, and in
    // particular its length is not the negative `|s| - i`.
    let (pool, roots) = parse(
        "(declare-fun s () String)(assert (<= (str.len s) 2))
         (assert (distinct (str.substr s 5 3) \"q\"))",
    );
    let ivs = ivs_of(&pool, &roots);
    let iv = ivs.l(node(&pool, &roots, "str.substr"));
    assert_eq!(iv.lo, Some(0));
    assert_eq!(iv.hi, Some(0));
}

#[test]
fn indexof_of_a_pattern_that_cannot_fit_is_still_minus_one() {
    // |s| <= 1 and |p| = 4, so `|s| - |p|` is -3 — but the answer is -1, and
    // an interval with an upper bound of -3 would be a wrong fact.
    let (pool, roots) = parse(
        "(declare-fun s () String)(assert (<= (str.len s) 1))
         (assert (distinct (str.indexof s \"abcd\" 0) 7))",
    );
    let ivs = ivs_of(&pool, &roots);
    let iv = ivs.i(node(&pool, &roots, "str.indexof"));
    assert_eq!((iv.lo, iv.hi), (Some(-1), Some(-1)));
}

#[test]
fn a_negated_chained_comparison_bounds_nothing() {
    // `(not (< a b c))` only says *some* pair fails; reading it as `a >= b`
    // and `b >= c` would be unsound.
    let (pool, roots) = parse(
        "(declare-fun a () Int)(declare-fun b () Int)(declare-fun c () Int)
         (assert (not (< a b c)))(assert (= a 0))",
    );
    let ivs = ivs_of(&pool, &roots);
    assert_eq!(ivs.i(var(&pool, &roots, "b")), Iv::TOP);
}

#[test]
fn regex_min_and_max_word_lengths_bound_a_membership() {
    let (pool, roots) = parse(
        "(declare-fun x () String)
         (assert (str.in_re x (re.++ (str.to_re \"ab\") (re.opt (str.to_re \"c\")))))",
    );
    let ivs = ivs_of(&pool, &roots);
    let iv = ivs.l(var(&pool, &roots, "x"));
    assert_eq!((iv.lo, iv.hi), (Some(2), Some(3)));
}

#[test]
fn a_membership_under_a_complement_bounds_nothing() {
    // The byte automaton for a complement is *not* length-faithful, so no
    // bound may be read off it.
    let (pool, roots) = parse(
        "(declare-fun x () String)
         (assert (str.in_re x (re.comp (str.to_re \"ab\"))))",
    );
    let ivs = ivs_of(&pool, &roots);
    assert_eq!(ivs.l(var(&pool, &roots, "x")), Iv::nonneg());
}

#[test]
fn negated_membership_bounds_nothing() {
    let (pool, roots) = parse(
        "(declare-fun x () String)
         (assert (not (str.in_re x (str.to_re \"abc\"))))",
    );
    let ivs = ivs_of(&pool, &roots);
    assert_eq!(ivs.l(var(&pool, &roots, "x")), Iv::nonneg());
}

#[test]
fn a_constraint_under_a_disjunction_is_not_harvested() {
    let (pool, roots) = parse(
        "(declare-fun x () String)(declare-fun b () Bool)
         (assert (or b (<= (str.len x) 3)))",
    );
    let ivs = ivs_of(&pool, &roots);
    assert_eq!(ivs.l(var(&pool, &roots, "x")), Iv::nonneg());
}

#[test]
fn min_word_len_agrees_with_enumeration() {
    let (pool, roots) = parse(
        "(declare-fun x () String)
         (assert (str.in_re x (re.union (str.to_re \"abcd\") (str.to_re \"z\"))))
         (assert (str.in_re x (re.+ (str.to_re \"qq\"))))
         (assert (str.in_re x (re.* (str.to_re \"p\"))))
         (assert (str.in_re x re.none))",
    );
    let nfas = crate::regex::build_all(&pool, &roots).expect("regexes compile");
    let mut got: Vec<Option<u32>> = Vec::new();
    pool.post_order(&roots, |p, t| {
        if op_name(p, t) == Some("str.in_re") {
            got.push(nfas[&p.args(t)[1]].min_word_len());
        }
    });
    got.sort_unstable();
    // union{abcd,z} -> 1, (qq)+ -> 2, p* -> 0, none -> empty language.
    assert_eq!(got, vec![None, Some(0), Some(1), Some(2)]);
}

#[test]
fn arithmetic_on_a_length_bounds_it_from_both_sides() {
    // The `restoreIpAddresses` shape: `|s| - 4 > 0` and `|s| - 5 <= 3`.
    let (pool, roots) = parse(
        "(declare-fun s () String)
         (assert (> (- (- (- (str.len s) 1) (+ 1 1)) 1) 0))
         (assert (<= (- (- (- (str.len s) 1) 1) (+ (+ 1 1) 1)) 3))",
    );
    let ivs = ivs_of(&pool, &roots);
    assert_eq!(
        (
            ivs.l(var(&pool, &roots, "s")).lo,
            ivs.l(var(&pool, &roots, "s")).hi
        ),
        (Some(5), Some(8))
    );
    assert!(!ivs.infeasible);
}

/// An interval that comes out empty is itself the refutation, and
/// [`abstraction`] hands it back as the constant `false`.
#[test]
fn an_empty_interval_refutes_outright() {
    let (mut pool, roots) = parse(
        "(declare-fun s () String)
         (assert (> (str.len s) 8))
         (assert (str.in_re s (re.++ (str.to_re \"ab\") (re.opt (str.to_re \"c\")))))",
    );
    let abs = abstraction(&mut pool, &roots).expect("an abstraction");
    assert_eq!(abs, vec![pool.false_term]);
}

/// ...and it must not fire on a satisfiable system with the same shape.
#[test]
fn a_feasible_system_is_not_refuted_outright() {
    let (mut pool, roots) = parse(
        "(declare-fun s () String)
         (assert (> (str.len s) 2))
         (assert (str.in_re s (re.++ (str.to_re \"ab\") (re.opt (str.to_re \"c\")))))",
    );
    let abs = abstraction(&mut pool, &roots).expect("an abstraction");
    assert_ne!(abs, vec![pool.false_term]);
}

/// Do the memberships of `src` conflict on lengths alone?
fn memberships_clash(src: &str) -> bool {
    let (pool, roots) = parse(src);
    let nfas = crate::regex::build_all(&pool, &roots).unwrap_or_default();
    let facts = top_level_facts(&pool, &roots);
    let ivs = ivs_of(&pool, &roots);
    memberships_conflict(&pool, &nfas, &facts, &ivs)
}

#[test]
fn length_sets_are_exact_where_an_interval_is_not() {
    // `L (ppJpp)*` has lengths {1, 6, 11, ...} and `L (ppJpp)* <` has
    // {2, 7, 12, ...}: disjoint, though both intervals are "at least 1".
    assert!(memberships_clash(
        "(declare-fun x () String)
         (assert (str.in_re x (re.++ (str.to_re \"L\") (re.* (str.to_re \"ppJpp\")))))
         (assert (str.in_re x (re.++ (str.to_re \"L\")
                   (re.++ (re.* (str.to_re \"ppJpp\")) (str.to_re \"<\")))))"
    ));
}

#[test]
fn length_sets_that_do_meet_are_left_alone() {
    // Same shape but the second language is shifted by five, so every length
    // of the first is a length of the second.
    assert!(!memberships_clash(
        "(declare-fun x () String)
         (assert (str.in_re x (re.++ (str.to_re \"L\") (re.* (str.to_re \"ppJpp\")))))
         (assert (str.in_re x (re.++ (str.to_re \"Lppjpp\") (re.* (str.to_re \"ppJpp\")))))"
    ));
}

#[test]
fn a_length_set_can_conflict_with_the_interval_alone() {
    // {0, 3, 6, ...} against a subject known to be four or five characters.
    assert!(memberships_clash(
        "(declare-fun x () String)
         (assert (str.in_re x (re.* (str.to_re \"abc\"))))
         (assert (>= (str.len x) 4))(assert (<= (str.len x) 5))"
    ));
    assert!(!memberships_clash(
        "(declare-fun x () String)
         (assert (str.in_re x (re.* (str.to_re \"abc\"))))
         (assert (>= (str.len x) 4))(assert (<= (str.len x) 6))"
    ));
}

#[test]
fn a_negated_membership_never_conflicts() {
    assert!(!memberships_clash(
        "(declare-fun x () String)
         (assert (not (str.in_re x (re.++ (str.to_re \"L\") (re.* (str.to_re \"ppJpp\"))))))
         (assert (str.in_re x (re.++ (str.to_re \"L\")
                   (re.++ (re.* (str.to_re \"ppJpp\")) (str.to_re \"<\")))))"
    ));
}

#[test]
fn a_complemented_membership_never_conflicts() {
    // The byte automaton for a complement has the wrong word lengths, so it
    // may not be read even though its length set is perfectly computable.
    assert!(!memberships_clash(
        "(declare-fun x () String)
         (assert (str.in_re x (re.comp (re.++ (str.to_re \"L\") (re.* (str.to_re \"ppJpp\"))))))
         (assert (str.in_re x (re.++ (str.to_re \"ab\") (re.* (str.to_re \"cde\")))))"
    ));
}

#[test]
fn length_set_membership_matches_enumeration() {
    let (pool, roots) = parse(
        "(declare-fun x () String)
         (assert (str.in_re x (re.++ (str.to_re \"L\") (re.* (str.to_re \"ppJpp\")))))
         (assert (str.in_re x (re.union (str.to_re \"ab\") (re.+ (str.to_re \"xyz\")))))
         (assert (str.in_re x re.none))",
    );
    let nfas = crate::regex::build_all(&pool, &roots).expect("regexes compile");
    let mut got: Vec<Vec<usize>> = Vec::new();
    pool.post_order(&roots, |p, t| {
        if op_name(p, t) == Some("str.in_re") {
            let set = nfas[&p.args(t)[1]]
                .length_set(ORBIT_BUDGET)
                .expect("orbit settles");
            got.push((0..14).filter(|&k| set.contains(k)).collect());
        }
    });
    got.sort();
    assert_eq!(
        got,
        vec![
            Vec::<usize>::new(),  // re.none
            vec![1, 6, 11],       // L (ppJpp)*
            vec![2, 3, 6, 9, 12], // ab | (xyz)+
        ]
    );
}
