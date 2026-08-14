//! Regular expressions as NFAs, encoded over bounded strings.
//!
//! Thompson construction gives a small NFA whose transitions carry character
//! *ranges* rather than single symbols, which keeps `re.range` and
//! `re.allchar` cheap. Acceptance over a bounded string is then a per-position
//! state vector: one Bool per (position, state), with the transition relation
//! encoded as an implication over the character at that position.

use crate::{BoundedStr, LowerError};
use rustc_hash::FxHashMap;
use smtrs_core::{Op, Sort, TermId, TermPool};

/// Cap on states produced by determinization or a product construction. The
/// symbolic encoding costs one Bool per (position, state), so the cap is set by
/// what is affordable to *encode*, not by what is representable: at a 64-slot
/// string bound, 512 states is already 32k Bools for a single membership test.
const DETERMINIZE_LIMIT: usize = 512;

/// Ceiling on the orbit [`Nfa::length_set`] walks, whatever budget it is given.
/// A language whose lengths have not repeated within four thousand steps has a
/// period no downstream consumer could use.
const MAX_ORBIT_STEPS: usize = 4096;

/// States past which [`Nfa::length_set`] does not even build its epsilon-free
/// view. That view is superlinear in the state count and the orbit runs over
/// state *sets*, so this is only ever worth attempting on a small automaton —
/// which the shape it exists for (a concatenation of starred literals) always
/// is, while the generated hundred-branch regexes never are.
const MAX_ORBIT_STATES: usize = 64;

#[derive(Clone, Copy, Debug)]
pub struct Range {
    pub lo: u8,
    pub hi: u8,
}

/// The set of word lengths of a language: `bits[k]` decides `k` below
/// `threshold`, and at or above it the answer repeats every `period` steps.
/// `bits` runs to exactly `threshold + period`. A finite language reaches the
/// empty state set, which is its own successor, so it comes out as a period of
/// one over a `false` bit rather than as a special case.
#[derive(Clone, Debug)]
pub struct LengthSet {
    bits: Vec<bool>,
    threshold: usize,
    period: usize,
}

impl LengthSet {
    /// Is `k` the length of some word of the language?
    pub fn contains(&self, k: usize) -> bool {
        if k < self.threshold {
            return self.bits[k];
        }
        if self.period == 0 {
            return false;
        }
        self.bits[self.threshold + (k - self.threshold) % self.period]
    }

    /// Above this, membership repeats with [`LengthSet::period`].
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    pub fn period(&self) -> usize {
        self.period
    }
}

/// A set of states, as a mask indexed by state number.
type StateSet = Vec<bool>;

/// Consuming transitions, indexed by source state: each entry is the byte
/// range that fires and the state it moves to.
type Trans = Vec<Vec<(Range, usize)>>;

#[derive(Clone, Debug)]
pub enum Edge {
    /// Consumes one character within the range.
    Consume(Range, usize),
    /// Free move.
    Epsilon(usize),
}

#[derive(Clone, Debug, Default)]
pub struct Nfa {
    pub states: Vec<Vec<Edge>>,
    pub start: usize,
    pub accept: usize,
}

impl Nfa {
    fn new_state(&mut self) -> usize {
        self.states.push(Vec::new());
        self.states.len() - 1
    }

    /// The empty language.
    fn none() -> Nfa {
        let mut n = Nfa::default();
        let s = n.new_state();
        let a = n.new_state();
        n.start = s;
        n.accept = a;
        n
    }

    fn epsilon() -> Nfa {
        let mut n = Nfa::default();
        let s = n.new_state();
        n.start = s;
        n.accept = s;
        n
    }

    fn single_range(r: Range) -> Nfa {
        let mut n = Nfa::default();
        let s = n.new_state();
        let a = n.new_state();
        n.states[s].push(Edge::Consume(r, a));
        n.start = s;
        n.accept = a;
        n
    }

    fn literal(bytes: &[u8]) -> Nfa {
        let mut n = Nfa::default();
        let mut cur = n.new_state();
        n.start = cur;
        for &byte in bytes {
            let next = n.new_state();
            n.states[cur].push(Edge::Consume(Range { lo: byte, hi: byte }, next));
            cur = next;
        }
        n.accept = cur;
        n
    }

    /// Splice `other`'s states in, returning its remapped (start, accept).
    fn absorb(&mut self, other: &Nfa) -> (usize, usize) {
        let base = self.states.len();
        for edges in &other.states {
            let remapped = edges
                .iter()
                .map(|e| match *e {
                    Edge::Consume(r, t) => Edge::Consume(r, t + base),
                    Edge::Epsilon(t) => Edge::Epsilon(t + base),
                })
                .collect();
            self.states.push(remapped);
        }
        (other.start + base, other.accept + base)
    }

    fn concat(parts: &[Nfa]) -> Nfa {
        let mut n = Nfa::default();
        let s = n.new_state();
        n.start = s;
        let mut cur = s;
        for p in parts {
            let (ps, pa) = n.absorb(p);
            n.states[cur].push(Edge::Epsilon(ps));
            cur = pa;
        }
        n.accept = cur;
        n
    }

    fn union(parts: &[Nfa]) -> Nfa {
        let mut n = Nfa::default();
        let s = n.new_state();
        let a = n.new_state();
        n.start = s;
        n.accept = a;
        for p in parts {
            let (ps, pa) = n.absorb(p);
            n.states[s].push(Edge::Epsilon(ps));
            n.states[pa].push(Edge::Epsilon(a));
        }
        n
    }

    fn star(inner: &Nfa) -> Nfa {
        let mut n = Nfa::default();
        let s = n.new_state();
        n.start = s;
        n.accept = s;
        let (is, ia) = n.absorb(inner);
        n.states[s].push(Edge::Epsilon(is));
        n.states[ia].push(Edge::Epsilon(s));
        n
    }

    fn opt(inner: &Nfa) -> Nfa {
        let eps = Nfa::epsilon();
        Nfa::union(&[inner.clone(), eps])
    }

    fn plus(inner: &Nfa) -> Nfa {
        let star = Nfa::star(inner);
        Nfa::concat(&[inner.clone(), star])
    }

    /// Epsilon-free view: start set, per-state consuming transitions, and the
    /// set of accepting states — all with epsilon closure already applied.
    /// Doing this once on the automaton keeps the symbolic encoding a single
    /// pass per character instead of a fixpoint over freshly built terms.
    pub fn epsilon_free(&self) -> (StateSet, Trans, StateSet) {
        let n = self.states.len();
        let closure_of = |q: usize| -> Vec<bool> {
            let mut set = vec![false; n];
            set[q] = true;
            self.closure(&mut set);
            set
        };
        let closures: Vec<Vec<bool>> = (0..n).map(closure_of).collect();

        let mut start = vec![false; n];
        start[self.start] = true;
        self.closure(&mut start);

        let mut trans: Vec<Vec<(Range, usize)>> = vec![Vec::new(); n];
        for q in 0..n {
            // Every state reachable from q by epsilon contributes its
            // consuming edges to q, with targets closed again.
            for (r, reachable) in closures[q].iter().enumerate() {
                if !reachable {
                    continue;
                }
                for e in &self.states[r] {
                    if let Edge::Consume(range, t) = *e {
                        for (tt, inc) in closures[t].iter().enumerate() {
                            if *inc {
                                trans[q].push((range, tt));
                            }
                        }
                    }
                }
            }
            trans[q].sort_by_key(|&(r, t)| (r.lo, r.hi, t));
            trans[q].dedup_by_key(|&mut (r, t)| (r.lo, r.hi, t));
        }
        let accept: Vec<bool> = (0..n).map(|q| closures[q][self.accept]).collect();
        (start, trans, accept)
    }

    /// The exact set of word lengths of the language, as an ultimately
    /// periodic set, or `None` when it did not settle within `cap` steps.
    ///
    /// Forget the alphabet and the automaton is a unary one, whose subset
    /// construction is a single orbit: `S_0` is the start set and `S_{k+1}` is
    /// everything reachable from `S_k` in one step, so `k` is a word length of
    /// the language exactly when `S_k` meets the accepting set. That orbit has
    /// no choices in it, so it is a rho: some `S_j` recurs, and from there the
    /// answer repeats with period `k - j` forever. Being over state *sets* the
    /// orbit can in principle be exponentially long, hence the cap — the
    /// regexes that motivate this (a concatenation of starred literals) settle
    /// in a handful of steps.
    ///
    /// This is strictly sharper than the [`Nfa::min_word_len`] /
    /// [`Nfa::max_word_len`] pair: `(re.++ (str.to_re "L") (re.* (str.to_re
    /// "ppJpp")))` has lengths `{1, 6, 11, ...}` where the interval says only
    /// "at least 1".
    pub fn length_set(&self, budget: usize) -> Option<LengthSet> {
        // Each orbit step is one pass over the transitions, so the budget buys
        // a step count; the epsilon-free view that precedes it is bounded
        // separately by [`MAX_ORBIT_STATES`]. Giving up costs only the sharper
        // answer, never a wrong one.
        if self.states.len() > MAX_ORBIT_STATES {
            return None;
        }
        let (start, trans, accept) = self.epsilon_free();
        let n = trans.len();
        let edges: usize = trans.iter().map(Vec::len).sum();
        let cap = (budget / edges.max(1)).min(MAX_ORBIT_STEPS);
        let mut seen: FxHashMap<Vec<bool>, usize> = FxHashMap::default();
        let mut bits: Vec<bool> = Vec::new();
        let mut cur = start;
        for k in 0..cap {
            if let Some(&j) = seen.get(&cur) {
                return Some(LengthSet {
                    bits,
                    threshold: j,
                    period: k - j,
                });
            }
            seen.insert(cur.clone(), k);
            bits.push((0..n).any(|q| cur[q] && accept[q]));
            let mut next = vec![false; n];
            for (q, edges) in trans.iter().enumerate() {
                if cur[q] {
                    for &(_, t) in edges {
                        next[t] = true;
                    }
                }
            }
            cur = next;
        }
        None
    }

    /// Length of the shortest word in the language, or `None` when the
    /// language is empty.
    ///
    /// Breadth-first over the epsilon-free automaton: the first accepting
    /// state reached is reached by a shortest path, and a path of `k` edges
    /// spells a word of `k` characters (every consuming edge has a non-empty
    /// range, since [`Range`] is built from `lo <= hi`). Unlike
    /// [`Nfa::max_word_len`] this needs no liveness filter — reachability from
    /// the start set to an accepting state is exactly what it computes.
    pub fn min_word_len(&self) -> Option<u32> {
        let (start, trans, accept) = self.epsilon_free();
        let n = trans.len();
        let mut seen = start.clone();
        let mut frontier: Vec<usize> = (0..n).filter(|&q| start[q]).collect();
        let mut depth = 0u32;
        while !frontier.is_empty() {
            if frontier.iter().any(|&q| accept[q]) {
                return Some(depth);
            }
            let mut next = Vec::new();
            for &q in &frontier {
                for &(_, t) in &trans[q] {
                    if !seen[t] {
                        seen[t] = true;
                        next.push(t);
                    }
                }
            }
            frontier = next;
            depth += 1;
        }
        None
    }

    /// Length of the longest word in the language, or `None` when the language
    /// is infinite.
    ///
    /// The language is infinite exactly when the epsilon-free automaton has a
    /// cycle among the states that are both reachable from the start set and
    /// co-reachable to an accepting state — a cycle anywhere else contributes
    /// no accepted word. With no such cycle the useful part of the automaton is
    /// a DAG and the answer is its longest path, in edges. An empty language
    /// (no live start state) reports 0, which is a valid upper bound because no
    /// word is accepted at all.
    pub fn max_word_len(&self) -> Option<u32> {
        let (start, trans, accept) = self.epsilon_free();
        let n = trans.len();

        let mut fwd = start.clone();
        let mut work: Vec<usize> = (0..n).filter(|&q| fwd[q]).collect();
        while let Some(q) = work.pop() {
            for &(_, t) in &trans[q] {
                if !fwd[t] {
                    fwd[t] = true;
                    work.push(t);
                }
            }
        }
        let mut rev: Vec<Vec<usize>> = vec![Vec::new(); n];
        for (q, edges) in trans.iter().enumerate() {
            for &(_, t) in edges {
                rev[t].push(q);
            }
        }
        let mut bwd = accept.clone();
        let mut work: Vec<usize> = (0..n).filter(|&q| bwd[q]).collect();
        while let Some(q) = work.pop() {
            for &p in &rev[q] {
                if !bwd[p] {
                    bwd[p] = true;
                    work.push(p);
                }
            }
        }
        let live: Vec<bool> = (0..n).map(|q| fwd[q] && bwd[q]).collect();

        // Longest path from each live state, by iterative DFS: 0 = unvisited,
        // 1 = on the stack (a second visit means a cycle), 2 = settled.
        const UNVISITED: u8 = 0;
        const OPEN: u8 = 1;
        const DONE: u8 = 2;
        let mut state = vec![UNVISITED; n];
        let mut best = vec![0u32; n];
        for root in (0..n).filter(|&q| live[q]) {
            if state[root] != UNVISITED {
                continue;
            }
            let mut stack: Vec<(usize, usize)> = vec![(root, 0)];
            state[root] = OPEN;
            while let Some(&(q, idx)) = stack.last() {
                if idx < trans[q].len() {
                    stack.last_mut().expect("stack is non-empty").1 += 1;
                    let t = trans[q][idx].1;
                    if !live[t] {
                        continue;
                    }
                    match state[t] {
                        UNVISITED => {
                            state[t] = OPEN;
                            stack.push((t, 0));
                        }
                        OPEN => return None, // cycle: unbounded length
                        _ => {}
                    }
                } else {
                    stack.pop();
                    let mut b = 0u32;
                    for &(_, t) in &trans[q] {
                        if live[t] {
                            b = b.max(best[t].saturating_add(1));
                        }
                    }
                    best[q] = b;
                    state[q] = DONE;
                }
            }
        }
        Some(
            (0..n)
                .filter(|&q| start[q] && live[q])
                .map(|q| best[q])
                .max()
                .unwrap_or(0),
        )
    }

    /// Subset construction: a *total* DFA over the byte alphabet, returned as
    /// per-state transitions coalesced back into ranges plus an accept mask.
    /// State 0 is the start. `None` if the construction exceeds `limit` states.
    ///
    /// Totality matters — complement is only correct if every (state, byte)
    /// pair has a target, so the empty subset is kept as an ordinary state
    /// rather than dropped.
    fn to_dfa(&self, limit: usize) -> Option<(Trans, StateSet)> {
        let (start, trans, accept) = self.epsilon_free();

        // Every transition range in the automaton contributes two boundaries,
        // and within a resulting interval no state can distinguish one byte from
        // another. So the subset step only has to try one representative byte
        // per interval, of which there are at most 2·edges+1 rather than 256 —
        // and the intervals come out already coalesced.
        let mut cuts: Vec<u8> = vec![0];
        for edges in &trans {
            for &(r, _) in edges {
                cuts.push(r.lo);
                if r.hi < 255 {
                    cuts.push(r.hi + 1);
                }
            }
        }
        cuts.sort_unstable();
        cuts.dedup();
        let intervals: Vec<Range> = (0..cuts.len())
            .map(|i| Range {
                lo: cuts[i],
                hi: if i + 1 < cuts.len() {
                    cuts[i + 1] - 1
                } else {
                    255
                },
            })
            .collect();

        let mut ids: FxHashMap<Vec<bool>, usize> = FxHashMap::default();
        let mut subsets: Vec<Vec<bool>> = Vec::new();
        let mut intern = |s: Vec<bool>, subsets: &mut Vec<Vec<bool>>| -> usize {
            *ids.entry(s.clone()).or_insert_with(|| {
                subsets.push(s);
                subsets.len() - 1
            })
        };
        intern(start, &mut subsets);

        let mut dfa: Vec<Vec<(Range, usize)>> = Vec::new();
        let mut cur = 0;
        while cur < subsets.len() {
            if subsets.len() > limit {
                return None;
            }
            let here = subsets[cur].clone();
            let mut edges: Vec<(Range, usize)> = Vec::new();
            for &iv in &intervals {
                let mut next = vec![false; here.len()];
                for (q, &live) in here.iter().enumerate() {
                    if !live {
                        continue;
                    }
                    for &(r, t) in &trans[q] {
                        if iv.lo >= r.lo && iv.lo <= r.hi {
                            next[t] = true;
                        }
                    }
                }
                let target = intern(next, &mut subsets);
                // Merge with the previous interval when it leads to the same
                // subset, so the encoded transition relation stays small.
                match edges.last_mut() {
                    Some((prev, t)) if *t == target && prev.hi as u16 + 1 == iv.lo as u16 => {
                        prev.hi = iv.hi;
                    }
                    _ => edges.push((iv, target)),
                }
            }
            dfa.push(edges);
            cur += 1;
        }
        let accepting = subsets
            .iter()
            .map(|s| s.iter().zip(&accept).any(|(&live, &acc)| live && acc))
            .collect();
        Some((dfa, accepting))
    }

    /// Rebuild an NFA from a DFA, funnelling the accepting states into the
    /// single accept state this representation carries.
    fn from_dfa(dfa: &[Vec<(Range, usize)>], accepting: &[bool]) -> Nfa {
        let mut n = Nfa::default();
        for _ in 0..dfa.len() {
            n.new_state();
        }
        let funnel = n.new_state();
        n.start = 0;
        n.accept = funnel;
        for (q, edges) in dfa.iter().enumerate() {
            for &(r, t) in edges {
                n.states[q].push(Edge::Consume(r, t));
            }
            if accepting[q] {
                n.states[q].push(Edge::Epsilon(funnel));
            }
        }
        n
    }

    /// Complement, over the byte alphabet. Requires determinization, so it can
    /// fail on a state blowup; the caller then reports the regex unsupported
    /// rather than guessing an answer.
    fn complement(&self, limit: usize) -> Option<Nfa> {
        let (dfa, accepting) = self.to_dfa(limit)?;
        let flipped: Vec<bool> = accepting.iter().map(|&a| !a).collect();
        Some(Nfa::from_dfa(&dfa, &flipped))
    }

    /// Intersection by product construction on the epsilon-free views. Ranges
    /// are intersected pairwise, so no determinization is needed.
    fn intersect(parts: &[Nfa], limit: usize) -> Option<Nfa> {
        let mut acc = parts[0].clone();
        for other in &parts[1..] {
            acc = Nfa::intersect2(&acc, other, limit)?;
        }
        Some(acc)
    }

    fn intersect2(a: &Nfa, b: &Nfa, limit: usize) -> Option<Nfa> {
        let (a_start, a_trans, a_acc) = a.epsilon_free();
        let (b_start, b_trans, b_acc) = b.epsilon_free();
        let (na, nb) = (a_trans.len(), b_trans.len());
        match na.checked_mul(nb) {
            Some(p) if p <= limit => {}
            _ => return None,
        }
        let mut n = Nfa::default();
        for _ in 0..na * nb {
            n.new_state();
        }
        let entry = n.new_state();
        let sink = n.new_state();
        n.start = entry;
        n.accept = sink;
        let idx = |i: usize, j: usize| i * nb + j;
        for i in 0..na {
            for j in 0..nb {
                if a_start[i] && b_start[j] {
                    n.states[entry].push(Edge::Epsilon(idx(i, j)));
                }
                if a_acc[i] && b_acc[j] {
                    n.states[idx(i, j)].push(Edge::Epsilon(sink));
                }
                for &(ra, ta) in &a_trans[i] {
                    for &(rb, tb) in &b_trans[j] {
                        let lo = ra.lo.max(rb.lo);
                        let hi = ra.hi.min(rb.hi);
                        if lo <= hi {
                            n.states[idx(i, j)].push(Edge::Consume(Range { lo, hi }, idx(ta, tb)));
                        }
                    }
                }
            }
        }
        Some(n)
    }

    /// Epsilon-closure of a state set.
    fn closure(&self, set: &mut [bool]) {
        let mut changed = true;
        while changed {
            changed = false;
            for s in 0..self.states.len() {
                if !set[s] {
                    continue;
                }
                for e in &self.states[s] {
                    if let Edge::Epsilon(t) = *e {
                        if !set[t] {
                            set[t] = true;
                            changed = true;
                        }
                    }
                }
            }
        }
    }
}

/// Build the NFA for every `RegLan`-sorted subterm of `roots`, keyed by term.
///
/// Both the bound analysis and the lowering need these automata, so they are
/// built once up front and shared: determinization (`re.comp` and `re.diff`,
/// which need a total DFA to complement) is the single most expensive step in
/// string lowering and must not run twice.
pub fn build_all(pool: &TermPool, roots: &[TermId]) -> Result<FxHashMap<TermId, Nfa>, LowerError> {
    let mut order: Vec<TermId> = Vec::new();
    pool.post_order(roots, |_, t| order.push(t));
    let mut nfas: FxHashMap<TermId, Nfa> = FxHashMap::default();
    for t in order {
        if pool.sort(t) != Sort::RegLan {
            continue;
        }
        let args: Vec<TermId> = pool.args(t).to_vec();
        let n = build(pool, pool.op(t), &args, &nfas)?;
        nfas.insert(t, n);
    }
    Ok(nfas)
}

/// The bytes a string term denotes, when that is fixed at build time.
///
/// Literals arrive as named variables, but generators also write things like
/// `(str.to_re (str.++ "A" "B"))`, whose argument is an *application* with a
/// constant value. Folding concatenations of literals here costs nothing and
/// is the difference between compiling such a regex and refusing it.
fn const_bytes(pool: &TermPool, t: TermId) -> Option<Vec<u8>> {
    match pool.op(t) {
        Op::Var(sym) => crate::literal_bytes(&pool.symbol(sym).name),
        Op::Other { name, .. } if pool.symbol(name).name == "str.++" => {
            let mut out = Vec::new();
            for &a in pool.args(t) {
                out.extend(const_bytes(pool, a)?);
            }
            Some(out)
        }
        _ => None,
    }
}

/// Build the NFA for a regex term, given the automata of its operands.
pub fn build(
    pool: &TermPool,
    op: Op,
    args: &[TermId],
    nfas: &FxHashMap<TermId, Nfa>,
) -> Result<Nfa, LowerError> {
    let sub = |t: TermId| -> Result<Nfa, LowerError> {
        match nfas.get(&t) {
            Some(n) => Ok(n.clone()),
            None => Err(LowerError::Unsupported("expected a regex operand".into())),
        }
    };
    let as_literal = |t: TermId| -> Result<Vec<u8>, LowerError> {
        if pool.sort(t) != Sort::Str {
            return Err(LowerError::Unsupported("expected a string operand".into()));
        }
        // Only strings with a statically known value can be compiled into an
        // automaton — but that includes concatenations of literals, which
        // generators emit freely.
        const_bytes(pool, t)
            .ok_or_else(|| LowerError::Unsupported("regex over a symbolic string".into()))
    };

    // `re.loop`/`re.^` carry their repetition counts as operator indices; every
    // other form ignores them. Nullary constants (`re.none`, `re.all`,
    // `re.allchar`) reach us as RegLan-sorted leaves rather than applications.
    let (opname, index0, index1) = match op {
        Op::Other {
            name,
            index0,
            index1,
        } => (pool.symbol(name).name.clone(), index0, index1),
        Op::Var(sym) => (pool.symbol(sym).name.clone(), 0, 0),
        _ => return Err(LowerError::Unsupported("unexpected regex operator".into())),
    };
    Ok(match opname.as_str() {
        "str.to_re" => Nfa::literal(&as_literal(args[0])?),
        "re.none" => Nfa::none(),
        "re.all" => Nfa::star(&Nfa::single_range(Range { lo: 0, hi: 255 })),
        "re.allchar" => Nfa::single_range(Range { lo: 0, hi: 255 }),
        "re.++" => {
            let parts: Result<Vec<Nfa>, LowerError> = args.iter().map(|&a| sub(a)).collect();
            Nfa::concat(&parts?)
        }
        "re.union" => {
            let parts: Result<Vec<Nfa>, LowerError> = args.iter().map(|&a| sub(a)).collect();
            Nfa::union(&parts?)
        }
        "re.*" => Nfa::star(&sub(args[0])?),
        "re.+" => Nfa::plus(&sub(args[0])?),
        "re.opt" => Nfa::opt(&sub(args[0])?),
        "re.range" => {
            let lo = as_literal(args[0])?;
            let hi = as_literal(args[1])?;
            // Ranges over non-single characters denote the empty language.
            if lo.len() != 1 || hi.len() != 1 || lo[0] > hi[0] {
                Nfa::none()
            } else {
                Nfa::single_range(Range {
                    lo: lo[0],
                    hi: hi[0],
                })
            }
        }
        "re.loop" | "re.^" => {
            let inner = sub(args[0])?;
            let (lo, hi) = (index0, index1.max(index0));
            let mut parts: Vec<Nfa> = (0..lo).map(|_| inner.clone()).collect();
            for _ in lo..hi {
                parts.push(Nfa::opt(&inner));
            }
            if parts.is_empty() {
                Nfa::epsilon()
            } else {
                Nfa::concat(&parts)
            }
        }
        // Complement needs a total DFA, so `re.comp` and `re.diff` go through
        // subset construction and can blow up; on the cap we refuse rather
        // than guess. (`re.inter` does not — see `intersect2`, which is a
        // product construction over epsilon-free views.)
        "re.comp" => {
            let inner = sub(args[0])?;
            inner
                .complement(DETERMINIZE_LIMIT)
                .ok_or_else(|| LowerError::Unsupported("re.comp state blowup".into()))?
        }
        "re.inter" => {
            let parts: Result<Vec<Nfa>, LowerError> = args.iter().map(|&a| sub(a)).collect();
            Nfa::intersect(&parts?, DETERMINIZE_LIMIT)
                .ok_or_else(|| LowerError::Unsupported("re.inter state blowup".into()))?
        }
        "re.diff" => {
            // `a \ b` is `a` intersected with the complement of `b`; n-ary
            // difference is left-associative.
            let parts: Result<Vec<Nfa>, LowerError> = args.iter().map(|&a| sub(a)).collect();
            let parts = parts?;
            let mut acc = parts[0].clone();
            for b in &parts[1..] {
                let nb = b
                    .complement(DETERMINIZE_LIMIT)
                    .ok_or_else(|| LowerError::Unsupported("re.diff state blowup".into()))?;
                acc = Nfa::intersect2(&acc, &nb, DETERMINIZE_LIMIT)
                    .ok_or_else(|| LowerError::Unsupported("re.diff state blowup".into()))?;
            }
            acc
        }
        other => return Err(LowerError::Unsupported(format!("regex operator {other}"))),
    })
}

/// Encode "the NFA accepts `s`" as a Boolean term.
///
/// One Bool per (position, state): `live[i][q]` says the NFA can be in state
/// `q` after consuming `i` characters. The automaton is made epsilon-free
/// first, so each position is a single pass over the transition relation.
pub fn accepts(pool: &mut TermPool, nfa: &Nfa, s: &BoundedStr, max_len: u32) -> TermId {
    let (start_set, trans, accept_set) = nfa.epsilon_free();
    let n = nfa.states.len();
    let tt = pool.true_term;
    let ff = pool.false_term;
    let mk = |pool: &mut TermPool, op: Op, args: &[TermId]| -> TermId {
        pool.mk(op, args)
            .expect("regex encoding built an ill-sorted term")
    };
    let or_of = |pool: &mut TermPool, args: &[TermId]| -> TermId {
        let mut v: Vec<TermId> = args.iter().copied().filter(|&a| a != ff).collect();
        if v.contains(&tt) {
            return tt;
        }
        v.sort_unstable();
        v.dedup();
        match v.len() {
            0 => ff,
            1 => v[0],
            _ => mk(pool, Op::Or, &v),
        }
    };
    let and_of = |pool: &mut TermPool, args: &[TermId]| -> TermId {
        let mut v: Vec<TermId> = args.iter().copied().filter(|&a| a != tt).collect();
        if v.contains(&ff) {
            return ff;
        }
        v.sort_unstable();
        v.dedup();
        match v.len() {
            0 => tt,
            1 => v[0],
            _ => mk(pool, Op::And, &v),
        }
    };

    let mut live: Vec<TermId> = (0..n).map(|q| if start_set[q] { tt } else { ff }).collect();

    // The string is accepted if the automaton is in an accepting state exactly
    // when the characters run out.
    let mut accept_disj = Vec::new();
    let accept_here = |pool: &mut TermPool, live: &[TermId], i: u64| -> TermId {
        let acc_states: Vec<TermId> = (0..n).filter(|&q| accept_set[q]).map(|q| live[q]).collect();
        let any = or_of(pool, &acc_states);
        let pos = pool.bv_u64(crate::INT_BITS, i);
        let at_end = mk(pool, Op::Eq, &[s.len, pos]);
        and_of(pool, &[at_end, any])
    };
    let a0 = accept_here(pool, &live, 0);
    accept_disj.push(a0);

    for i in 0..max_len as usize {
        let ch = s.chars[i];
        let mut incoming: Vec<Vec<TermId>> = vec![Vec::new(); n];
        for q in 0..n {
            if live[q] == ff {
                continue;
            }
            for &(r, t) in &trans[q] {
                let in_range = if r.lo == 0 && r.hi == 255 {
                    tt
                } else if r.lo == r.hi {
                    let c = pool.bv_u64(crate::CHAR_BITS, r.lo as u64);
                    mk(pool, Op::Eq, &[ch, c])
                } else {
                    let lo = pool.bv_u64(crate::CHAR_BITS, r.lo as u64);
                    let hi = pool.bv_u64(crate::CHAR_BITS, r.hi as u64);
                    let a = mk(pool, Op::BvUle, &[lo, ch]);
                    let b2 = mk(pool, Op::BvUle, &[ch, hi]);
                    and_of(pool, &[a, b2])
                };
                let step = and_of(pool, &[live[q], in_range]);
                if step != ff {
                    incoming[t].push(step);
                }
            }
        }
        live = incoming.into_iter().map(|v| or_of(pool, &v)).collect();
        let a = accept_here(pool, &live, (i + 1) as u64);
        accept_disj.push(a);
    }
    or_of(pool, &accept_disj)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Concrete NFA simulation, so language properties can be checked without
    /// going through the SMT encoding.
    fn accepts_concrete(nfa: &Nfa, s: &[u8]) -> bool {
        let (start, trans, accept) = nfa.epsilon_free();
        let mut live = start;
        for &byte in s {
            let mut next = vec![false; live.len()];
            for (q, &on) in live.iter().enumerate() {
                if !on {
                    continue;
                }
                for &(r, t) in &trans[q] {
                    if byte >= r.lo && byte <= r.hi {
                        next[t] = true;
                    }
                }
            }
            live = next;
        }
        live.iter().zip(&accept).any(|(&on, &acc)| on && acc)
    }

    fn lit(s: &str) -> Nfa {
        Nfa::literal(s.as_bytes())
    }

    /// The longest accepted word, cross-checked against brute-force
    /// enumeration over a two-letter alphabet.
    #[test]
    fn max_word_len_matches_enumeration() {
        let cases: Vec<Nfa> = vec![
            Nfa::none(),
            Nfa::epsilon(),
            lit("ab"),
            Nfa::union(&[lit("a"), lit("abc")]),
            Nfa::opt(&lit("ab")),
            Nfa::concat(&[lit("a"), Nfa::opt(&lit("b")), Nfa::opt(&lit("c"))]),
            Nfa::union(&[lit("ab"), lit("b")]).complement(4096).unwrap(),
        ];
        for re in &cases {
            let got = re.max_word_len();
            // Longest accepted word over {a,b,c} up to length 6.
            let mut longest: Option<usize> = None;
            let mut words: Vec<Vec<u8>> = vec![Vec::new()];
            for _ in 0..=6 {
                let mut next = Vec::new();
                for w in &words {
                    if accepts_concrete(re, w) {
                        longest = Some(longest.unwrap_or(0).max(w.len()));
                    }
                    for c in *b"abc" {
                        let mut e = w.clone();
                        e.push(c);
                        next.push(e);
                    }
                }
                words = next;
            }
            match got {
                Some(m) => assert!(
                    longest.unwrap_or(0) as u32 <= m,
                    "claimed bound {m} is below an accepted word of length {:?}",
                    longest
                ),
                // Infinite: enumeration must have found words at the cap.
                None => assert_eq!(
                    longest,
                    Some(6),
                    "claimed infinite but enumeration disagrees"
                ),
            }
        }
    }

    #[test]
    fn starred_language_is_infinite() {
        assert_eq!(Nfa::star(&lit("a")).max_word_len(), None);
        assert_eq!(Nfa::plus(&lit("ab")).max_word_len(), None);
        // A cycle that cannot reach an accepting state does not make the
        // language infinite.
        let dead_loop = Nfa::union(&[lit("ab"), Nfa::concat(&[Nfa::star(&lit("z")), Nfa::none()])]);
        assert_eq!(dead_loop.max_word_len(), Some(2));
    }

    #[test]
    fn finite_language_lengths() {
        assert_eq!(Nfa::none().max_word_len(), Some(0));
        assert_eq!(Nfa::epsilon().max_word_len(), Some(0));
        assert_eq!(lit("abcd").max_word_len(), Some(4));
        assert_eq!(Nfa::union(&[lit("a"), lit("abc")]).max_word_len(), Some(3));
        assert_eq!(Nfa::opt(&lit("ab")).max_word_len(), Some(2));
    }

    #[test]
    fn determinization_preserves_the_language() {
        let re = Nfa::union(&[lit("ab"), lit("ac"), Nfa::star(&lit("b"))]);
        let (dfa, acc) = re.to_dfa(4096).unwrap();
        let round_trip = Nfa::from_dfa(&dfa, &acc);
        for w in ["", "ab", "ac", "b", "bb", "bbb", "a", "abc", "ba"] {
            assert_eq!(
                accepts_concrete(&re, w.as_bytes()),
                accepts_concrete(&round_trip, w.as_bytes()),
                "disagreement on {w:?}"
            );
        }
    }

    #[test]
    fn complement_inverts_membership() {
        let re = Nfa::concat(&[lit("a"), Nfa::star(&lit("b"))]);
        let comp = re.complement(4096).unwrap();
        for w in ["", "a", "ab", "abb", "b", "ba", "aa", "abc"] {
            assert_ne!(
                accepts_concrete(&re, w.as_bytes()),
                accepts_concrete(&comp, w.as_bytes()),
                "complement agreed with the original on {w:?}"
            );
        }
    }

    /// Double complement is the identity on the language. This is what catches
    /// the classic determinization bug of dropping the empty subset: without
    /// that dead state the complement wrongly rejects every extension of a word
    /// that has already left the language.
    #[test]
    fn double_complement_is_identity() {
        let re = Nfa::union(&[lit("ab"), lit("b")]);
        let twice = re.complement(4096).unwrap().complement(4096).unwrap();
        for w in ["", "a", "b", "ab", "abb", "ba", "bb"] {
            assert_eq!(
                accepts_concrete(&re, w.as_bytes()),
                accepts_concrete(&twice, w.as_bytes()),
                "disagreement on {w:?}"
            );
        }
    }

    #[test]
    fn intersection_is_conjunction() {
        // Words over {a,b} of length 2, intersected with words starting `a`.
        let any = Nfa::single_range(Range { lo: b'a', hi: b'b' });
        let len2 = Nfa::concat(&[any.clone(), any.clone()]);
        let starts_a = Nfa::concat(&[lit("a"), Nfa::star(&any)]);
        let both = Nfa::intersect(&[len2.clone(), starts_a.clone()], 4096).unwrap();
        for w in ["", "a", "aa", "ab", "ba", "bb", "aaa", "aba"] {
            let expect =
                accepts_concrete(&len2, w.as_bytes()) && accepts_concrete(&starts_a, w.as_bytes());
            assert_eq!(expect, accepts_concrete(&both, w.as_bytes()), "on {w:?}");
        }
    }

    #[test]
    fn state_cap_refuses_rather_than_guessing() {
        let any = Nfa::single_range(Range { lo: 0, hi: 255 });
        let wide = Nfa::star(&Nfa::union(&[
            Nfa::concat(&[any.clone(), any.clone(), any.clone()]),
            Nfa::concat(&[any.clone(), any.clone()]),
        ]));
        assert!(wide.complement(2).is_none());
    }
}
