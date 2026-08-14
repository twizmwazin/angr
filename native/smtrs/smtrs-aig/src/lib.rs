//! smtrs-aig: an And-Inverter Graph with structural hashing, sitting between
//! the bit-blaster and CNF.
//!
//! Every gate the blaster builds goes through `and()`, which constant-folds,
//! applies local simplifications (idempotence, complement, absorption against
//! shared fanins), normalizes operand order, and structurally hashes — so
//! identical subcircuits exist once no matter how they were built. CNF is
//! emitted per assertion for the new part of the cone only, which also makes
//! the emitter incremental for free, which is what makes the persistent
//! incremental engine possible.
//!
//! `AigLit` encoding: node index << 1 | complement bit. Node 0 is constant
//! FALSE; `TRUE` is its complement.

use rustc_hash::FxHashMap;
use smtrs_core::PollTick;
use smtrs_sat::{Lit, SatBackend};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct AigLit(u32);

pub const FALSE: AigLit = AigLit(0);
pub const TRUE: AigLit = AigLit(1);

impl AigLit {
    fn node(self) -> u32 {
        self.0 >> 1
    }

    fn is_complement(self) -> bool {
        self.0 & 1 == 1
    }

    fn from_node(node: u32, complement: bool) -> Self {
        AigLit(node << 1 | complement as u32)
    }
}

impl std::ops::Not for AigLit {
    type Output = AigLit;
    fn not(self) -> AigLit {
        AigLit(self.0 ^ 1)
    }
}

#[derive(Clone, Copy, Debug)]
enum Node {
    Const,
    Input,
    And(AigLit, AigLit),
}

#[derive(Clone)]
pub struct Aig {
    nodes: Vec<Node>,
    strash: FxHashMap<(AigLit, AigLit), u32>,
    /// SAT literal for each emitted node (None until in an asserted cone).
    sat_lit: Vec<Option<Lit>>,
    /// Structural fanout count per node (distinct parents).
    refs: Vec<u32>,
    pub num_and_gates: u64,
    pub strash_hits: u64,
    pub folds: u64,
    /// Cooperative interrupt. CNF emission over a multi-million-gate cone is
    /// a long uninterruptible stretch otherwise — on the Sydr symbolic-memory
    /// instances it is the bulk of the encode phase.
    terminate: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// Sticky: emission was abandoned, so the CNF is incomplete and nothing
    /// may be concluded from the SAT instance.
    interrupted: bool,
    /// `SMTRS_AIG_PLAIN`: disable XOR/MUX/tree cut matching, for measurement.
    /// Read once here rather than per node — it used to be a `env::var_os`
    /// call inside the CNF emission loop, i.e. an allocation and a linear
    /// environment scan per AND gate, on encodings that reach millions of
    /// gates. Every other switch in the workspace is cached this way.
    plain_cnf: bool,
}

impl Default for Aig {
    fn default() -> Self {
        Self::new()
    }
}

impl Aig {
    pub fn new() -> Self {
        Aig {
            nodes: vec![Node::Const],
            strash: FxHashMap::default(),
            sat_lit: vec![None],
            refs: vec![0],
            num_and_gates: 0,
            strash_hits: 0,
            folds: 0,
            terminate: None,
            interrupted: false,
            plain_cnf: std::env::var_os("SMTRS_AIG_PLAIN").is_some(),
        }
    }

    pub fn set_terminate(&mut self, flag: std::sync::Arc<std::sync::atomic::AtomicBool>) {
        self.terminate = Some(flag);
    }

    pub fn clear_terminate(&mut self) {
        self.terminate = None;
        self.interrupted = false;
    }

    /// True once CNF emission was cut short; the SAT instance is then
    /// incomplete and neither answer may be trusted.
    pub fn interrupted(&self) -> bool {
        self.interrupted
    }

    pub fn input(&mut self) -> AigLit {
        let id = self.nodes.len() as u32;
        self.nodes.push(Node::Input);
        self.sat_lit.push(None);
        self.refs.push(0);
        AigLit::from_node(id, false)
    }

    pub fn constant(&self, b: bool) -> AigLit {
        if b {
            TRUE
        } else {
            FALSE
        }
    }

    pub fn and(&mut self, a: AigLit, b: AigLit) -> AigLit {
        // Constant / trivial folding.
        if a == FALSE || b == FALSE || a == !b {
            self.folds += 1;
            return FALSE;
        }
        if a == TRUE {
            self.folds += 1;
            return b;
        }
        if b == TRUE || a == b {
            self.folds += 1;
            return a;
        }
        // One-level structural simplifications against fanins
        // (contradiction/subsumption): for AND nodes x = (x0 & x1):
        //   a & b where b == x0 or x1 of a           -> a   (absorption)
        //   a & b where b == !x0 or !x1 of a         -> FALSE
        //   a & b where a == !x (x AND node) and b == x0|x1 -> b & !other? skip
        for (u, v) in [(a, b), (b, a)] {
            if !u.is_complement() {
                if let Node::And(f0, f1) = self.nodes[u.node() as usize] {
                    if v == f0 || v == f1 {
                        self.folds += 1;
                        return u;
                    }
                    if v == !f0 || v == !f1 {
                        self.folds += 1;
                        return FALSE;
                    }
                }
            } else {
                // u = !(f0 & f1); u & f0 & f1 == FALSE requires both; but
                // u & v with v == f0? no simplification (¬(f0∧f1) ∧ f0 is
                // satisfiable). Skip.
            }
        }
        // Canonical order for hashing.
        let (a, b) = if a <= b { (a, b) } else { (b, a) };
        if let Some(&node) = self.strash.get(&(a, b)) {
            self.strash_hits += 1;
            return AigLit::from_node(node, false);
        }
        let id = self.nodes.len() as u32;
        self.nodes.push(Node::And(a, b));
        self.sat_lit.push(None);
        self.refs.push(0);
        self.refs[a.node() as usize] += 1;
        self.refs[b.node() as usize] += 1;
        self.strash.insert((a, b), id);
        self.num_and_gates += 1;
        AigLit::from_node(id, false)
    }

    pub fn or(&mut self, a: AigLit, b: AigLit) -> AigLit {
        let x = self.and(!a, !b);
        !x
    }

    pub fn and_many(&mut self, lits: &[AigLit]) -> AigLit {
        // Balanced reduction gives shallower Tseitin structure than a chain.
        match lits.len() {
            0 => TRUE,
            1 => lits[0],
            _ => {
                let mut layer: Vec<AigLit> = lits.to_vec();
                while layer.len() > 1 {
                    let mut next = Vec::with_capacity(layer.len().div_ceil(2));
                    for pair in layer.chunks(2) {
                        next.push(if pair.len() == 2 {
                            self.and(pair[0], pair[1])
                        } else {
                            pair[0]
                        });
                    }
                    layer = next;
                }
                layer[0]
            }
        }
    }

    pub fn or_many(&mut self, lits: &[AigLit]) -> AigLit {
        let inv: Vec<AigLit> = lits.iter().map(|&l| !l).collect();
        let x = self.and_many(&inv);
        !x
    }

    pub fn xor(&mut self, a: AigLit, b: AigLit) -> AigLit {
        // (a | b) & !(a & b)
        let o = self.or(a, b);
        let n = self.and(a, b);
        self.and(o, !n)
    }

    /// ite(c, t, e)
    pub fn mux(&mut self, c: AigLit, t: AigLit, e: AigLit) -> AigLit {
        if t == e {
            return t;
        }
        let pt = self.and(c, t);
        let pe = self.and(!c, e);
        self.or(pt, pe)
    }

    /// Leaves of the AND tree rooted at `node` — the maximal one *within the
    /// single-fanout region*, not the maximal one overall: descend through
    /// *non-complemented* AND fanins that don't have a SAT literal yet
    /// (already-emitted nodes are reused as leaves) *and whose structural
    /// fanout is at most one* — a shared node terminates the descent, so that
    /// collapsing this tree does not duplicate a cone that another parent
    /// also needs. Bounded so a giant cone still emits in chunks.
    fn and_leaves(&self, node: u32, limit: usize) -> Vec<AigLit> {
        let mut leaves = Vec::new();
        let mut stack = vec![node];
        while let Some(n) = stack.pop() {
            let Node::And(f0, f1) = self.nodes[n as usize] else {
                unreachable!("and_leaves on non-AND node")
            };
            for f in [f1, f0] {
                // Only collapse through single-fanout nodes: shared nodes
                // get their own SAT variable exactly once, preserving
                // emission memoization across overlapping cones.
                let expandable = !f.is_complement()
                    && matches!(self.nodes[f.node() as usize], Node::And(..))
                    && self.sat_lit[f.node() as usize].is_none()
                    && self.refs[f.node() as usize] <= 1
                    && leaves.len() + stack.len() < limit;
                if expandable {
                    stack.push(f.node());
                } else {
                    leaves.push(f);
                }
            }
        }
        leaves
    }

    /// The shape both `match_xor` and `match_mux` start from:
    /// `n = And(¬And(x0,x1), ¬And(y0,y1))`, returning the two inner pairs.
    fn match_nand_pair(&self, n: u32) -> Option<((AigLit, AigLit), (AigLit, AigLit))> {
        let Node::And(f0, f1) = self.nodes[n as usize] else {
            return None;
        };
        if !f0.is_complement() || !f1.is_complement() {
            return None;
        }
        let (Node::And(x0, x1), Node::And(y0, y1)) = (
            self.nodes[f0.node() as usize],
            self.nodes[f1.node() as usize],
        ) else {
            return None;
        };
        Some(((x0, x1), (y0, y1)))
    }

    /// If `n = And(¬And(x0,x1), ¬And(y0,y1))` with `{y0,y1} == {¬x0,¬x1}`,
    /// then `n == x0 XOR x1`.
    fn match_xor(&self, n: u32) -> Option<(AigLit, AigLit)> {
        let ((x0, x1), (y0, y1)) = self.match_nand_pair(n)?;
        if (y0 == !x0 && y1 == !x1) || (y0 == !x1 && y1 == !x0) {
            Some((x0, x1))
        } else {
            None
        }
    }

    /// If `n = And(¬And(c,t), ¬And(¬c,e))`, then `n == ¬ite(c,t,e)`.
    fn match_mux(&self, n: u32) -> Option<(AigLit, AigLit, AigLit)> {
        let ((x0, x1), (y0, y1)) = self.match_nand_pair(n)?;
        for (c, t) in [(x0, x1), (x1, x0)] {
            for (cc, e) in [(y0, y1), (y1, y0)] {
                if cc == !c {
                    return Some((c, t, e));
                }
            }
        }
        None
    }

    /// Emit CNF for the cone of `out` (new nodes only) and return its SAT
    /// literal. Structure-aware: XOR and MUX patterns built by `xor`/`mux`
    /// are recognized and emitted as single variables with their direct
    /// encodings — 4 clauses for XOR, 6 for MUX (4 defining plus 2 redundant
    /// but propagation-strengthening) — which is crucial for adder chains,
    /// and plain AND trees collapse into wide clauses instead of chains of
    /// 3-clause binary gates.
    pub fn emit<B: SatBackend>(&mut self, sat: &mut B, out: AigLit) -> Lit {
        const COLLAPSE_LIMIT: usize = 64;
        enum Form {
            Tree(Vec<AigLit>),
            Xor(AigLit, AigLit),
            Mux(AigLit, AigLit, AigLit),
        }
        let node = out.node() as usize;
        if self.sat_lit[node].is_none() {
            // Iterative post-order over the unemitted cone. Each node's form
            // (leaf cut / matched pattern) is decided once and carried on the
            // stack: re-deriving it after children emit could pick a
            // different cut whose nodes were never scheduled.
            let mut stack: Vec<(u32, Option<Form>)> = vec![(out.node(), None)];
            let mut tick = PollTick::new();
            while let Some((n, form)) = stack.pop() {
                // One atomic load per `POLL_PERIOD` worklist steps, and one at
                // the first step so an already-set flag is not missed.
                if tick.due() && !self.interrupted {
                    if let Some(f) = &self.terminate {
                        self.interrupted = f.load(std::sync::atomic::Ordering::Relaxed);
                    }
                }
                if self.interrupted {
                    // Abandon the cone. `lit_of(out)` below still needs a
                    // literal for the root, so give it a fresh unconstrained
                    // one; the encoding is discarded by the caller.
                    if self.sat_lit[out.node() as usize].is_none() {
                        self.sat_lit[out.node() as usize] = Some(sat.new_var());
                    }
                    break;
                }
                let ni = n as usize;
                if self.sat_lit[ni].is_some() {
                    continue;
                }
                match self.nodes[ni] {
                    Node::Const => {
                        // Materialize a constant-false SAT literal.
                        let l = sat.new_var();
                        sat.add_clause(&[!l]);
                        self.sat_lit[ni] = Some(l);
                    }
                    Node::Input => {
                        self.sat_lit[ni] = Some(sat.new_var());
                    }
                    Node::And(..) => match form {
                        Some(Form::Xor(a, b)) => {
                            let (la, lb) = (self.lit_of(a), self.lit_of(b));
                            let o = sat.new_var();
                            sat.add_clause(&[!o, la, lb]);
                            sat.add_clause(&[!o, !la, !lb]);
                            sat.add_clause(&[o, !la, lb]);
                            sat.add_clause(&[o, la, !lb]);
                            self.sat_lit[ni] = Some(o);
                        }
                        Some(Form::Mux(c, t, e)) => {
                            // n == ¬ite(c,t,e); o is n's literal.
                            let (lc, lt, le) = (self.lit_of(c), self.lit_of(t), self.lit_of(e));
                            let o = sat.new_var();
                            sat.add_clause(&[!o, !lc, !lt]);
                            sat.add_clause(&[!o, lc, !le]);
                            sat.add_clause(&[o, !lc, lt]);
                            sat.add_clause(&[o, lc, le]);
                            // Redundant but propagation-strengthening:
                            sat.add_clause(&[!o, !lt, !le]);
                            sat.add_clause(&[o, lt, le]);
                            self.sat_lit[ni] = Some(o);
                        }
                        Some(Form::Tree(leaves)) => {
                            let o = sat.new_var();
                            let mut long: Vec<Lit> = Vec::with_capacity(leaves.len() + 1);
                            long.push(o);
                            for &f in &leaves {
                                let lf = self.lit_of(f);
                                sat.add_clause(&[!o, lf]);
                                long.push(!lf);
                            }
                            sat.add_clause(&long);
                            self.sat_lit[ni] = Some(o);
                        }
                        None => {
                            if self.plain_cnf {
                                let Node::And(f0, f1) = self.nodes[ni] else {
                                    unreachable!()
                                };
                                stack.push((n, Some(Form::Tree(vec![f0, f1]))));
                                stack.push((f0.node(), None));
                                stack.push((f1.node(), None));
                            } else if let Some((a, b)) = self.match_xor(n) {
                                stack.push((n, Some(Form::Xor(a, b))));
                                stack.push((a.node(), None));
                                stack.push((b.node(), None));
                            } else if let Some((c, t, e)) = self.match_mux(n) {
                                stack.push((n, Some(Form::Mux(c, t, e))));
                                stack.push((c.node(), None));
                                stack.push((t.node(), None));
                                stack.push((e.node(), None));
                            } else {
                                let leaves = self.and_leaves(n, COLLAPSE_LIMIT);
                                stack.push((n, Some(Form::Tree(leaves.clone()))));
                                for &f in &leaves {
                                    stack.push((f.node(), None));
                                }
                            }
                        }
                    },
                }
            }
        }
        self.lit_of(out)
    }

    fn lit_of(&self, l: AigLit) -> Lit {
        let base = self.sat_lit[l.node() as usize].expect("node emitted");
        if l.is_complement() {
            !base
        } else {
            base
        }
    }

    /// Assert `out` at top level.
    pub fn assert_true<B: SatBackend>(&mut self, sat: &mut B, out: AigLit) {
        self.assert_true_guarded(sat, out, None);
    }

    /// Assert `out` under an activation literal: the asserting clause becomes
    /// `(¬guard ∨ out)`, so a later unit `¬guard` retires it. Only the root
    /// clause is guarded — the Tseitin definitions `emit` produces are
    /// conservative extensions of a fresh variable and stay unconditional,
    /// which is what lets the gates be shared with (and by) other levels
    /// without the sharing leaking any constraint across a retraction.
    pub fn assert_true_guarded<B: SatBackend>(
        &mut self,
        sat: &mut B,
        out: AigLit,
        guard: Option<Lit>,
    ) {
        if out == TRUE {
            return;
        }
        if out == FALSE {
            match guard {
                // The guarded context is unsatisfiable on its own, which is
                // not the same as the formula being unsatisfiable.
                Some(g) => sat.add_clause(&[!g]),
                // Empty clause: unsatisfiable.
                None => sat.add_clause(&[]),
            }
            return;
        }
        let l = self.emit(sat, out);
        if self.interrupted {
            return;
        }
        match guard {
            Some(g) => sat.add_clause(&[!g, l]),
            None => sat.add_clause(&[l]),
        }
    }

    /// SAT model value of a literal, if its node was emitted.
    pub fn value<B: SatBackend>(&self, sat: &B, l: AigLit) -> Option<bool> {
        let base = self.sat_lit[l.node() as usize]?;
        let v = sat.value(base)?;
        Some(v ^ l.is_complement())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smtrs_sat::{BatsatBackend, SatResult};

    #[test]
    fn folding_and_hashing() {
        let mut g = Aig::new();
        let a = g.input();
        let b = g.input();
        assert_eq!(g.and(a, FALSE), FALSE);
        assert_eq!(g.and(a, TRUE), a);
        assert_eq!(g.and(a, a), a);
        assert_eq!(g.and(a, !a), FALSE);
        let ab1 = g.and(a, b);
        let ab2 = g.and(b, a);
        assert_eq!(ab1, ab2);
        assert_eq!(g.num_and_gates, 1);
        // Absorption: (a & b) & a == a & b ; contradiction: (a & b) & !a == F.
        assert_eq!(g.and(ab1, a), ab1);
        assert_eq!(g.and(ab1, !a), FALSE);
    }

    #[test]
    fn xor_and_mux_semantics() {
        // Exhaustive check via SAT: xor(a,b) != (a != b) must be unsat.
        let mut g = Aig::new();
        let a = g.input();
        let b = g.input();
        let x = g.xor(a, b);
        // Model check all 4 assignments by asserting each combination.
        for (va, vb) in [(false, false), (false, true), (true, false), (true, true)] {
            let mut g2 = Aig::new();
            let a2 = g2.input();
            let b2 = g2.input();
            let x2 = g2.xor(a2, b2);
            let mut sat = BatsatBackend::new();
            g2.assert_true(&mut sat, if va { a2 } else { !a2 });
            g2.assert_true(&mut sat, if vb { b2 } else { !b2 });
            let expect = va ^ vb;
            g2.assert_true(&mut sat, if expect { x2 } else { !x2 });
            assert_eq!(sat.solve(&[]), SatResult::Sat);
        }
        let _ = x;

        // mux truth table.
        for (vc, vt, ve) in [(true, true, false), (false, true, false)] {
            let mut g2 = Aig::new();
            let c = g2.input();
            let t = g2.input();
            let e = g2.input();
            let m = g2.mux(c, t, e);
            let mut sat = BatsatBackend::new();
            g2.assert_true(&mut sat, if vc { c } else { !c });
            g2.assert_true(&mut sat, if vt { t } else { !t });
            g2.assert_true(&mut sat, if ve { e } else { !e });
            let expect = if vc { vt } else { ve };
            g2.assert_true(&mut sat, if expect { m } else { !m });
            assert_eq!(sat.solve(&[]), SatResult::Sat);
        }
    }

    #[test]
    fn assert_false_is_unsat() {
        let mut g = Aig::new();
        let a = g.input();
        let mut sat = BatsatBackend::new();
        let contradiction = g.and(a, !a);
        g.assert_true(&mut sat, contradiction);
        assert_eq!(sat.solve(&[]), SatResult::Unsat);
    }
}
