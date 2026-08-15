//! Hash-consed term DAG.
//!
//! Terms are `TermId(u32)` handles into a single arena. Construction interns
//! structurally identical nodes, so equality of `TermId` is structural
//! equality of terms, and DAG traversals can memoize by id. Operand lists live
//! in one shared pool (`args`), keeping nodes small and cache-friendly.

use crate::bvconst::BvConst;
use crate::op::Op;
use crate::sort::Sort;
use rustc_hash::FxHashMap;
use std::cell::Cell;
use std::hash::{Hash, Hasher};

/// Largest bit-vector width the solver will construct, for any term.
///
/// Widths and extension amounts come straight from the input, so without a cap
/// `((_ repeat 4000000000) x)` either overflows the width arithmetic or asks
/// the blaster for a circuit that cannot be built, and does so before any
/// timeout is polled. The widest bit-vector in the corpus is 32_768 bits, so
/// 2^24 leaves a factor of about 500.
pub const MAX_BV_WIDTH: u32 = 1 << 24;

/// Bounds on `(_ FloatingPoint eb sb)`, likewise input-supplied. The widest
/// format in the corpus is `(15, 64)`; IEEE binary128 is `(15, 113)`.
pub const MAX_FP_EXP_WIDTH: u32 = 64;
pub const MAX_FP_SIG_WIDTH: u32 = 4096;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct TermId(pub u32);

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct SymbolId(pub u32);

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct BvConstId(pub u32);

#[derive(Clone, Copy, Debug)]
struct Node {
    op: Op,
    sort: Sort,
    args_start: u32,
    args_len: u32,
}

#[derive(Debug)]
pub struct Symbol {
    pub name: String,
    pub sort: Sort,
}

/// Empty marker for a hash-cons table slot. Real slots hold a `TermId.0`, so
/// the sentinel costs one addressable id at the very top of the range — far
/// past any pool this solver can build (`nodes.len()` is a `usize` truncated
/// into a `u32` id already).
const EMPTY_SLOT: u32 = u32::MAX;

/// Open-addressed index from a node's `(op, args)` to its `TermId`.
///
/// The previous form was `FxHashMap<NodeKey, TermId>` with
/// `NodeKey { op, args: Box<[TermId]> }`, which allocated and freed an owned
/// operand box on *every* interning attempt — including the 71% that hit an
/// existing node and threw the box away. Measured over 55 fast QF_BV
/// instances that was 365 674 interning calls, 231 281 of them with 1..=4
/// operands, so a malloc/free pair per constructed term on the hottest path
/// in the solver.
///
/// Here the slots hold nothing but the id, and the key is read back out of
/// the arena (`nodes[id]`, `args[start..start+len]`) whenever a probe needs to
/// compare. Nothing is allocated per lookup and the table is 4 bytes a slot.
///
/// **Soundness.** The table is only ever a *hint*: a probe returns an id only
/// after [`slot_matches`] has compared the full key — the operator and every
/// operand, in order. A bad hash can therefore only cost probes or, at worst,
/// fail to find an existing node and duplicate it, which loses sharing but
/// cannot merge two structurally different terms. Merging requires
/// [`slot_matches`] itself to be wrong, and that is a whole-key comparison.
struct InternTable {
    /// Power-of-two length; `EMPTY_SLOT` where unoccupied.
    slots: Vec<u32>,
    len: usize,
}

/// Where a probe stopped: at the node itself, or at the empty slot it belongs
/// in if it is not there.
enum Probe {
    Found(TermId),
    Vacant(usize),
}

#[derive(Debug)]
pub enum SortError {
    Mismatch { op: String, detail: String },
}

impl std::fmt::Display for SortError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SortError::Mismatch { op, detail } => write!(f, "sort error in {op}: {detail}"),
        }
    }
}

impl std::error::Error for SortError {}

/// Reusable traversal state for [`TermPool::post_order`], parked on the pool
/// between calls.
///
/// `post_order` used to open each call with `vec![false; self.nodes.len()]` —
/// an allocation and a zeroing pass proportional to the *whole pool*, however
/// small the traversal. Over the same 55 fast instances that was 13 624 calls
/// summing to 66.5 MB of freshly zeroed bitmap to visit 645 199 nodes, and
/// 91% of the calls visited between 4 and 63 nodes against a pool averaging
/// 4 879. Stamping with a per-call epoch instead means nothing is zeroed on
/// entry and the buffer is allocated once per pool rather than once per call.
#[derive(Default)]
struct Traversal {
    /// `stamp[i] == epoch` iff term `i` has been emitted this traversal.
    /// Entries below `epoch` are stale and read as unvisited, so the buffer
    /// never needs clearing.
    stamp: Vec<u32>,
    /// Always >= 1 while a traversal is running, so freshly grown (zero)
    /// entries can never be mistaken for visited.
    epoch: u32,
    stack: Vec<(TermId, bool)>,
}

pub struct TermPool {
    nodes: Vec<Node>,
    args: Vec<TermId>,
    intern: InternTable,
    bv_consts: Vec<BvConst>,
    bv_intern: FxHashMap<BvConst, BvConstId>,
    symbols: Vec<Symbol>,
    /// Symbols the theory lowerings derive from source symbols (an FP
    /// variable's IEEE bits, a string variable's length and character slots),
    /// interned per (source, tag, index) so that re-running a lowering
    /// reproduces the *same* symbols — and, terms being hash-consed, the same
    /// terms. That determinism is what lets a persistent engine survive a
    /// re-lowering: the solver compares the re-lowered assertions against
    /// what the engine already blasted, and fresh symbols per run would make
    /// that comparison fail every time.
    derived: FxHashMap<(SymbolId, &'static str, u32), SymbolId>,
    /// Parked traversal scratch. A `Cell` rather than a `RefCell` because
    /// `post_order` hands `&self` to its callback and callbacks do nest: the
    /// buffer is *moved out* for the duration of a traversal, so a nested call
    /// transparently gets a fresh one instead of panicking on a double borrow.
    /// The epoch travels with the buffer, so whichever traversal parks last
    /// leaves a self-consistent pair behind.
    traversal: Cell<Option<Box<Traversal>>>,
    /// DAG-walk instrumentation; see [`TermPool::walk_counters`]. Kept
    /// because a traversal count is the one measure of this pipeline's work
    /// that a loaded machine cannot move: wall time on a shared box says
    /// nothing, but "this change visits 40% fewer term nodes" is the same
    /// number on an idle machine and a busy one. Cost is one local increment
    /// per emitted node and one `Cell` write per walk.
    counters: Cell<WalkCounters>,
    /// Interned `true`/`false` for cheap access.
    pub true_term: TermId,
    pub false_term: TermId,
}

/// How much DAG walking this pool has been asked to do.
///
/// Wall-clock timing on a shared machine is not evidence; the number of term
/// nodes a query visits is, because it cannot move under load. Every traversal
/// that walks the term graph — `post_order`, `find_post_order`, and the
/// solver's own incremental prefix scan via [`TermPool::record_walk`] —
/// accumulates here, so "visits per query" is one subtraction.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct WalkCounters {
    /// Term nodes handed to a traversal's callback.
    pub visits: u64,
    /// Traversals started.
    pub walks: u64,
}

impl Default for TermPool {
    fn default() -> Self {
        Self::new()
    }
}

impl TermPool {
    pub fn new() -> Self {
        let mut pool = TermPool {
            nodes: Vec::new(),
            args: Vec::new(),
            intern: InternTable {
                slots: vec![EMPTY_SLOT; 64],
                len: 0,
            },
            bv_consts: Vec::new(),
            bv_intern: FxHashMap::default(),
            symbols: Vec::new(),
            derived: FxHashMap::default(),
            traversal: Cell::new(None),
            counters: Cell::new(WalkCounters::default()),
            true_term: TermId(0),
            false_term: TermId(0),
        };
        pool.true_term = pool.intern_node(Op::True, &[], Sort::Bool);
        pool.false_term = pool.intern_node(Op::False, &[], Sort::Bool);
        pool
    }

    pub fn num_terms(&self) -> usize {
        self.nodes.len()
    }

    pub fn op(&self, t: TermId) -> Op {
        self.nodes[t.0 as usize].op
    }

    pub fn sort(&self, t: TermId) -> Sort {
        self.nodes[t.0 as usize].sort
    }

    pub fn args(&self, t: TermId) -> &[TermId] {
        let n = &self.nodes[t.0 as usize];
        &self.args[n.args_start as usize..(n.args_start + n.args_len) as usize]
    }

    pub fn bv_const(&self, id: BvConstId) -> &BvConst {
        &self.bv_consts[id.0 as usize]
    }

    /// The BvConst value of a term, if it is a BV constant node.
    pub fn as_bv_const(&self, t: TermId) -> Option<&BvConst> {
        match self.op(t) {
            Op::BvConst(id) => Some(self.bv_const(id)),
            _ => None,
        }
    }

    pub fn symbol(&self, s: SymbolId) -> &Symbol {
        &self.symbols[s.0 as usize]
    }

    pub fn width(&self, t: TermId) -> u32 {
        self.sort(t).bv_width().expect("term is not a bit-vector")
    }

    /// Hash of a node key. Only ever used to pick a starting slot — see the
    /// soundness note on [`InternTable`].
    fn key_hash(op: Op, args: &[TermId]) -> u64 {
        let mut h = rustc_hash::FxHasher::default();
        op.hash(&mut h);
        // Hashing the slice writes a length prefix, so `[a]` and `[a, a]`
        // cannot land on the same starting slot by construction.
        args.hash(&mut h);
        h.finish()
    }

    /// Does the node in `slot` have exactly this key? The full comparison the
    /// hash-consing invariant rests on.
    fn slot_matches(nodes: &[Node], argpool: &[TermId], id: u32, op: Op, args: &[TermId]) -> bool {
        let n = &nodes[id as usize];
        n.op == op
            && n.args_len as usize == args.len()
            && argpool[n.args_start as usize..n.args_start as usize + args.len()] == *args
    }

    /// Linear probe for `(op, args)`. The table is kept below 7/8 full, so a
    /// vacant slot always exists and the loop always terminates.
    fn probe(
        slots: &[u32],
        nodes: &[Node],
        argpool: &[TermId],
        op: Op,
        args: &[TermId],
        hash: u64,
    ) -> Probe {
        let mask = slots.len() - 1;
        let mut i = (hash as usize) & mask;
        loop {
            let s = slots[i];
            if s == EMPTY_SLOT {
                return Probe::Vacant(i);
            }
            if Self::slot_matches(nodes, argpool, s, op, args) {
                return Probe::Found(TermId(s));
            }
            i = (i + 1) & mask;
        }
    }

    /// Double the table and re-place every id. Called before the node that
    /// triggered it exists, so the arena is consistent throughout.
    fn grow_intern(&mut self) {
        let mut slots = vec![EMPTY_SLOT; self.intern.slots.len() * 2];
        let mask = slots.len() - 1;
        for &s in &self.intern.slots {
            if s == EMPTY_SLOT {
                continue;
            }
            let n = &self.nodes[s as usize];
            let args = &self.args[n.args_start as usize..(n.args_start + n.args_len) as usize];
            let mut i = (Self::key_hash(n.op, args) as usize) & mask;
            while slots[i] != EMPTY_SLOT {
                i = (i + 1) & mask;
            }
            slots[i] = s;
        }
        self.intern.slots = slots;
    }

    fn intern_node(&mut self, op: Op, args: &[TermId], sort: Sort) -> TermId {
        let hash = Self::key_hash(op, args);
        let mut vacant =
            match Self::probe(&self.intern.slots, &self.nodes, &self.args, op, args, hash) {
                Probe::Found(id) => return id,
                Probe::Vacant(i) => i,
            };
        // Keep the load factor under 7/8 so probing always finds a hole.
        if (self.intern.len + 1) * 8 >= self.intern.slots.len() * 7 {
            self.grow_intern();
            vacant = match Self::probe(&self.intern.slots, &self.nodes, &self.args, op, args, hash)
            {
                Probe::Vacant(i) => i,
                // Growth re-places existing ids only; it cannot invent the
                // node we just failed to find.
                Probe::Found(_) => unreachable!("grow_intern invented a node"),
            };
        }
        let args_start = self.args.len() as u32;
        self.args.extend_from_slice(args);
        let id = TermId(self.nodes.len() as u32);
        // Not a `debug_assert`: the sentinel is an invariant this table
        // introduced (the `FxHashMap` it replaced had no reserved id), release
        // is what ships, and the failure is silent — an id equal to the marker
        // reads back as a vacant slot forever, so the node is re-created on
        // every lookup and the pool stops being hash-consed. One predictable
        // branch on the *miss* path, next to two `Vec` pushes.
        assert!(id.0 != EMPTY_SLOT, "term id collided with the empty marker");
        self.nodes.push(Node {
            op,
            sort,
            args_start,
            args_len: args.len() as u32,
        });
        self.intern.slots[vacant] = id.0;
        self.intern.len += 1;
        id
    }

    // ---- leaf constructors ----

    pub fn bool_const(&mut self, b: bool) -> TermId {
        if b {
            self.true_term
        } else {
            self.false_term
        }
    }

    pub fn bv(&mut self, c: BvConst) -> TermId {
        let width = c.width();
        let id = match self.bv_intern.get(&c) {
            Some(&id) => id,
            None => {
                let id = BvConstId(self.bv_consts.len() as u32);
                self.bv_consts.push(c.clone());
                self.bv_intern.insert(c, id);
                id
            }
        };
        self.intern_node(Op::BvConst(id), &[], Sort::BitVec(width))
    }

    pub fn bv_u64(&mut self, width: u32, value: u64) -> TermId {
        self.bv(BvConst::from_u64(width, value))
    }

    /// Declare a fresh symbol. The caller (parser) is responsible for name
    /// scoping; the pool allows duplicate names (each gets a distinct id).
    pub fn fresh_symbol(&mut self, name: impl Into<String>, sort: Sort) -> SymbolId {
        let id = SymbolId(self.symbols.len() as u32);
        self.symbols.push(Symbol {
            name: name.into(),
            sort,
        });
        id
    }

    /// The symbol a theory lowering derives from `base` under `tag`/`index`
    /// (an FP variable's IEEE bits, a string variable's `i`th character slot),
    /// interning it on first use so every later lowering run reproduces the
    /// same symbol. `name` is only evaluated for that first minting; it is the
    /// display name and carries no identity. A given (base, tag, index) must
    /// always be requested at the same sort — the derivation it names is a
    /// fixed function of the source symbol.
    pub fn derived_symbol(
        &mut self,
        base: SymbolId,
        tag: &'static str,
        index: u32,
        sort: Sort,
        name: impl FnOnce() -> String,
    ) -> SymbolId {
        if let Some(&sym) = self.derived.get(&(base, tag, index)) {
            debug_assert_eq!(
                self.symbols[sym.0 as usize].sort, sort,
                "derived symbol {tag}/{index} of {} re-requested at a different sort",
                self.symbols[base.0 as usize].name
            );
            return sym;
        }
        let sym = self.fresh_symbol(name(), sort);
        self.derived.insert((base, tag, index), sym);
        sym
    }

    pub fn var(&mut self, sym: SymbolId) -> TermId {
        let sort = self.symbols[sym.0 as usize].sort;
        self.intern_node(Op::Var(sym), &[], sort)
    }

    /// FP special constants (`NaN`, `+oo`, `-oo`, `+zero`, `-zero`) in the
    /// given format.
    pub fn fp_const(&mut self, op: Op, eb: u32, sb: u32) -> TermId {
        debug_assert!(matches!(op, Op::FpNan | Op::FpInf(_) | Op::FpZero(_)));
        self.intern_node(op, &[], Sort::Float(eb, sb))
    }

    /// Rounding-mode literal (0=RNE 1=RNA 2=RTP 3=RTN 4=RTZ).
    pub fn rm(&mut self, mode: u8) -> TermId {
        self.intern_node(Op::RmConst(mode), &[], Sort::RoundingMode)
    }

    /// A term with an unsupported operator (kept only for parse fidelity).
    pub fn other(
        &mut self,
        name: SymbolId,
        index0: u32,
        index1: u32,
        args: &[TermId],
        sort: Sort,
    ) -> TermId {
        self.intern_node(
            Op::Other {
                name,
                index0,
                index1,
            },
            args,
            sort,
        )
    }

    // ---- checked constructor for all supported ops ----

    /// Build a term, checking operand sorts and computing the result sort.
    /// Normalizes commutative operand order for better sharing. Does NOT
    /// rewrite/simplify — that is smtrs-rewrite's job.
    pub fn mk(&mut self, op: Op, args: &[TermId]) -> Result<TermId, SortError> {
        let sort = self.check(op, args)?;
        if op.is_commutative() && args.len() > 1 {
            // Commutative normalization used to heap-allocate a `Vec` to sort
            // in, once per call — 107 709 times over 55 fast QF_BV instances,
            // 90.7% of them for exactly two operands. Anything that fits the
            // stack buffer sorts without touching the allocator.
            const INLINE: usize = 8;
            if args.len() <= INLINE {
                let mut buf = [TermId(0); INLINE];
                let sorted = &mut buf[..args.len()];
                sorted.copy_from_slice(args);
                sorted.sort_unstable();
                Ok(self.intern_node(op, sorted, sort))
            } else {
                let mut sorted: Vec<TermId> = args.to_vec();
                sorted.sort_unstable();
                Ok(self.intern_node(op, &sorted, sort))
            }
        } else {
            Ok(self.intern_node(op, args, sort))
        }
    }

    fn err(op: Op, detail: impl Into<String>) -> SortError {
        SortError::Mismatch {
            op: format!("{op:?}"),
            detail: detail.into(),
        }
    }

    /// Build a `Sort::BitVec` from a width derived by arithmetic on
    /// input-supplied widths and indices, rejecting anything past
    /// [`MAX_BV_WIDTH`].
    ///
    /// The arithmetic itself (`w + n`, `w * n`, a `concat` fold) is done by the
    /// caller in `u64` so that it cannot wrap before we see it: on a release
    /// build, where `overflow-checks` is off, a wrapping `u32` add would not
    /// crash but would produce a term whose recorded sort is *narrower than the
    /// term really is*, which every later pass would then trust. Rejecting is
    /// the only safe answer, and the cap keeps the rejection well clear of any
    /// width a real benchmark uses.
    fn bv_sort(op: Op, w: u64) -> Result<Sort, SortError> {
        if w == 0 {
            return Err(Self::err(op, "zero-width bit-vector"));
        }
        if w > MAX_BV_WIDTH as u64 {
            return Err(Self::err(
                op,
                format!("bit-vector width {w} exceeds the {MAX_BV_WIDTH} limit"),
            ));
        }
        Ok(Sort::BitVec(w as u32))
    }

    /// Reject floating-point formats that no encoding can represent.
    ///
    /// `(_ FloatingPoint eb sb)` is unconstrained in the input, and the
    /// word-blaster's unpacked form assumes both fields are wide enough to
    /// carry a sign and a hidden bit: `sb - 2` and `1 << (eb - 1)` both appear
    /// unguarded in `smtrs-fp`, so `sb < 2` or `eb < 2` reaches them as an
    /// underflow rather than as an error.
    fn check_fp_format(op: Op, eb: u32, sb: u32) -> Result<Sort, SortError> {
        if !(2..=MAX_FP_EXP_WIDTH).contains(&eb) || !(2..=MAX_FP_SIG_WIDTH).contains(&sb) {
            return Err(Self::err(
                op,
                format!("unsupported floating-point format ({eb}, {sb})"),
            ));
        }
        Ok(Sort::Float(eb, sb))
    }

    fn expect_arity(&self, op: Op, args: &[TermId], n: usize) -> Result<(), SortError> {
        if args.len() != n {
            return Err(Self::err(op, format!("expected {n} operands")));
        }
        Ok(())
    }

    fn expect_rm(&self, op: Op, t: TermId) -> Result<(), SortError> {
        if self.sort(t) != Sort::RoundingMode {
            return Err(Self::err(op, "expected a RoundingMode operand"));
        }
        Ok(())
    }

    fn bv_width_of(&self, op: Op, t: TermId) -> Result<u32, SortError> {
        self.sort(t)
            .bv_width()
            .ok_or_else(|| Self::err(op, "operand is not a bit-vector"))
    }

    fn float_sort_of(&self, op: Op, t: TermId) -> Result<Sort, SortError> {
        match self.sort(t) {
            s @ Sort::Float(..) => Ok(s),
            _ => Err(Self::err(op, "operand is not a floating-point term")),
        }
    }

    fn all_same_bv(&self, op: Op, args: &[TermId], min: usize) -> Result<u32, SortError> {
        if args.len() < min {
            return Err(Self::err(op, format!("expected at least {min} operands")));
        }
        let w = self
            .sort(args[0])
            .bv_width()
            .ok_or_else(|| Self::err(op, "operand is not a bit-vector"))?;
        for &a in &args[1..] {
            if self.sort(a) != Sort::BitVec(w) {
                return Err(Self::err(op, "operand widths differ"));
            }
        }
        Ok(w)
    }

    fn check(&self, op: Op, args: &[TermId]) -> Result<Sort, SortError> {
        use Op::*;
        Ok(match op {
            True | False => Sort::Bool,
            BvConst(id) => Sort::BitVec(self.bv_consts[id.0 as usize].width()),
            Var(sym) => self.symbols[sym.0 as usize].sort,
            Other { .. } => return Err(Self::err(op, "Other terms must use TermPool::other")),

            Not => {
                if args.len() != 1 || self.sort(args[0]) != Sort::Bool {
                    return Err(Self::err(op, "expected one Bool operand"));
                }
                Sort::Bool
            }
            Implies | And | Or | Xor => {
                if args.len() < 2 || args.iter().any(|&a| self.sort(a) != Sort::Bool) {
                    return Err(Self::err(op, "expected >= 2 Bool operands"));
                }
                Sort::Bool
            }
            Eq | Distinct => {
                if args.len() < 2 {
                    return Err(Self::err(op, "expected >= 2 operands"));
                }
                let s = self.sort(args[0]);
                if args.iter().any(|&a| self.sort(a) != s) {
                    return Err(Self::err(op, "operand sorts differ"));
                }
                Sort::Bool
            }
            Ite => {
                if args.len() != 3
                    || self.sort(args[0]) != Sort::Bool
                    || self.sort(args[1]) != self.sort(args[2])
                {
                    return Err(Self::err(op, "expected (Bool, T, T)"));
                }
                self.sort(args[1])
            }

            BvNeg | BvNot => {
                let w = self.all_same_bv(op, args, 1)?;
                if args.len() != 1 {
                    return Err(Self::err(op, "expected one operand"));
                }
                Sort::BitVec(w)
            }
            BvAdd | BvMul | BvAnd | BvOr | BvXor => Sort::BitVec(self.all_same_bv(op, args, 2)?),
            BvSub | BvUdiv | BvUrem | BvSdiv | BvSrem | BvSmod | BvNand | BvNor | BvXnor
            | BvShl | BvLshr | BvAshr => {
                let w = self.all_same_bv(op, args, 2)?;
                if args.len() != 2 {
                    return Err(Self::err(op, "expected two operands"));
                }
                Sort::BitVec(w)
            }
            BvComp => {
                let _ = self.all_same_bv(op, args, 2)?;
                if args.len() != 2 {
                    return Err(Self::err(op, "expected two operands"));
                }
                Sort::BitVec(1)
            }

            Concat => {
                if args.is_empty() {
                    return Err(Self::err(op, "expected >= 1 operand"));
                }
                let mut w = 0u64;
                for &a in args {
                    w += self
                        .sort(a)
                        .bv_width()
                        .ok_or_else(|| Self::err(op, "operand is not a bit-vector"))?
                        as u64;
                }
                Self::bv_sort(op, w)?
            }
            Extract { hi, lo } => {
                let w = self.all_same_bv(op, args, 1)?;
                if args.len() != 1 || hi < lo || hi >= w {
                    return Err(Self::err(
                        op,
                        format!("bad extract [{hi}:{lo}] on width {w}"),
                    ));
                }
                Sort::BitVec(hi - lo + 1)
            }
            ZeroExtend(n) | SignExtend(n) => {
                let w = self.all_same_bv(op, args, 1)?;
                if args.len() != 1 {
                    return Err(Self::err(op, "expected one operand"));
                }
                Self::bv_sort(op, w as u64 + n as u64)?
            }
            RotateLeft(_) | RotateRight(_) => {
                let w = self.all_same_bv(op, args, 1)?;
                if args.len() != 1 {
                    return Err(Self::err(op, "expected one operand"));
                }
                Sort::BitVec(w)
            }
            Repeat(n) => {
                let w = self.all_same_bv(op, args, 1)?;
                if args.len() != 1 || n == 0 {
                    return Err(Self::err(op, "expected one operand, n >= 1"));
                }
                Self::bv_sort(op, w as u64 * n as u64)?
            }

            BvUlt | BvUle | BvUgt | BvUge | BvSlt | BvSle | BvSgt | BvSge => {
                let _ = self.all_same_bv(op, args, 2)?;
                if args.len() != 2 {
                    return Err(Self::err(op, "expected two operands"));
                }
                Sort::Bool
            }

            // ---- floating point ----
            RmConst(_) => Sort::RoundingMode,
            FpFromBits => {
                if args.len() != 3 {
                    return Err(Self::err(op, "expected (sign, exp, sig) operands"));
                }
                let sign_w = self.bv_width_of(op, args[0])?;
                let eb = self.bv_width_of(op, args[1])?;
                let sig_w = self.bv_width_of(op, args[2])?;
                if sign_w != 1 {
                    return Err(Self::err(op, "sign operand must be 1 bit"));
                }
                Self::check_fp_format(op, eb, sig_w.saturating_add(1))?
            }
            FpNan | FpInf(_) | FpZero(_) => {
                return Err(Self::err(op, "FP constants must use TermPool::fp_const"))
            }
            FpAbs | FpNeg => {
                self.expect_arity(op, args, 1)?;
                self.float_sort_of(op, args[0])?
            }
            FpAdd | FpSub | FpMul | FpDiv => {
                self.expect_arity(op, args, 3)?;
                self.expect_rm(op, args[0])?;
                let s = self.float_sort_of(op, args[1])?;
                if self.sort(args[2]) != s {
                    return Err(Self::err(op, "operand formats differ"));
                }
                s
            }
            FpSqrt | FpRoundToIntegral => {
                self.expect_arity(op, args, 2)?;
                self.expect_rm(op, args[0])?;
                self.float_sort_of(op, args[1])?
            }
            FpFma => {
                self.expect_arity(op, args, 4)?;
                self.expect_rm(op, args[0])?;
                let s = self.float_sort_of(op, args[1])?;
                if self.sort(args[2]) != s || self.sort(args[3]) != s {
                    return Err(Self::err(op, "operand formats differ"));
                }
                s
            }
            FpRem | FpMin | FpMax => {
                self.expect_arity(op, args, 2)?;
                let s = self.float_sort_of(op, args[0])?;
                if self.sort(args[1]) != s {
                    return Err(Self::err(op, "operand formats differ"));
                }
                s
            }
            FpLeq | FpLt | FpGeq | FpGt | FpEq => {
                if args.len() < 2 {
                    return Err(Self::err(op, "expected >= 2 operands"));
                }
                let s = self.float_sort_of(op, args[0])?;
                if args.iter().any(|&a| self.sort(a) != s) {
                    return Err(Self::err(op, "operand formats differ"));
                }
                Sort::Bool
            }
            FpIsNormal | FpIsSubnormal | FpIsZero | FpIsInfinite | FpIsNan | FpIsNegative
            | FpIsPositive => {
                self.expect_arity(op, args, 1)?;
                self.float_sort_of(op, args[0])?;
                Sort::Bool
            }
            FpFromIeeeBv { eb, sb } => {
                self.expect_arity(op, args, 1)?;
                let w = self.bv_width_of(op, args[0])?;
                let sort = Self::check_fp_format(op, eb, sb)?;
                if w as u64 != eb as u64 + sb as u64 {
                    return Err(Self::err(op, "bit width does not match format"));
                }
                sort
            }
            FpToFp { eb, sb } => {
                self.expect_arity(op, args, 2)?;
                self.expect_rm(op, args[0])?;
                self.float_sort_of(op, args[1])?;
                Self::check_fp_format(op, eb, sb)?
            }
            FpFromSignedBv { eb, sb } | FpFromUnsignedBv { eb, sb } => {
                self.expect_arity(op, args, 2)?;
                self.expect_rm(op, args[0])?;
                self.bv_width_of(op, args[1])?;
                Self::check_fp_format(op, eb, sb)?
            }
            FpToIeeeBv => {
                self.expect_arity(op, args, 1)?;
                match self.float_sort_of(op, args[0])? {
                    // The format was validated when the operand was built.
                    Sort::Float(eb, sb) => Self::bv_sort(op, eb as u64 + sb as u64)?,
                    _ => unreachable!(),
                }
            }
            FpToUbv(m) | FpToSbv(m) => {
                self.expect_arity(op, args, 2)?;
                self.expect_rm(op, args[0])?;
                self.float_sort_of(op, args[1])?;
                Self::bv_sort(op, m as u64)?
            }
        })
    }

    /// DAG-walk instrumentation accumulated so far; see [`WalkCounters`].
    pub fn walk_counters(&self) -> WalkCounters {
        self.counters.get()
    }

    /// Fold an externally-run DAG walk into [`TermPool::walk_counters`], so
    /// that a traversal which keeps its own visited set (the solver's
    /// incremental prefix scan) is counted on the same scale as the pool's.
    pub fn record_walk(&self, visits: u64) {
        let mut c = self.counters.get();
        c.visits += visits;
        c.walks += 1;
        self.counters.set(c);
    }

    /// Iterative post-order traversal from `roots`, calling `f` on each
    /// reachable term exactly once (children before parents). Iterative so
    /// that pathological term depth (deep concat/ite chains) cannot overflow
    /// the stack.
    pub fn post_order(&self, roots: &[TermId], mut f: impl FnMut(&Self, TermId)) {
        self.walk(roots, |pool, t| {
            f(pool, t);
            false
        });
    }

    /// Post-order traversal that stops at the first term `f` accepts, and
    /// returns it.
    ///
    /// Same order as [`TermPool::post_order`], so "the first node satisfying
    /// `f`" is the same node either way — a predicate written as a full walk
    /// that latches the first hit can be rewritten as this without changing
    /// which hit it reports. What changes is that the nodes *after* the hit
    /// are never visited.
    pub fn find_post_order(
        &self,
        roots: &[TermId],
        mut f: impl FnMut(&Self, TermId) -> bool,
    ) -> Option<TermId> {
        let mut hit = None;
        self.walk(roots, |pool, t| {
            if f(pool, t) {
                hit = Some(t);
                true
            } else {
                false
            }
        });
        hit
    }

    /// The traversal both public forms are built from: `f` returns `true` to
    /// stop the walk.
    fn walk(&self, roots: &[TermId], mut f: impl FnMut(&Self, TermId) -> bool) {
        // Move the scratch out for the duration: `f` receives `&self` and is
        // allowed to start its own traversal, which then gets its own buffer.
        let mut tr = self.traversal.take().unwrap_or_default();
        // A traversal cannot create terms (`&self`), so the pool size — and
        // with it every id we may stamp — is fixed for the whole loop.
        if tr.stamp.len() < self.nodes.len() {
            tr.stamp.resize(self.nodes.len(), 0);
        }
        tr.epoch = match tr.epoch.checked_add(1) {
            Some(e) => e,
            // 2^32 traversals against one buffer: every stamp is stale by
            // definition, so clear once and restart the count.
            None => {
                tr.stamp.fill(0);
                1
            }
        };
        let epoch = tr.epoch;
        let stack = &mut tr.stack;
        let stamp = &mut tr.stamp;
        stack.clear();
        stack.extend(roots.iter().rev().map(|&r| (r, false)));
        let mut visits = 0u64;
        while let Some((t, children_done)) = stack.pop() {
            if stamp[t.0 as usize] == epoch {
                continue;
            }
            if children_done {
                stamp[t.0 as usize] = epoch;
                visits += 1;
                if f(self, t) {
                    break;
                }
            } else {
                stack.push((t, true));
                for &c in self.args(t).iter().rev() {
                    if stamp[c.0 as usize] != epoch {
                        stack.push((c, false));
                    }
                }
            }
        }
        self.traversal.set(Some(tr));
        self.record_walk(visits);
    }

    /// `post_order` over a **caller-owned** visit map that is never reset: a
    /// node already marked in `seen` is neither descended into nor handed to
    /// `f`, and every node that *is* handed to `f` is marked before the call
    /// returns.
    ///
    /// This is for a *sequence* of traversals over one pool whose results
    /// compose — model reconstruction evaluating one defining term per
    /// eliminated variable is the case it exists for. Each defining term's
    /// cone overlaps its neighbours' heavily, so a plain `post_order` per
    /// definition re-walks the same nodes once per definition and the total is
    /// quadratic in the pool; threading one map makes it linear.
    ///
    /// The contract runs both ways: because a marked node is silently skipped,
    /// the caller must keep whatever it derived from that node. A caller that
    /// abandons a traversal part-way (an error) has marked nodes it never
    /// processed and must clear the map.
    pub fn post_order_memo(
        &self,
        seen: &mut Vec<bool>,
        roots: &[TermId],
        mut f: impl FnMut(&Self, TermId),
    ) {
        if seen.len() < self.nodes.len() {
            seen.resize(self.nodes.len(), false);
        }
        // Same reason as `post_order`: `f` gets `&self` and may nest.
        let mut tr = self.traversal.take().unwrap_or_default();
        let stack = &mut tr.stack;
        stack.clear();
        stack.extend(
            roots
                .iter()
                .rev()
                .filter(|r| !seen[r.0 as usize])
                .map(|&r| (r, false)),
        );
        let mut emitted = 0u64;
        while let Some((t, children_done)) = stack.pop() {
            if seen[t.0 as usize] {
                continue;
            }
            if children_done {
                seen[t.0 as usize] = true;
                emitted += 1;
                f(self, t);
            } else {
                stack.push((t, true));
                for &c in self.args(t).iter().rev() {
                    if !seen[c.0 as usize] {
                        stack.push((c, false));
                    }
                }
            }
        }
        self.traversal.set(Some(tr));
        self.record_walk(emitted);
    }

    /// Rebuild `root` with every occurrence of a key in `map` replaced by its
    /// value (used for define-fun expansion and rewriting). Substitution is
    /// simultaneous, not iterated: replacements are not re-visited.
    pub fn substitute(
        &mut self,
        root: TermId,
        map: &FxHashMap<TermId, TermId>,
    ) -> Result<TermId, SortError> {
        Ok(self.substitute_many(&[root], map)?[0])
    }

    /// `substitute` over several roots sharing one rebuild cache.
    pub fn substitute_many(
        &mut self,
        roots: &[TermId],
        map: &FxHashMap<TermId, TermId>,
    ) -> Result<Vec<TermId>, SortError> {
        if map.is_empty() {
            return Ok(roots.to_vec());
        }
        let mut cache: FxHashMap<TermId, TermId> = map.clone();
        // Collect the traversal first (post_order takes &self; rebuilding needs &mut).
        let mut order: Vec<TermId> = Vec::new();
        self.post_order(roots, |_, t| order.push(t));
        // One rebuild buffer for the whole walk. The old shape allocated two
        // `Vec`s per node — a copy of the operands purely to end the borrow on
        // the pool, and the mapped list — then compared them to decide whether
        // anything had changed. Mapping straight into a reused buffer and
        // tracking the change as it goes does the same work with no
        // per-node allocation and no second pass over the operands.
        let mut new_args: Vec<TermId> = Vec::new();
        for t in order {
            if cache.contains_key(&t) {
                continue;
            }
            let op = self.op(t);
            new_args.clear();
            let mut changed = false;
            for &a in self.args(t) {
                let na = cache[&a];
                changed |= na != a;
                new_args.push(na);
            }
            let new_t = if !changed {
                t
            } else {
                match op {
                    Op::Other {
                        name,
                        index0,
                        index1,
                    } => {
                        let sort = self.sort(t);
                        self.other(name, index0, index1, &new_args, sort)
                    }
                    _ => self.mk(op, &new_args)?,
                }
            };
            cache.insert(t, new_t);
        }
        Ok(roots.iter().map(|r| cache[r]).collect())
    }

    /// Does `haystack` contain any of `needles` as a subterm? Early-exit DFS
    /// with a hash-set visited (cost proportional to the haystack, not the
    /// whole pool).
    pub fn contains_any(&self, haystack: TermId, needles: &impl Fn(TermId) -> bool) -> bool {
        let mut visited: rustc_hash::FxHashSet<TermId> = rustc_hash::FxHashSet::default();
        let mut stack = vec![haystack];
        while let Some(t) = stack.pop() {
            if needles(t) {
                return true;
            }
            if !visited.insert(t) {
                continue;
            }
            stack.extend_from_slice(self.args(t));
        }
        false
    }

    /// Render a term back to SMT-LIB text (primarily for debugging, model
    /// output, and emitting rewrite-soundness queries).
    pub fn display(&self, t: TermId) -> String {
        let mut out = String::new();
        self.write_term(t, &mut out);
        out
    }

    fn write_term(&self, t: TermId, out: &mut String) {
        // Iterative rendering with an explicit work stack (deep terms again).
        enum Item {
            Term(TermId),
            Text(&'static str),
        }
        let mut stack = vec![Item::Term(t)];
        while let Some(item) = stack.pop() {
            match item {
                Item::Text(s) => out.push_str(s),
                Item::Term(t) => {
                    let op = self.op(t);
                    let args = self.args(t);
                    let head: String = match op {
                        Op::True => "true".into(),
                        Op::False => "false".into(),
                        Op::BvConst(id) => self.bv_const(id).to_binary_string(),
                        Op::Var(sym) => self.symbol(sym).name.clone(),
                        Op::Not => "not".into(),
                        Op::Implies => "=>".into(),
                        Op::And => "and".into(),
                        Op::Or => "or".into(),
                        Op::Xor => "xor".into(),
                        Op::Eq => "=".into(),
                        Op::Distinct => "distinct".into(),
                        Op::Ite => "ite".into(),
                        Op::BvNeg => "bvneg".into(),
                        Op::BvAdd => "bvadd".into(),
                        Op::BvSub => "bvsub".into(),
                        Op::BvMul => "bvmul".into(),
                        Op::BvUdiv => "bvudiv".into(),
                        Op::BvUrem => "bvurem".into(),
                        Op::BvSdiv => "bvsdiv".into(),
                        Op::BvSrem => "bvsrem".into(),
                        Op::BvSmod => "bvsmod".into(),
                        Op::BvNot => "bvnot".into(),
                        Op::BvAnd => "bvand".into(),
                        Op::BvOr => "bvor".into(),
                        Op::BvXor => "bvxor".into(),
                        Op::BvNand => "bvnand".into(),
                        Op::BvNor => "bvnor".into(),
                        Op::BvXnor => "bvxnor".into(),
                        Op::BvComp => "bvcomp".into(),
                        Op::BvShl => "bvshl".into(),
                        Op::BvLshr => "bvlshr".into(),
                        Op::BvAshr => "bvashr".into(),
                        Op::Concat => "concat".into(),
                        Op::Extract { hi, lo } => format!("(_ extract {hi} {lo})"),
                        Op::ZeroExtend(n) => format!("(_ zero_extend {n})"),
                        Op::SignExtend(n) => format!("(_ sign_extend {n})"),
                        Op::RotateLeft(n) => format!("(_ rotate_left {n})"),
                        Op::RotateRight(n) => format!("(_ rotate_right {n})"),
                        Op::Repeat(n) => format!("(_ repeat {n})"),
                        Op::BvUlt => "bvult".into(),
                        Op::BvUle => "bvule".into(),
                        Op::BvUgt => "bvugt".into(),
                        Op::BvUge => "bvuge".into(),
                        Op::BvSlt => "bvslt".into(),
                        Op::BvSle => "bvsle".into(),
                        Op::BvSgt => "bvsgt".into(),
                        Op::BvSge => "bvsge".into(),
                        Op::Other { name, .. } => self.symbol(name).name.clone(),
                        Op::RmConst(m) => ["RNE", "RNA", "RTP", "RTN", "RTZ"][m as usize].into(),
                        Op::FpFromBits => "fp".into(),
                        Op::FpNan => "NaN".into(),
                        Op::FpInf(neg) => {
                            if neg {
                                "-oo".into()
                            } else {
                                "+oo".into()
                            }
                        }
                        Op::FpZero(neg) => {
                            if neg {
                                "-zero".into()
                            } else {
                                "+zero".into()
                            }
                        }
                        Op::FpAbs => "fp.abs".into(),
                        Op::FpNeg => "fp.neg".into(),
                        Op::FpAdd => "fp.add".into(),
                        Op::FpSub => "fp.sub".into(),
                        Op::FpMul => "fp.mul".into(),
                        Op::FpDiv => "fp.div".into(),
                        Op::FpSqrt => "fp.sqrt".into(),
                        Op::FpFma => "fp.fma".into(),
                        Op::FpRoundToIntegral => "fp.roundToIntegral".into(),
                        Op::FpRem => "fp.rem".into(),
                        Op::FpMin => "fp.min".into(),
                        Op::FpMax => "fp.max".into(),
                        Op::FpLeq => "fp.leq".into(),
                        Op::FpLt => "fp.lt".into(),
                        Op::FpGeq => "fp.geq".into(),
                        Op::FpGt => "fp.gt".into(),
                        Op::FpEq => "fp.eq".into(),
                        Op::FpIsNormal => "fp.isNormal".into(),
                        Op::FpIsSubnormal => "fp.isSubnormal".into(),
                        Op::FpIsZero => "fp.isZero".into(),
                        Op::FpIsInfinite => "fp.isInfinite".into(),
                        Op::FpIsNan => "fp.isNaN".into(),
                        Op::FpIsNegative => "fp.isNegative".into(),
                        Op::FpIsPositive => "fp.isPositive".into(),
                        Op::FpFromIeeeBv { eb, sb }
                        | Op::FpToFp { eb, sb }
                        | Op::FpFromSignedBv { eb, sb } => format!("(_ to_fp {eb} {sb})"),
                        Op::FpFromUnsignedBv { eb, sb } => {
                            format!("(_ to_fp_unsigned {eb} {sb})")
                        }
                        Op::FpToIeeeBv => "fp.to_ieee_bv".into(),
                        Op::FpToUbv(m) => format!("(_ fp.to_ubv {m})"),
                        Op::FpToSbv(m) => format!("(_ fp.to_sbv {m})"),
                    };
                    if args.is_empty() {
                        out.push_str(&head);
                    } else {
                        out.push('(');
                        out.push_str(&head);
                        stack.push(Item::Text(")"));
                        for &a in args.iter().rev() {
                            stack.push(Item::Term(a));
                            stack.push(Item::Text(" "));
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_consing() {
        let mut p = TermPool::new();
        let x = p.fresh_symbol("x", Sort::BitVec(8));
        let xt = p.var(x);
        let a = p.bv_u64(8, 5);
        let t1 = p.mk(Op::BvAdd, &[xt, a]).unwrap();
        let t2 = p.mk(Op::BvAdd, &[a, xt]).unwrap(); // commutative normalization
        assert_eq!(t1, t2);
        let t3 = p.mk(Op::BvSub, &[xt, a]).unwrap();
        assert_ne!(t1, t3);
        assert_eq!(p.sort(t1), Sort::BitVec(8));
    }

    #[test]
    fn sort_errors() {
        let mut p = TermPool::new();
        let x = p.fresh_symbol("x", Sort::BitVec(8));
        let y = p.fresh_symbol("y", Sort::BitVec(16));
        let (xt, yt) = (p.var(x), p.var(y));
        assert!(p.mk(Op::BvAdd, &[xt, yt]).is_err());
        assert!(p.mk(Op::Extract { hi: 8, lo: 0 }, &[xt]).is_err());
        assert!(p.mk(Op::Extract { hi: 7, lo: 0 }, &[xt]).is_ok());
    }

    #[test]
    fn display_roundtrip_shape() {
        let mut p = TermPool::new();
        let x = p.fresh_symbol("x", Sort::BitVec(4));
        let xt = p.var(x);
        let c = p.bv_u64(4, 3);
        let add = p.mk(Op::BvAdd, &[c, xt]).unwrap();
        let ext = p.mk(Op::Extract { hi: 1, lo: 0 }, &[add]).unwrap();
        // Commutative operands are normalized by TermId order (x interned first).
        assert_eq!(p.display(ext), "((_ extract 1 0) (bvadd x #b0011))");
    }

    /// The invariant the open-addressed hash-cons table exists to preserve:
    /// one id per distinct `(op, args)` and never one id for two of them.
    /// Driven past several table growths, with keys chosen to exercise the
    /// cases a length-blind or arity-blind probe would confuse: same operands
    /// under different operators, same operator over prefixes of one operand
    /// list, and repeated operands.
    #[test]
    fn intern_bijection_across_growth() {
        let mut p = TermPool::new();
        let vars: Vec<TermId> = (0..40)
            .map(|i| {
                let s = p.fresh_symbol(format!("v{i}"), Sort::BitVec(8));
                p.var(s)
            })
            .collect();

        let mut keys: Vec<(Op, Vec<TermId>)> = Vec::new();
        for i in 0..vars.len() {
            for j in 0..vars.len() {
                for op in [Op::BvSub, Op::BvUdiv, Op::BvShl] {
                    keys.push((op, vec![vars[i], vars[j]]));
                }
                // Repeated operand, and a one-operand key over the same head.
                keys.push((Op::BvSub, vec![vars[i], vars[i]]));
                keys.push((Op::BvNot, vec![vars[i]]));
            }
            // Growing arity over a shared prefix: a probe that ignored length
            // would collapse these onto each other.
            for n in 1..=6usize.min(vars.len()) {
                keys.push((Op::Concat, vars[..n].to_vec()));
            }
        }

        let mut seen: FxHashMap<(Op, Vec<TermId>), TermId> = FxHashMap::default();
        for (op, args) in &keys {
            let t = p.mk(*op, args).unwrap();
            // Structurally equal keys must intern to the same id...
            if let Some(&prev) = seen.get(&(*op, args.clone())) {
                assert_eq!(prev, t, "same key interned to two ids: {op:?} {args:?}");
            }
            seen.insert((*op, args.clone()), t);
            // ...and the node the id names must be exactly the key we asked
            // for (this is what rules out a wrong merge).
            assert_eq!(p.op(t), *op);
            assert_eq!(p.args(t), &args[..]);
        }
        // Distinct keys must have distinct ids.
        let ids: std::collections::BTreeSet<TermId> = seen.values().copied().collect();
        assert_eq!(ids.len(), seen.len(), "two distinct keys share an id");
        // The exercise has to have actually grown the table several times.
        assert!(p.intern.slots.len() >= 4096, "table never grew");
        assert_eq!(p.intern.len, p.num_terms());
    }

    /// The whole hash-consing invariant rests on `slot_matches`, since a probe
    /// returns an id only when it says yes. Exercise it directly rather than
    /// through `intern_node`: going through the table, a key that differs only
    /// in arity also hashes differently and so never reaches the comparison,
    /// which would leave the arity check untested by construction.
    #[test]
    fn slot_matches_compares_the_whole_key() {
        let mut p = TermPool::new();
        let vs: Vec<TermId> = (0..3)
            .map(|i| {
                let s = p.fresh_symbol(format!("s{i}"), Sort::BitVec(8));
                p.var(s)
            })
            .collect();
        let cat2 = p.mk(Op::Concat, &[vs[0], vs[1]]).unwrap();
        let ext = p.mk(Op::Extract { hi: 3, lo: 0 }, &[vs[0]]).unwrap();
        let m = |id: TermId, op: Op, args: &[TermId]| {
            TermPool::slot_matches(&p.nodes, &p.args, id.0, op, args)
        };
        assert!(m(cat2, Op::Concat, &[vs[0], vs[1]]));
        // A prefix of the operand list is not the same node, even though the
        // operands it does have all agree.
        assert!(!m(cat2, Op::Concat, &[vs[0]]));
        assert!(!m(cat2, Op::Concat, &[]));
        // Nor is a longer list that starts the same way.
        assert!(!m(cat2, Op::Concat, &[vs[0], vs[1], vs[2]]));
        // Same operands, different operator.
        assert!(!m(cat2, Op::BvAdd, &[vs[0], vs[1]]));
        // Same arity and operator, different operands — and order matters for
        // the non-commutative ops that reach `intern_node` unsorted.
        assert!(!m(cat2, Op::Concat, &[vs[0], vs[2]]));
        assert!(!m(cat2, Op::Concat, &[vs[1], vs[0]]));
        // Indices carried in the operator are part of it.
        assert!(m(ext, Op::Extract { hi: 3, lo: 0 }, &[vs[0]]));
        assert!(!m(ext, Op::Extract { hi: 4, lo: 0 }, &[vs[0]]));
        assert!(!m(ext, Op::Extract { hi: 3, lo: 1 }, &[vs[0]]));
    }

    /// A commutative op with more operands than the inline sort buffer must
    /// normalize exactly like one that fits it.
    #[test]
    fn commutative_normalization_past_the_inline_buffer() {
        let mut p = TermPool::new();
        let vars: Vec<TermId> = (0..12)
            .map(|i| {
                let s = p.fresh_symbol(format!("b{i}"), Sort::Bool);
                p.var(s)
            })
            .collect();
        for n in [2usize, 8, 9, 12] {
            let fwd: Vec<TermId> = vars[..n].to_vec();
            let rev: Vec<TermId> = fwd.iter().rev().copied().collect();
            let a = p.mk(Op::And, &fwd).unwrap();
            let b = p.mk(Op::And, &rev).unwrap();
            assert_eq!(a, b, "operand order leaked at arity {n}");
            let mut want = fwd.clone();
            want.sort_unstable();
            assert_eq!(p.args(a), &want[..], "not sorted at arity {n}");
        }
    }

    /// `post_order` parks and reuses one stamp buffer. Repeated calls must
    /// stay independent, growth of the pool between calls must be picked up,
    /// and a traversal started from inside a traversal's callback must not
    /// disturb the outer one.
    #[test]
    fn post_order_reused_scratch_is_independent() {
        let mut p = TermPool::new();
        let x = p.fresh_symbol("x", Sort::BitVec(8));
        let xt = p.var(x);
        let c = p.bv_u64(8, 7);
        let add = p.mk(Op::BvAdd, &[xt, c]).unwrap();
        let mul = p.mk(Op::BvMul, &[add, xt]).unwrap();

        let collect = |p: &TermPool, root: TermId| {
            let mut v = Vec::new();
            p.post_order(&[root], |_, t| v.push(t));
            v
        };
        let first = collect(&p, mul);
        // Same roots twice in a row: stale stamps from call 1 must not make
        // call 2 skip anything.
        assert_eq!(first, collect(&p, mul));
        // Children before parents, each node once.
        assert_eq!(*first.last().unwrap(), mul);
        let mut sorted = first.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), first.len());

        // Terms built after the buffer was sized must still be stampable.
        let sub = p.mk(Op::BvSub, &[mul, c]).unwrap();
        let after = collect(&p, sub);
        assert_eq!(after.len(), first.len() + 1);
        assert_eq!(*after.last().unwrap(), sub);

        // Nested traversal from inside the callback.
        let mut outer = Vec::new();
        let mut inner_total = 0usize;
        p.post_order(&[sub], |pool, t| {
            outer.push(t);
            pool.post_order(&[t], |_, _| inner_total += 1);
        });
        assert_eq!(outer, after, "nested traversal disturbed the outer one");
        assert!(inner_total >= after.len());

        // And the outer traversal is still repeatable afterwards.
        assert_eq!(collect(&p, sub), after);
    }

    /// `post_order_memo` is the traversal a *sequence* of related evaluations
    /// shares. Its whole contract is what it leaves out, so the properties to
    /// pin are: the union over a sequence emits every reachable node exactly
    /// once; the emission order is still children-before-parents *within what
    /// is emitted*; and a fresh map reproduces `post_order` exactly.
    #[test]
    fn post_order_memo_emits_each_node_once_across_a_sequence() {
        let mut p = TermPool::new();
        let x = p.fresh_symbol("x", Sort::BitVec(8));
        let xt = p.var(x);
        let y = p.fresh_symbol("y", Sort::BitVec(8));
        let yt = p.var(y);
        let c = p.bv_u64(8, 7);
        // A chain whose cones nest, which is the model-reconstruction shape.
        let a1 = p.mk(Op::BvAdd, &[xt, c]).unwrap();
        let a2 = p.mk(Op::BvMul, &[a1, yt]).unwrap();
        let a3 = p.mk(Op::BvSub, &[a2, a1]).unwrap();

        // A fresh map must reproduce `post_order` exactly.
        let mut plain = Vec::new();
        p.post_order(&[a3], |_, t| plain.push(t));
        let mut seen = Vec::new();
        let mut memo = Vec::new();
        p.post_order_memo(&mut seen, &[a3], |_, t| memo.push(t));
        assert_eq!(plain, memo, "a fresh memo is not a plain post_order");

        // Threading one map over the chain: the union is the same set, with no
        // node emitted twice even though the cones overlap almost entirely.
        let mut seen = Vec::new();
        let mut all = Vec::new();
        for root in [a1, a2, a3] {
            let mut here = Vec::new();
            p.post_order_memo(&mut seen, &[root], |_, t| here.push(t));
            // Children before parents among the newly emitted nodes.
            for (i, &t) in here.iter().enumerate() {
                for &arg in p.args(t) {
                    if let Some(j) = here.iter().position(|&u| u == arg) {
                        assert!(j < i, "operand emitted after its parent");
                    }
                }
            }
            all.extend(here);
        }
        let mut sorted = all.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), all.len(), "a node was emitted twice");
        assert_eq!(sorted, {
            let mut want = plain.clone();
            want.sort_unstable();
            want
        });

        // Re-running a root whose cone is fully marked emits nothing at all —
        // that is the saving, stated as a property rather than as a timing.
        let mut again = 0usize;
        p.post_order_memo(&mut seen, &[a3], |_, _| again += 1);
        assert_eq!(again, 0);

        // Nodes created after the map was sized are still reachable.
        let a4 = p.mk(Op::BvXor, &[a3, c]).unwrap();
        let mut fresh = Vec::new();
        p.post_order_memo(&mut seen, &[a4], |_, t| fresh.push(t));
        assert_eq!(fresh, vec![a4]);
    }

    /// `substitute_many` decides whether to rebuild a node from an
    /// incrementally tracked flag rather than by comparing the mapped operand
    /// list against the original. The two must agree: unchanged subterms keep
    /// their id (that is what makes substitution cheap and sharing-preserving),
    /// changed ones rebuild, and the substitution stays simultaneous —
    /// replacements are not themselves re-substituted.
    #[test]
    fn substitute_rebuilds_exactly_the_changed_subterms() {
        let mut p = TermPool::new();
        let mk_var = |p: &mut TermPool, n: &str| {
            let s = p.fresh_symbol(n, Sort::BitVec(8));
            p.var(s)
        };
        let (x, y, z) = (
            mk_var(&mut p, "x"),
            mk_var(&mut p, "y"),
            mk_var(&mut p, "z"),
        );
        let untouched = p.mk(Op::BvSub, &[y, z]).unwrap();
        let touched = p.mk(Op::BvSub, &[x, z]).unwrap();
        let root = p.mk(Op::BvMul, &[untouched, touched]).unwrap();

        let mut map = FxHashMap::default();
        map.insert(x, y);
        let out = p.substitute(root, &map).unwrap();

        // The x-free side keeps its identity; the x-bearing side is rebuilt.
        assert_eq!(p.args(out)[0], untouched);
        let rebuilt = p.args(out)[1];
        assert_ne!(rebuilt, touched);
        assert_eq!(p.args(rebuilt), &[y, z]);

        // Simultaneous, not iterated: mapping x->y and y->z at once must not
        // carry x all the way to z.
        let mut chain = FxHashMap::default();
        chain.insert(x, y);
        chain.insert(y, z);
        let sub = p.substitute(touched, &chain).unwrap();
        assert_eq!(p.args(sub), &[y, z]);

        // A root that is itself a key maps directly, and an empty map is the
        // identity on every root.
        assert_eq!(p.substitute(x, &map).unwrap(), y);
        let empty = FxHashMap::default();
        assert_eq!(
            p.substitute_many(&[root, x, y], &empty).unwrap(),
            vec![root, x, y]
        );
        // Nothing in the map at all reachable from the root: identity, and no
        // new terms invented.
        let before = p.num_terms();
        let mut unrelated = FxHashMap::default();
        unrelated.insert(z, x);
        let _ = p.substitute(untouched, &map).unwrap();
        assert_eq!(p.substitute(untouched, &map).unwrap(), untouched);
        assert_eq!(p.num_terms(), before);
        let _ = unrelated;
    }

    /// The stamp buffer must survive the epoch counter wrapping.
    #[test]
    fn post_order_survives_epoch_wrap() {
        let mut p = TermPool::new();
        let x = p.fresh_symbol("x", Sort::BitVec(8));
        let xt = p.var(x);
        let c = p.bv_u64(8, 3);
        let add = p.mk(Op::BvAdd, &[xt, c]).unwrap();
        let mut want = Vec::new();
        p.post_order(&[add], |_, t| want.push(t));

        // Force the parked buffer to the last epoch before the wrap, and set
        // every stamp to the value the epoch restarts at. Only clearing the
        // buffer on the wrap keeps those stamps from reading as "already
        // visited" and swallowing the whole traversal.
        let mut tr = p.traversal.take().unwrap();
        tr.epoch = u32::MAX;
        tr.stamp.fill(1);
        p.traversal.set(Some(tr));

        let mut got = Vec::new();
        p.post_order(&[add], |_, t| got.push(t));
        assert_eq!(got, want, "wrap lost the traversal");
        let mut again = Vec::new();
        p.post_order(&[add], |_, t| again.push(t));
        assert_eq!(again, want, "traversal after the wrap was not independent");
    }
}
