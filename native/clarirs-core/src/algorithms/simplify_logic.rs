//! Two-level minimization of boolean structure.
//!
//! [`AstNode::simplify_logic`] treats every node that is not an `And`, `Or` or
//! `Not` as an opaque predicate, computes the truth table of the expression
//! over those predicates and rebuilds it as a minimal sum of products or
//! product of sums using the Quine-McCluskey algorithm.
//!
//! The algorithm, its heuristics and the order in which it emits operands
//! follow `sympy.simplify_logic(expr, deep=False)`, so it produces the same
//! expressions sympy does.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::Arc;

use crate::prelude::*;

/// A term of the minimization: one entry per variable, `0` or `1` for a
/// literal of that polarity and [`DONT_CARE`] for a variable the term does not
/// mention.
type Term = Vec<u8>;

const DONT_CARE: u8 = 3;

impl<'c> AstNode<'c> {
    /// Simplifies the boolean structure of this expression.
    ///
    /// Every subexpression that is not an `And`, `Or` or `Not` is a predicate.
    /// A comparison and its negation count as the same predicate: `a != b`,
    /// `a >u b`, `a >=u b`, `a >s b` and `a >=s b` are read as the negation
    /// of `a == b`, `a <=u b`, `a <u b`, `a <=s b` and `a <s b`.
    ///
    /// When the expression has at most `max_predicates` distinct predicates it
    /// is rewritten as a minimal sum of products or product of sums,
    /// whichever the truth table suggests is smaller. Otherwise only the
    /// boolean structure is normalized: nested operations are flattened, and
    /// duplicate operands, double negations and constants are removed.
    ///
    /// Operands are ordered by size, then by kind, then by the order in which
    /// their predicates first appear in this expression, so the result does
    /// not depend on the hashes of the predicates. Every node of the result is
    /// built through the context and simplified.
    pub fn simplify_logic(
        self: &Arc<Self>,
        max_predicates: usize,
    ) -> Result<AstRef<'c>, ClarirsError> {
        if !self.ast_type().is_bool() {
            return Err(ClarirsError::TypeError(
                "simplify_logic expects a boolean expression".to_string(),
            ));
        }
        let ctx = self.context();
        let mut predicates = Predicates::default();
        let expr = predicates.read(self)?;
        if !matches!(expr, Expr::Not(_) | Expr::And(_) | Expr::Or(_)) {
            return predicates.build(ctx, &expr);
        }

        let mut variables = Vec::new();
        expr.collect_vars(&mut variables);
        variables.sort_unstable();
        variables.dedup();
        if variables.len() > max_predicates {
            return predicates.build(ctx, &expr);
        }

        // Minterms in ascending order, with the first variable as the most
        // significant bit.
        let n = variables.len();
        let mut values = vec![false; predicates.len()];
        let mut minterms = Vec::new();
        for row in 0..1usize << n {
            for (i, &var) in variables.iter().enumerate() {
                values[var] = (row >> (n - 1 - i)) & 1 == 1;
            }
            if expr.eval(&values) {
                minterms.push(to_term(row, n));
            }
        }

        // A function that is true on at least half of its rows is written as a
        // sum of products, any other as a product of sums.
        let simplified = if 2 * minterms.len() >= 1 << n {
            sop_form(&variables, &minterms)
        } else {
            pos_form(&variables, &minterms)
        };
        predicates.build(ctx, &simplified)
    }
}

fn to_term(row: usize, n: usize) -> Term {
    (0..n).map(|i| ((row >> (n - 1 - i)) & 1) as u8).collect()
}

/// The predicates of an expression, numbered in the order they are first
/// encountered.
#[derive(Default)]
struct Predicates<'c> {
    asts: Vec<AstRef<'c>>,
    index: HashMap<u64, usize>,
}

impl<'c> Predicates<'c> {
    fn len(&self) -> usize {
        self.asts.len()
    }

    fn read(&mut self, ast: &AstRef<'c>) -> Result<Expr, ClarirsError> {
        let ctx = ast.context();
        let negated = match ast.op() {
            AstOp::Not(arg) => return Ok(Expr::not(self.read(arg)?)),
            AstOp::And(args) => {
                return Ok(Expr::and(
                    args.iter()
                        .map(|arg| self.read(arg))
                        .collect::<Result<_, _>>()?,
                ));
            }
            AstOp::Or(args) => {
                return Ok(Expr::or(
                    args.iter()
                        .map(|arg| self.read(arg))
                        .collect::<Result<_, _>>()?,
                ));
            }
            AstOp::BoolV(value) => return Ok(Expr::Const(*value)),
            AstOp::Neq(a, b) if !a.ast_type().is_float() => Some(ctx.eq_(a, b)?),
            AstOp::UGT(a, b) => Some(ctx.ule(a, b)?),
            AstOp::UGE(a, b) => Some(ctx.ult(a, b)?),
            AstOp::SGT(a, b) => Some(ctx.sle(a, b)?),
            AstOp::SGE(a, b) => Some(ctx.slt(a, b)?),
            _ => None,
        };
        if let Some(negated) = negated {
            return Ok(Expr::not(self.read(&negated.simplify()?)?));
        }

        let next = self.asts.len();
        let var = *self.index.entry(ast.hash()).or_insert(next);
        if var == next {
            self.asts.push(ast.clone());
        }
        Ok(Expr::Var(var))
    }

    fn build(&self, ctx: &'c Context<'c>, expr: &Expr) -> Result<AstRef<'c>, ClarirsError> {
        let build_all = |args: &[Expr]| {
            args.iter()
                .map(|arg| self.build(ctx, arg))
                .collect::<Result<Vec<_>, _>>()
        };
        match expr {
            Expr::Var(var) => Ok(self.asts[*var].clone()),
            Expr::Const(value) => ctx.boolv(*value),
            Expr::Not(arg) => ctx.not(self.build(ctx, arg)?)?.simplify(),
            Expr::And(args) => ctx.and(build_all(args)?)?.simplify(),
            Expr::Or(args) => ctx.or(build_all(args)?)?.simplify(),
        }
    }
}

/// A boolean expression over numbered predicates. The constructors normalize
/// the way sympy's do: `And`/`Or` are flattened, drop their identity, collapse
/// to their absorbing element, drop duplicate operands and sort the rest;
/// `Not` cancels double negation and folds constants.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Expr {
    Var(usize),
    Const(bool),
    Not(Box<Expr>),
    And(Vec<Expr>),
    Or(Vec<Expr>),
}

impl Expr {
    fn not(arg: Expr) -> Expr {
        match arg {
            Expr::Const(value) => Expr::Const(!value),
            Expr::Not(inner) => *inner,
            arg => Expr::Not(Box::new(arg)),
        }
    }

    fn and(args: Vec<Expr>) -> Expr {
        Self::lattice(args, true)
    }

    fn or(args: Vec<Expr>) -> Expr {
        Self::lattice(args, false)
    }

    /// Builds an `And` (`is_and`) or an `Or`, whose identity is `is_and` and
    /// whose absorbing element is `!is_and`.
    fn lattice(args: Vec<Expr>, is_and: bool) -> Expr {
        let mut flat = Vec::with_capacity(args.len());
        for arg in args {
            match arg {
                Expr::Const(value) if value == is_and => {}
                Expr::Const(value) => return Expr::Const(value),
                Expr::And(inner) if is_and => flat.extend(inner),
                Expr::Or(inner) if !is_and => flat.extend(inner),
                arg => flat.push(arg),
            }
        }
        flat.sort_by(Expr::ordered);
        flat.dedup();
        match flat.len() {
            0 => Expr::Const(is_and),
            1 => flat.pop().unwrap(),
            _ if is_and => Expr::And(flat),
            _ => Expr::Or(flat),
        }
    }

    fn eval(&self, values: &[bool]) -> bool {
        match self {
            Expr::Var(var) => values[*var],
            Expr::Const(value) => *value,
            Expr::Not(arg) => !arg.eval(values),
            Expr::And(args) => args.iter().all(|arg| arg.eval(values)),
            Expr::Or(args) => args.iter().any(|arg| arg.eval(values)),
        }
    }

    fn collect_vars(&self, vars: &mut Vec<usize>) {
        match self {
            Expr::Var(var) => vars.push(*var),
            Expr::Const(_) => {}
            Expr::Not(arg) => arg.collect_vars(vars),
            Expr::And(args) | Expr::Or(args) => {
                args.iter().for_each(|arg| arg.collect_vars(vars));
            }
        }
    }

    fn node_count(&self) -> usize {
        match self {
            Expr::Var(_) | Expr::Const(_) => 1,
            Expr::Not(arg) => 1 + arg.node_count(),
            Expr::And(args) | Expr::Or(args) => {
                1 + args.iter().map(Expr::node_count).sum::<usize>()
            }
        }
    }

    /// sympy's `ordered`: smaller expressions first, ties broken by
    /// [`Expr::sort_key`].
    fn ordered(a: &Expr, b: &Expr) -> Ordering {
        a.node_count()
            .cmp(&b.node_count())
            .then_with(|| Expr::sort_key(a, b))
    }

    /// sympy's `default_sort_key`: by class (symbols, then `And`, `Not`,
    /// `Or`), then by name for symbols, else by operand count and then by the
    /// operands in their stored order.
    fn sort_key(a: &Expr, b: &Expr) -> Ordering {
        fn rank(e: &Expr) -> u8 {
            match e {
                Expr::Const(_) => 0,
                Expr::Var(_) => 1,
                Expr::And(_) => 2,
                Expr::Not(_) => 3,
                Expr::Or(_) => 4,
            }
        }
        fn args(e: &Expr) -> &[Expr] {
            match e {
                Expr::Not(arg) => std::slice::from_ref(arg),
                Expr::And(args) | Expr::Or(args) => args,
                Expr::Var(_) | Expr::Const(_) => &[],
            }
        }
        rank(a).cmp(&rank(b)).then_with(|| match (a, b) {
            (Expr::Var(x), Expr::Var(y)) => x.cmp(y),
            (Expr::Const(x), Expr::Const(y)) => x.cmp(y),
            _ => {
                let (a, b) = (args(a), args(b));
                a.len().cmp(&b.len()).then_with(|| {
                    a.iter()
                        .zip(b)
                        .map(|(x, y)| Expr::sort_key(x, y))
                        .find(|o| o.is_ne())
                        .unwrap_or(Ordering::Equal)
                })
            }
        })
    }
}

/// The minimal sum of products covering `minterms`.
fn sop_form(variables: &[usize], minterms: &[Term]) -> Expr {
    let primes = simplified_pairs(minterms.to_vec());
    let essential = rem_redundancy(&primes, minterms);
    Expr::or(
        essential
            .iter()
            .map(|term| {
                Expr::and(
                    literals(variables, term)
                        .map(|(var, value)| literal(var, value == 1))
                        .collect(),
                )
            })
            .collect(),
    )
}

/// The minimal product of sums excluding every row not in `minterms`.
fn pos_form(variables: &[usize], minterms: &[Term]) -> Expr {
    if minterms.is_empty() {
        return Expr::Const(false);
    }
    let n = variables.len();
    let maxterms = (0..1usize << n)
        .map(|row| to_term(row, n))
        .filter(|term| !minterms.contains(term))
        .collect::<Vec<_>>();
    let primes = simplified_pairs(maxterms.clone());
    let essential = rem_redundancy(&primes, &maxterms);
    Expr::and(
        essential
            .iter()
            .map(|term| {
                Expr::or(
                    literals(variables, term)
                        .map(|(var, value)| literal(var, value == 0))
                        .collect(),
                )
            })
            .collect(),
    )
}

fn literals<'a>(variables: &'a [usize], term: &'a Term) -> impl Iterator<Item = (usize, u8)> + 'a {
    variables
        .iter()
        .zip(term)
        .filter(|&(_, &value)| value != DONT_CARE)
        .map(|(&var, &value)| (var, value))
}

fn literal(var: usize, positive: bool) -> Expr {
    if positive {
        Expr::Var(var)
    } else {
        Expr::not(Expr::Var(var))
    }
}

/// The index of the only position at which `a` and `b` differ, if there is
/// exactly one.
fn check_pair(a: &Term, b: &Term) -> Option<usize> {
    let mut index = None;
    for (i, (x, y)) in a.iter().zip(b).enumerate() {
        if x != y {
            if index.is_some() {
                return None;
            }
            index = Some(i);
        }
    }
    index
}

/// The prime implicants of `terms`: repeatedly merges pairs of terms that
/// differ in a single position.
fn simplified_pairs(terms: Vec<Term>) -> Vec<Term> {
    let Some(width) = terms.first().map(Vec::len) else {
        return terms;
    };
    let mut by_ones = vec![Vec::new(); width + 2];
    for (i, term) in terms.iter().enumerate() {
        by_ones[term.iter().filter(|&&t| t == 1).count()].push(i);
    }

    let mut merged = Vec::new();
    let mut used = vec![false; terms.len()];
    for k in 0..width {
        for &i in &by_ones[k] {
            for &j in &by_ones[k + 1] {
                if let Some(index) = check_pair(&terms[i], &terms[j]) {
                    used[i] = true;
                    used[j] = true;
                    let mut term = terms[i].clone();
                    term[index] = DONT_CARE;
                    if !merged.contains(&term) {
                        merged.push(term);
                    }
                }
            }
        }
    }

    let mut result = if merged.is_empty() {
        merged
    } else {
        simplified_pairs(merged)
    };
    result.extend(
        terms
            .into_iter()
            .zip(used)
            .filter(|(_, used)| !used)
            .map(|(term, _)| term),
    );
    result
}

/// Selects the prime implicants (`primes`) needed to cover `terms`, by
/// eliminating dominated rows and columns of the covering matrix and, when
/// that stalls, greedily picking the implicant covering the most terms.
fn rem_redundancy(primes: &[Term], terms: &[Term]) -> Vec<Term> {
    if terms.is_empty() {
        return Vec::new();
    }
    let nterms = terms.len();
    let nprimes = primes.len();

    let mut dom = vec![vec![false; nprimes]; nterms];
    let mut colcount = vec![0usize; nprimes];
    let mut rowcount = vec![0usize; nterms];
    for (p, prime) in primes.iter().enumerate() {
        for (t, term) in terms.iter().enumerate() {
            if prime
                .iter()
                .zip(term)
                .all(|(&x, &y)| x == DONT_CARE || x == y)
            {
                dom[t][p] = true;
                colcount[p] += 1;
                rowcount[t] += 1;
            }
        }
    }

    let mut changed = true;
    while changed {
        changed = false;

        // A term whose covering implicants include all of another term's is
        // covered whenever that term is: drop it.
        for r in 0..nterms {
            if rowcount[r] == 0 {
                continue;
            }
            for r2 in 0..nterms {
                if r != r2
                    && rowcount[r] != 0
                    && rowcount[r] <= rowcount[r2]
                    && (0..nprimes).all(|p| dom[r2][p] >= dom[r][p])
                {
                    rowcount[r2] = 0;
                    changed = true;
                    for p in 0..nprimes {
                        if dom[r2][p] {
                            dom[r2][p] = false;
                            colcount[p] -= 1;
                        }
                    }
                }
            }
        }

        // An implicant covering a subset of another's terms is not needed.
        // Columns are snapshotted on first use in each round.
        let mut colcache: Vec<Option<Vec<bool>>> = vec![None; nprimes];
        let column = |dom: &[Vec<bool>], p: usize| (0..nterms).map(|t| dom[t][p]).collect();
        for c in 0..nprimes {
            if colcount[c] == 0 {
                continue;
            }
            if colcache[c].is_none() {
                colcache[c] = Some(column(&dom, c));
            }
            for c2 in 0..nprimes {
                if c != c2 && colcount[c2] != 0 && colcount[c] >= colcount[c2] {
                    if colcache[c2].is_none() {
                        colcache[c2] = Some(column(&dom, c2));
                    }
                    let (col, col2) = (
                        colcache[c].as_ref().unwrap(),
                        colcache[c2].as_ref().unwrap(),
                    );
                    if (0..nterms).all(|t| col[t] >= col2[t]) {
                        colcount[c2] = 0;
                        changed = true;
                        for t in 0..nterms {
                            if col2[t] && dom[t][c2] {
                                dom[t][c2] = false;
                                rowcount[t] -= 1;
                            }
                        }
                    }
                }
            }
        }

        if !changed {
            // Commit to the implicant covering the most terms, if it covers
            // at least two.
            let mut best = None;
            let mut most = 0;
            for (c, &count) in colcount.iter().enumerate() {
                if count > most {
                    best = Some(c);
                    most = count;
                }
            }
            if let Some(best) = best.filter(|_| most > 1) {
                let col = colcache[best].clone().unwrap_or_else(|| column(&dom, best));
                for p in (0..nprimes).filter(|&p| p != best) {
                    for t in 0..nterms {
                        if col[t] && dom[t][p] {
                            dom[t][p] = false;
                            changed = true;
                            rowcount[t] -= 1;
                            colcount[p] -= 1;
                        }
                    }
                }
            }
        }
    }

    primes
        .iter()
        .zip(colcount)
        .filter(|(_, count)| *count != 0)
        .map(|(prime, _)| prime.clone())
        .collect()
}

#[cfg(test)]
mod tests;
