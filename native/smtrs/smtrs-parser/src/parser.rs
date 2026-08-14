//! SMT-LIB 2.6 script parser building terms directly into a `TermPool`.
//!
//! Bool, QF_BV and every floating-point construct parse into their own `Op`
//! variants. String, regex, Int and UF terms become `Op::Other` nodes with
//! sorts inferred from the head symbol; `smtrs-str` lowers most of those away
//! later. Constructs we cannot represent at all (arrays, `fp.to_real`)
//! produce `ParseError::Unsupported`, which the CLI reports as `unknown`
//! rather than a hard failure.
//!
//! The parser is the trust boundary: widths, arities, indices and nesting
//! depth all come from the input, and `TermPool::check` cannot validate the
//! arity of an `Op::Other` head. Everything rejected here is something a
//! later pass would otherwise index, allocate or recurse on unguarded.

use crate::lexer::{LexError, Lexer, Token};
use rustc_hash::FxHashMap;
use smtrs_core::{
    BvConst, Op, Sort, SortError, SymbolId, TermId, TermPool, MAX_BV_WIDTH, MAX_FP_EXP_WIDTH,
    MAX_FP_SIG_WIDTH,
};

#[derive(Debug)]
pub enum Command {
    SetLogic(String),
    /// `(set-info :status sat)` etc. — only :status is retained.
    SetStatus(String),
    /// `(set-option :key value)`. Only options the engine acts on are emitted;
    /// the rest are still consumed and dropped.
    SetOption(String, String),
    /// The asserted formula, plus the name of a **top-level** `:named`
    /// annotation (`(assert (! phi :named n))`) if there was one.
    ///
    /// Only the top level counts: SMT-LIB's unsat cores name asserted
    /// formulas, and an annotation buried inside one names a subterm, which is
    /// not something `get-unsat-core` may return. Nested `:named` annotations
    /// still land in [`Script::named`], which is what makes them usable as
    /// abbreviations in later terms.
    Assert(TermId, Option<String>),
    CheckSat,
    CheckSatAssuming(Vec<TermId>),
    GetModel,
    GetValue(Vec<TermId>),
    /// Nonstandard OMT-style extension: unsigned optimum of a BV term.
    Minimize(TermId),
    Maximize(TermId),
    GetUnsatCore,
    Push(u32),
    Pop(u32),
    Echo(String),
    Reset,
    Exit,
}

#[derive(Debug)]
pub enum ParseError {
    Syntax {
        line: usize,
        col: usize,
        message: String,
    },
    /// The script uses features outside the supported fragment (arrays,
    /// quantifiers, unknown sorts...). The file is well-formed SMT-LIB as far
    /// as we can tell; we just cannot represent it.
    Unsupported(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Syntax { line, col, message } => {
                write!(f, "syntax error at {line}:{col}: {message}")
            }
            ParseError::Unsupported(m) => write!(f, "unsupported: {m}"),
        }
    }
}

impl std::error::Error for ParseError {}

/// A name in scope: a bound term (let/named/0-ary define-fun/declared const)
/// or a function (declare-fun with arguments / define-fun with parameters).
#[derive(Clone)]
enum Binding {
    Term(TermId),
    DeclaredFun {
        sym: SymbolId,
        params: Vec<Sort>,
        ret: Sort,
    },
    DefinedFun {
        params: Vec<TermId>,
        body: TermId,
    },
}

pub struct Parser<'a> {
    lexer: Lexer<'a>,
    pool: &'a mut TermPool,
    /// Scoped name resolution: name -> stack of bindings (innermost last).
    scopes: FxHashMap<&'a str, Vec<Binding>>,
    /// Names bound per let-scope so we can pop them.
    scope_stack: Vec<Vec<&'a str>>,
    /// Every `:named` annotation seen, at any depth. Also bound as a term
    /// abbreviation, so `(check-sat-assuming (n))` resolves.
    pub named: Vec<(String, TermId)>,
    /// Name from a `:named` annotation applied to the whole term of the
    /// `assert` currently being parsed (depth 1 — see [`Command::Assert`]).
    /// Consumed and cleared by the `assert` command.
    top_named: Option<String>,
    /// 0-ary declared constants, in declaration order (for get-model).
    pub declared: Vec<SymbolId>,
    /// Interned theory symbols and literals: identical occurrences must map
    /// to the same SymbolId or hash-consing (and term equality) breaks.
    interned: FxHashMap<(String, Sort), SymbolId>,
    /// `(define-sort Name () <sort>)` aliases (0-ary only).
    sort_aliases: FxHashMap<String, Sort>,
    /// Current `parse_term` nesting depth; see [`MAX_TERM_DEPTH`].
    depth: u32,
}

/// Nesting limit for the recursive-descent term parser.
///
/// `parse_term` recurses through `parse_term_after_lparen` and `parse_args`,
/// so nesting depth in the *input* is stack depth in the parser, and a ~1 MB
/// file of nested `(not ...)` overflows the stack. That is not recoverable:
/// a stack overflow aborts the process, so the CLI's catch-the-panic wrapper
/// never runs and the run dies with no diagnostic. The rest of the pipeline
/// is already iterative for exactly this reason (`TermPool::post_order`,
/// `write_term`); the parser was the gap.
///
/// The limit is set from a scan of the whole corpus, not a sample: across all
/// 189_686 benchmark files the deepest term is **17_100** parens
/// (`QF_BV/sage/app7/bench_1669.smt2`; the whole sage/app7 family sits above
/// 12_000). A 400-file sample said 3_350 and a limit chosen from it rejected
/// four valid benchmarks, so the number below is deliberately ~6x the true
/// maximum.
///
/// There is a wide safe window to aim at: real input needs ~17k frames and
/// overflowing `smtrs-cli`'s 1 GiB stack takes millions, so anything in the
/// 10^5..10^6 range both accepts every real benchmark and stops the
/// unbounded case. Note this bounds recursion; it does not promise any stack
/// will do — the caller still has to provide one that reaches the limit,
/// which is why the CLI runs the pipeline on a 1 GiB thread.
const MAX_TERM_DEPTH: u32 = 100_000;

/// Cap on `(_ re.loop lo hi)` / `(_ re.^ n)` repetition counts. Each unit
/// materialises a copy of the inner NFA, so the bound is an allocation size
/// taken straight from the input.
const MAX_REGEX_REPEAT: u32 = 4096;

type PResult<T> = Result<T, ParseError>;

impl<'a> Parser<'a> {
    pub fn new(input: &'a str, pool: &'a mut TermPool) -> Self {
        Parser {
            lexer: Lexer::new(input),
            pool,
            scopes: FxHashMap::default(),
            scope_stack: Vec::new(),
            named: Vec::new(),
            top_named: None,
            declared: Vec::new(),
            interned: FxHashMap::default(),
            sort_aliases: FxHashMap::default(),
            depth: 0,
        }
    }

    fn intern_symbol(&mut self, name: &str, sort: Sort) -> SymbolId {
        if let Some(&sym) = self.interned.get(&(name.to_string(), sort)) {
            return sym;
        }
        let sym = self.pool.fresh_symbol(name, sort);
        self.interned.insert((name.to_string(), sort), sym);
        sym
    }

    fn syntax(&self, pos: usize, message: impl Into<String>) -> ParseError {
        let (line, col) = self.lexer.line_col(pos);
        ParseError::Syntax {
            line,
            col,
            message: message.into(),
        }
    }

    fn sort_err(&self, e: SortError) -> ParseError {
        let (line, col) = self.lexer.line_col(self.lexer.pos());
        ParseError::Syntax {
            line,
            col,
            message: e.to_string(),
        }
    }

    fn next(&mut self) -> PResult<Option<Token<'a>>> {
        self.lexer
            .next_token()
            .map_err(|e: LexError| self.syntax_at(e.pos, e.message))
    }

    fn syntax_at(&self, pos: usize, message: String) -> ParseError {
        let (line, col) = self.lexer.line_col(pos);
        ParseError::Syntax { line, col, message }
    }

    fn expect(&mut self) -> PResult<Token<'a>> {
        let pos = self.lexer.pos();
        self.next()?
            .ok_or_else(|| self.syntax(pos, "unexpected end of input"))
    }

    fn expect_lparen(&mut self) -> PResult<()> {
        let pos = self.lexer.pos();
        match self.expect()? {
            Token::LParen => Ok(()),
            t => Err(self.syntax(pos, format!("expected '(', got {t:?}"))),
        }
    }

    fn expect_rparen(&mut self) -> PResult<()> {
        let pos = self.lexer.pos();
        match self.expect()? {
            Token::RParen => Ok(()),
            t => Err(self.syntax(pos, format!("expected ')', got {t:?}"))),
        }
    }

    fn expect_symbol(&mut self) -> PResult<&'a str> {
        let pos = self.lexer.pos();
        match self.expect()? {
            Token::Symbol(s) => Ok(s),
            t => Err(self.syntax(pos, format!("expected symbol, got {t:?}"))),
        }
    }

    fn expect_numeral_u32(&mut self) -> PResult<u32> {
        let pos = self.lexer.pos();
        match self.expect()? {
            Token::Numeral(n) => n
                .parse::<u32>()
                .map_err(|_| self.syntax(pos, format!("numeral out of range: {n}"))),
            t => Err(self.syntax(pos, format!("expected numeral, got {t:?}"))),
        }
    }

    /// Skip one complete s-expression (attribute values, unsupported info).
    fn skip_sexpr(&mut self) -> PResult<()> {
        let pos = self.lexer.pos();
        match self.expect()? {
            Token::LParen => {
                let mut depth = 1usize;
                while depth > 0 {
                    match self.expect()? {
                        Token::LParen => depth += 1,
                        Token::RParen => depth -= 1,
                        _ => {}
                    }
                }
                Ok(())
            }
            Token::RParen => Err(self.syntax(pos, "unexpected ')'")),
            _ => Ok(()),
        }
    }

    /// Parse the next command; None at end of input.
    pub fn next_command(&mut self) -> PResult<Option<Command>> {
        loop {
            match self.next()? {
                None => return Ok(None),
                Some(Token::LParen) => {}
                Some(t) => {
                    let pos = self.lexer.pos();
                    return Err(self.syntax(pos, format!("expected '(', got {t:?}")));
                }
            }
            let name = self.expect_symbol()?;
            match name {
                "set-logic" => {
                    let logic = self.expect_symbol()?.to_string();
                    self.expect_rparen()?;
                    return Ok(Some(Command::SetLogic(logic)));
                }
                "set-info" => {
                    let pos = self.lexer.pos();
                    let kw = match self.expect()? {
                        Token::Keyword(k) => k,
                        t => return Err(self.syntax(pos, format!("expected keyword, got {t:?}"))),
                    };
                    if kw == "status" {
                        let status = self.expect_symbol()?.to_string();
                        self.expect_rparen()?;
                        return Ok(Some(Command::SetStatus(status)));
                    }
                    self.skip_sexpr()?;
                    self.expect_rparen()?;
                }
                "set-option" => {
                    // (set-option :kw value). The value is captured but only
                    // the options the engine acts on become a command; the
                    // rest are consumed and dropped, as before.
                    let pos = self.lexer.pos();
                    let key = match self.expect()? {
                        Token::Keyword(k) => k.to_string(),
                        t => return Err(self.syntax(pos, format!("expected keyword, got {t:?}"))),
                    };
                    let mut value: Option<String> = None;
                    // Value is optional for boolean-ish options in the wild.
                    loop {
                        let save = self.lexer.pos();
                        match self.expect()? {
                            Token::RParen => break,
                            Token::LParen => {
                                let mut depth = 1usize;
                                while depth > 0 {
                                    match self.expect()? {
                                        Token::LParen => depth += 1,
                                        Token::RParen => depth -= 1,
                                        _ => {}
                                    }
                                }
                            }
                            Token::Symbol(s) => {
                                if value.is_none() {
                                    value = Some(s.to_string());
                                }
                            }
                            _ => {
                                let _ = save;
                            }
                        }
                    }
                    if key == "produce-unsat-cores" {
                        return Ok(Some(Command::SetOption(
                            key,
                            value.unwrap_or_else(|| "true".to_string()),
                        )));
                    }
                }
                "define-sort" => {
                    let alias = self.expect_symbol()?.to_string();
                    self.expect_lparen()?;
                    // Only 0-ary sort aliases (all the corpus uses).
                    match self.expect()? {
                        Token::RParen => {}
                        _ => return Err(ParseError::Unsupported("parametric define-sort".into())),
                    }
                    let sort = self.parse_sort()?;
                    self.expect_rparen()?;
                    self.sort_aliases.insert(alias, sort);
                }
                "declare-const" => {
                    let sym_name = self.expect_symbol()?;
                    let sort = self.parse_sort()?;
                    self.expect_rparen()?;
                    self.declare(sym_name, &[], sort)?;
                }
                "declare-fun" => {
                    let sym_name = self.expect_symbol()?;
                    self.expect_lparen()?;
                    let mut params = Vec::new();
                    loop {
                        let save = self.lexer.pos();
                        match self.expect()? {
                            Token::RParen => break,
                            Token::LParen => {
                                // Sorts can be compound: re-parse from '('.
                                let s = self.parse_sort_after_lparen()?;
                                params.push(s);
                            }
                            Token::Symbol(s) => params.push(self.simple_sort(save, s)?),
                            t => return Err(self.syntax(save, format!("expected sort, got {t:?}"))),
                        }
                    }
                    let ret = self.parse_sort()?;
                    self.expect_rparen()?;
                    self.declare(sym_name, &params, ret)?;
                }
                "define-fun" => {
                    let sym_name = self.expect_symbol()?;
                    self.expect_lparen()?;
                    let mut params: Vec<(&str, Sort)> = Vec::new();
                    loop {
                        let save = self.lexer.pos();
                        match self.expect()? {
                            Token::RParen => break,
                            Token::LParen => {
                                let p_name = self.expect_symbol()?;
                                let p_sort = self.parse_sort()?;
                                self.expect_rparen()?;
                                params.push((p_name, p_sort));
                            }
                            t => {
                                return Err(
                                    self.syntax(save, format!("expected sorted var, got {t:?}"))
                                )
                            }
                        }
                    }
                    let _ret = self.parse_sort()?;
                    // Bind params as fresh vars in a new scope, parse body.
                    self.push_scope();
                    let mut param_terms = Vec::new();
                    for (p_name, p_sort) in &params {
                        let sym = self.pool.fresh_symbol(*p_name, *p_sort);
                        let var = self.pool.var(sym);
                        self.bind(p_name, Binding::Term(var));
                        param_terms.push(var);
                    }
                    let body = self.parse_term()?;
                    self.pop_scope();
                    self.expect_rparen()?;
                    if param_terms.is_empty() {
                        self.bind_global(sym_name, Binding::Term(body));
                    } else {
                        self.bind_global(
                            sym_name,
                            Binding::DefinedFun {
                                params: param_terms,
                                body,
                            },
                        );
                    }
                }
                "assert" => {
                    self.top_named = None;
                    let t = self.parse_term()?;
                    let name = self.top_named.take();
                    self.expect_rparen()?;
                    if self.pool.sort(t) != Sort::Bool {
                        return Err(ParseError::Unsupported(
                            "assert of non-Bool term".to_string(),
                        ));
                    }
                    return Ok(Some(Command::Assert(t, name)));
                }
                "check-sat" => {
                    self.expect_rparen()?;
                    return Ok(Some(Command::CheckSat));
                }
                "check-sat-assuming" => {
                    let terms = self.parse_term_list()?;
                    return Ok(Some(Command::CheckSatAssuming(terms)));
                }
                "get-model" => {
                    self.expect_rparen()?;
                    return Ok(Some(Command::GetModel));
                }
                "minimize" | "maximize" => {
                    let t = self.parse_term()?;
                    self.expect_rparen()?;
                    return Ok(Some(if name == "minimize" {
                        Command::Minimize(t)
                    } else {
                        Command::Maximize(t)
                    }));
                }
                "get-value" => {
                    let terms = self.parse_term_list()?;
                    return Ok(Some(Command::GetValue(terms)));
                }
                "get-unsat-core" => {
                    self.expect_rparen()?;
                    return Ok(Some(Command::GetUnsatCore));
                }
                "push" | "pop" => {
                    let save = self.lexer.pos();
                    let n = match self.expect()? {
                        Token::RParen => {
                            return Ok(Some(if name == "push" {
                                Command::Push(1)
                            } else {
                                Command::Pop(1)
                            }))
                        }
                        Token::Numeral(n) => n
                            .parse::<u32>()
                            .map_err(|_| self.syntax(save, "bad push/pop count"))?,
                        t => return Err(self.syntax(save, format!("expected numeral, got {t:?}"))),
                    };
                    self.expect_rparen()?;
                    return Ok(Some(if name == "push" {
                        Command::Push(n)
                    } else {
                        Command::Pop(n)
                    }));
                }
                "echo" => {
                    let pos = self.lexer.pos();
                    let msg = match self.expect()? {
                        Token::StringLit(s) => s.to_string(),
                        t => return Err(self.syntax(pos, format!("expected string, got {t:?}"))),
                    };
                    self.expect_rparen()?;
                    return Ok(Some(Command::Echo(msg)));
                }
                "reset" => {
                    self.expect_rparen()?;
                    return Ok(Some(Command::Reset));
                }
                "exit" => {
                    self.expect_rparen()?;
                    return Ok(Some(Command::Exit));
                }
                "get-info"
                | "get-assertions"
                | "get-option"
                | "get-assignment"
                | "get-unsat-assumptions"
                | "declare-sort"
                | "declare-datatype"
                | "declare-datatypes"
                | "define-fun-rec"
                | "define-funs-rec" => {
                    return Err(ParseError::Unsupported(format!("command {name}")));
                }
                other => {
                    return Err(ParseError::Unsupported(format!("command {other}")));
                }
            }
        }
    }

    // ---- scoping ----

    fn push_scope(&mut self) {
        self.scope_stack.push(Vec::new());
    }

    fn pop_scope(&mut self) {
        for name in self.scope_stack.pop().expect("scope underflow") {
            let stack = self.scopes.get_mut(name).expect("binding missing");
            stack.pop();
            if stack.is_empty() {
                self.scopes.remove(name);
            }
        }
    }

    fn bind(&mut self, name: &'a str, b: Binding) {
        self.scopes.entry(name).or_default().push(b);
        self.scope_stack
            .last_mut()
            .expect("bind outside scope")
            .push(name);
    }

    fn bind_global(&mut self, name: &'a str, b: Binding) {
        self.scopes.entry(name).or_default().push(b);
    }

    fn lookup(&self, name: &str) -> Option<&Binding> {
        self.scopes.get(name).and_then(|s| s.last())
    }

    fn declare(&mut self, name: &'a str, params: &[Sort], ret: Sort) -> PResult<()> {
        if params.is_empty() {
            let sym = self.pool.fresh_symbol(name, ret);
            let var = self.pool.var(sym);
            self.declared.push(sym);
            self.bind_global(name, Binding::Term(var));
        } else {
            let sym = self.pool.fresh_symbol(name, ret);
            self.bind_global(
                name,
                Binding::DeclaredFun {
                    sym,
                    params: params.to_vec(),
                    ret,
                },
            );
        }
        Ok(())
    }

    // ---- sorts ----

    fn parse_sort(&mut self) -> PResult<Sort> {
        let pos = self.lexer.pos();
        match self.expect()? {
            Token::Symbol(s) => self.simple_sort(pos, s),
            Token::LParen => self.parse_sort_after_lparen(),
            t => Err(self.syntax(pos, format!("expected sort, got {t:?}"))),
        }
    }

    fn simple_sort(&self, pos: usize, s: &str) -> PResult<Sort> {
        if let Some(&alias) = self.sort_aliases.get(s) {
            return Ok(alias);
        }
        Ok(match s {
            "Bool" => Sort::Bool,
            "Int" => Sort::Int,
            "String" => Sort::Str,
            "RoundingMode" => Sort::RoundingMode,
            "RegLan" => Sort::RegLan,
            "Float16" => Sort::Float(5, 11),
            "Float32" => Sort::Float(8, 24),
            "Float64" => Sort::Float(11, 53),
            "Float128" => Sort::Float(15, 113),
            "Real" => return Err(ParseError::Unsupported("Real sort".into())),
            other => {
                let _ = pos;
                return Err(ParseError::Unsupported(format!("sort {other}")));
            }
        })
    }

    /// Parse a compound sort after having consumed its '('.
    fn parse_sort_after_lparen(&mut self) -> PResult<Sort> {
        let pos = self.lexer.pos();
        let head = self.expect_symbol()?;
        match head {
            "_" => {
                let name = self.expect_symbol()?;
                match name {
                    "BitVec" => {
                        let w = self.expect_numeral_u32()?;
                        self.expect_rparen()?;
                        if w == 0 {
                            return Err(self.syntax(pos, "zero-width BitVec"));
                        }
                        if w > MAX_BV_WIDTH {
                            return Err(self.syntax(pos, format!("BitVec width {w} is too large")));
                        }
                        Ok(Sort::BitVec(w))
                    }
                    "FloatingPoint" => {
                        let e = self.expect_numeral_u32()?;
                        let s = self.expect_numeral_u32()?;
                        self.expect_rparen()?;
                        // SMT-LIB requires eb >= 2 and sb >= 2; `smtrs-fp`
                        // computes `sb - 2` and `1 << (eb - 1)` unguarded.
                        if !(2..=MAX_FP_EXP_WIDTH).contains(&e)
                            || !(2..=MAX_FP_SIG_WIDTH).contains(&s)
                        {
                            return Err(self.syntax(
                                pos,
                                format!("unsupported FloatingPoint format ({e}, {s})"),
                            ));
                        }
                        Ok(Sort::Float(e, s))
                    }
                    other => Err(ParseError::Unsupported(format!("sort (_ {other} ...)"))),
                }
            }
            "Array" => Err(ParseError::Unsupported("Array sort".into())),
            other => Err(ParseError::Unsupported(format!("sort ({other} ...)"))),
        }
    }

    // ---- terms ----

    /// A parenthesised term sequence, as `check-sat-assuming` and `get-value`
    /// both take: `( t1 t2 ... )`, consuming both parentheses.
    fn parse_term_list(&mut self) -> PResult<Vec<TermId>> {
        self.expect_lparen()?;
        let mut terms = Vec::new();
        loop {
            let save = self.lexer.pos();
            match self.expect()? {
                Token::RParen => break,
                Token::LParen => terms.push(self.parse_term_after_lparen()?),
                Token::Symbol(s) => terms.push(self.atom_term(save, s)?),
                t => return Err(self.syntax(save, format!("expected term, got {t:?}"))),
            }
        }
        self.expect_rparen()?;
        Ok(terms)
    }

    pub fn parse_term(&mut self) -> PResult<TermId> {
        let pos = self.lexer.pos();
        match self.expect()? {
            Token::LParen => self.parse_term_after_lparen(),
            Token::Symbol(s) => self.atom_term(pos, s),
            Token::Binary(b) => {
                let c = BvConst::from_binary_str(b)
                    .ok_or_else(|| self.syntax(pos, "bad binary literal"))?;
                Ok(self.pool.bv(c))
            }
            Token::Hex(h) => {
                let c =
                    BvConst::from_hex_str(h).ok_or_else(|| self.syntax(pos, "bad hex literal"))?;
                Ok(self.pool.bv(c))
            }
            Token::Numeral(n) => {
                // Bare numeral: Int literal (strings/LIA benchmarks).
                Ok(self.other_leaf(&format!("int!{n}"), Sort::Int))
            }
            Token::StringLit(s) => {
                let name = format!("str!\"{s}\"");
                Ok(self.other_leaf(&name, Sort::Str))
            }
            t => Err(self.syntax(pos, format!("expected term, got {t:?}"))),
        }
    }

    /// A symbol in term position.
    fn atom_term(&mut self, pos: usize, s: &'a str) -> PResult<TermId> {
        if let Some(b) = self.lookup(s) {
            match b.clone() {
                Binding::Term(t) => return Ok(t),
                Binding::DefinedFun { .. } | Binding::DeclaredFun { .. } => {
                    return Err(self.syntax(pos, format!("function {s} used without arguments")))
                }
            }
        }
        match s {
            "true" => Ok(self.pool.true_term),
            "false" => Ok(self.pool.false_term),
            // FP rounding modes and other 0-ary theory symbols.
            "RNE" | "roundNearestTiesToEven" => Ok(self.pool.rm(0)),
            "RNA" | "roundNearestTiesToAway" => Ok(self.pool.rm(1)),
            "RTP" | "roundTowardPositive" => Ok(self.pool.rm(2)),
            "RTN" | "roundTowardNegative" => Ok(self.pool.rm(3)),
            "RTZ" | "roundTowardZero" => Ok(self.pool.rm(4)),
            "re.none" | "re.all" | "re.allchar" => Ok(self.other_leaf(s, Sort::RegLan)),
            _ if s.starts_with("bv") => {
                // Legacy `bvN`-style constants only appear via (_ bvN w).
                Err(self.syntax(pos, format!("unknown symbol {s}")))
            }
            _ => Err(self.syntax(pos, format!("unknown symbol {s}"))),
        }
    }

    fn other_leaf(&mut self, name: &str, sort: Sort) -> TermId {
        let sym = self.intern_symbol(name, sort);
        self.pool.var(sym)
    }

    /// Parse a term after having consumed its opening '('.
    fn parse_term_after_lparen(&mut self) -> PResult<TermId> {
        // This is the function the recursion actually cycles through:
        // `parse_args` calls it directly rather than going back through
        // `parse_term`, so the depth counter has to live here to see every
        // level of nesting.
        if self.depth >= MAX_TERM_DEPTH {
            let pos = self.lexer.pos();
            return Err(self.syntax(pos, format!("term nested deeper than {MAX_TERM_DEPTH}")));
        }
        self.depth += 1;
        let r = self.parse_term_after_lparen_inner();
        self.depth -= 1;
        r
    }

    fn parse_term_after_lparen_inner(&mut self) -> PResult<TermId> {
        let pos = self.lexer.pos();
        match self.expect()? {
            Token::Symbol("let") => {
                self.expect_lparen()?;
                // Parse all bindings (values in the outer scope), then bind.
                let mut bindings: Vec<(&str, TermId)> = Vec::new();
                loop {
                    let save = self.lexer.pos();
                    match self.expect()? {
                        Token::RParen => break,
                        Token::LParen => {
                            let name = self.expect_symbol()?;
                            let value = self.parse_term()?;
                            self.expect_rparen()?;
                            bindings.push((name, value));
                        }
                        t => return Err(self.syntax(save, format!("expected binding, got {t:?}"))),
                    }
                }
                self.push_scope();
                for (name, value) in bindings {
                    self.bind(name, Binding::Term(value));
                }
                let body = self.parse_term()?;
                self.pop_scope();
                self.expect_rparen()?;
                Ok(body)
            }
            Token::Symbol("!") => {
                let t = self.parse_term()?;
                // Attributes until ')'.
                loop {
                    let save = self.lexer.pos();
                    match self.expect()? {
                        Token::RParen => break,
                        Token::Keyword("named") => {
                            let name = self.expect_symbol()?;
                            self.named.push((name.to_string(), t));
                            self.bind_global(name, Binding::Term(t));
                            // `parse_term_after_lparen` owns the depth
                            // counter, so an annotation wrapping the whole
                            // term of a command sits at exactly depth 1.
                            if self.depth == 1 {
                                self.top_named = Some(name.to_string());
                            }
                        }
                        Token::Keyword(_) => self.skip_sexpr()?,
                        tok => {
                            return Err(
                                self.syntax(save, format!("expected attribute, got {tok:?}"))
                            )
                        }
                    }
                }
                Ok(t)
            }
            Token::Symbol("forall") | Token::Symbol("exists") => {
                Err(ParseError::Unsupported("quantifiers".into()))
            }
            Token::Symbol("_") => {
                // Indexed identifier in term position: (_ bvN w) etc.
                let name = self.expect_symbol()?;
                if let Some(digits) = name.strip_prefix("bv") {
                    let w_pos = self.lexer.pos();
                    let w = self.expect_numeral_u32()?;
                    self.expect_rparen()?;
                    let c = BvConst::from_decimal(w, digits)
                        .ok_or_else(|| self.syntax(w_pos, "bad (_ bvN w) literal"))?;
                    Ok(self.pool.bv(c))
                } else {
                    match name {
                        "+oo" | "-oo" | "+zero" | "-zero" | "NaN" => {
                            let e = self.expect_numeral_u32()?;
                            let sb = self.expect_numeral_u32()?;
                            self.expect_rparen()?;
                            // `fp_const` interns directly and so never reaches
                            // `TermPool::check`; this is the only place these
                            // formats are validated.
                            if !(2..=MAX_FP_EXP_WIDTH).contains(&e)
                                || !(2..=MAX_FP_SIG_WIDTH).contains(&sb)
                            {
                                return Err(self.syntax(
                                    pos,
                                    format!("unsupported floating-point format ({e}, {sb})"),
                                ));
                            }
                            let op = match name {
                                "+oo" => Op::FpInf(false),
                                "-oo" => Op::FpInf(true),
                                "+zero" => Op::FpZero(false),
                                "-zero" => Op::FpZero(true),
                                _ => Op::FpNan,
                            };
                            Ok(self.pool.fp_const(op, e, sb))
                        }
                        other => Err(ParseError::Unsupported(format!(
                            "indexed identifier (_ {other})"
                        ))),
                    }
                }
            }
            Token::LParen => {
                // ((_ op idx...) args...) — indexed operator application.
                let op_pos = self.lexer.pos();
                match self.expect()? {
                    Token::Symbol("_") => {
                        let name = self.expect_symbol()?;
                        let indexed = self.parse_indexed_op(op_pos, name)?;
                        let args = self.parse_args()?;
                        self.apply_indexed(op_pos, indexed, args)
                    }
                    t => Err(self.syntax(op_pos, format!("expected (_ op ...), got {t:?}"))),
                }
            }
            Token::Symbol(head) => {
                let args = self.parse_args()?;
                self.apply(pos, head, args)
            }
            t => Err(self.syntax(pos, format!("expected operator, got {t:?}"))),
        }
    }

    fn parse_args(&mut self) -> PResult<Vec<TermId>> {
        let mut args = Vec::new();
        loop {
            let save = self.lexer.pos();
            match self.expect()? {
                Token::RParen => return Ok(args),
                Token::LParen => args.push(self.parse_term_after_lparen()?),
                Token::Symbol(s) => args.push(self.atom_term(save, s)?),
                Token::Binary(b) => {
                    let c = BvConst::from_binary_str(b)
                        .ok_or_else(|| self.syntax(save, "bad binary literal"))?;
                    args.push(self.pool.bv(c));
                }
                Token::Hex(h) => {
                    let c = BvConst::from_hex_str(h)
                        .ok_or_else(|| self.syntax(save, "bad hex literal"))?;
                    args.push(self.pool.bv(c));
                }
                Token::Numeral(n) => {
                    let v = self.other_leaf(&format!("int!{n}"), Sort::Int);
                    args.push(v);
                }
                Token::StringLit(s) => {
                    let name = format!("str!\"{s}\"");
                    let v = self.other_leaf(&name, Sort::Str);
                    args.push(v);
                }
                t => return Err(self.syntax(save, format!("expected term, got {t:?}"))),
            }
        }
    }

    /// Indexed operators: name + numeral indices, ')' consumed.
    fn parse_indexed_op(&mut self, pos: usize, name: &'a str) -> PResult<(&'a str, Vec<u32>)> {
        let mut indices = Vec::new();
        loop {
            let save = self.lexer.pos();
            match self.expect()? {
                Token::RParen => break,
                Token::Numeral(n) => indices.push(
                    n.parse::<u32>()
                        .map_err(|_| self.syntax(save, "index out of range"))?,
                ),
                t => return Err(self.syntax(save, format!("expected index, got {t:?}"))),
            }
        }
        if indices.is_empty() {
            return Err(self.syntax(pos, "indexed operator without indices"));
        }
        Ok((name, indices))
    }

    fn apply_indexed(
        &mut self,
        pos: usize,
        (name, indices): (&'a str, Vec<u32>),
        args: Vec<TermId>,
    ) -> PResult<TermId> {
        let mk = |p: &mut Self, op: Op, args: &[TermId]| -> PResult<TermId> {
            p.pool.mk(op, args).map_err(|e| p.sort_err(e))
        };
        match name {
            "extract" if indices.len() == 2 => mk(
                self,
                Op::Extract {
                    hi: indices[0],
                    lo: indices[1],
                },
                &args,
            ),
            "zero_extend" if indices.len() == 1 => {
                if indices[0] == 0 && args.len() == 1 {
                    return Ok(args[0]);
                }
                mk(self, Op::ZeroExtend(indices[0]), &args)
            }
            "sign_extend" if indices.len() == 1 => {
                if indices[0] == 0 && args.len() == 1 {
                    return Ok(args[0]);
                }
                mk(self, Op::SignExtend(indices[0]), &args)
            }
            "rotate_left" if indices.len() == 1 => mk(self, Op::RotateLeft(indices[0]), &args),
            "rotate_right" if indices.len() == 1 => mk(self, Op::RotateRight(indices[0]), &args),
            "repeat" if indices.len() == 1 => mk(self, Op::Repeat(indices[0]), &args),
            // FP conversions. (_ to_fp eb sb) is overloaded on arity/sorts:
            //   1 BV operand           -> reinterpret IEEE bits
            //   rm + FP                -> FP-to-FP
            //   rm + BV                -> signed BV to FP
            "to_fp" if indices.len() == 2 => {
                let (eb, sb) = (indices[0], indices[1]);
                let op = match args.len() {
                    1 => Op::FpFromIeeeBv { eb, sb },
                    2 if matches!(self.pool.sort(args[1]), Sort::Float(..)) => {
                        Op::FpToFp { eb, sb }
                    }
                    2 => Op::FpFromSignedBv { eb, sb },
                    _ => return Err(self.syntax(pos, "bad (_ to_fp ...) application")),
                };
                mk(self, op, &args)
            }
            "to_fp_unsigned" if indices.len() == 2 => mk(
                self,
                Op::FpFromUnsignedBv {
                    eb: indices[0],
                    sb: indices[1],
                },
                &args,
            ),
            "fp.to_ubv" if indices.len() == 1 => mk(self, Op::FpToUbv(indices[0]), &args),
            "fp.to_sbv" if indices.len() == 1 => mk(self, Op::FpToSbv(indices[0]), &args),
            "re.loop" | "re.^" => {
                if args.len() != 1 {
                    return Err(self.syntax(pos, format!("{name}: expected 1 argument")));
                }
                let (lo, hi) = (indices[0], indices.get(1).copied().unwrap_or(0));
                // The NFA builder materialises one copy of the inner automaton
                // per repetition, so an input-supplied bound is an unbounded
                // allocation that no timeout interrupts.
                if lo.max(hi) > MAX_REGEX_REPEAT {
                    return Err(ParseError::Unsupported(format!(
                        "{name} repetition count above {MAX_REGEX_REPEAT}"
                    )));
                }
                Ok(self.other_app(name, lo, hi, &args, Sort::RegLan))
            }
            "divisible" if indices.len() == 1 => {
                if args.len() != 1 {
                    return Err(self.syntax(pos, "divisible: expected 1 argument"));
                }
                Ok(self.other_app(name, indices[0], 0, &args, Sort::Bool))
            }
            other => Err(self.syntax(pos, format!("unknown indexed operator (_ {other} ...)"))),
        }
    }

    /// Permitted argument counts for the theory symbols that become
    /// `Op::Other`, as `(min, max)`.
    ///
    /// `TermPool::check` deliberately does not sort-check `Op::Other` — it has
    /// no arity table for heads it does not interpret — so the parser is the
    /// *only* place a malformed application of one can be rejected. That
    /// matters because `smtrs-str`'s lowering runs before
    /// `Solver::unsupported_reason` and indexes `args` positionally: without
    /// this table `(str.contains "a")` reaches `args[1]` and panics, and about
    /// twenty-five sites across `smtrs-str`'s `lib.rs`, `bounds.rs` and
    /// `regex.rs` have the same shape. Validating once here is what keeps
    /// them all unreachable.
    ///
    /// The counts match what those consumers actually index, not just the
    /// SMT-LIB signature, so a term that passes this check cannot index out of
    /// bounds later.
    fn other_arity(head: &str) -> Option<(usize, usize)> {
        const MANY: usize = usize::MAX;
        Some(match head {
            "str.len" | "str.rev" | "str.is_digit" | "str.to_int" | "str.to.int"
            | "str.to_code" | "str.from_int" | "str.from_code" | "int.to.str" | "str.to_re"
            | "re.*" | "re.+" | "re.opt" | "re.comp" | "abs" | "int-neg" => (1, 1),
            "str.at" | "str.contains" | "str.prefixof" | "str.suffixof" | "str.in_re"
            | "re.range" | "mod" => (2, 2),
            // `:left-assoc` / `:chainable` in the theory definitions, so more
            // than two operands is well-formed.
            "div" | "str.<" | "str.<=" => (2, MANY),
            "str.substr" | "str.replace" | "str.replace_all" | "str.replace_re"
            | "str.replace_re_all" | "str.update" | "str.indexof" => (3, 3),
            // `-` is unary negation at one argument (rewritten to `int-neg`
            // below) and n-ary subtraction above that.
            "str.++" | "re.++" | "re.union" | "re.inter" | "+" | "*" | "-" => (1, MANY),
            "re.diff" | "<" | "<=" | ">" | ">=" => (2, MANY),
            _ => return None,
        })
    }

    /// Reject an `Op::Other` application whose argument count no consumer can
    /// handle. See [`Self::other_arity`].
    fn check_other_arity(&self, pos: usize, head: &str, n: usize) -> PResult<()> {
        if let Some((lo, hi)) = Self::other_arity(head) {
            if n < lo || n > hi {
                let want = if lo == hi {
                    format!("{lo}")
                } else if hi == usize::MAX {
                    format!("at least {lo}")
                } else {
                    format!("{lo} to {hi}")
                };
                return Err(self.syntax(pos, format!("{head}: expected {want} arguments, got {n}")));
            }
        }
        Ok(())
    }

    fn other_app(
        &mut self,
        name: &str,
        index0: u32,
        index1: u32,
        args: &[TermId],
        sort: Sort,
    ) -> TermId {
        let sym = self.intern_symbol(name, sort);
        self.pool.other(sym, index0, index1, args, sort)
    }

    /// Apply a (non-indexed) head symbol to parsed args.
    fn apply(&mut self, pos: usize, head: &'a str, args: Vec<TermId>) -> PResult<TermId> {
        // User-defined / declared functions shadow theory symbols.
        if let Some(b) = self.lookup(head) {
            match b.clone() {
                Binding::Term(t) => {
                    if args.is_empty() {
                        return Ok(t);
                    }
                    return Err(self.syntax(pos, format!("{head} applied to arguments")));
                }
                Binding::DeclaredFun { sym, params, ret } => {
                    if params.len() != args.len() {
                        return Err(self.syntax(pos, format!("{head}: arity mismatch")));
                    }
                    // This mints an `Op::Other` carrying the *declared* name,
                    // so a declaration that shadows a theory head produces a
                    // term indistinguishable from the theory's own -- and the
                    // consumers named in `other_arity`'s comment index it
                    // positionally. Reaching `pool.other` without the same
                    // check the theory path below performs is what let
                    // `(declare-fun str.contains (String) Bool)` panic
                    // `smtrs-str` at `args[1]`. The check has to be here too,
                    // not only there, or the invariant that comment claims
                    // does not hold.
                    self.check_other_arity(pos, head, args.len())?;
                    return Ok(self.pool.other(sym, 0, 0, &args, ret));
                }
                Binding::DefinedFun { params, body } => {
                    if params.len() != args.len() {
                        return Err(self.syntax(pos, format!("{head}: arity mismatch")));
                    }
                    let map: FxHashMap<TermId, TermId> =
                        params.iter().copied().zip(args.iter().copied()).collect();
                    return self
                        .pool
                        .substitute(body, &map)
                        .map_err(|e| self.sort_err(e));
                }
            }
        }

        let mk = |p: &mut Self, op: Op, args: &[TermId]| -> PResult<TermId> {
            p.pool.mk(op, args).map_err(|e| p.sort_err(e))
        };

        // Heads that build `Op::Other` get no sort check in the pool, so their
        // arity has to be validated here; everything else is checked by `mk`.
        self.check_other_arity(pos, head, args.len())?;

        match head {
            // Core.
            "not" => mk(self, Op::Not, &args),
            "=>" => mk(self, Op::Implies, &args),
            "and" => match args.len() {
                0 => Ok(self.pool.true_term),
                1 => Ok(args[0]),
                _ => mk(self, Op::And, &args),
            },
            "or" => match args.len() {
                0 => Ok(self.pool.false_term),
                1 => Ok(args[0]),
                _ => mk(self, Op::Or, &args),
            },
            "xor" => mk(self, Op::Xor, &args),
            "=" => {
                if args.iter().any(|&a| !self.term_supported_sort(a)) {
                    return Ok(self.other_bool(head, &args));
                }
                mk(self, Op::Eq, &args)
            }
            "distinct" => {
                if args.iter().any(|&a| !self.term_supported_sort(a)) {
                    return Ok(self.other_bool(head, &args));
                }
                mk(self, Op::Distinct, &args)
            }
            "ite" => {
                if args.len() == 3 && !self.term_supported_sort(args[1]) {
                    let sort = self.pool.sort(args[1]);
                    return Ok(self.other_app(head, 0, 0, &args, sort));
                }
                mk(self, Op::Ite, &args)
            }

            // BV.
            "bvneg" => mk(self, Op::BvNeg, &args),
            "bvadd" => mk(self, Op::BvAdd, &args),
            "bvsub" => self.left_assoc(Op::BvSub, args),
            "bvmul" => mk(self, Op::BvMul, &args),
            "bvudiv" => self.left_assoc(Op::BvUdiv, args),
            "bvurem" => self.left_assoc(Op::BvUrem, args),
            "bvsdiv" => self.left_assoc(Op::BvSdiv, args),
            "bvsrem" => self.left_assoc(Op::BvSrem, args),
            "bvsmod" => self.left_assoc(Op::BvSmod, args),
            "bvnot" => mk(self, Op::BvNot, &args),
            "bvand" => mk(self, Op::BvAnd, &args),
            "bvor" => mk(self, Op::BvOr, &args),
            "bvxor" => mk(self, Op::BvXor, &args),
            "bvnand" => self.left_assoc(Op::BvNand, args),
            "bvnor" => self.left_assoc(Op::BvNor, args),
            "bvxnor" => self.left_assoc(Op::BvXnor, args),
            "bvcomp" => mk(self, Op::BvComp, &args),
            "bvshl" => self.left_assoc(Op::BvShl, args),
            "bvlshr" => self.left_assoc(Op::BvLshr, args),
            "bvashr" => self.left_assoc(Op::BvAshr, args),
            "concat" => mk(self, Op::Concat, &args),
            "bvult" => mk(self, Op::BvUlt, &args),
            "bvule" => mk(self, Op::BvUle, &args),
            "bvugt" => mk(self, Op::BvUgt, &args),
            "bvuge" => mk(self, Op::BvUge, &args),
            "bvslt" => mk(self, Op::BvSlt, &args),
            "bvsle" => mk(self, Op::BvSle, &args),
            "bvsgt" => mk(self, Op::BvSgt, &args),
            "bvsge" => mk(self, Op::BvSge, &args),

            // Floating point.
            "fp" => mk(self, Op::FpFromBits, &args),
            "fp.abs" => mk(self, Op::FpAbs, &args),
            "fp.neg" => mk(self, Op::FpNeg, &args),
            "fp.add" => mk(self, Op::FpAdd, &args),
            "fp.sub" => mk(self, Op::FpSub, &args),
            "fp.mul" => mk(self, Op::FpMul, &args),
            "fp.div" => mk(self, Op::FpDiv, &args),
            "fp.sqrt" => mk(self, Op::FpSqrt, &args),
            "fp.fma" => mk(self, Op::FpFma, &args),
            "fp.roundToIntegral" => mk(self, Op::FpRoundToIntegral, &args),
            "fp.rem" => mk(self, Op::FpRem, &args),
            "fp.min" => mk(self, Op::FpMin, &args),
            "fp.max" => mk(self, Op::FpMax, &args),
            "fp.leq" => mk(self, Op::FpLeq, &args),
            "fp.lt" => mk(self, Op::FpLt, &args),
            "fp.geq" => mk(self, Op::FpGeq, &args),
            "fp.gt" => mk(self, Op::FpGt, &args),
            "fp.eq" => mk(self, Op::FpEq, &args),
            "fp.isNormal" => mk(self, Op::FpIsNormal, &args),
            "fp.isSubnormal" => mk(self, Op::FpIsSubnormal, &args),
            "fp.isZero" => mk(self, Op::FpIsZero, &args),
            "fp.isInfinite" => mk(self, Op::FpIsInfinite, &args),
            "fp.isNaN" => mk(self, Op::FpIsNan, &args),
            "fp.isNegative" => mk(self, Op::FpIsNegative, &args),
            "fp.isPositive" => mk(self, Op::FpIsPositive, &args),
            "fp.to_ieee_bv" => mk(self, Op::FpToIeeeBv, &args),
            "fp.to_real" => Err(ParseError::Unsupported("fp.to_real".into())),

            // Strings.
            "str.++" => Ok(self.other_app(head, 0, 0, &args, Sort::Str)),
            "str.len" => Ok(self.other_app(head, 0, 0, &args, Sort::Int)),
            "str.at" | "str.substr" | "str.replace" | "str.replace_all" | "str.replace_re"
            | "str.replace_re_all" | "str.rev" | "str.update" => {
                Ok(self.other_app(head, 0, 0, &args, Sort::Str))
            }
            "str.contains" | "str.prefixof" | "str.suffixof" | "str.in_re" | "str.<" | "str.<="
            | "str.is_digit" => Ok(self.other_bool(head, &args)),
            "str.indexof" | "str.to_int" | "str.to_code" => {
                Ok(self.other_app(head, 0, 0, &args, Sort::Int))
            }
            "str.from_int" | "str.from_code" | "int.to.str" => {
                Ok(self.other_app(head, 0, 0, &args, Sort::Str))
            }
            "str.to.int" => Ok(self.other_app(head, 0, 0, &args, Sort::Int)),
            "str.to_re" | "re.++" | "re.union" | "re.inter" | "re.*" | "re.+" | "re.opt"
            | "re.range" | "re.comp" | "re.diff" => {
                Ok(self.other_app(head, 0, 0, &args, Sort::RegLan))
            }

            // Ints (strings' length arithmetic).
            "+" | "-" | "*" | "div" | "mod" | "abs" => {
                if args.len() == 1 && head == "-" {
                    return Ok(self.other_app("int-neg", 0, 0, &args, Sort::Int));
                }
                Ok(self.other_app(head, 0, 0, &args, Sort::Int))
            }
            "<" | "<=" | ">" | ">=" => Ok(self.other_bool(head, &args)),

            "select" | "store" => Err(ParseError::Unsupported("arrays".into())),

            other => Err(self.syntax(pos, format!("unknown operator {other}"))),
        }
    }

    fn other_bool(&mut self, name: &str, args: &[TermId]) -> TermId {
        self.other_app(name, 0, 0, args, Sort::Bool)
    }

    /// Sorts the solver can reason about. Floating point and strings are both
    /// lowered to bit-vectors before solving, so `=`/`distinct`/`ite` over them
    /// are built as real terms rather than opaque nodes.
    fn term_supported_sort(&self, t: TermId) -> bool {
        matches!(
            self.pool.sort(t),
            Sort::Bool
                | Sort::BitVec(_)
                | Sort::Float(..)
                | Sort::RoundingMode
                | Sort::Str
                | Sort::Int
        )
    }

    /// SMT-LIB left-associative chains for binary-only Ops:
    /// (op a b c) == (op (op a b) c).
    fn left_assoc(&mut self, op: Op, args: Vec<TermId>) -> PResult<TermId> {
        if args.len() < 2 {
            return Err(ParseError::Unsupported(format!("{op:?} with < 2 args")));
        }
        let mut acc = args[0];
        for &a in &args[1..] {
            acc = self.pool.mk(op, &[acc, a]).map_err(|e| self.sort_err(e))?;
        }
        Ok(acc)
    }
}

/// Parse a complete script.
pub fn parse_script(input: &str, pool: &mut TermPool) -> Result<Script, ParseError> {
    let mut parser = Parser::new(input, pool);
    let mut commands = Vec::new();
    while let Some(cmd) = parser.next_command()? {
        let is_exit = matches!(cmd, Command::Exit);
        commands.push(cmd);
        if is_exit {
            break;
        }
    }
    Ok(Script {
        commands,
        named: parser.named,
        declared: parser.declared,
    })
}

pub struct Script {
    pub commands: Vec<Command>,
    pub named: Vec<(String, TermId)>,
    /// 0-ary declared constants in declaration order.
    pub declared: Vec<SymbolId>,
}
