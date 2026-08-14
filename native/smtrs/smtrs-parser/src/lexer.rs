//! Zero-copy SMT-LIB 2.6 lexer.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Token<'a> {
    LParen,
    RParen,
    /// Simple or |quoted| symbol (quoted: without the pipes).
    Symbol(&'a str),
    /// :keyword (without the colon).
    Keyword(&'a str),
    /// Decimal numeral, e.g. `42`.
    Numeral(&'a str),
    /// Decimal with a fraction part, e.g. `1.5`.
    Decimal(&'a str),
    /// `#b0101` (without the `#b`).
    Binary(&'a str),
    /// `#xdead` (without the `#x`).
    Hex(&'a str),
    /// `"..."` string literal (raw contents, `""` escapes not decoded).
    StringLit(&'a str),
}

pub struct Lexer<'a> {
    input: &'a str,
    bytes: &'a [u8],
    pos: usize,
}

#[derive(Debug)]
pub struct LexError {
    pub pos: usize,
    pub message: String,
}

impl<'a> Lexer<'a> {
    pub fn new(input: &'a str) -> Self {
        Lexer {
            input,
            bytes: input.as_bytes(),
            pos: 0,
        }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Line/column (1-based) for error reporting.
    pub fn line_col(&self, pos: usize) -> (usize, usize) {
        let mut line = 1;
        let mut col = 1;
        for &b in &self.bytes[..pos.min(self.bytes.len())] {
            if b == b'\n' {
                line += 1;
                col = 1;
            } else {
                col += 1;
            }
        }
        (line, col)
    }

    fn skip_trivia(&mut self) {
        while self.pos < self.bytes.len() {
            match self.bytes[self.pos] {
                b' ' | b'\t' | b'\r' | b'\n' => self.pos += 1,
                b';' => {
                    while self.pos < self.bytes.len() && self.bytes[self.pos] != b'\n' {
                        self.pos += 1;
                    }
                }
                _ => break,
            }
        }
    }

    fn is_symbol_byte(b: u8) -> bool {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'~' | b'!'
                    | b'@'
                    | b'$'
                    | b'%'
                    | b'^'
                    | b'&'
                    | b'*'
                    | b'_'
                    | b'-'
                    | b'+'
                    | b'='
                    | b'<'
                    | b'>'
                    | b'.'
                    | b'?'
                    | b'/'
            )
    }

    pub fn next_token(&mut self) -> Result<Option<Token<'a>>, LexError> {
        self.skip_trivia();
        if self.pos >= self.bytes.len() {
            return Ok(None);
        }
        let start = self.pos;
        let b = self.bytes[start];
        let tok = match b {
            b'(' => {
                self.pos += 1;
                Token::LParen
            }
            b')' => {
                self.pos += 1;
                Token::RParen
            }
            b'|' => {
                self.pos += 1;
                let sym_start = self.pos;
                while self.pos < self.bytes.len() && self.bytes[self.pos] != b'|' {
                    self.pos += 1;
                }
                if self.pos >= self.bytes.len() {
                    return Err(self.err(start, "unterminated |symbol|"));
                }
                let sym = &self.input[sym_start..self.pos];
                self.pos += 1;
                Token::Symbol(sym)
            }
            b'"' => {
                self.pos += 1;
                let lit_start = self.pos;
                loop {
                    if self.pos >= self.bytes.len() {
                        return Err(self.err(start, "unterminated string literal"));
                    }
                    if self.bytes[self.pos] == b'"' {
                        // `""` is an escaped quote inside the literal.
                        if self.pos + 1 < self.bytes.len() && self.bytes[self.pos + 1] == b'"' {
                            self.pos += 2;
                            continue;
                        }
                        break;
                    }
                    self.pos += 1;
                }
                let lit = &self.input[lit_start..self.pos];
                self.pos += 1;
                Token::StringLit(lit)
            }
            b':' => {
                self.pos += 1;
                let kw_start = self.pos;
                while self.pos < self.bytes.len() && Self::is_symbol_byte(self.bytes[self.pos]) {
                    self.pos += 1;
                }
                Token::Keyword(&self.input[kw_start..self.pos])
            }
            b'#' => {
                if start + 1 >= self.bytes.len() {
                    return Err(self.err(start, "dangling #"));
                }
                match self.bytes[start + 1] {
                    b'b' => {
                        self.pos += 2;
                        let d_start = self.pos;
                        while self.pos < self.bytes.len()
                            && matches!(self.bytes[self.pos], b'0' | b'1')
                        {
                            self.pos += 1;
                        }
                        if self.pos == d_start {
                            return Err(self.err(start, "empty binary literal"));
                        }
                        Token::Binary(&self.input[d_start..self.pos])
                    }
                    b'x' => {
                        self.pos += 2;
                        let d_start = self.pos;
                        while self.pos < self.bytes.len()
                            && self.bytes[self.pos].is_ascii_hexdigit()
                        {
                            self.pos += 1;
                        }
                        if self.pos == d_start {
                            return Err(self.err(start, "empty hex literal"));
                        }
                        Token::Hex(&self.input[d_start..self.pos])
                    }
                    other => return Err(self.err(start, format!("unexpected #{}", other as char))),
                }
            }
            b'0'..=b'9' => {
                while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_digit() {
                    self.pos += 1;
                }
                // Decimal?
                if self.pos + 1 < self.bytes.len()
                    && self.bytes[self.pos] == b'.'
                    && self.bytes[self.pos + 1].is_ascii_digit()
                {
                    self.pos += 1;
                    while self.pos < self.bytes.len() && self.bytes[self.pos].is_ascii_digit() {
                        self.pos += 1;
                    }
                    Token::Decimal(&self.input[start..self.pos])
                } else {
                    Token::Numeral(&self.input[start..self.pos])
                }
            }
            b if Self::is_symbol_byte(b) => {
                while self.pos < self.bytes.len() && Self::is_symbol_byte(self.bytes[self.pos]) {
                    self.pos += 1;
                }
                Token::Symbol(&self.input[start..self.pos])
            }
            other => {
                return Err(self.err(start, format!("unexpected character {:?}", other as char)))
            }
        };
        Ok(Some(tok))
    }

    fn err(&self, pos: usize, message: impl Into<String>) -> LexError {
        LexError {
            pos,
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks(s: &str) -> Vec<Token<'_>> {
        let mut l = Lexer::new(s);
        let mut out = Vec::new();
        while let Some(t) = l.next_token().unwrap() {
            out.push(t);
        }
        out
    }

    #[test]
    fn basic() {
        assert_eq!(
            toks("(assert (= x #b01)) ; comment\n(check-sat)"),
            vec![
                Token::LParen,
                Token::Symbol("assert"),
                Token::LParen,
                Token::Symbol("="),
                Token::Symbol("x"),
                Token::Binary("01"),
                Token::RParen,
                Token::RParen,
                Token::LParen,
                Token::Symbol("check-sat"),
                Token::RParen,
            ]
        );
    }

    #[test]
    fn literals_and_quotes() {
        assert_eq!(
            toks("#xDEAD 42 1.5 :status |a b| \"hi\"\"there\""),
            vec![
                Token::Hex("DEAD"),
                Token::Numeral("42"),
                Token::Decimal("1.5"),
                Token::Keyword("status"),
                Token::Symbol("a b"),
                Token::StringLit("hi\"\"there"),
            ]
        );
    }
}
