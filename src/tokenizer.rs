// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! SQL Tokenizer
//!
//! The tokenizer (a.k.a. lexer) converts a string into a sequence of tokens.
//!
//! The tokens then form the input for the parser, which outputs an Abstract Syntax Tree (AST).

use super::dialect::keywords::ALL_KEYWORDS;
use super::dialect::Dialect;

pub type Span = std::ops::Range<usize>;

struct Ptr<'a> {
    text: &'a str,
    pos: usize,
}

impl<'a> Ptr<'a> {
    fn new(text: &'a str) -> Self {
        Ptr { text: text, pos: 0 }
    }

    fn chars(&self) -> std::str::Chars<'_> {
        self.text[self.pos..].chars()
    }

    fn peek(&self) -> Option<char> {
        self.chars().next()
    }

    fn at(&self, c: char) -> bool {
        self.peek() == Some(c)
    }

    fn at_p(&self, pred: impl Fn(char) -> bool) -> bool {
        match self.peek() {
            Some(c) if pred(c) => true,
            _ => false,
        }
    }

    #[allow(dead_code)]
    fn nth(&self, n: usize) -> Option<char> {
        self.chars().nth(n)
    }

    fn nth_is(&self, n: usize, pred: impl Fn(char) -> bool) -> bool {
        self.chars().nth(n).map(pred) == Some(true)
    }

    #[allow(dead_code)]
    fn at_str(&self, s: &str) -> bool {
        self.text[self.pos..].starts_with(s)
    }

    fn at_str_case_insensitive(&self, s: &str) -> bool {
        let mut n = 0;
        for (c1, c2) in self.chars().zip(s.chars()) {
            if c1.to_ascii_lowercase() != c2.to_ascii_lowercase() {
                return false;
            }
            n += 1;
        }

        n == s.len()
    }

    fn next(&mut self) -> Option<char> {
        let c = self.chars().next()?;
        self.pos += c.len_utf8();
        Some(c)
    }

    fn bump_while(&mut self, pred: impl Fn(char) -> bool) {
        loop {
            match self.peek() {
                Some(c) if pred(c) => {
                    self.next();
                }
                _ => break,
            }
        }
    }

    fn current_text(&self) -> &str {
        &self.text[..self.pos]
    }

    #[allow(dead_code)]
    fn rest_text(&self) -> &str {
        &self.text[self.pos..]
    }

    /// better name?
    fn reset(&mut self) {
        self.text = &self.text[self.pos..];
        self.pos = 0;
    }
}

/// SQL Token enumeration
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TokenKind {
    /// A keyword (like SELECT) or an optionally quoted SQL identifier
    Word(Word),
    /// An unsigned numeric literal
    Number(String),
    /// A character that could not be tokenized
    Char(char),
    /// Single quoted string: i.e: 'string'
    SingleQuotedString(String),
    /// "National" string literal: i.e: N'string'
    NationalStringLiteral(String),
    /// Hexadecimal string literal: i.e.: X'deadbeef'
    HexStringLiteral(String),
    /// Comma
    Comma,
    /// Whitespace (space, tab, etc)
    Whitespace(Whitespace),
    /// Equality operator `=`
    Eq,
    /// Not Equals operator `<>` (or `!=` in some dialects)
    Neq,
    /// Less Than operator `<`
    Lt,
    /// Greater han operator `>`
    Gt,
    /// Less Than Or Equals operator `<=`
    LtEq,
    /// Greater Than Or Equals operator `>=`
    GtEq,
    /// Plus operator `+`
    Plus,
    /// Minus operator `-`
    Minus,
    /// Multiplication operator `*`
    Mult,
    /// Division operator `/`
    Div,
    /// Modulo Operator `%`
    Mod,
    /// Left parenthesis `(`
    LParen,
    /// Right parenthesis `)`
    RParen,
    /// Period (used for compound identifiers or projections into nested types)
    Period,
    /// Colon `:`
    Colon,
    /// DoubleColon `::` (used for casting in postgresql)
    DoubleColon,
    /// SemiColon `;` used as separator for COPY and payload
    SemiColon,
    /// Backslash `\` used in terminating the COPY payload with `\.`
    Backslash,
    /// Left bracket `[`
    LBracket,
    /// Right bracket `]`
    RBracket,
    /// Ampersand &
    Ampersand,
    /// Left brace `{`
    LBrace,
    /// Right brace `}`
    RBrace,
}

impl ToString for TokenKind {
    fn to_string(&self) -> String {
        match self {
            TokenKind::Word(ref w) => w.to_string(),
            TokenKind::Number(ref n) => n.to_string(),
            TokenKind::Char(ref c) => c.to_string(),
            TokenKind::SingleQuotedString(ref s) => format!("'{}'", s),
            TokenKind::NationalStringLiteral(ref s) => format!("N'{}'", s),
            TokenKind::HexStringLiteral(ref s) => format!("X'{}'", s),
            TokenKind::Comma => ",".to_string(),
            TokenKind::Whitespace(ws) => ws.to_string(),
            TokenKind::Eq => "=".to_string(),
            TokenKind::Neq => "<>".to_string(),
            TokenKind::Lt => "<".to_string(),
            TokenKind::Gt => ">".to_string(),
            TokenKind::LtEq => "<=".to_string(),
            TokenKind::GtEq => ">=".to_string(),
            TokenKind::Plus => "+".to_string(),
            TokenKind::Minus => "-".to_string(),
            TokenKind::Mult => "*".to_string(),
            TokenKind::Div => "/".to_string(),
            TokenKind::Mod => "%".to_string(),
            TokenKind::LParen => "(".to_string(),
            TokenKind::RParen => ")".to_string(),
            TokenKind::Period => ".".to_string(),
            TokenKind::Colon => ":".to_string(),
            TokenKind::DoubleColon => "::".to_string(),
            TokenKind::SemiColon => ";".to_string(),
            TokenKind::Backslash => "\\".to_string(),
            TokenKind::LBracket => "[".to_string(),
            TokenKind::RBracket => "]".to_string(),
            TokenKind::Ampersand => "&".to_string(),
            TokenKind::LBrace => "{".to_string(),
            TokenKind::RBrace => "}".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Token {
    pub kind: TokenKind,
    pub span: Span,
}

impl TokenKind {
    pub fn make_keyword(keyword: &str) -> Self {
        TokenKind::make_word(keyword, None)
    }
    pub fn make_word(word: &str, quote_style: Option<char>) -> Self {
        let word_uppercase = word.to_uppercase();
        //TODO: need to reintroduce FnvHashSet at some point .. iterating over keywords is
        // not fast but I want the simplicity for now while I experiment with pluggable
        // dialects
        let is_keyword = quote_style == None && ALL_KEYWORDS.contains(&word_uppercase.as_str());
        TokenKind::Word(Word {
            value: word.to_string(),
            quote_style,
            keyword: if is_keyword {
                word_uppercase
            } else {
                "".to_string()
            },
        })
    }
}

/// A keyword (like SELECT) or an optionally quoted SQL identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Word {
    /// The value of the token, without the enclosing quotes, and with the
    /// escape sequences (if any) processed (TODO: escapes are not handled)
    pub value: String,
    /// An identifier can be "quoted" (&lt;delimited identifier> in ANSI parlance).
    /// The standard and most implementations allow using double quotes for this,
    /// but some implementations support other quoting styles as well (e.g. \[MS SQL])
    pub quote_style: Option<char>,
    /// If the word was not quoted and it matched one of the known keywords,
    /// this will have one of the values from dialect::keywords, otherwise empty
    pub keyword: String,
}

impl ToString for Word {
    fn to_string(&self) -> String {
        match self.quote_style {
            Some(s) if s == '"' || s == '[' || s == '`' => {
                format!("{}{}{}", s, self.value, Word::matching_end_quote(s))
            }
            None => self.value.clone(),
            _ => panic!("Unexpected quote_style!"),
        }
    }
}
impl Word {
    fn matching_end_quote(ch: char) -> char {
        match ch {
            '"' => '"', // ANSI and most dialects
            '[' => ']', // MS SQL
            '`' => '`', // MySQL
            _ => panic!("unexpected quoting style!"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Whitespace {
    Space,
    Newline,
    Tab,
    SingleLineComment(String),
    MultiLineComment(String),
}

impl ToString for Whitespace {
    fn to_string(&self) -> String {
        match self {
            Whitespace::Space => " ".to_string(),
            Whitespace::Newline => "\n".to_string(),
            Whitespace::Tab => "\t".to_string(),
            Whitespace::SingleLineComment(s) => format!("--{}", s),
            Whitespace::MultiLineComment(s) => format!("/*{}*/", s),
        }
    }
}

/// Tokenizer error
#[derive(Debug, PartialEq)]
pub struct TokenizerError(String);

/// SQL Tokenizer
pub struct Tokenizer<'a> {
    dialect: &'a dyn Dialect,
    pub query: String,
    pub line: u64,
    pub col: u64,
}

impl<'a> Tokenizer<'a> {
    /// Create a new SQL tokenizer for the specified SQL statement
    pub fn new(dialect: &'a dyn Dialect, query: &str) -> Self {
        Self {
            dialect,
            query: query.to_string(),
            line: 1,
            col: 1,
        }
    }

    /// Tokenize the statement and produce a vector of tokens
    pub fn tokenize(&mut self) -> Result<Vec<Token>, TokenizerError> {
        let mut start = 0;
        let mut ptr = Ptr::new(&self.query);

        let mut tokens: Vec<Token> = vec![];

        while let Some(token) = self.next_token(&mut ptr)? {
            match &token {
                TokenKind::Whitespace(Whitespace::Newline) => {
                    self.line += 1;
                    self.col = 1;
                }

                TokenKind::Whitespace(Whitespace::Tab) => self.col += 4,
                TokenKind::Word(w) if w.quote_style == None => self.col += w.value.len() as u64,
                TokenKind::Word(w) if w.quote_style != None => self.col += w.value.len() as u64 + 2,
                TokenKind::Number(s) => self.col += s.len() as u64,
                TokenKind::SingleQuotedString(s) => self.col += s.len() as u64,
                _ => self.col += 1,
            }
            let end = start + ptr.pos;
            tokens.push(Token {
                kind: token,
                span: start..end,
            });
            ptr.reset();
            start = end;
        }
        Ok(tokens)
    }

    /// Get the next token or return None
    fn next_token(&self, ptr: &mut Ptr<'_>) -> Result<Option<TokenKind>, TokenizerError> {
        //println!("next_token: {:?}", chars.peek());
        match ptr.peek() {
            Some(ch) => match ch {
                ' ' => self.consume_and_return(ptr, TokenKind::Whitespace(Whitespace::Space)),
                '\t' => self.consume_and_return(ptr, TokenKind::Whitespace(Whitespace::Tab)),
                '\n' => self.consume_and_return(ptr, TokenKind::Whitespace(Whitespace::Newline)),
                '\r' => {
                    // Emit a single Whitespace::Newline token for \r and \r\n
                    ptr.next();
                    if let Some('\n') = ptr.peek() {
                        ptr.next();
                    }
                    Ok(Some(TokenKind::Whitespace(Whitespace::Newline)))
                }
                'N' => {
                    ptr.next(); // consume, to check the next char
                    match ptr.peek() {
                        Some('\'') => {
                            // N'...' - a <national character string literal>
                            let s = self.tokenize_single_quoted_string(ptr);
                            Ok(Some(TokenKind::NationalStringLiteral(s)))
                        }
                        _ => {
                            // regular identifier starting with an "N"
                            let s = self.tokenize_word('N', ptr);
                            Ok(Some(TokenKind::make_word(&s, None)))
                        }
                    }
                }
                // The spec only allows an uppercase 'X' to introduce a hex
                // string, but PostgreSQL, at least, allows a lowercase 'x' too.
                x @ 'x' | x @ 'X' => {
                    ptr.next(); // consume, to check the next char
                    match ptr.peek() {
                        Some('\'') => {
                            // X'...' - a <binary string literal>
                            let s = self.tokenize_single_quoted_string(ptr);
                            Ok(Some(TokenKind::HexStringLiteral(s)))
                        }
                        _ => {
                            // regular identifier starting with an "X"
                            let s = self.tokenize_word(x, ptr);
                            Ok(Some(TokenKind::make_word(&s, None)))
                        }
                    }
                }
                // identifier or keyword
                ch if self.dialect.is_identifier_start(ch) => {
                    ptr.next(); // consume the first char
                    let s = self.tokenize_word(ch, ptr);
                    Ok(Some(TokenKind::make_word(&s, None)))
                }
                // string
                '\'' => {
                    let s = self.tokenize_single_quoted_string(ptr);
                    Ok(Some(TokenKind::SingleQuotedString(s)))
                }
                // delimited (quoted) identifier
                quote_start if self.dialect.is_delimited_identifier_start(quote_start) => {
                    ptr.next(); // consume the opening quote
                    let quote_end = Word::matching_end_quote(quote_start);
                    let s = peeking_take_while(ptr, |ch| ch != quote_end);
                    if ptr.next() == Some(quote_end) {
                        Ok(Some(TokenKind::make_word(&s, Some(quote_start))))
                    } else {
                        Err(TokenizerError(format!(
                            "Expected close delimiter '{}' before EOF.",
                            quote_end
                        )))
                    }
                }
                // numbers
                '0'..='9' => {
                    // TODO: https://jakewheat.github.io/sql-overview/sql-2011-foundation-grammar.html#unsigned-numeric-literal
                    let s = peeking_take_while(ptr, |ch| match ch {
                        '0'..='9' | '.' => true,
                        _ => false,
                    });
                    Ok(Some(TokenKind::Number(s)))
                }
                // punctuation
                '(' => self.consume_and_return(ptr, TokenKind::LParen),
                ')' => self.consume_and_return(ptr, TokenKind::RParen),
                ',' => self.consume_and_return(ptr, TokenKind::Comma),
                // operators
                '-' => {
                    ptr.next(); // consume the '-'
                    match ptr.peek() {
                        Some('-') => {
                            ptr.next(); // consume the second '-', starting a single-line comment
                            let mut s = peeking_take_while(ptr, |ch| ch != '\n');
                            if let Some(ch) = ptr.next() {
                                assert_eq!(ch, '\n');
                                s.push(ch);
                            }
                            Ok(Some(TokenKind::Whitespace(Whitespace::SingleLineComment(
                                s,
                            ))))
                        }
                        // a regular '-' operator
                        _ => Ok(Some(TokenKind::Minus)),
                    }
                }
                '/' => {
                    ptr.next(); // consume the '/'
                    match ptr.peek() {
                        Some('*') => {
                            ptr.next(); // consume the '*', starting a multi-line comment
                            self.tokenize_multiline_comment(ptr)
                        }
                        // a regular '/' operator
                        _ => Ok(Some(TokenKind::Div)),
                    }
                }
                '+' => self.consume_and_return(ptr, TokenKind::Plus),
                '*' => self.consume_and_return(ptr, TokenKind::Mult),
                '%' => self.consume_and_return(ptr, TokenKind::Mod),
                '=' => self.consume_and_return(ptr, TokenKind::Eq),
                '.' => self.consume_and_return(ptr, TokenKind::Period),
                '!' => {
                    ptr.next(); // consume
                    match ptr.peek() {
                        Some('=') => self.consume_and_return(ptr, TokenKind::Neq),
                        _ => Err(TokenizerError(format!(
                            "Tokenizer Error at Line: {}, Col: {}",
                            self.line, self.col
                        ))),
                    }
                }
                '<' => {
                    ptr.next(); // consume
                    match ptr.peek() {
                        Some('=') => self.consume_and_return(ptr, TokenKind::LtEq),
                        Some('>') => self.consume_and_return(ptr, TokenKind::Neq),
                        _ => Ok(Some(TokenKind::Lt)),
                    }
                }
                '>' => {
                    ptr.next(); // consume
                    match ptr.peek() {
                        Some('=') => self.consume_and_return(ptr, TokenKind::GtEq),
                        _ => Ok(Some(TokenKind::Gt)),
                    }
                }
                ':' => {
                    ptr.next();
                    match ptr.peek() {
                        Some(':') => self.consume_and_return(ptr, TokenKind::DoubleColon),
                        _ => Ok(Some(TokenKind::Colon)),
                    }
                }
                ';' => self.consume_and_return(ptr, TokenKind::SemiColon),
                '\\' => self.consume_and_return(ptr, TokenKind::Backslash),
                '[' => self.consume_and_return(ptr, TokenKind::LBracket),
                ']' => self.consume_and_return(ptr, TokenKind::RBracket),
                '&' => self.consume_and_return(ptr, TokenKind::Ampersand),
                '{' => self.consume_and_return(ptr, TokenKind::LBrace),
                '}' => self.consume_and_return(ptr, TokenKind::RBrace),
                other => self.consume_and_return(ptr, TokenKind::Char(other)),
            },
            None => Ok(None),
        }
    }

    /// Tokenize an identifier or keyword, after the first char is already consumed.
    fn tokenize_word(&self, first_char: char, ptr: &mut Ptr<'_>) -> String {
        let mut s = first_char.to_string();
        s.push_str(&peeking_take_while(ptr, |ch| {
            self.dialect.is_identifier_part(ch)
        }));
        s
    }

    /// Read a single quoted string, starting with the opening quote.
    fn tokenize_single_quoted_string(&self, ptr: &mut Ptr<'_>) -> String {
        //TODO: handle escaped quotes in string
        //TODO: handle newlines in string
        //TODO: handle EOF before terminating quote
        //TODO: handle 'string' <white space> 'string continuation'
        let mut s = String::new();
        ptr.next(); // consume the opening quote
        while let Some(ch) = ptr.peek() {
            match ch {
                '\'' => {
                    ptr.next(); // consume
                    let escaped_quote = ptr.peek().map(|c| c == '\'').unwrap_or(false);
                    if escaped_quote {
                        s.push('\'');
                        ptr.next();
                    } else {
                        break;
                    }
                }
                _ => {
                    ptr.next(); // consume
                    s.push(ch);
                }
            }
        }
        s
    }

    fn tokenize_multiline_comment(
        &self,
        ptr: &mut Ptr<'_>,
    ) -> Result<Option<TokenKind>, TokenizerError> {
        let mut s = String::new();
        let mut maybe_closing_comment = false;
        // TODO: deal with nested comments
        loop {
            match ptr.next() {
                Some(ch) => {
                    if maybe_closing_comment {
                        if ch == '/' {
                            break Ok(Some(TokenKind::Whitespace(Whitespace::MultiLineComment(s))));
                        } else {
                            s.push('*');
                        }
                    }
                    maybe_closing_comment = ch == '*';
                    if !maybe_closing_comment {
                        s.push(ch);
                    }
                }
                None => {
                    break Err(TokenizerError(
                        "Unexpected EOF while in a multi-line comment".to_string(),
                    ));
                }
            }
        }
    }

    fn consume_and_return(
        &self,
        ptr: &mut Ptr<'_>,
        t: TokenKind,
    ) -> Result<Option<TokenKind>, TokenizerError> {
        ptr.next();
        Ok(Some(t))
    }
}

/// Read from `chars` until `predicate` returns `false` or EOF is hit.
/// Return the characters read as String, and keep the first non-matching
/// char available as `chars.next()`.
fn peeking_take_while(ptr: &mut Ptr<'_>, mut predicate: impl FnMut(char) -> bool) -> String {
    let mut s = String::new();
    while let Some(ch) = ptr.peek() {
        if predicate(ch) {
            ptr.next(); // consume
            s.push(ch);
        } else {
            break;
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::super::dialect::GenericDialect;
    use super::*;

    #[test]
    fn tokenize_select_1() {
        let sql = String::from("SELECT 1");
        let dialect = GenericDialect {};
        let mut tokenizer = Tokenizer::new(&dialect, &sql);
        let tokens = tokenizer.tokenize().unwrap();

        let expected = vec![
            TokenKind::make_keyword("SELECT"),
            TokenKind::Whitespace(Whitespace::Space),
            TokenKind::Number(String::from("1")),
        ];

        compare(expected, tokens);
    }

    #[test]
    fn tokenize_scalar_function() {
        let sql = String::from("SELECT sqrt(1)");
        let dialect = GenericDialect {};
        let mut tokenizer = Tokenizer::new(&dialect, &sql);
        let tokens = tokenizer.tokenize().unwrap();

        let expected = vec![
            TokenKind::make_keyword("SELECT"),
            TokenKind::Whitespace(Whitespace::Space),
            TokenKind::make_word("sqrt", None),
            TokenKind::LParen,
            TokenKind::Number(String::from("1")),
            TokenKind::RParen,
        ];

        compare(expected, tokens);
    }

    #[test]
    fn tokenize_simple_select() {
        let sql = String::from("SELECT * FROM customer WHERE id = 1 LIMIT 5");
        let dialect = GenericDialect {};
        let mut tokenizer = Tokenizer::new(&dialect, &sql);
        let tokens = tokenizer.tokenize().unwrap();

        let expected = vec![
            TokenKind::make_keyword("SELECT"),
            TokenKind::Whitespace(Whitespace::Space),
            TokenKind::Mult,
            TokenKind::Whitespace(Whitespace::Space),
            TokenKind::make_keyword("FROM"),
            TokenKind::Whitespace(Whitespace::Space),
            TokenKind::make_word("customer", None),
            TokenKind::Whitespace(Whitespace::Space),
            TokenKind::make_keyword("WHERE"),
            TokenKind::Whitespace(Whitespace::Space),
            TokenKind::make_word("id", None),
            TokenKind::Whitespace(Whitespace::Space),
            TokenKind::Eq,
            TokenKind::Whitespace(Whitespace::Space),
            TokenKind::Number(String::from("1")),
            TokenKind::Whitespace(Whitespace::Space),
            TokenKind::make_keyword("LIMIT"),
            TokenKind::Whitespace(Whitespace::Space),
            TokenKind::Number(String::from("5")),
        ];

        compare(expected, tokens);
    }

    #[test]
    fn tokenize_string_predicate() {
        let sql = String::from("SELECT * FROM customer WHERE salary != 'Not Provided'");
        let dialect = GenericDialect {};
        let mut tokenizer = Tokenizer::new(&dialect, &sql);
        let tokens = tokenizer.tokenize().unwrap();

        let expected = vec![
            TokenKind::make_keyword("SELECT"),
            TokenKind::Whitespace(Whitespace::Space),
            TokenKind::Mult,
            TokenKind::Whitespace(Whitespace::Space),
            TokenKind::make_keyword("FROM"),
            TokenKind::Whitespace(Whitespace::Space),
            TokenKind::make_word("customer", None),
            TokenKind::Whitespace(Whitespace::Space),
            TokenKind::make_keyword("WHERE"),
            TokenKind::Whitespace(Whitespace::Space),
            TokenKind::make_word("salary", None),
            TokenKind::Whitespace(Whitespace::Space),
            TokenKind::Neq,
            TokenKind::Whitespace(Whitespace::Space),
            TokenKind::SingleQuotedString(String::from("Not Provided")),
        ];

        compare(expected, tokens);
    }

    #[test]
    fn tokenize_invalid_string() {
        let sql = String::from("\nمصطفىh");

        let dialect = GenericDialect {};
        let mut tokenizer = Tokenizer::new(&dialect, &sql);
        let tokens = tokenizer.tokenize().unwrap();
        println!("tokens: {:#?}", tokens);
        let expected = vec![
            TokenKind::Whitespace(Whitespace::Newline),
            TokenKind::Char('م'),
            TokenKind::Char('ص'),
            TokenKind::Char('ط'),
            TokenKind::Char('ف'),
            TokenKind::Char('ى'),
            TokenKind::make_word("h", None),
        ];
        compare(expected, tokens);
    }

    #[test]
    fn tokenize_invalid_string_cols() {
        let sql = String::from("\n\nSELECT * FROM table\tمصطفىh");

        let dialect = GenericDialect {};
        let mut tokenizer = Tokenizer::new(&dialect, &sql);
        let tokens = tokenizer.tokenize().unwrap();
        println!("tokens: {:#?}", tokens);
        let expected = vec![
            TokenKind::Whitespace(Whitespace::Newline),
            TokenKind::Whitespace(Whitespace::Newline),
            TokenKind::make_keyword("SELECT"),
            TokenKind::Whitespace(Whitespace::Space),
            TokenKind::Mult,
            TokenKind::Whitespace(Whitespace::Space),
            TokenKind::make_keyword("FROM"),
            TokenKind::Whitespace(Whitespace::Space),
            TokenKind::make_keyword("table"),
            TokenKind::Whitespace(Whitespace::Tab),
            TokenKind::Char('م'),
            TokenKind::Char('ص'),
            TokenKind::Char('ط'),
            TokenKind::Char('ف'),
            TokenKind::Char('ى'),
            TokenKind::make_word("h", None),
        ];
        compare(expected, tokens);
    }

    #[test]
    fn tokenize_is_null() {
        let sql = String::from("a IS NULL");
        let dialect = GenericDialect {};
        let mut tokenizer = Tokenizer::new(&dialect, &sql);
        let tokens = tokenizer.tokenize().unwrap();

        let expected = vec![
            TokenKind::make_word("a", None),
            TokenKind::Whitespace(Whitespace::Space),
            TokenKind::make_keyword("IS"),
            TokenKind::Whitespace(Whitespace::Space),
            TokenKind::make_keyword("NULL"),
        ];

        compare(expected, tokens);
    }

    #[test]
    fn tokenize_comment() {
        let sql = String::from("0--this is a comment\n1");

        let dialect = GenericDialect {};
        let mut tokenizer = Tokenizer::new(&dialect, &sql);
        let tokens = tokenizer.tokenize().unwrap();
        let expected = vec![
            TokenKind::Number("0".to_string()),
            TokenKind::Whitespace(Whitespace::SingleLineComment(
                "this is a comment\n".to_string(),
            )),
            TokenKind::Number("1".to_string()),
        ];
        compare(expected, tokens);
    }

    #[test]
    fn tokenize_comment_at_eof() {
        let sql = String::from("--this is a comment");

        let dialect = GenericDialect {};
        let mut tokenizer = Tokenizer::new(&dialect, &sql);
        let tokens = tokenizer.tokenize().unwrap();
        let expected = vec![TokenKind::Whitespace(Whitespace::SingleLineComment(
            "this is a comment".to_string(),
        ))];
        compare(expected, tokens);
    }

    #[test]
    fn tokenize_multiline_comment() {
        let sql = String::from("0/*multi-line\n* /comment*/1");

        let dialect = GenericDialect {};
        let mut tokenizer = Tokenizer::new(&dialect, &sql);
        let tokens = tokenizer.tokenize().unwrap();
        let expected = vec![
            TokenKind::Number("0".to_string()),
            TokenKind::Whitespace(Whitespace::MultiLineComment(
                "multi-line\n* /comment".to_string(),
            )),
            TokenKind::Number("1".to_string()),
        ];
        compare(expected, tokens);
    }

    #[test]
    fn tokenize_multiline_comment_with_even_asterisks() {
        let sql = String::from("\n/** Comment **/\n");

        let dialect = GenericDialect {};
        let mut tokenizer = Tokenizer::new(&dialect, &sql);
        let tokens = tokenizer.tokenize().unwrap();
        let expected = vec![
            TokenKind::Whitespace(Whitespace::Newline),
            TokenKind::Whitespace(Whitespace::MultiLineComment("* Comment *".to_string())),
            TokenKind::Whitespace(Whitespace::Newline),
        ];
        compare(expected, tokens);
    }

    #[test]
    fn tokenize_mismatched_quotes() {
        let sql = String::from("\"foo");

        let dialect = GenericDialect {};
        let mut tokenizer = Tokenizer::new(&dialect, &sql);
        assert_eq!(
            tokenizer.tokenize(),
            Err(TokenizerError(
                "Expected close delimiter '\"' before EOF.".to_string(),
            ))
        );
    }

    #[test]
    fn tokenize_newlines() {
        let sql = String::from("line1\nline2\rline3\r\nline4\r");

        let dialect = GenericDialect {};
        let mut tokenizer = Tokenizer::new(&dialect, &sql);
        let tokens = tokenizer.tokenize().unwrap();
        let expected = vec![
            TokenKind::make_word("line1", None),
            TokenKind::Whitespace(Whitespace::Newline),
            TokenKind::make_word("line2", None),
            TokenKind::Whitespace(Whitespace::Newline),
            TokenKind::make_word("line3", None),
            TokenKind::Whitespace(Whitespace::Newline),
            TokenKind::make_word("line4", None),
            TokenKind::Whitespace(Whitespace::Newline),
        ];
        compare(expected, tokens);
    }

    fn compare(expected: Vec<TokenKind>, actual: Vec<Token>) {
        let actual: Vec<TokenKind> = actual.into_iter().map(|t| t.kind).collect();
        // println!("------------------------------");
        // println!("tokens   = {:?}", actual);
        // println!("expected = {:?}", expected);
        // println!("------------------------------");
        assert_eq!(expected, actual);
    }

}
