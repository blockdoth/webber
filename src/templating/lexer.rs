use std::collections::HashMap;
use std::fmt::Debug;

use std::time::SystemTime;
use std::vec;

use crate::runtime::markdown::Span;
use crate::runtime::templating::parser::TemplateParser;

#[derive(Debug, Clone)]
pub struct TemplateInfo {
    pub input: String,
    pub newlines: Vec<usize>,
    pub last_modified: SystemTime,
}

#[derive(Debug, Clone)]
pub struct TemplatePositionData {
    pub file: String,
    pub span: Option<Span>,
}

#[derive(Clone, Debug)]
pub struct Position {
    pub line: usize,
    pub column: usize,
}

#[derive(Debug, PartialEq, Clone)]
pub enum TemplateToken {
    Text(Span),
    Number(Span),
    Identifier(Span),
    Literal(Span),
    Dot(Span),
    BracketOpen(Span),
    BracketClose(Span),
    Equals(Span),
    Whitespace(Span),
    If(Span),
    Else(Span),
    For(Span),
    In(Span),
    EndIf(Span),
    EndElse(Span),
    EndFor(Span),
    NewLine(Span),
    Block(Span),
    EndBlock(Span),
    Extends(Span),
    Date(Span),
    Skip(Span),
}

#[derive(Debug, PartialEq, Clone)]
pub enum TemplateTokenTyp {
    Text,
    Identifier,
    Literal,
    If,
    Else,
    For,
    In,
    EndIf,
    EndElse,
    EndFor,
    Block,
    EndBlock,
    Extends,
    NewLine,
    Whitespace,
    Dot,
    Date,
    Equals,
    BracketOpen,
    BracketClose,
    Number,
    Skip,
}

impl TemplateToken {
    pub fn typ(&self) -> TemplateTokenTyp {
        use TemplateToken as Token;
        use TemplateTokenTyp as Typ;

        match self {
            Token::Text(_) => Typ::Text,
            Token::Number(_) => Typ::Number,
            Token::Identifier(_) => Typ::Identifier,
            Token::If(_) => Typ::If,
            Token::Else(_) => Typ::Else,
            Token::For(_) => Typ::For,
            Token::In(_) => Typ::In,
            Token::EndIf(_) => Typ::EndIf,
            Token::EndElse(_) => Typ::EndElse,
            Token::EndFor(_) => Typ::EndFor,
            Token::Block(_) => Typ::Block,
            Token::BracketOpen(_) => Typ::BracketOpen,
            Token::BracketClose(_) => Typ::BracketClose,
            Token::EndBlock(_) => Typ::EndBlock,
            Token::Extends(_) => Typ::Extends,
            Token::NewLine(_) => Typ::NewLine,
            Token::Whitespace(_) => Typ::Whitespace,
            Token::Dot(_) => Typ::Dot,
            Token::Date(_) => Typ::Date,
            Token::Equals(_) => Typ::Equals,
            Token::Literal(_) => Typ::Literal,
            Token::Skip(_) => Typ::Skip,
        }
    }

    pub fn span(&self) -> &Span {
        match self {
            Self::Text(span)
            | Self::Number(span)
            | Self::Identifier(span)
            | Self::Dot(span)
            | Self::Equals(span)
            | Self::Whitespace(span)
            | Self::If(span)
            | Self::Else(span)
            | Self::For(span)
            | Self::In(span)
            | Self::EndIf(span)
            | Self::BracketOpen(span)
            | Self::BracketClose(span)
            | Self::EndElse(span)
            | Self::EndFor(span)
            | Self::NewLine(span)
            | Self::Block(span)
            | Self::EndBlock(span)
            | Self::Date(span)
            | Self::Extends(span)
            | Self::Literal(span) => span,
            Self::Skip(span) => span,
        }
    }

    pub fn start(&self) -> usize {
        self.span().start
    }

    pub fn end(&self) -> usize {
        self.span().end
    }
}

// === Template lexer
pub struct TemplateLexer<'a> {
    file_path: &'a str,
    input: &'a str,
    newlines: Vec<usize>,
}

impl<'a> TemplateLexer<'a> {
    pub fn lex(file_path: &'a str, input: &'a str) -> TemplateParser<'a> {
        use TemplateToken::*;

        let mut lexer = TemplateLexer {
            file_path,
            input,
            newlines: vec![],
        };

        let mut tokens = vec![];
        let input: &'a str = lexer.input;

        let mut text_start = 0;
        let mut cursor = 0;

        while cursor < input.len() {
            let rest = &input[cursor..];

            if rest.starts_with("{{") {
                if text_start < cursor {
                    tokens.push(Text(Span::from_double(text_start, cursor)));
                }
                let code_start = cursor + 2;

                let Some(code_len) = input[code_start..].find("}}") else {
                    // Not closed
                    tokens.push(Text(Span::from_double(cursor, input.len())));
                    cursor = input.len();
                    text_start = cursor;
                    break;
                };

                let code_end = code_start + code_len;

                tokens.extend(lexer.lex_code(code_start, code_end));
                cursor = code_end + 2;
                text_start = cursor;
            } else if let Some(c) = rest.chars().next() {
                if c == '\n' {
                    lexer.newlines.push(cursor + 1);
                }

                cursor += c.len_utf8();
            }
        }

        if text_start < input.len() {
            tokens.push(Text(Span::from_double(text_start, input.len())));
        }

        TemplateParser {
            file_path: lexer.file_path,
            input: lexer.input,
            newlines: lexer.newlines,
            blocks: HashMap::new(),
            tokens,
            cursor: 0,
        }
    }

    fn lex_code(&mut self, start: usize, end: usize) -> Vec<TemplateToken> {
        use TemplateToken::*;

        type LookupTable<'a> = &'a [(&'a str, fn(Span) -> TemplateToken)];

        const KEYWORDS: LookupTable = &[
            ("endBlock", EndBlock),
            ("endElse", EndElse),
            ("extends", Extends),
            ("endFor", EndFor),
            ("endIf", EndIf),
            ("block", Block),
            ("date", Date),
            ("skip", Skip),
            ("else", Else),
            ("for", For),
            ("if", If),
            ("in", In),
        ];

        let input: &'a str = self.input;
        let mut tokens = vec![];

        let mut cursor = start;

        let mut start_ident = start;
        while cursor < end {
            let rest = &input[cursor..];

            if let Some((token, length)) =
                match rest.chars().next().expect("non-empty rest invariant") {
                    '.' => Some((Dot(Span::from_double(cursor, cursor + 1)), 1)),
                    '[' => Some((BracketOpen(Span::from_double(cursor, cursor + 1)), 1)),
                    ']' => Some((BracketClose(Span::from_double(cursor, cursor + 1)), 1)),

                    '\n' => {
                        let next = cursor + 1;
                        self.newlines.push(next);

                        Some((NewLine(Span::from_double(cursor, next)), 1))
                    }

                    ' ' => {
                        let length = rest.chars().take_while(|&c| c == ' ').count();

                        Some((
                            Whitespace(Span::from_double(cursor, cursor + length)),
                            length,
                        ))
                    }

                    '=' => {
                        let length = rest.chars().take_while(|&c| c == '=').count();

                        Some((Equals(Span::from_double(cursor, cursor + length)), length))
                    }
                    '"' => {
                        let start = cursor + 1;
                        let Some(path_len) = input[start..end].find("\"") else {
                            // Not closed
                            tokens.push(Literal(Span::from_double(start, input.len())));
                            break;
                        };
                        cursor += path_len;
                        start_ident = cursor;
                        Some((
                            Literal(Span::from_double(start, start + path_len)),
                            path_len,
                        ))
                    }

                    _ => None,
                }
            {
                Self::flush_ident(&mut tokens, input, start_ident, cursor);

                tokens.push(token);
                cursor += length;
                start_ident = cursor;
                continue;
            } else if let Some((make_token, keyword_end)) =
                KEYWORDS.iter().find_map(|(keyword, make_token)| {
                    if !rest.starts_with(keyword) {
                        return None;
                    }

                    let keyword_end = cursor + keyword.len();

                    // Do not tokenize the "if" in identifiers such as "iffy"
                    if Self::valid_keyword(input, cursor, keyword_end) {
                        Some((make_token, keyword_end))
                    } else {
                        None
                    }
                })
            {
                Self::flush_ident(&mut tokens, input, start_ident, cursor);

                tokens.push(make_token(Span::from_double(cursor, keyword_end)));
                cursor = keyword_end;
                start_ident = cursor;
            } else {
                cursor += 1;
            }
        }
        Self::flush_ident(&mut tokens, input, start_ident, end);

        tokens
    }

    fn valid_keyword(input: &str, start: usize, end: usize) -> bool {
        let valid_before = input[..start]
            .chars()
            .next_back()
            .is_none_or(|c| matches!(c, ' ' | '\n' | '{' | '}'));

        let valid_after = input[end..]
            .chars()
            .next()
            .is_none_or(|c| matches!(c, ' ' | '\n' | '{' | '}'));

        valid_before && valid_after
    }

    fn flush_ident(tokens: &mut Vec<TemplateToken>, input: &str, start: usize, end: usize) {
        if start >= end {
            return;
        }

        let span = Span::from_double(start, end);
        let text = &input[start..end];

        if text.bytes().all(|c| c.is_ascii_digit()) {
            tokens.push(TemplateToken::Number(span));
        } else {
            tokens.push(TemplateToken::Identifier(span));
        }
    }
}
