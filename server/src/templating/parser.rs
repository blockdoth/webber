use crate::runtime::markdown::Span;
use crate::runtime::misc::date::DateFormat;
use crate::runtime::templating::error::{TemplateError, TemplateErrorMsg};
use crate::runtime::templating::lexer::TemplateTokenTyp::{Literal, Whitespace};
use crate::runtime::templating::lexer::TokenStream;
use crate::runtime::templating::lexer::{TemplateInfo, TemplatePosData};
use crate::runtime::templating::lexer::{TemplateLexer, TemplateToken, TemplateTokenTyp};
use crate::runtime::templating::template::Template;
use std::collections::HashMap;
use std::fmt::Debug;

use std::rc::Rc;
use std::time::SystemTime;
use std::vec;

#[derive(Debug, Clone)]
pub struct TemplateNode {
    pub expr: TemplateStatement,
    pub pos: TemplatePosData,
}

#[derive(Debug, Clone)]
pub enum UnaryOperator {
    Not,
}

#[derive(Debug, Clone)]
pub enum BinaryOperator {
    Equals,
}

#[derive(Debug, Clone)]
pub enum TemplateExpr {
    Grouping(Vec<TemplateNode>),
    Text(String),
    Number(i64),
    Bool(bool),
    Variable(String),
    Field {
        parent: Box<TemplateNode>,
        name: String,
        optional: bool,
    },
    Index {
        parent: Box<TemplateNode>,
        name: Box<TemplateNode>,
    },
    Range {
        parent: Box<TemplateNode>,
        start: Box<TemplateNode>,
        end: Box<TemplateNode>,
    },
    BinaryOp {
        op: BinaryOperator,
        left: Box<TemplateNode>,
        right: Box<TemplateNode>,
    },
    UnaryOp {
        op: UnaryOperator,
        operand: Box<TemplateNode>,
    },
    Date {
        date_var: Box<TemplateNode>,
        format: DateFormat,
    },
}

#[derive(Debug, Clone)]
pub enum TemplateStatement {
    Content(Vec<TemplateNode>),
    Expression(Vec<TemplateNode>),
    If {
        condition: Box<TemplateNode>,
        then_branch: Vec<TemplateNode>,
        else_branch: Option<Vec<TemplateNode>>,
    },
    For {
        iter_bind: ForIterBind,
        iter_src: Box<TemplateNode>,
        body: Vec<TemplateNode>,
    },
    Block {
        ident: String,
        body: Vec<TemplateNode>,
    },
    //  ---
    Grouping(Vec<TemplateNode>),
    Text(String),
    Number(i64),
    Bool(bool),
    Variable(String),
    Field {
        parent: Box<TemplateNode>,
        name: String,
        optional: bool,
    },
    Index {
        parent: Box<TemplateNode>,
        name: Box<TemplateNode>,
    },
    Range {
        parent: Box<TemplateNode>,
        start: Box<TemplateNode>,
        end: Box<TemplateNode>,
    },
    BinaryOp {
        op: BinaryOperator,
        left: Box<TemplateNode>,
        right: Box<TemplateNode>,
    },
    UnaryOp {
        op: UnaryOperator,
        operand: Box<TemplateNode>,
    },
    Date {
        date_var: Box<TemplateNode>,
        format: DateFormat,
    },
}

#[derive(Debug, Clone)]
pub enum ForIterBind {
    Simple(String),
    Object((String, String)), // TODO expand
}

#[derive(Clone, Debug, PartialEq)]
pub enum TemplateStatementKind {
    If,
    For,
    Block,
    Content,
    Expr,
    // ---
    Text,
    Date,
    Variable,
    Bool,
    Number,
    Field,
    Index,
    Grouping,
    BinaryOp,
    UnaryOp,
    Range,
}


impl TemplateStatement {
    fn kind(&self) -> TemplateStatementKind {
        match self {
            TemplateStatement::Content(_) => TemplateStatementKind::Content,
            TemplateStatement::If { .. } => TemplateStatementKind::If,
            TemplateStatement::For { .. } => TemplateStatementKind::For,
            TemplateStatement::Block { .. } => TemplateStatementKind::Block,
            TemplateStatement::Expression(_) => TemplateStatementKind::Expr,
            // ---
            TemplateStatement::Grouping(_) => TemplateStatementKind::Grouping,
            TemplateStatement::Text(_) => TemplateStatementKind::Text,
            TemplateStatement::Number(_) => TemplateStatementKind::Number,
            TemplateStatement::Bool(_) => TemplateStatementKind::Bool,
            TemplateStatement::Variable(_) => TemplateStatementKind::Variable,
            TemplateStatement::Field { .. } => TemplateStatementKind::Field,
            TemplateStatement::Index { .. } => TemplateStatementKind::Index,
            TemplateStatement::Range { .. } => TemplateStatementKind::Range,
            TemplateStatement::BinaryOp { .. } => TemplateStatementKind::BinaryOp,
            TemplateStatement::UnaryOp { .. } => TemplateStatementKind::UnaryOp,
            TemplateStatement::Date { .. } => TemplateStatementKind::Date,
        }
    }
}


pub struct TemplateParser<'a> {
    pub file_path: Rc<str>,
    pub input: &'a str,
    pub newlines: Vec<usize>,
    pub blocks: HashMap<String, Vec<TemplateNode>>,
    pub stream: TokenStream,
}

impl TemplateParser<'_> {
    pub fn parse(input: &str, file_path: &str) -> Result<Template, TemplateError> {
        let file_path: Rc<str> = Rc::from(file_path);
        let mut parser = TemplateLexer::lex(file_path.clone(), input);

        let parent = parser.parse_parent();
        let template = parser.parse_until(&[])?;

        Ok(Template {
            template,
            parent,
            blocks: parser.blocks,
            origin_file: file_path,
            last_modified: SystemTime::now(),
            input: input.to_owned(),
            newlines: parser.newlines,
        })
    }

    fn show_next_n_tokens(&mut self, mut n: usize) {
        print!("next {n} tokens: ");
        while n > 0 {
            if let Some(tok) = self.stream.next() {
                let tok_str = tok.span().to_str(self.input);
                match tok {
                    TemplateToken::Text(_) => print!("{tok_str}, "),
                    TemplateToken::Number(_) => print!("{tok_str}, "),
                    TemplateToken::Identifier(_) => print!("{tok_str}, "),
                    TemplateToken::Literal(_) => print!("\"{tok_str}\", "),
                    _ => print!("{:?}, ", tok.typ()),
                }
            }
            n -= 1;
        }
        println!();
    }

    fn parse_parent(&mut self) -> Option<String> {
        self.stream.try_consume(TemplateTokenTyp::Extends)?;
        self.stream.try_consume(TemplateTokenTyp::Whitespace)?;
        let node = self.stream.try_consume(TemplateTokenTyp::Literal)?;

        Some(node.span().to_str(self.input).to_owned())
    }

    fn span_to_position(&self, span: Span) -> TemplatePosData {
        TemplatePosData {
            file: self.file_path.clone(),
            span: Some(span),
        }
    }

    fn range_to_position(&self, start: usize, end: usize) -> TemplatePosData {
        TemplatePosData {
            file: self.file_path.clone(),
            span: Some(Span::from_double(start, end)),
        }
    }

    fn error(&self, typ: TemplateErrorMsg, pos: TemplatePosData) -> TemplateError {
        TemplateError {
            typ,
            pos: Some(pos),
            info: Some(Box::new(TemplateInfo {
                input: self.input.to_owned(),
                newlines: self.newlines.clone(),
                last_modified: SystemTime::now(),
            })),
        }
    }

    fn parse_until(
        &mut self,
        stop: &[TemplateTokenTyp],
    ) -> Result<Vec<TemplateNode>, TemplateError> {
        use TemplateToken::*;
        let mut parsed_nodes = vec![];

        while let Some(next_token) = self.stream.peek() {
            if stop.contains(&next_token.typ()) {
                break;
            }

            let nodes = match next_token {
                If(_) => self.parse_if()?,
                For(_) => self.parse_for()?,
                Block(_) => self.parse_block()?,
                Whitespace(_) | NewLine(_) => {
                    self.stream.skip(1);
                    continue;
                }
                Extends(span) => {
                    return Err(self.error(
                        TemplateErrorMsg::ExtendsNotFirstLine,
                        self.span_to_position(span.clone()),
                    ));
                }
                Date(_) => self.parse_date()?,
                Identifier(_) => self.parse_var()?,

                Text(_) => {
                    let text_span = self.consume(TemplateTokenTyp::Text)?;
                    let text_str = text_span.to_str(self.input).to_string();
                    TemplateNode {
                        expr: TemplateStatement::Text(text_str),
                        pos: self.position_from_span(text_span),
                    }
                }
                tok => {
                    return Err(self.error(
                        TemplateErrorMsg::DidNotExpectToken(tok.typ()),
                        self.range_to_position(tok.start() - 1, tok.end() - 1),
                    ));
                }
            };

            parsed_nodes.push(nodes);
        }

        Ok(parsed_nodes)
    }

    fn make_grouping(&self, nodes: Vec<TemplateNode>) -> TemplateNode {
        let pos = match (nodes.first(), nodes.last()) {
            (Some(first), Some(last)) => match (first.pos.span.as_ref(), last.pos.span.as_ref()) {
                (Some(first_span), Some(last_span)) => {
                    self.position_from_span(Span::from_double(first_span.start, last_span.end))
                }
                _ => self.position_from_self(),
            },
            _ => self.position_from_self(),
        };

        TemplateNode {
            expr: TemplateStatement::Grouping(nodes),
            pos,
        }
    }

    fn position_from_span(&self, span: Span) -> TemplatePosData {
        TemplatePosData {
            file: self.file_path.clone(),
            span: Some(span),
        }
    }

    fn position_from_self(&self) -> TemplatePosData {
        TemplatePosData {
            file: self.file_path.clone(),
            span: None,
        }
    }
    fn position_at_eof(&self) -> TemplatePosData {
        TemplatePosData {
            file: self.file_path.clone(),
            span: Some(Span::from_single(self.input.len())),
        }
    }

    fn consume(&mut self, expected: TemplateTokenTyp) -> Result<Span, TemplateError> {
        let Some(token) = self.stream.peek() else {
            return Err(self.error(TemplateErrorMsg::UnexpectedEOF, self.position_at_eof()));
        };

        if token.typ() != expected {
            return Err(self.error(
                TemplateErrorMsg::UnexpectedToken(token.typ(), expected),
                self.span_to_position(token.span().clone()),
            ));
        }

        Ok(self.stream.next().unwrap().span().clone())
    }

    fn parse_if(&mut self) -> Result<TemplateNode, TemplateError> {
        use TemplateTokenTyp::*;

        let start_tok = self.consume(If)?;
        self.consume(Whitespace)?;

        let condition = Box::new(self.parse_expression()?);

        let then_branch = self.parse_until(&[Else, EndIf])?;

        let next_tok = self.stream.peek().unwrap();
        match next_tok.typ() {
            Else => {
                // Self::show_next_n_tokens(tokens, 3);
                self.consume(Else)?;
                let else_branch = Some(self.parse_until(&[EndElse])?);
                let end_tok = self.consume(EndElse)?;
                Ok(TemplateNode {
                    expr: TemplateStatement::If {
                        condition,
                        then_branch,
                        else_branch,
                    },
                    pos: self.range_to_position(start_tok.start, end_tok.end),
                })
            }
            EndIf => {
                let end_tok = self.consume(EndIf)?;

                Ok(TemplateNode {
                    expr: TemplateStatement::If {
                        condition,
                        then_branch,
                        else_branch: None,
                    },
                    pos: self.range_to_position(start_tok.start, end_tok.end),
                })
            }
            tok => Err(self.error(
                TemplateErrorMsg::UnexpectedTokenOptions(tok, vec![Else, EndIf]),
                self.span_to_position(next_tok.span().clone()),
            ))?,
        }
    }

    fn parse_for(&mut self) -> Result<TemplateNode, TemplateError> {
        use TemplateTokenTyp::*;
        let start_tok = self.consume(For)?;
        self.consume(Whitespace)?;

        let key_bind = self.consume(Identifier)?;
        let iter_bind = if self.stream.try_consume(Comma).is_some() {
            self.stream.try_consume(Whitespace);
            let value_bind = self.consume(Identifier)?;
            ForIterBind::Object((
                key_bind.to_str(self.input).to_string(),
                value_bind.to_str(self.input).to_string(),
            ))
        } else {
            ForIterBind::Simple(key_bind.to_str(self.input).to_string())
        };

        self.consume(Whitespace)?;
        self.consume(In)?;
        self.consume(Whitespace)?;

        // Self::show_next_n_tokens(tokens, 3);
        let iter_src = Box::new(self.parse_expression()?);

        // Self::show_next_n_tokens(tokens, 3);
        let body = self.parse_until(&[EndFor])?;

        let end_tok = self.consume(EndFor)?;

        Ok(TemplateNode {
            expr: TemplateStatement::For {
                iter_bind,
                iter_src,
                body,
            },
            pos: self.range_to_position(start_tok.start, end_tok.end),
        })
    }

    fn parse_block(&mut self) -> Result<TemplateNode, TemplateError> {
        use TemplateTokenTyp::*;

        let start_tok = self.consume(Block)?;
        self.consume(Whitespace)?;
        let ident_span = self.consume(Literal)?;
        let ident = ident_span.to_str(self.input).to_string();

        let body = self.parse_until(&[EndBlock])?;
        let end_tok = self.consume(EndBlock)?;

        self.blocks.insert(ident.clone(), body.clone());

        Ok(TemplateNode {
            expr: TemplateStatement::Block { ident, body },
            pos: self.position_from_span(Span::from_double(start_tok.start, end_tok.end)),
        })
    }

    fn parse_expression(&mut self) -> Result<TemplateNode, TemplateError> {
        let expr = self.parse_primary()?;
        self.parse_postfix(expr)
    }

    fn parse_primary(&mut self) -> Result<TemplateNode, TemplateError> {
        match self.stream.peek().map(TemplateToken::typ) {
            Some(TemplateTokenTyp::Identifier) => self.parse_var(),
            Some(TemplateTokenTyp::Number) => self.parse_number(),
            Some(TemplateTokenTyp::Literal) => self.parse_literal(),
            Some(TemplateTokenTyp::Date) => self.parse_date(),
            _ => todo!(),
        }
    }
    fn parse_var(&mut self) -> Result<TemplateNode, TemplateError> {
        let ident_span = self.consume(TemplateTokenTyp::Identifier)?;
        let ident_str = ident_span.to_str(self.input).to_string();
        Ok(TemplateNode {
            expr: TemplateStatement::Variable(ident_str),
            pos: self.position_from_span(ident_span),
        })
    }

    fn parse_postfix(&mut self, _parent: TemplateNode) -> Result<TemplateNode, TemplateError> {
        todo!()
    }

    fn parse_number(&mut self) -> Result<TemplateNode, TemplateError> {
        todo!()
    }

    fn parse_literal(&mut self) -> Result<TemplateNode, TemplateError> {
        todo!()
    }

    fn parse_date(&mut self) -> Result<TemplateNode, TemplateError> {
        let start_tok = self.consume(TemplateTokenTyp::Date)?;
        self.consume(Whitespace)?;

        let node = Box::new(self.parse_expression()?);

        self.consume(Whitespace)?;
        let format_span = self.consume(Literal)?;
        let format_str = format_span.to_str(self.input);

        let Some(format) = DateFormat::parse(format_str) else {
            return Err(self.error(
                TemplateErrorMsg::UnknownDateFormat(format_str.to_string()),
                self.range_to_position(format_span.start, format_span.end),
            ));
        };

        Ok(TemplateNode {
            expr: TemplateStatement::Date {
                date_var: node,
                format,
            },
            pos: self.range_to_position(start_tok.start - 1, format_span.end),
        })
    }
}
