use crate::runtime::markdown::Span;
use crate::runtime::templating::error::{TemplateError, TemplateErrorMsg};
use crate::runtime::templating::lexer::{TemplateInfo, TemplatePositionData};
use crate::runtime::templating::lexer::{TemplateLexer, TemplateToken, TemplateTokenTyp};
use crate::runtime::templating::template::Template;
use std::collections::HashMap;
use std::fmt::{Debug, Display};

use std::time::SystemTime;
use std::{fmt, vec};

pub struct TemplateParser<'a> {
    pub file_path: &'a str,
    pub input: &'a str,
    pub newlines: Vec<usize>,
    pub blocks: HashMap<String, Vec<TemplateNode>>,
    pub tokens: Vec<TemplateToken>,
    pub cursor: usize,
}

impl TemplateParser<'_> {
    pub fn parse(input: &str, file_path: &str) -> Result<Template, TemplateError> {
        let mut parser = TemplateLexer::lex(file_path, input);

        let parent = parser.parse_parent();
        let template = parser.parse_until(&[])?;
        Ok(Template {
            template,
            parent,
            blocks: parser.blocks,
            origin_file: file_path.to_string(),
            last_modified: SystemTime::now(),
            input: input.to_owned(),
            newlines: parser.newlines,
        })
    }

    fn show_next_n_tokens(&self, n: usize) {
        let len = if self.cursor + n < self.tokens.len() {
            n
        } else {
            self.tokens.len() - self.cursor
        };

        print!("next {n} tokens: ");
        for tok in &self.tokens[self.cursor..self.cursor + len] {
            let tok_str = tok.span().to_str(self.input);
            match tok {
                TemplateToken::Text(_) => print!("{tok_str}, "),
                TemplateToken::Number(_) => print!("{tok_str}, "),
                TemplateToken::Identifier(_) => print!("'{tok_str}', "),
                TemplateToken::Literal(_) => print!("~{tok_str}~, "),
                _ => print!("{:?}, ", tok.typ()),
            }
        }
        println!();
    }

    fn parse_parent(&mut self) -> Option<String> {
        use TemplateToken::*;
        match &self.tokens.as_slice() {
            [Extends(..), Whitespace(..), Literal(span), ..] => {
                self.cursor = 3;

                Some(span.to_str(self.input).to_owned())
            }
            _ => None,
        }
    }

    fn span_to_position(&self, span: &Span) -> TemplatePositionData {
        TemplatePositionData {
            file: self.file_path.to_string(),
            span: Some(span.clone()),
        }
    }

    fn range_to_position(&self, start: usize, end: usize) -> TemplatePositionData {
        TemplatePositionData {
            file: self.file_path.to_string(),
            span: Some(Span::from_double(start, end)),
        }
    }

    fn error(&self, typ: TemplateErrorMsg, pos: TemplatePositionData) -> TemplateError {
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

        while self.cursor < self.tokens.len() {
            let next_token = self.next_token()?;

            if stop.contains(&next_token.typ()) {
                break;
            }

            let nodes = match next_token {
                If(_) => self.parse_if()?,

                For(_) => self.parse_for()?,
                Block(_) => self.parse_block()?,
                Whitespace(_) | NewLine(_) => {
                    self.cursor += 1;
                    continue;
                }
                Extends(span) => {
                    return Err(self.error(
                        TemplateErrorMsg::ExtendsNotFirstLine,
                        self.span_to_position(span),
                    ));
                }
                Date(_) => self.parse_date()?,
                Identifier(_) => self.parse_var()?,

                Text(span) => {
                    let text = TemplateNode {
                        data: TemplateNodeData::Text(span.to_str(self.input).to_owned()),
                        pos: self.span_to_position(span),
                    };
                    self.consume(TemplateTokenTyp::Text)?;
                    text
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

    fn next_token(&self) -> Result<&TemplateToken, TemplateError> {
        if self.cursor >= self.tokens.len() {
            Err(self.error(
                TemplateErrorMsg::UnexpectedEOF,
                self.span_to_position(
                    self.tokens
                        .last()
                        .expect("token list should not be empty")
                        .span(),
                ),
            ))
        } else {
            Ok(&self.tokens[self.cursor])
        }
    }

    fn consume(&mut self, expected: TemplateTokenTyp) -> Result<Span, TemplateError> {
        let Some(token) = self.tokens.get(self.cursor) else {
            let position = if let Some(token) = self.tokens.last() {
                self.span_to_position(token.span())
            } else {
                let input_len = self.input.len();
                self.span_to_position(&Span::from_double(input_len, input_len))
            };
            return Err(self.error(TemplateErrorMsg::UnexpectedEOF, position));
        };

        if token.typ() != expected {
            return Err(self.error(
                TemplateErrorMsg::UnexpectedToken(token.typ(), expected),
                self.span_to_position(token.span()),
            ));
        }

        self.cursor += 1;

        Ok(token.span().clone())
    }

    fn try_consume(&mut self, expected: TemplateTokenTyp) -> Option<Span> {
        let token = self.tokens.get(self.cursor)?;

        if token.typ() != expected {
            return None;
        }
        self.cursor += 1;

        Some(token.span().clone())
    }

    fn parse_if_cond(&mut self) -> Result<ConditionExpr, TemplateError> {
        use TemplateTokenTyp::*;

        if let Some(span) = self.try_consume(Literal) {
            match span.to_str(self.input) {
                "true" => return Ok(ConditionExpr::Literal(true)),
                "false" => return Ok(ConditionExpr::Literal(false)),
                _ => {}
            }
        }

        let cond_node = self.parse_var()?;

        let cond_1 = match cond_node.data {
            TemplateNodeData::Variable(path) => path,
            node => {
                let span = cond_node.pos.span.expect("todo");
                return Err(self.error(
                    TemplateErrorMsg::UnexpectedTemplateValueType(
                        TemplateNodeKind::Variable,
                        node.kind(),
                    ),
                    self.span_to_position(&span),
                ));
            }
        };

        let _ = self.try_consume(Whitespace);
        if let Some(span) = self.try_consume(Equals)
            && span.len() == 2
        {
            let _ = self.try_consume(Whitespace);
            if let Some(literal) = self.try_consume(Literal) {
                return Ok(ConditionExpr::LiteralComp(
                    cond_1,
                    literal.to_str(self.input).to_string(),
                ));
            }

            let cond_node = self.parse_var()?;

            let span = cond_node.pos.span.expect("todo");
            match cond_node.data {
                TemplateNodeData::Variable(cond_2) => {
                    return Ok(ConditionExpr::VarComp(cond_1, cond_2));
                }
                node => {
                    return Err(self.error(
                        TemplateErrorMsg::UnexpectedTemplateValueType(
                            TemplateNodeKind::Variable,
                            node.kind(),
                        ),
                        self.span_to_position(&span),
                    ));
                }
            }
        }
        Ok(ConditionExpr::Var(cond_1))
    }

    fn parse_if(&mut self) -> Result<TemplateNode, TemplateError> {
        use TemplateTokenTyp::*;

        let start_tok = self.consume(If)?;
        self.consume(Whitespace)?;

        let condition = self.parse_if_cond()?;

        let then_branch = self.parse_until(&[Else, EndIf])?;

        let next_tok = self.next_token()?;
        let next_tok_span = next_tok.span();
        match next_tok.typ() {
            Else => {
                // Self::show_next_n_tokens(tokens, 3);
                self.consume(Else)?;
                let else_branch = self.parse_until(&[EndElse])?;
                let end_tok = self.consume(EndElse)?;
                Ok(TemplateNode {
                    data: TemplateNodeData::If {
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
                    data: TemplateNodeData::If {
                        condition,
                        then_branch,
                        else_branch: vec![],
                    },
                    pos: self.range_to_position(start_tok.start, end_tok.end),
                })
            }
            tok => Err(self.error(
                TemplateErrorMsg::UnexpectedTokenOptions(tok, vec![Else, EndIf]),
                self.span_to_position(next_tok_span),
            ))?,
        }
    }

    fn parse_var(&mut self) -> Result<TemplateNode, TemplateError> {
        let base_span = self.consume(TemplateTokenTyp::Identifier)?;
        let base = base_span.to_str(self.input).to_owned();

        let mut indices = Vec::new();
        let mut end_span = base_span.end;

        loop {
            let parsed = match self.tokens.get(self.cursor) {
                Some(TemplateToken::Dot(_)) => Some(self.parse_field_access()?),

                Some(TemplateToken::BracketOpen(_)) => Some(self.parse_index()?),

                _ => None,
            };

            let Some((end, index)) = parsed else {
                break;
            };

            indices.push(index);
            end_span = end;
        }

        Ok(TemplateNode {
            data: TemplateNodeData::Variable(Var { base, indices }),
            pos: self.span_to_position(&Span::from_double(base_span.start, end_span)),
        })
    }

    fn parse_field_access(&mut self) -> Result<(usize, VarIndex), TemplateError> {
        self.consume(TemplateTokenTyp::Dot)?;

        let field_span = self.consume(TemplateTokenTyp::Identifier)?;

        Ok((
            field_span.end,
            VarIndex::Field {
                field: field_span.to_str(self.input).to_owned(),
                span: field_span,
            },
        ))
    }

    fn parse_index(&mut self) -> Result<(usize, VarIndex), TemplateError> {
        self.consume(TemplateTokenTyp::BracketOpen)?;

        let index = if let Some(number_span) = self.try_consume(TemplateTokenTyp::Number) {
            let number_str = number_span.to_str(self.input);

            let number = number_str.parse::<usize>().map_err(|_| {
                self.error(
                    TemplateErrorMsg::UnableToParseNumber(number_str.to_owned()),
                    self.span_to_position(&number_span),
                )
            })?;

            VarIndex::Index {
                idx: number,
                span: number_span,
            }
        } else {
            let var_node = self.parse_var()?;

            let TemplateNodeData::Variable(var) = var_node.data else {
                unreachable!();
            };

            VarIndex::Var {
                var,
                span: var_node.pos.span.expect("invariant"),
            }
        };

        let close_span = self.consume(TemplateTokenTyp::BracketClose)?;

        Ok((close_span.end, index))
    }

    fn parse_date(&mut self) -> Result<TemplateNode, TemplateError> {
        use TemplateTokenTyp::*;

        let start_tok = self.consume(Date)?;
        let whitespace_tok = self.consume(Whitespace)?;

        let node = self.parse_var()?;
        let node_span = node.pos.span.expect("msg");
        let date_var = if let TemplateNodeData::Variable(var) = node.data {
            var
        } else {
            return Err(self.error(
                TemplateErrorMsg::UnexpectedTemplateValueType(
                    TemplateNodeKind::Variable,
                    node.data.kind(),
                ),
                self.range_to_position(whitespace_tok.end, node_span.end),
            ));
        };

        self.consume(Whitespace)?;
        let format_span = self.consume(Literal)?;

        Ok(TemplateNode {
            data: TemplateNodeData::Date {
                date_var,
                format: format_span.to_str(self.input).to_owned(),
            },
            pos: self.range_to_position(start_tok.start - 1, format_span.end),
        })
    }

    fn parse_for(&mut self) -> Result<TemplateNode, TemplateError> {
        use TemplateTokenTyp::*;
        let start_tok = self.consume(For)?;
        let whitespace_tok = self.consume(Whitespace)?;

        let node = self.parse_var()?;
        let node_span = node.pos.span.expect("msg");
        let bind = if let TemplateNodeData::Variable(var) = node.data {
            if var.indices.is_empty() {
                var.base
            } else {
                return Err(self.error(
                    TemplateErrorMsg::MultiLevelForLoopBind(Box::new(var)),
                    self.range_to_position(whitespace_tok.end, node_span.end),
                ));
            }
        } else {
            return Err(self.error(
                TemplateErrorMsg::UnexpectedTemplateValueType(
                    TemplateNodeKind::Variable,
                    node.data.kind(),
                ),
                self.range_to_position(whitespace_tok.end, node_span.end),
            ));
        };

        self.consume(Whitespace)?;
        self.consume(In)?;
        self.consume(Whitespace)?;

        // Self::show_next_n_tokens(tokens, 3);
        let iter_node = self.parse_var()?;
        let iter_span = iter_node.pos.span.expect("todo");
        let iter_src = match iter_node.data {
            TemplateNodeData::Variable(path) => path,
            node => {
                return Err(self.error(
                    TemplateErrorMsg::UnexpectedTemplateValueType(
                        TemplateNodeKind::Variable,
                        node.kind(),
                    ),
                    self.span_to_position(&iter_span),
                ));
            }
        };
        // Self::show_next_n_tokens(&self, 10);
        let skip = if self.try_consume(Whitespace).is_some()
            && self.consume(Skip).is_ok()
            && self.consume(Whitespace).is_ok()
            && let Ok(number_span) = self.consume(Number)
        {
            let number_str = number_span.to_str(self.input);

            number_str.parse::<usize>().map_err(|_| {
                self.error(
                    TemplateErrorMsg::UnableToParseNumber(number_str.to_owned()),
                    self.span_to_position(&number_span),
                )
            })?
        } else {
            0
        };
        // Self::show_next_n_tokens(tokens, 3);
        let body: Vec<TemplateNode> = self.parse_until(&[EndFor])?;
        let end_tok = self.consume(EndFor)?;

        Ok(TemplateNode {
            data: TemplateNodeData::For {
                iter_bind: bind,
                iter_src,
                body,
                skip,
            },
            pos: self.range_to_position(start_tok.start, end_tok.end),
        })
    }

    fn parse_block(&mut self) -> Result<TemplateNode, TemplateError> {
        use TemplateTokenTyp::*;

        let start_tok = self.consume(Block)?;
        self.consume(Whitespace)?;
        let ident_node = self.parse_var()?;
        let ident = match ident_node.data {
            TemplateNodeData::Variable(var) if var.indices.is_empty() => var.base,
            TemplateNodeData::Variable(var) => Err(self.error(
                TemplateErrorMsg::GenericError(format!(
                    "blocks can only contain single level identifiers {var}"
                )),
                ident_node.pos,
            ))?,
            node => {
                return Err(self.error(
                    TemplateErrorMsg::UnexpectedTemplateValueType(
                        TemplateNodeKind::Variable,
                        node.kind(),
                    ),
                    ident_node.pos,
                ));
            }
        };

        let body = self.parse_until(&[EndBlock])?;
        let end_tok = self.consume(EndBlock)?;

        self.blocks.insert(ident.clone(), body.clone());

        Ok(TemplateNode {
            data: TemplateNodeData::Block {
                ident: ident.to_string(),
                body,
            },
            pos: self.range_to_position(start_tok.start, end_tok.end),
        })
    }
}

// === Templates ===

#[derive(Debug, Clone)]
pub struct TemplateNode {
    pub data: TemplateNodeData,
    pub pos: TemplatePositionData,
}

#[derive(Debug, Clone, PartialEq)]
pub enum VarIndex {
    Field { field: String, span: Span },
    Index { idx: usize, span: Span },
    Var { var: Var, span: Span },
}

impl Display for VarIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VarIndex::Field { field, .. } => write!(f, "{field}"),
            VarIndex::Index { idx, .. } => write!(f, "[{idx}]"),
            VarIndex::Var { var, .. } => write!(f, "[{var}]"),
        }
    }
}

impl VarIndex {
    pub fn len(&self) -> usize {
        match self {
            VarIndex::Field { field, .. } => field.len(),
            VarIndex::Index { idx, .. } => idx.to_string().len() + 2, // [idx]
            VarIndex::Var { var, .. } => var.to_string().len() + 2,   // [idx]
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Var {
    pub base: String,
    pub indices: Vec<VarIndex>,
}

impl Display for Var {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.base)?;
        for i in &self.indices {
            match i {
                VarIndex::Field { field, .. } => write!(f, ".{field}")?,
                VarIndex::Index { idx, .. } => write!(f, "[{idx}]")?,
                VarIndex::Var { var, .. } => write!(f, "[{var}]")?,
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum TemplateNodeData {
    Text(String),
    Variable(Var),
    Date {
        date_var: Var,
        format: String,
    },
    If {
        condition: ConditionExpr,
        then_branch: Vec<TemplateNode>,
        else_branch: Vec<TemplateNode>,
    },
    For {
        iter_bind: String,
        iter_src: Var,
        body: Vec<TemplateNode>,
        skip: usize,
    },
    Block {
        ident: String,
        body: Vec<TemplateNode>,
    },
}

#[derive(Debug, Clone)]
pub enum ConditionExpr {
    Var(Var),
    Literal(bool),
    LiteralComp(Var, String),
    VarComp(Var, Var),
}

#[derive(Clone, Debug, PartialEq)]
pub enum TemplateNodeKind {
    Text,
    Date,
    Variable,
    If,
    For,
    Block,
}

impl TemplateNodeData {
    fn kind(&self) -> TemplateNodeKind {
        match self {
            TemplateNodeData::Text(_) => TemplateNodeKind::Text,
            TemplateNodeData::Variable { .. } => TemplateNodeKind::Variable,
            TemplateNodeData::Date { .. } => TemplateNodeKind::Date,
            TemplateNodeData::If { .. } => TemplateNodeKind::If,
            TemplateNodeData::For { .. } => TemplateNodeKind::For,
            TemplateNodeData::Block { .. } => TemplateNodeKind::Block,
        }
    }
}

impl fmt::Display for TemplateNodeData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TemplateNodeData::Text(text) => write!(f, "{}", text),
            TemplateNodeData::Variable(var) => {
                write!(f, "{var}")
            }
            TemplateNodeData::If {
                condition,
                then_branch,
                else_branch,
            } => {
                let then_branch_str = then_branch
                    .iter()
                    .map(|n| format!("{}", n.data))
                    .collect::<Vec<_>>()
                    .join("\n");

                let else_branch_str = else_branch
                    .iter()
                    .map(|n| format!("{}", n.data))
                    .collect::<Vec<_>>()
                    .join("\n");

                match condition {
                    ConditionExpr::Var(var) => write!(
                        f,
                        "if {var} then {{\n \t{then_branch_str}\n}} else {{\n\t{else_branch_str}\n}}",
                    ),
                    ConditionExpr::VarComp(var_1, var_2) => write!(
                        f,
                        "if {var_1} == {var_2} then {{\n \t{then_branch_str}\n}} else {{\n\t{else_branch_str}\n}}"
                    ),
                    ConditionExpr::LiteralComp(var, literal) => write!(
                        f,
                        "if {var} == \"{literal}\" then {{\n \t{then_branch_str}\n}} else {{\n\t{else_branch_str}\n}}",
                    ),
                    ConditionExpr::Literal(literal) => write!(
                        f,
                        "if \"{}\" then {{\n \t{then_branch_str}\n}} else {{\n\t{else_branch_str}\n}}",
                        literal
                    ),
                }
            }
            TemplateNodeData::For {
                iter_bind,
                iter_src,
                body,
                skip,
            } => {
                let body_str = body
                    .iter()
                    .skip(*skip)
                    .map(|n| format!("{}", n.data))
                    .collect::<Vec<_>>()
                    .join("\n");

                write!(f, "for {iter_bind} in {iter_src} {{\n{body_str}\n}}")
            }
            TemplateNodeData::Block { ident, body } => {
                let body_str = body
                    .iter()
                    .map(|n| format!("{}", n.data))
                    .collect::<Vec<_>>()
                    .join("\n");
                write!(f, "block {ident} {{\n{body_str}\n}}")
            }
            TemplateNodeData::Date { date_var, format } => {
                write!(f, "block {date_var} {format:?}")
            }
        }
    }
}
