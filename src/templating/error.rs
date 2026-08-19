use std::borrow::Cow;
use std::error::Error;
use std::fmt::{Debug, Display};

use std::fmt;
use std::time::SystemTime;

use crate::runtime::markdown::Span;
use crate::runtime::templating::context::Context;
use crate::runtime::templating::lexer::{
    Position, TemplateInfo, TemplatePositionData, TemplateTokenTyp,
};
use crate::runtime::templating::parser::{TemplateNodeKind, Var};
use crate::runtime::templating::template::Template;
use crate::runtime::templating::values::TemplateValueKind;

#[derive(Debug, Clone)]
pub struct TemplateError {
    pub typ: TemplateErrorMsg,
    pub pos: Option<TemplatePositionData>,
    pub info: Option<Box<TemplateInfo>>, // Box because otherwise clippy complains about Result size
}

impl Error for TemplateError {}

impl fmt::Display for TemplateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} {:?}", self.typ, self.pos)
    }
}

impl From<std::io::Error> for TemplateError {
    fn from(e: std::io::Error) -> Self {
        TemplateError::no_info(TemplateErrorMsg::GenericError(e.to_string()))
    }
}
impl From<std::fmt::Error> for TemplateError {
    fn from(e: std::fmt::Error) -> Self {
        TemplateError::no_info(TemplateErrorMsg::GenericError(e.to_string()))
    }
}

impl TemplateError {
    pub fn new(typ: TemplateErrorMsg, pos: TemplatePositionData) -> TemplateError {
        TemplateError {
            typ,
            pos: Some(pos),
            info: None,
        }
    }

    pub fn no_info(typ: TemplateErrorMsg) -> Self {
        Self {
            typ,
            pos: None,
            info: None,
        }
    }
    pub fn only_file(typ: TemplateErrorMsg, file: &str) -> Self {
        Self {
            typ,
            pos: Some(TemplatePositionData {
                file: file.to_owned(),
                span: None,
            }),
            info: None,
        }
    }

    pub fn enhance_error(self, template: &Template) -> Self {
        TemplateError {
            typ: self.typ,
            pos: self.pos,
            info: Some(Box::new(TemplateInfo {
                input: template.input.clone(),
                newlines: template.newlines.clone(),
                last_modified: template.last_modified,
            })),
        }
    }

    pub fn render_error<'a>(
        &self,
        error_template: Option<&Template>,
        render_buffer: &'a mut String,
    ) -> Cow<'a, str> {
        render_buffer.clear();
        let (file_info, code_snippet) = self.render_error_info();

        if let Some(error_template) = error_template {
            let mut context = Context::new();

            context.insert_global("hotreload", cfg!(debug_assertions));
            context.insert_global("file", file_info);
            context.insert_global("code_snippet", code_snippet);
            context.insert_global("error_msg", self.typ.to_string());
            Cow::Borrowed(
                error_template
                    .render(&context, render_buffer)
                    .expect("needs to work"),
            )
        } else {
            Cow::Owned(format!("{file_info}\n{code_snippet}"))
        }
    }

    fn render_error_info(&self) -> (String, String) {
        if let Some(pos) = &self.pos
            && let Some(info) = &self.info
        {
            if let Some(span) = &pos.span {
                let code_str = span.to_line(&info.input, &info.newlines);

                let start_pos = TemplateError::compute_line_col(&info.newlines, span.start);
                let end_pos = TemplateError::compute_line_col(&info.newlines, span.end);

                let file_str = format!("{}:{}:{}", pos.file, start_pos.line, start_pos.column);
                let code_snippet = TemplateError::format_code_snippet(
                    code_str,
                    start_pos.line,
                    start_pos.column,
                    end_pos.column,
                );
                (file_str, code_snippet)
            } else {
                (format!("File: {}", pos.file), String::from("No code"))
            }
        } else {
            (String::from("No File"), String::from("No code"))
        }
    }

    fn format_code_snippet(
        code_snippet: &str,
        line: usize,
        start_col: usize,
        end_col: usize,
    ) -> String {
        let code_len = code_snippet.chars().count();

        let code_snippet = Self::escape_html(code_snippet);

        let end = end_col.max(start_col + 1).min(code_len);

        let line_str = format!("{line}");
        let gutter_width = line_str.len();

        format!(
            "{:width$} |\n\
         {:>width$} | {}\n\
         {:width$} | {}{}",
            "",
            line,
            code_snippet,
            "",
            " ".repeat(start_col + 1),
            "^".repeat(end.saturating_sub(start_col).max(1)),
            width = gutter_width,
        )
    }

    //  Inspired by
    // https://github.com/rust-lang/rust/blob/main/compiler/rustc_span/src/lib.rs#L2391
    fn compute_line_col(newlines: &[usize], offset: usize) -> Position {
        let line = newlines.partition_point(|&newline| newline <= offset);

        let line_start = if line == 0 { 0 } else { newlines[line - 1] };

        Position {
            line: line + 1,
            column: offset - line_start,
        }
    }

    fn escape_html(html: &str) -> String {
        let mut escaped = String::with_capacity(html.len());

        for c in html.chars() {
            match c {
                '&' => escaped.push_str("&amp;"),
                '<' => escaped.push_str("&lt;"),
                '>' => escaped.push_str("&gt;"),
                '"' => escaped.push_str("&quot;"),
                '\'' => escaped.push_str("&#39;"),
                _ => escaped.push(c),
            }
        }

        escaped
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TemplateErrorKind {
    Parse,
    Render,
    Internal,
}

impl Display for TemplateErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse => f.write_str("Parse error"),
            Self::Render => f.write_str("Render error"),
            Self::Internal => f.write_str("Internal error"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum TemplateErrorMsg {
    VariableNotFound(String),
    TemplateValueNotOfExptectedType(TemplateValueKind, TemplateValueKind),
    FieldNotFoundOnVariable(Box<Var>, String),
    UnexpectedToken(TemplateTokenTyp, TemplateTokenTyp),
    DidNotExpectToken(TemplateTokenTyp),
    UnexpectedTokenOptions(TemplateTokenTyp, Vec<TemplateTokenTyp>),
    GenericError(String),
    UnknownDateFormat(String),
    MultiLevelForLoopBind(Box<Var>),
    UnexpectedTemplateValueType(TemplateNodeKind, TemplateNodeKind),
    CantCompareTemplateValues(TemplateValueKind, TemplateValueKind),
    CantCompareWithLiteral(TemplateValueKind),
    IndexNotInRange(i64, usize),
    UnableToParseNumber(String),
    ExtendsNotFirstLine,
    UnexpectedEOF,
}

impl TemplateErrorMsg {
    fn kind(&self) -> TemplateErrorKind {
        use TemplateErrorKind::*;
        use TemplateErrorMsg::*;

        match self {
            VariableNotFound(_)
            | UnknownDateFormat(_)
            | FieldNotFoundOnVariable(_, _)
            | TemplateValueNotOfExptectedType(_, _)
            | CantCompareTemplateValues(_, _)
            | IndexNotInRange(_, _)
            | CantCompareWithLiteral(_) => Render,

            UnexpectedToken(_, _)
            | DidNotExpectToken(_)
            | UnexpectedTokenOptions(_, _)
            | MultiLevelForLoopBind(_)
            | UnexpectedTemplateValueType(_, _)
            | UnableToParseNumber(_)
            | ExtendsNotFirstLine
            | UnexpectedEOF => Parse,

            GenericError(_) => Internal,
        }
    }
}

impl Display for TemplateErrorMsg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use TemplateErrorMsg::*;
        let error_kind = self.kind();
        match self {
            VariableNotFound(var) => {
                write!(f, "{error_kind}: Variable '{var}' was not found in context")
            }
            FieldNotFoundOnVariable(var, field) => {
                write!(
                    f,
                    "{error_kind}: Field '{field}' was not found on variable '{var}'"
                )
            }
            IndexNotInRange(start, len) => {
                if *start < 0 {
                    write!(
                        f,
                        "{error_kind}: Can not index list of length {len} with negative number {start}"
                    )
                } else {
                    write!(
                        f,
                        "{error_kind}: Index '{start}' out of range of list of len {len}"
                    )
                }
            }

            TemplateValueNotOfExptectedType(actual, expected) => {
                write!(
                    f,
                    "{error_kind}: TemplateValue '{actual:?}' is not of expected type {expected:?}"
                )
            }

            UnexpectedToken(found, expected) => {
                write!(
                    f,
                    "{error_kind}: Unexpected token: {found:?}, expected: {expected:?}"
                )
            }
            UnknownDateFormat(format) => {
                write!(f, "{error_kind}: Unknown date format {format:?}")
            }
            DidNotExpectToken(tok) => {
                write!(f, "{error_kind}: Did not expect token {tok:?}")
            }
            UnexpectedTokenOptions(found, expected) => {
                write!(
                    f,
                    "{error_kind}: Unexpected token {found:?}, expected one of: "
                )?;

                for (i, tok) in expected.iter().enumerate() {
                    if i != 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{tok:?}")?;
                }

                Ok(())
            }
            GenericError(msg) => {
                write!(f, "{error_kind}: {msg}")
            }
            MultiLevelForLoopBind(bind) => {
                write!(
                    f,
                    "{error_kind}: For-loop binding must be a single identifier, found '{bind}'",
                )
            }
            UnexpectedTemplateValueType(expected, found) => {
                write!(
                    f,
                    "{error_kind}: Expected template node of type {expected:?}, found {found:?}"
                )
            }
            CantCompareTemplateValues(lhs, rhs) => {
                write!(
                    f,
                    "{error_kind}: Cannot compare values of type {lhs:?} and {rhs:?}"
                )
            }
            CantCompareWithLiteral(kind) => {
                write!(
                    f,
                    "{error_kind}: Cannot compare value of type {kind:?} with a literal"
                )
            }
            UnableToParseNumber(string) => {
                write!(f, "{error_kind}: Unable to parse {string} to number")
            }
            ExtendsNotFirstLine => {
                write!(
                    f,
                    "{error_kind}: 'extends' must appear as the first template statement"
                )
            }
            UnexpectedEOF => {
                write!(f, "{error_kind}: Unexpected end of file")
            }
        }
    }
}
