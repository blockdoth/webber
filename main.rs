#![feature(tcp_linger)]
#![allow(unexpected_cfgs)]
#![allow(dead_code, unused, unused_mut)]

use std::cmp::{max, min};
use std::collections::{HashMap, HashSet, VecDeque};
use std::error::Error;
use std::f32::consts::E;
use std::fmt::{Debug, Display};
use std::fs::Metadata;
use std::io::{self, Read, Write};
use std::iter::Peekable;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{panicking, sleep};
use std::time::{Duration, Instant, SystemTime};
use std::vec::IntoIter;
use std::{char, fmt, fs, thread, vec};

const SOCKET_ADDR: &str = "127.0.0.1:4000";
const ASSETS_PATH: &str = "./assets/";
const TEMPLATES_PATH: &str = "./templates/";

#[cfg(generated)]
include!(concat!(env!("OUT_DIR"), "/generated.rs"));

fn main() -> Result<(), TemplateError> {
    if std::env::args().any(|arg| arg.contains("build-script-build")) {
        println!("cargo:warning=Running in build script");
        comptime();
    } else {
        println!("Running normally");

        let mut assets = Assets::load_embedded_or_new();
        println!("Asset count: {:?}", assets.static_.lock().unwrap().len());

        let templates = Templates::load_templates(TEMPLATES_PATH)?;

        #[cfg(debug_assertions)]
        fs_watcher(&assets, &templates);

        let app = Router::new(assets, templates)
            .route_static("/home", "/index.html")
            .route_static("/about", "/projects.html")
            .route_static("/posts", "/projects.html")
            .route_dynamic("/posts/:name", "/post.html")
            .fallback("/index.html");

        let listener: TcpListener = TcpListener::bind(SOCKET_ADDR).expect("Unable to bind to socket");
        println!("Started listening on socket http://{SOCKET_ADDR}");

        app.serve(listener);
    }
    Ok(())
}

fn comptime() {
    println!("cargo:rerun-if-changed=none");
    println!("cargo:rustc-cfg=generated");

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let file_path = Path::new(&out_dir).join("generated.rs");

    let asset_paths = walk_dir(ASSETS_PATH);

    let mut assets_str = String::new();
    assets_str.push_str("fn load_embedded_assets() -> AssetTrie {\n");
    assets_str.push_str("\tlet mut assets = AssetTrie::new();\n");

    for asset_path in asset_paths {
        let path_key = asset_path.to_string_lossy();
        let full_path = format!("{}/{}", std::env::current_dir().expect("current dir").to_string_lossy(), path_key);

        assets_str.push_str(&format!("\tlet path = PathBuf::from(\"{}\");\n", path_key));
        assets_str.push_str(&format!("\tlet asset_typ = AssetType::from_path(&PathBuf::from(\"{}\"));\n", full_path));
        assets_str.push_str("\tlet content = Content::load_from_path(&path, &asset_typ);\n");
        assets_str.push_str("\tlet asset = Asset { content, asset_typ, last_modified: SystemTime::now(), internal: false};\n");
        assets_str.push_str("\tassets.insert(path,asset);\n");
        // println!("cargo:warning=Loaded {asset_path:?}");
    }
    assets_str.push_str("\tassets\n");
    assets_str.push_str("}\n");

    fs::write(&file_path, assets_str).unwrap();
    println!("cargo:warning=End of build script");
}

// === Templating ===

struct Templates {
    templates: Arc<Mutex<HashMap<String, Template>>>,
    context: Arc<Mutex<HashMap<String, TemplateValue>>>,
}

impl Templates {
    fn load_templates<P: AsRef<Path> + Debug + Copy>(root_path: P) -> Result<Templates, TemplateError> {
        let paths = walk_dir(root_path);

        println!("Found {} template paths in {:?}", paths.len(), root_path);

        let mut templates = HashMap::new();

        for path in &paths {
            let template = Template::load(path)?;

            let rel_path = path
                .strip_prefix(root_path)
                .map_err(|e| TemplateParseError::no_info(TemplateParseErrorMsg::GenericError(e.to_string())))?
                .to_string_lossy()
                .to_string();

            templates.insert(rel_path, template);
        }

        let mut template_context = HashMap::new();

        Self::insert_templates(&templates, &mut template_context)?;

        Ok(Templates {
            templates: Arc::new(Mutex::new(templates)),
            context: Arc::new(Mutex::new(template_context)),
        })
    }

    fn insert_templates(templates: &HashMap<String, Template>, template_context: &mut HashMap<String, TemplateValue>) -> Result<(), TemplateError> {
        println!("Inserting {} templates into assets", templates.len());

        let posts = Posts {
            ball_container: BallContainer { is_empty: false },
            data: vec![
                Post {
                    title: "title 1".to_string(),
                    intro: "intro 1".to_string(),
                    display: false,
                },
                Post {
                    title: "title 2".to_string(),
                    intro: "intro 2".to_string(),
                    display: true,
                },
            ],
        };

        template_context.insert("posts".to_string(), posts.to_template_value());
        template_context.insert("variable".to_string(), "arbitrary var".to_template_value());
        template_context.insert("hotreload".to_string(), true.to_template_value());

        for key in templates.keys() {
            println!("{:?}", key);
        }

        for (path, template) in templates {
            let html = match template.render(template_context) {
                Ok(html) => html,
                Err(e) => {
                    println!("Required vars {:?}", template.required_variables);
                    Err(e)?
                }
            };
            // println!("{i:#?}");
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
enum TemplateValue {
    Text(String),
    Bool(bool),
    List(Vec<TemplateValue>),
    Object(HashMap<String, TemplateValue>),
}

#[derive(Clone, Debug)]
enum TemplateValueKind {
    Text,
    Bool,
    List,
    Object,
}

impl TemplateValue {
    fn kind(&self) -> TemplateValueKind {
        match self {
            TemplateValue::Text(_) => TemplateValueKind::Text,
            TemplateValue::Bool(_) => TemplateValueKind::Bool,
            TemplateValue::List(_) => TemplateValueKind::List,
            TemplateValue::Object(_) => TemplateValueKind::Object,
        }
    }
}

trait ToTemplateValue {
    fn to_template_value(&self) -> TemplateValue;
}

impl ToTemplateValue for &str {
    fn to_template_value(&self) -> TemplateValue {
        TemplateValue::Text(self.to_string())
    }
}

impl ToTemplateValue for String {
    fn to_template_value(&self) -> TemplateValue {
        TemplateValue::Text(self.to_string())
    }
}

impl ToTemplateValue for bool {
    fn to_template_value(&self) -> TemplateValue {
        TemplateValue::Bool(*self)
    }
}

impl<T: ToTemplateValue> ToTemplateValue for Vec<T> {
    fn to_template_value(&self) -> TemplateValue {
        TemplateValue::List(self.iter().map(|item| item.to_template_value()).collect())
    }
}

macro_rules! impl_to_template_value {
    ($type:ty, { $($field:ident),* }) => {
        impl ToTemplateValue for $type {
            fn to_template_value(&self) -> TemplateValue {
                TemplateValue::Object(HashMap::from([
                    $((stringify!($field).to_string(), self.$field.to_template_value())),*
                ]))
            }
        }
    };
}

struct Posts {
    ball_container: BallContainer,
    data: Vec<Post>,
}
struct BallContainer {
    is_empty: bool,
}

struct Post {
    title: String,
    intro: String,
    display: bool,
}

impl_to_template_value!(BallContainer, { is_empty });
impl_to_template_value!(Posts, { ball_container, data});
impl_to_template_value!(Post, { title, intro, display});

#[derive(Debug)]
struct TemplateNode {
    data: TemplateNodeData,
    pos: TemplatePositionData,
}

#[derive(Debug)]
enum TemplateNodeData {
    Text(String),
    Variable(Vec<String>),
    If {
        condition: Vec<String>,
        then_branch: Vec<TemplateNode>,
        else_branch: Vec<TemplateNode>,
    },
    For {
        iter_bind: String,
        iter_src: Vec<String>,
        body: Vec<TemplateNode>,
    },
}

#[derive(Clone, Debug)]
enum TemplateNodeKind {
    Text,
    Variable,
    If,
    For,
}

impl TemplateNodeData {
    fn kind(&self) -> TemplateNodeKind {
        match self {
            TemplateNodeData::Text(_) => TemplateNodeKind::Text,
            TemplateNodeData::Variable(_) => TemplateNodeKind::Variable,
            TemplateNodeData::If { .. } => TemplateNodeKind::If,
            TemplateNodeData::For { .. } => TemplateNodeKind::For,
        }
    }
}

impl fmt::Display for TemplateNodeData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TemplateNodeData::Text(text) => write!(f, "{}", text),
            TemplateNodeData::Variable(parts) => {
                write!(f, "{}", parts.join("."))
            }
            TemplateNodeData::If {
                condition,
                then_branch,
                else_branch,
            } => {
                let then_branch_str = then_branch.iter().map(|n| format!("{}", n.data)).collect::<Vec<_>>().join("\n");

                let else_branch_str = else_branch.iter().map(|n| format!("{}", n.data)).collect::<Vec<_>>().join("\n");

                write!(
                    f,
                    "if {} then {{\n \t{}\n}} else {{\n\t{}\n}}",
                    condition.join("."),
                    then_branch_str,
                    else_branch_str
                )
            }
            TemplateNodeData::For { iter_bind, iter_src, body } => {
                let body_str = body.iter().map(|n| format!("{}", n.data)).collect::<Vec<_>>().join("\n");

                write!(f, "for {} in {} {{\n{}\n}}", iter_bind, iter_src.join("."), body_str)
            }
        }
    }
}

#[derive(Debug, Clone)]
struct TemplateToken {
    kind: TemplateTokenKind,
    metadata: TemplatePositionData,
}

#[derive(Debug, PartialEq, Clone)]
enum TemplateTokenKind {
    Text(String),
    Identifier(String),
    Dot,
    If,
    Else,
    For,
    In,
    EndIf,
    EndElse,
    EndFor,
    NewLine,
    // ParenOpen(PositionData),
    // ParenClose(PositionData),
}

#[derive(Debug, Clone)]
struct TemplatePositionData {
    file: Rc<String>,
    start_pos: Position,
    end_pos: Position,
}

impl Default for TemplatePositionData {
    fn default() -> Self {
        Self {
            file: Rc::new("".to_owned()),
            start_pos: Position { line: 0, column: 0 },
            end_pos: Position { line: 0, column: 0 },
        }
    }
}

#[derive(Clone, Debug)]
struct Position {
    line: usize,
    column: usize,
}

#[derive(Debug)]
struct Template {
    ast: Vec<TemplateNode>,
    required_variables: Vec<String>,
    origin_file: String,
}

#[derive(Debug)]
struct TemplateParseError {
    typ: TemplateParseErrorMsg,
    pos: Option<TemplatePositionData>,
}

impl TemplatePositionData {
    fn merge(&self, other: &TemplatePositionData) -> Result<Self, TemplateParseError> {
        if self.file != other.file {
            Err(TemplateParseError::no_info(TemplateParseErrorMsg::MergingSpansFromDifferentFiles(
                self.file.to_string(),
                other.file.to_string(),
            )))
        } else {
            Ok(TemplatePositionData {
                file: self.file.clone(),
                start_pos: Position {
                    line: min(self.start_pos.line, other.start_pos.line),
                    column: min(self.start_pos.column, other.start_pos.column),
                },
                end_pos: Position {
                    line: max(self.end_pos.line, other.end_pos.line),
                    column: max(self.end_pos.line, other.end_pos.line),
                },
            })
        }
    }
}

#[derive(Debug)]
enum TemplateParseErrorMsg {
    UnexpectedToken(TemplateTokenKind, TemplateTokenKind),
    BrokenInvariant(TemplateTokenKind, TemplateTokenKind),
    ExpectButEOF(TemplateTokenKind),
    GenericError(String),
    UnexpectedTemplateValueType(TemplateNodeKind, TemplateNodeKind),
    MergingSpansFromDifferentFiles(String, String),
    UnexpectedEOF,
}

#[derive(Debug)]
struct TemplateRenderError {
    typ: TemplateRenderErrorMsg,
    path: String,
}

#[derive(Debug)]
enum TemplateRenderErrorMsg {
    VariableNotFound(String),
    FieldNotFoundOnVariable(String, String),
    NodeNotOfExpectedType(String, TemplateNodeKind),
    VariableNotOfExpectedType(String, TemplateValueKind),
    ContextError(String),
}

#[derive(Debug)]
enum TemplateError {
    Parse(TemplateParseError),
    Render(TemplateRenderError),
}

impl fmt::Display for TemplateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TemplateError::Parse(e) => write!(f, "Template Parse error: {}", e),
            TemplateError::Render(e) => write!(f, "Template Render error: {}", e),
        }
    }
}

impl From<std::io::Error> for TemplateError {
    fn from(e: std::io::Error) -> Self {
        TemplateError::Parse(TemplateParseError::no_info(TemplateParseErrorMsg::GenericError(e.to_string())))
    }
}

impl TemplateParseError {
    fn new(typ: TemplateParseErrorMsg, pos: TemplatePositionData) -> Self {
        Self { typ, pos: Some(pos) }
    }
    fn no_info(typ: TemplateParseErrorMsg) -> Self {
        Self { typ, pos: None }
    }
}

impl TemplateRenderError {
    fn new(typ: TemplateRenderErrorMsg, path: String) -> Self {
        Self { typ, path }
    }
}

impl From<TemplateParseError> for TemplateError {
    fn from(e: TemplateParseError) -> Self {
        TemplateError::Parse(e)
    }
}

impl From<TemplateRenderError> for TemplateError {
    fn from(e: TemplateRenderError) -> Self {
        TemplateError::Render(e)
    }
}

impl fmt::Display for TemplateParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} {:?}", self.typ, self.pos)
    }
}

impl fmt::Display for TemplateRenderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.typ)
    }
}

struct TemplateParser {
    tokens: Peekable<IntoIter<TemplateToken>>,
    prev: Option<TemplateToken>,
}

impl TemplateParser {
    fn lex(input_str: &str, path_string: &str) -> Self {
        let lexed = Self::lex_template(input_str, path_string);

        // for i in &lexed {
        //     println!("{:?}", i.kind);
        // }

        Self {
            tokens: lexed.into_iter().peekable(),
            prev: None,
        }
    }

    fn lex_template<'a>(input: &'a str, file_path: &'a str) -> Vec<TemplateToken> {
        use TemplateTokenKind::*;

        let mut lexed = vec![];
        let mut cursor = 0;
        let input_len = input.len();

        let mut in_block = false;
        let mut start_block = 0;

        let mut metadata: TemplatePositionData = TemplatePositionData {
            file: Rc::new(file_path.to_owned()),
            start_pos: Position { line: 0, column: 0 },
            end_pos: Position { line: 0, column: 0 },
        };

        while cursor < input_len {
            let rest = &input[cursor..];

            if rest.starts_with("\n") {
                metadata.end_pos.line += 1;
                metadata.end_pos.column = 0;
            }
            if rest.starts_with("{{") {
                if !in_block {
                    let prev_text = input[start_block..cursor].to_string();

                    lexed.push(TemplateToken {
                        kind: Text(prev_text),
                        metadata: metadata.clone(),
                    });
                }
                metadata.start_pos.column = metadata.end_pos.column;
                cursor += 2;
                metadata.end_pos.column += 2;
                start_block = cursor;
                in_block = true;
                // lexed.push(TemplateToken::ParenOpen);
            } else if rest.starts_with("}}") {
                if in_block {
                    let code_text = &input[start_block..cursor];
                    let mut lexed_code = Self::lex_code(code_text, file_path, &mut metadata);
                    lexed.append(&mut lexed_code);
                }
                // lexed.push(TemplateToken::ParenClose);
                cursor += 2;
                metadata.end_pos.column += 2;
                // TODO make less hit
                while cursor < input.len() && input[cursor..cursor + 1].starts_with(" ") {
                    cursor += 1;
                    metadata.end_pos.column += 1;
                }
                if input[cursor..].starts_with("\n") {
                    cursor += 1;
                    metadata.end_pos.column += 1;
                }
                start_block = cursor;
                in_block = false;
            } else {
                cursor += 1;
                metadata.end_pos.column += 1;
            }
        }
        lexed
    }

    fn lex_code<'a>(input: &'a str, file_path: &'a str, metadata: &mut TemplatePositionData) -> Vec<TemplateToken> {
        use TemplateTokenKind::*;

        let mut lexed = vec![];

        let mut cursor = 0;
        let input_len = input.len();

        let mut push_ident = false;
        let mut start_ident = 0;
        let mut end_ident = 0;
        while cursor < input_len {
            let rest = &input[cursor..];

            end_ident = cursor;
            let tok = if rest.starts_with(".") {
                Some((Dot, 1, false))
            } else if rest.starts_with("if") {
                Some((If, 2, false))
            } else if rest.starts_with("else") {
                Some((Else, 4, false))
            } else if rest.starts_with("for") {
                Some((For, 3, false))
            } else if rest.starts_with(" in ") {
                Some((In, 4, false))
            } else if rest.starts_with("endIf") {
                Some((EndIf, 5, false))
            } else if rest.starts_with("endElse") {
                Some((EndElse, 6, false))
            } else if rest.starts_with("endFor") {
                Some((EndFor, 6, false))
            } else if rest.starts_with(r"\n") {
                Some((NewLine, 2, true))
            } else {
                None
            };

            if let Some((tok, tok_size, newline)) = tok {
                cursor += tok_size;
                metadata.end_pos.column += tok_size;
                if newline {
                    metadata.start_pos.line += 1;
                }

                if start_ident != end_ident {
                    let ident = input[start_ident..end_ident].trim().to_string();
                    lexed.push(TemplateToken {
                        kind: Identifier(ident),
                        metadata: metadata.clone(),
                    });
                }
                lexed.push(TemplateToken {
                    kind: tok,
                    metadata: metadata.clone(),
                });
                start_ident = cursor;
                end_ident = cursor;
                push_ident = false;
            }

            cursor += 1;
        }
        if start_ident + 1 != cursor {
            let ident = input[start_ident..].trim().to_string();

            lexed.push(TemplateToken {
                kind: Identifier(ident),
                metadata: metadata.clone(),
            });
        }
        lexed
    }

    fn next_token(&mut self) -> Result<TemplateToken, TemplateError> {
        match self.tokens.next() {
            Some(next) => {
                self.prev = Some(next.clone());
                Ok(next)
            }
            None => {
                if let Some(prev) = &self.prev {
                    Err(TemplateParseError::new(TemplateParseErrorMsg::UnexpectedEOF, prev.metadata.clone()))?
                } else {
                    Err(TemplateParseError::no_info(TemplateParseErrorMsg::UnexpectedEOF))?
                }
            }
        }
    }

    fn peek(&mut self) -> Option<&TemplateToken> {
        self.tokens.peek()
    }

    fn consume(&mut self, expected_token_kind: TemplateTokenKind) -> Result<TemplateToken, TemplateError> {
        match self.tokens.next() {
            Some(token) => {
                if token.kind == expected_token_kind {
                    Ok(token)
                } else {
                    Err(TemplateParseError::new(
                        TemplateParseErrorMsg::UnexpectedToken(token.kind, expected_token_kind),
                        token.metadata,
                    ))?
                }
            }
            None => {
                let pos = if let Some(prev) = &self.prev {
                    prev.metadata.clone()
                } else {
                    TemplatePositionData::default()
                };
                Err(TemplateParseError::new(TemplateParseErrorMsg::ExpectButEOF(expected_token_kind), pos))?
            }
        }
    }

    fn parse(&mut self) -> Result<Vec<TemplateNode>, TemplateError> {
        self.parse_until(&[])
    }

    fn parse_until(&mut self, stop: &[TemplateTokenKind]) -> Result<Vec<TemplateNode>, TemplateError> {
        use TemplateTokenKind::*;
        let mut parsed = vec![];

        while let Some(next_token) = &self.tokens.peek() {
            if stop.contains(&next_token.kind) {
                break;
            }
            match &next_token.kind {
                If => {
                    parsed.push(self.parse_if()?);
                    // println!("Parsed if");
                }
                Identifier(ident) => {
                    parsed.push(self.parse_var()?);
                    // println!("Parsed identifier");
                }
                For => {
                    parsed.push(self.parse_for()?);
                    // println!("Parsed for");
                }
                Identifier(ident) => {}
                Text(text) => {
                    parsed.push(TemplateNode {
                        data: TemplateNodeData::Text(text.to_owned()), // TODO not copy
                        pos: next_token.metadata.clone(),
                    });
                    self.next_token()?;
                }
                _ => {
                    self.next_token()?;
                }
            }
        }

        Ok(parsed)
    }

    fn parse_if(&mut self) -> Result<TemplateNode, TemplateError> {
        use TemplateTokenKind::*;

        let start_if = self.consume(If)?;

        // self.show_next_n_tokens(3);
        let cond_node = self.parse_var()?;
        let condition = match cond_node.data {
            TemplateNodeData::Variable(path) => path,
            node => {
                return Err(TemplateParseError::new(
                    TemplateParseErrorMsg::UnexpectedTemplateValueType(TemplateNodeKind::Variable, node.kind()),
                    cond_node.pos,
                ))?;
            }
        };
        // println!("{:?}", condition);
        // self.show_next_n_tokens(3);
        let then_branch = self.parse_until(&[Else, EndIf])?;
        // println!("{:?}", then_branch);
        // Self::show_next_n_tokens(tokens, 3);
        match self.next_token()?.kind {
            Else => {
                // Self::show_next_n_tokens(tokens, 3);
                let else_branch = self.parse_until(&[EndElse])?;
                self.consume(EndElse)?;

                let pos = match else_branch.last() {
                    Some(else_branch) => start_if.metadata.merge(&else_branch.pos)?,
                    None => match then_branch.last() {
                        Some(then_branch) => start_if.metadata.merge(&then_branch.pos)?,
                        None => start_if.metadata.merge(&cond_node.pos)?,
                    },
                };

                Ok(TemplateNode {
                    data: TemplateNodeData::If {
                        condition,
                        then_branch,
                        else_branch,
                    },
                    pos,
                })
            }
            EndIf => {
                let pos = match then_branch.last() {
                    Some(then_branch) => start_if.metadata.merge(&then_branch.pos)?,
                    None => start_if.metadata.merge(&cond_node.pos)?,
                };

                Ok(TemplateNode {
                    data: TemplateNodeData::If {
                        condition,
                        then_branch,
                        else_branch: vec![],
                    },
                    pos,
                })
            }
            _ => todo!(),
        }
    }

    fn parse_for(&mut self) -> Result<TemplateNode, TemplateError> {
        use TemplateTokenKind::*;
        let start_token = self.consume(For)?;

        // Self::show_next_n_tokens(tokens, 3);
        let token = self.next_token()?;

        let var = match token.kind {
            Identifier(text) => text,
            _ => todo!(),
        };

        self.consume(In)?;

        // Self::show_next_n_tokens(tokens, 3);
        let iter_node = self.parse_var()?;
        let iter_src = match iter_node.data {
            TemplateNodeData::Variable(path) => path,
            node => {
                return Err(TemplateParseError::new(
                    TemplateParseErrorMsg::UnexpectedTemplateValueType(TemplateNodeKind::Variable, node.kind()),
                    iter_node.pos,
                ))?;
            }
        };

        // Self::show_next_n_tokens(tokens, 3);
        let body: Vec<TemplateNode> = self.parse_until(&[EndFor])?;
        self.consume(EndFor)?;

        let pos = match body.last() {
            Some(last) => start_token.metadata.merge(&last.pos)?,
            None => start_token.metadata.merge(&iter_node.pos)?,
        };
        Ok(TemplateNode {
            data: TemplateNodeData::For {
                iter_bind: var,
                iter_src,
                body,
            },
            pos,
        })
    }

    fn parse_var(&mut self) -> Result<TemplateNode, TemplateError> {
        use TemplateTokenKind::*;

        let mut ident = vec![];

        let mut current_token = self.next_token()?;
        let start_token = current_token.clone();

        while let TemplateTokenKind::Identifier(text) = &current_token.kind {
            ident.push(text.clone());

            match self.peek() {
                Some(tok) if tok.kind == Dot => {
                    self.consume(Dot);
                    current_token = self.next_token()?;
                }
                _ => break,
            }
        }

        let current_token_metadata = current_token.metadata;
        Ok(TemplateNode {
            data: TemplateNodeData::Variable(ident),
            pos: start_token.metadata.merge(&current_token_metadata)?,
        })
    }

    fn show_next_n_tokens(&mut self, n: usize) {
        let mut clone = self.tokens.clone();
        print!("Next {} tokens: ", n);
        for _ in 0..n {
            match clone.next() {
                Some(tok) => print!("({:?}) ", tok.kind),
                None => break,
            }
        }
        println!();
    }
}

impl Template {
    fn load<P: AsRef<Path> + Debug + Copy>(path: P) -> Result<Self, TemplateError> {
        let path_string = path.as_ref().to_string_lossy().to_string();

        let template_str = match fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                return Err(TemplateParseError::new(
                    TemplateParseErrorMsg::GenericError(e.to_string()),
                    TemplatePositionData {
                        file: Rc::new(path_string),
                        start_pos: Position { line: 0, column: 0 },
                        end_pos: Position { line: 0, column: 0 },
                    },
                ))?;
            }
        };

        let parsed = TemplateParser::lex(&template_str, &path_string).parse()?;

        // for i in &parsed {
        //     print!("{}", i.data);
        // }
        let required_variables = Self::get_required_vars(&parsed);

        Ok(Template {
            ast: parsed,
            required_variables,
            origin_file: path_string,
        })
    }

    fn render(&self, context: &HashMap<String, TemplateValue>) -> Result<String, TemplateError> {
        // println!("{:?}", &self.ast);
        Self::render_helper(&self.ast, context)
    }

    fn render_helper(nodes: &Vec<TemplateNode>, context: &HashMap<String, TemplateValue>) -> Result<String, TemplateError> {
        use TemplateNodeData::*;
        let mut res = String::new();
        for node in nodes {
            match &node.data {
                Text(text) => res.push_str(text),
                Variable(ident_fields) => {
                    if let TemplateValue::Text(text) = Self::resolve_var(ident_fields, context, node.pos.file.as_str())? {
                        res.push_str(text);
                    } else {
                        return Err(TemplateRenderError::new(
                            TemplateRenderErrorMsg::NodeNotOfExpectedType(ident_fields.concat(), TemplateNodeKind::Text),
                            node.pos.file.to_string(),
                        ))?;
                    }
                }
                If {
                    condition,
                    then_branch,
                    else_branch,
                } => {
                    if let TemplateValue::Bool(cond) = *Self::resolve_var(condition, context, node.pos.file.as_str())? {
                        let cond_str = if cond {
                            Self::render_helper(then_branch, context)?
                        } else {
                            Self::render_helper(else_branch, context)?
                        };
                        res.push_str(&cond_str);
                    } else {
                        return Err(TemplateRenderError::new(
                            TemplateRenderErrorMsg::VariableNotOfExpectedType(condition.concat(), TemplateValueKind::Bool),
                            node.pos.file.to_string(),
                        ))?;
                    }
                }
                For { iter_bind, iter_src, body } => {
                    if let TemplateValue::List(iter) = Self::resolve_var(iter_src, context, node.pos.file.as_str())? {
                        let mut for_res = String::new();
                        for it in iter {
                            let mut local_context = context.clone(); // TODO use stack frames
                            local_context.insert(iter_bind.to_string(), it.clone());
                            for_res.push_str(&Self::render_helper(body, &local_context)?);
                        }
                        res.push_str(&for_res);
                    } else {
                        return Err(TemplateRenderError::new(
                            TemplateRenderErrorMsg::VariableNotOfExpectedType(iter_src.concat(), TemplateValueKind::List),
                            node.pos.file.to_string(),
                        ))?;
                    }
                }
            };
            // print!("> {}", &node_str);
        }

        Ok(res)
    }

    fn resolve_var<'a>(
        ident_fields: &[String],
        context: &'a HashMap<String, TemplateValue>,
        path: &str,
    ) -> Result<&'a TemplateValue, TemplateRenderError> {
        let mut current = context.get(&ident_fields[0]).ok_or(TemplateRenderError::new(
            TemplateRenderErrorMsg::VariableNotFound(ident_fields[0].to_string()),
            path.to_string(),
        ))?;
        // println!("{:?}", current);
        // println!("{:?}", context);
        let mut idx = 1;
        for field in &ident_fields[1..] {
            current = if let TemplateValue::Object(map) = current {
                if let Some(obj) = map.get(field.as_str()) {
                    obj
                } else {
                    return Err(TemplateRenderError::new(
                        TemplateRenderErrorMsg::FieldNotFoundOnVariable(ident_fields[1..idx].concat(), field.to_string()),
                        path.to_string(),
                    ));
                }
            } else {
                return Err(TemplateRenderError::new(
                    TemplateRenderErrorMsg::VariableNotOfExpectedType(field.to_string(), TemplateValueKind::List),
                    path.to_string(),
                ))?;
            };
            idx += 1;
        }
        Ok(current)
    }

    fn get_required_vars(ast: &[TemplateNode]) -> Vec<String> {
        ast.iter()
            .filter_map(|node| {
                if let TemplateNodeData::Variable(fields) = &node.data {
                    Some(fields.join("."))
                } else {
                    None
                }
            })
            .collect()
    }
}
//  === end templating ===
//

// === Routing ===

struct Router {
    assets: Assets,
    templates: Templates,
    routes: HashMap<PathBuf, String>,
    fallback: Option<String>,
}

impl Router {
    fn new(assets: Assets, templates: Templates) -> Self {
        Router {
            assets,
            templates,
            routes: HashMap::new(),
            fallback: None,
        }
    }

    fn route_static(mut self, path: &str, template: &str) -> Self {
        self.routes.insert(path.into(), template.to_string());
        self
    }

    fn route_dynamic(mut self, path: &str, base_template: &str) -> Self {
        let path = PathBuf::from(path);

        for asset in self.assets.generated.lock().expect("Fs watcher died").get_partial(&path) {}

        self.routes.insert(path, base_template.to_string());
        self
    }

    fn fallback(mut self, page: &str) -> Self {
        self.fallback = Some(page.to_string());
        self
    }

    fn serve(&self, listener: TcpListener) {
        let mut buffer: [u8; 8192] = [0; 8192]; // 8kb buffer
        let mut active_streams: Vec<TcpStream> = vec![];
        let mut check_alive_timer = Instant::now();

        let mut it = 0;

        'main: loop {
            print!("Loop it {it}\r");
            it += 1;

            if active_streams.is_empty() {
                listener.set_nonblocking(false).expect("Unable to set socket to nonblocking mode");
            } else {
                listener.set_nonblocking(true).expect("Unable to set socket to nonblocking mode");
            }

            if let Ok((mut stream, peer_addr)) = listener.accept() {
                println!("[{peer_addr}] Connected");
                stream.set_nonblocking(true).expect("Failed to change blocking of stream");

                let n = loop {
                    match stream.read(&mut buffer) {
                        Ok(0) => {
                            println!("[{peer_addr}] Disconnected");
                            continue 'main;
                        }
                        Ok(n) => break n,
                        _ => continue,
                    };
                };

                let (header, body) = HttpServer::parse_request(&buffer[..n]).expect("Unable to parse request");

                println!(
                    "[{peer_addr}] Received {:?} request for {:?} of length {}",
                    header.typ,
                    header.path,
                    body.len()
                );

                let mut is_ws = false;

                match header.path.as_str() {
                    #[cfg(debug_assertions)]
                    "/ws" => {
                        print!("[{peer_addr:?}] Upgrading websocket ... ");
                        let response = HttpServer::upgrade_websocket(header);
                        stream.write_all(&response).expect("Failed to write to stream");
                        stream.flush().expect("Failed to flush stream");
                        is_ws = true;
                    }
                    path => {
                        let asset = match header.typ {
                            HttpRequestType::GET => {
                                let key = PathBuf::from(format!("./assets{}", path));
                                // println!("{key:?}");
                                let guard = self.assets.static_.lock().expect("Cant get lock");
                                guard.get(&key)
                            }
                        };
                        // println!("{:?}", asset);
                        let response = if let Some(asset) = asset {
                            // let response_content = if asset.asset_typ == AssetType::Md
                            //     && let Content::Text(content) = asset.content
                            // {
                            //     let main_template = {
                            //         #[cfg(debug_assertions)]
                            //         let template_path = PathBuf::from("./assets/templates/main-hotreload.html");
                            //         #[cfg(not(debug_assertions))]
                            //         let template_path = PathBuf::from("./assets/templates/main.html");

                            //         let guard = assets.lock().expect("unable to unlock");
                            //         let asset = guard.get(&template_path).expect("Failed to find main template");

                            //         match (&asset.asset_typ, asset.content.clone()) {
                            //             (AssetType::Html, Content::Text(html)) => SimpleTemplate { html },
                            //             _ => panic!("Main template must be html"),
                            //         }
                            //     };
                            //     Content::Text(main_template.populate(vec![("body".to_string(), content)]))
                            // } else {
                            //     asset.content
                            // };
                            // println!("{:?}", response_content);

                            HttpServer::build_response(HttpResponseCode::Ok, asset.asset_typ, asset.content)
                        } else {
                            let body = Content::Text(format!("resource at {} not found", path));
                            HttpServer::build_response(HttpResponseCode::NotFound, AssetType::Text, body)
                        };

                        let _ = stream.write(&response).expect("Failed to write to stream");
                        stream.flush().expect("Failed to flush stream");
                        #[cfg(not(debug_assertions))]
                        {
                            stream.set_linger(Some(Duration::from_secs(0))).expect("Unable to change linger time");
                            stream.shutdown(std::net::Shutdown::Both).expect("Unable to close connection");
                        }
                    }
                };

                #[cfg(debug_assertions)]
                {
                    if is_ws {
                        // thread::sleep(Duration::from_secs(2));
                        active_streams.push(stream);
                        println!("Active connections {}", active_streams.len());
                    }
                }
            }
            #[cfg(debug_assertions)]
            {
                let should_reload = self.assets.reload.load(Ordering::Relaxed);

                if should_reload || check_alive_timer.elapsed() > Duration::from_secs(1) {
                    check_alive_timer = Instant::now();
                    active_streams.retain(|mut stream| {
                        let connection_is_alive = match stream.read(&mut [0]) {
                            Ok(0) => false,
                            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => true,
                            _ => false,
                        };

                        if connection_is_alive && let Ok(peer_addr) = stream.peer_addr() {
                            if should_reload {
                                let _ = HttpServer::send_ws_message(stream, "reload");
                                println!("[{peer_addr:?}] Reloaded");
                            }
                            // println!("[{peer_addr:?}] Connection still alive");
                            true
                        } else {
                            println!("Closing connection");
                            let _ = stream.shutdown(std::net::Shutdown::Both);

                            false
                        }
                    });
                    if should_reload {
                        self.assets.reload.store(false, Ordering::Relaxed);
                    }
                }
            }
        }
    }
}

enum HttpResponseCode {
    Ok = 200,
    NotFound = 404,
    BadRequest = 400,
}

#[derive(Debug)]
struct HttpRequestHeader {
    typ: HttpRequestType,
    path: String,
    _origin: Option<String>,
    _user_agent: Option<String>,
    sec_websocket_key: Option<String>,
    sec_websocket_version: Option<String>,
    upgrade: Option<String>,
    content_typ: AssetType,
}

#[derive(Debug)]
#[allow(clippy::upper_case_acronyms)]
enum HttpRequestType {
    GET,
}

struct HttpServer {}

impl HttpServer {
    fn upgrade_websocket(header: HttpRequestHeader) -> Vec<u8> {
        if let Some(_) = header.upgrade
            && let Some(sec_websocket_key) = header.sec_websocket_key
            && let Some(_) = header.sec_websocket_version
        {
            let magic_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
            let websocket_accept = base64(&sha1(format!("{}{magic_string}", sec_websocket_key.trim())));
            println!("Succeeded");
            format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {websocket_accept}\r\n\r\n"
            )
            .as_bytes()
            .to_vec()
        } else {
            println!("Failed");
            Self::build_response(
                HttpResponseCode::BadRequest,
                AssetType::Text,
                Content::Text("Invalid websocket upgrade request".to_owned()),
            )
        }
    }

    fn send_ws_message(mut stream: &TcpStream, msg: &str) -> Result<(), io::Error> {
        let mut frame = Vec::new();
        frame.push(0x81); // first bit for FIN frame and 8th bit for message type text 
        frame.push(msg.len() as u8); // should technically u7, but not needed for my use case
        frame.extend_from_slice(msg.as_bytes());
        stream.write_all(&frame)?;
        stream.flush()
    }

    fn parse_request(buffer: &[u8]) -> Result<(HttpRequestHeader, Content), io::Error> {
        if let Some(pos) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            let header = Self::parse_header(String::from_utf8_lossy(&buffer[..pos]).to_string()).expect("Unable to parse header");

            let content = match header.content_typ {
                AssetType::Png => Content::Binary(buffer[pos + 4..].to_vec()),
                _ => Content::Text(String::from_utf8_lossy(&buffer[pos + 4..]).to_string()),
            };

            Ok((header, content))
        } else {
            Err(io::Error::new(io::ErrorKind::InvalidData, "could not find header/body separator"))
        }
    }

    fn build_response(code: HttpResponseCode, content_typ: AssetType, content: Content) -> Vec<u8> {
        let status = match code {
            HttpResponseCode::Ok => "200 Ok",
            HttpResponseCode::NotFound => "404 Not Found",
            HttpResponseCode::BadRequest => "400 Bad Request",
        };

        match content {
            Content::Text(txt) => format!(
                "HTTP/1.1 {status}\r\nContent-Type: {content_typ}\r\nContent-Length: {}\r\n\r\n{txt}",
                txt.len()
            )
            .as_bytes()
            .to_vec(),
            Content::Binary(bytes) => {
                let mut res = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {content_typ}\r\nContent-Length: {}\r\n\r\n",
                    bytes.len()
                )
                .as_bytes()
                .to_vec();
                res.extend_from_slice(&bytes);
                res
            }
        }
    }

    fn parse_header(header_str: String) -> Result<HttpRequestHeader, io::Error> {
        let mut lines = header_str.lines();

        let first_line = lines.next().expect("Unable to get next line");
        let mut first_line_words = first_line.split_ascii_whitespace();

        let request_type = match first_line_words.next() {
            Some("GET") => HttpRequestType::GET,
            invalid => {
                return Err(io::Error::new(io::ErrorKind::InvalidData, format!("invalid request type {invalid:?}")));
            }
        };

        let path = if let Some(path) = first_line_words.next() {
            path
        } else {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid request path"));
        };

        let mut origin = None;
        let mut sec_websocket_key = None;
        let mut sec_websocket_version = None;
        let mut user_agent = None;
        let mut upgrade = None;
        let mut content_typ = AssetType::Unknown;

        for line in lines {
            if let Some((key, value)) = line.split_once(':') {
                let value = value.to_string();
                match key.to_ascii_lowercase().as_str() {
                    "origin" => origin = Some(value),
                    "sec-websocket-key" => sec_websocket_key = Some(value),
                    "sec-websocket-version" => sec_websocket_version = Some(value),
                    "user-agent" => user_agent = Some(value),
                    "upgrade" => upgrade = Some(value),
                    "content-type" => {
                        content_typ = match value.as_str() {
                            "text/plain" => AssetType::Text,
                            "text/html" => AssetType::Html,
                            "text/css" => AssetType::Css,
                            "text/javascript" => AssetType::Js,
                            "image/png" => AssetType::Png,
                            _ => AssetType::Unknown,
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(HttpRequestHeader {
            typ: request_type,
            path: path.to_owned(),
            _origin: origin,
            _user_agent: user_agent,
            sec_websocket_key,
            sec_websocket_version,
            upgrade,
            content_typ,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum AssetType {
    Text = 1,
    Html = 2,
    Css = 3,
    Js = 4,
    Png = 5,
    Md = 6,
    Unknown = 7,
}

impl AssetType {
    fn is_text(&self) -> bool {
        use AssetType::*;
        matches!(self, Text | Html | Css | Js | Md)
    }
    fn from_path(path: &Path) -> AssetType {
        match path.extension().and_then(|s| s.to_str()) {
            Some("html") => AssetType::Html,
            Some("txt") => AssetType::Text,
            Some("css") => AssetType::Css,
            Some("js") => AssetType::Js,
            Some("png") => AssetType::Png,
            Some("md") => AssetType::Md,
            _ => AssetType::Unknown,
        }
    }
}

impl fmt::Display for AssetType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            AssetType::Text => "text/plain",
            AssetType::Html => "text/html",
            AssetType::Css => "text/css",
            AssetType::Js => "text/javascript",
            AssetType::Png => "image/png",
            AssetType::Md => "text/html",
            AssetType::Unknown => "text/plain",
        })
    }
}

#[derive(Clone, Debug)]
struct Asset {
    last_modified: SystemTime,
    content: Content,
    internal: bool,
    asset_typ: AssetType,
}

#[derive(Clone, Debug)]
enum Content {
    Binary(Vec<u8>),
    Text(String),
}

impl Content {
    fn len(&self) -> usize {
        match self {
            Content::Binary(bytes) => bytes.len(),
            Content::Text(text) => text.len(),
        }
    }
    fn load_from_path(path: &Path, content_typ: &AssetType) -> Content {
        match content_typ {
            AssetType::Png | AssetType::Unknown => Content::Binary(fs::read(path).expect("Unable to read file into binary")),
            AssetType::Md => {
                let markdown = fs::read_to_string(path).expect("Unable read file into string");
                let html = MarkdownParser::html(MarkdownParser::parse(&markdown));
                Content::Text(html)
            }
            _ => Content::Text(fs::read_to_string(path).expect("Unable read file into string")),
        }
    }

    fn load_template(path: &Path, template_context: &Arc<Mutex<HashMap<String, TemplateValue>>>) -> Result<String, TemplateError> {
        let hashmap = template_context.lock().expect("Failed to acquite lock for template context");
        Template::load(path)?.render(&hashmap)
    }
}

// Err(e) => {
//   println!("{e}");
//   continue;
// }

fn walk_dir<P: AsRef<Path> + Debug>(rootdir: P) -> Vec<PathBuf> {
    let mut asset_paths = vec![];
    let mut stack = vec![rootdir.as_ref().to_path_buf()];

    while let Some(dir_path) = stack.pop() {
        let dir = match fs::read_dir(&dir_path) {
            Ok(dir) => dir,
            Err(error) => {
                println!("Error while trying to open asset dir at {rootdir:?}: {error}");
                continue;
            }
        };

        for file in dir {
            if let Ok(file) = file
                && let Ok(metadata) = file.metadata()
            {
                if metadata.is_dir() {
                    stack.push(file.path());
                    continue;
                };
                let file_path = file.path();
                asset_paths.push(file_path.clone());
            }
        }
    }
    asset_paths
}

fn fs_watcher(assets: &Assets, templates: &Templates) {
    let template_context = templates.context.clone();
    let asset_trie = assets.static_.clone();
    let reload = assets.reload.clone();
    let _ = thread::spawn(move || {
        println!("Started file watcher thread");
        loop {
            let mut asset_paths = walk_dir(ASSETS_PATH);
            asset_paths.append(&mut walk_dir(TEMPLATES_PATH));
            let asset_set: HashSet<PathBuf> = asset_paths.iter().cloned().collect();

            let mut map = asset_trie.lock().expect("Unable to acquire lock");
            for path in &asset_paths {
                let metadata = match path.metadata() {
                    Ok(m) => m,
                    Err(_) => continue,
                };

                let last_modified = match metadata.modified() {
                    Ok(t) => t,
                    Err(_) => continue,
                };

                match map.get_ref_mut(path) {
                    Some(existing_asset) => {
                        if last_modified > existing_asset.last_modified {
                            existing_asset.content = if path.starts_with(TEMPLATES_PATH) && existing_asset.asset_typ == AssetType::Html {
                                Content::Text(match Content::load_template(path, &template_context) {
                                    Ok(c) => c,
                                    Err(e) => {
                                        eprintln!("Template error: {}", e);
                                        continue;
                                    }
                                })
                            } else {
                                Content::load_from_path(path, &existing_asset.asset_typ)
                            };

                            existing_asset.last_modified = last_modified;
                            reload.store(true, Ordering::Release);

                            println!(
                                "Updated file {:?}, edited {} minutes ago",
                                path,
                                last_modified.elapsed().unwrap().as_secs() / 60
                            );
                        }
                    }
                    None => {
                        let content_typ = AssetType::from_path(path);
                        let content = if path.starts_with(TEMPLATES_PATH) && content_typ == AssetType::Html {
                            Content::Text(match Content::load_template(path, &template_context) {
                                Ok(c) => c,
                                Err(e) => {
                                    eprintln!("Template error: {}", e);
                                    continue;
                                }
                            })
                        } else {
                            Content::load_from_path(path, &content_typ)
                        };

                        map.insert(
                            path.clone(),
                            Asset {
                                last_modified,
                                content,
                                asset_typ: content_typ,
                                internal: false,
                            },
                        );
                        reload.store(true, Ordering::Release);
                        println!(
                            "Added file {:?}, edited {:?} minutes ago",
                            path,
                            last_modified.elapsed().expect("Unable to get time elapsed").as_secs() / 60
                        );
                    }
                }
            }
            if map.remove_other_than_except_generated(asset_paths) {
                reload.store(true, Ordering::Release);
            }

            sleep(Duration::from_millis(100));
        }
    });
}

#[derive(Default, Debug, Clone)]
struct TrieNode {
    asset: Option<Asset>,
    children: HashMap<String, TrieNode>,
}

struct Assets {
    static_: Arc<Mutex<AssetTrie>>,
    generated: Arc<Mutex<AssetTrie>>,
    reload: Arc<AtomicBool>,
}

impl Assets {
    fn load_embedded_or_new() -> Self {
        #[cfg(generated)]
        let mut assets = load_embedded_assets();
        #[cfg(not(generated))]
        let mut assets = AssetTrie::new();

        let generated = Self::compile_generated_assets(&mut assets);
        Self {
            static_: Arc::new(Mutex::new(assets)),
            generated: Arc::new(Mutex::new(generated)),
            reload: Arc::new(AtomicBool::new(false)),
        }
    }

    fn compile_generated_assets(assets: &mut AssetTrie) -> AssetTrie {
        let mut generated_assets = AssetTrie::new();

        for (path, asset) in assets.collect_kv_mut() {
            match asset.asset_typ {
                AssetType::Md => {
                    if let Content::Text(content) = &asset.content {
                        let html = MarkdownParser::html(MarkdownParser::parse(content));
                        asset.internal = true;
                        generated_assets.insert(path, Asset { 
                          last_modified: SystemTime::now(), 
                          content: Content::Text(html), 
                          internal: false, 
                          asset_typ: AssetType::Html 
                        });
                      }
                    }
                _ => continue,
            }
        }
        println!("Compiled {} generated assets", generated_assets.len());
        generated_assets
    }
}

#[derive(Default, Debug, Clone)]
struct AssetTrie {
    root: TrieNode,
    paths: HashSet<PathBuf>,
}

impl AssetTrie {
    fn new() -> Self {
        AssetTrie {
            root: TrieNode::default(),
            paths: HashSet::new(),
        }
    }

    fn insert(&mut self, path: PathBuf, asset: Asset) {
        let mut current_node = &mut self.root;

        for component in path.components() {
            let key = component.as_os_str().to_string_lossy().to_string();
            current_node = current_node.children.entry(key).or_default();
        }
        current_node.asset = Some(asset);
        self.paths.insert(path);
    }

    fn get_ref_mut(&mut self, path: &Path) -> Option<&mut Asset> {
        let mut current_node = &mut self.root;

        for component in path.components() {
            let key = component.as_os_str().to_string_lossy().to_string();
            match current_node.children.get_mut(&key) {
                Some(node) => current_node = node,
                None => break,
            }
        }

        current_node.asset.as_mut()
    }

    fn get(&self, path: &Path) -> Option<Asset> {
        let mut current_node = &self.root;

        for component in path.components() {
            let key = component.as_os_str().to_string_lossy().to_string();
            match current_node.children.get(&key) {
                Some(node) => current_node = node,
                None => break,
            }
        }

        current_node.asset.clone()
    }

    fn get_partial(&self, path: &Path) -> Vec<&Asset> {
        let mut current_node = &self.root;

        for component in path.components() {
            let key = component.as_os_str().to_string_lossy();

            match current_node.children.get(key.as_ref()) {
                Some(node) => current_node = node,
                None => break,
            }
        }

        let mut result = Vec::new();
        let mut stack = vec![current_node];

        while let Some(node) = stack.pop() {
            if let Some(asset) = &node.asset {
                result.push(asset);
            }
            stack.extend(node.children.values());
        }
        result
    }
    // TODO less dirty
    fn collect_kv_mut(&mut self) -> Vec<(PathBuf, &mut Asset)> {
        let mut result = Vec::new();

        Self::dfs(&mut self.root, &mut PathBuf::new(), &mut result);

        result
    }

    fn dfs<'a>(node: &'a mut TrieNode, path: &mut PathBuf, result: &mut Vec<(PathBuf, &'a mut Asset)>) {
        if let Some(asset) = node.asset.as_mut() {
            result.push((path.clone(), asset));
        }

        for (key, child) in node.children.iter_mut() {
            path.push(key);
            Self::dfs(child, path, result);
            path.pop();
        }
    }

    fn contains(&self, path: &Path) -> bool {
        let mut current_node = &self.root;

        for component in path.components() {
            let key = component.as_os_str().to_string_lossy().to_string();
            match current_node.children.get(&key) {
                Some(node) => current_node = node,
                None => return false,
            }
        }

        current_node.asset.is_some()
    }

    fn remove(&mut self, path: &Path) -> bool {
        let mut current_node = &mut self.root;

        for component in path.components() {
            let key = component.as_os_str().to_string_lossy().to_string();
            if let Some(node) = current_node.children.get_mut(&key) {
                current_node = node;
            } else {
                return false;
            }
        }

        current_node.asset = None;
        self.paths.remove(path);
        // TODO remove the emtpy data nodes left behind
        true
    }
    fn remove_other_than_except_generated(&mut self, current_paths: Vec<PathBuf>) -> bool {
        let current_paths_set: HashSet<PathBuf> = current_paths.into_iter().collect();

        let paths_to_delete: Vec<PathBuf> = self.paths.difference(&current_paths_set).cloned().collect();

        let mut changed = false;

        for path in &paths_to_delete {
            if path.to_string_lossy().starts_with("$") {
                continue;
            };
            println!("Removed file {:?}", path);
            changed |= self.remove(path);
        }
        self.paths = current_paths_set;

        changed
    }

    fn len(&self) -> usize {
        self.paths.len()
    }
}

const BASE64_CONVERSION: [char; 64] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c',
    'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5',
    '6', '7', '8', '9', '+', '/',
];

fn base64(bytes: &[u8]) -> String {
    let len = 4 * bytes.len().div_ceil(3); // exact output size
    let mut encoded = String::with_capacity(len);

    let mut i = 0;
    while i + 3 < bytes.len() {
        let merged = (bytes[i] as u32) << 16 | (bytes[i + 1] as u32) << 8 | (bytes[i + 2] as u32);

        encoded.push(BASE64_CONVERSION[((merged >> 18) & 0b111111) as usize]);
        encoded.push(BASE64_CONVERSION[((merged >> 12) & 0b111111) as usize]);
        encoded.push(BASE64_CONVERSION[((merged >> 6) & 0b111111) as usize]);
        encoded.push(BASE64_CONVERSION[(merged & 0b111111) as usize]);
        i += 3;
    }

    match bytes.len() - i {
        2 => {
            let merged = (bytes[i] as u32) << 16 | (bytes[i + 1] as u32) << 8;

            encoded.push(BASE64_CONVERSION[((merged >> 18) & 0b111111) as usize]);
            encoded.push(BASE64_CONVERSION[((merged >> 12) & 0b111111) as usize]);
            encoded.push(BASE64_CONVERSION[((merged >> 6) & 0b111111) as usize]);
            encoded.push('=');
        }
        1 => {
            let merged = (bytes[i] as u32) << 16;

            encoded.push(BASE64_CONVERSION[((merged >> 18) & 0b111111) as usize]);
            encoded.push(BASE64_CONVERSION[((merged >> 12) & 0b111111) as usize]);
            encoded.push('=');
            encoded.push('=');
        }
        _ => {}
    }

    encoded
}

// Build based on:
// https://en.wikipedia.org/wiki/SHA-1
// https://www.thespatula.io/rust/rust_sha1/
fn sha1(input: String) -> [u8; 20] {
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xEFCDAB89;
    let mut h2: u32 = 0x98BADCFE;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xC3D2E1F0;

    let mut bytes = input.as_bytes().to_vec();
    let length = bytes.len() as u64 * 8;

    // Padding
    bytes.push(0x80);

    while (bytes.len() * 8) % 512 != 448 {
        bytes.push(0);
    }

    bytes.extend_from_slice(&length.to_be_bytes());

    let mut words = [0u32; 80];

    for chunk in bytes.chunks_exact(64) {
        // Chunks of 512 bits
        for i in 0..16 {
            words[i] =
                ((chunk[4 * i] as u32) << 24) | ((chunk[4 * i + 1] as u32) << 16) | ((chunk[4 * i + 2] as u32) << 8) | (chunk[4 * i + 3] as u32);
        }
        for i in 16..80 {
            // w[i] = (w[i-3] xor w[i-8] xor w[i-14] xor w[i-16]) leftrotate 1
            words[i] = (words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16]).rotate_left(1);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;

        for (i, word) in words.iter().enumerate() {
            let (f, k) = if i < 20 {
                ((b & c) | (!b & d), 0x5A827999)
            } else if i < 40 {
                (b ^ c ^ d, 0x6ED9EBA1)
            } else if i < 60 {
                ((b & c) | (b & d) | (c & d), 0x8F1BBCDC)
            } else {
                (b ^ c ^ d, 0xCA62C1D6)
            };

            let temp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(*word);

            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut digest = [0u8; 20];
    digest[..4].copy_from_slice(&h0.to_be_bytes());
    digest[4..8].copy_from_slice(&h1.to_be_bytes());
    digest[8..12].copy_from_slice(&h2.to_be_bytes());
    digest[12..16].copy_from_slice(&h3.to_be_bytes());
    digest[16..20].copy_from_slice(&h4.to_be_bytes());
    digest
}

#[derive(Debug)]
enum MarkdownNode<'a> {
    Document(Vec<MarkdownNode<'a>>),

    // Block
    Paragraph(Vec<MarkdownNode<'a>>),
    Heading { level: u8, children: Vec<MarkdownNode<'a>> },
    CodeBlock { language: Option<&'a str>, content: Vec<&'a str> },
    OrderedList(Vec<MarkdownNode<'a>>),
    UnorderedList(Vec<MarkdownNode<'a>>),
    ListItem(Vec<MarkdownNode<'a>>),
    BlockQuote(Vec<MarkdownNode<'a>>),
    HorizontalLine,
    Table,

    // Inline
    Text(&'a str),
    Italic(Vec<MarkdownNode<'a>>),
    Bold(Vec<MarkdownNode<'a>>),
    InlineCode(&'a str),
    Link { text: Vec<MarkdownNode<'a>>, url: &'a str },
}

#[derive(Debug, Clone)]
enum MarkDownBlock<'a> {
    Heading { level: u8, content: &'a str },
    Paragraph { content: Vec<&'a str> },
    OrderedList { content: Vec<&'a str> },
    UnorderedList { content: Vec<&'a str> },
    BlockQuote { content: Vec<&'a str> },
    Table { content: Vec<&'a str> },
    CodeBlock { language: &'a str, content: Vec<&'a str> },
    BreakLine,
}

#[derive(Debug, Eq, PartialEq)]
enum BlockTyp {
    Paragraph,
    OrderedList,
    UnorderedList,
    BlockQuote,
    CodeBlockLine,
    CodeBlockBlock,
    HorizontalLine,
    Table,
    Misc,
}
struct MarkdownParser<'a> {
    ast: MarkdownNode<'a>,
}

impl<'a> MarkdownParser<'a> {
    fn parse(input: &'a str) -> MarkdownNode<'a> {
        let mut active_block = vec![];
        let mut blocks: Vec<MarkDownBlock> = vec![];

        let mut current_block_typ: BlockTyp = BlockTyp::Misc;

        let mut code_block_language = "";

        for untrimmed_line in input.lines() {
            let line = untrimmed_line.trim_start();

            // match
            if line.is_empty() {
                Self::end_block(&mut current_block_typ, &mut active_block, &mut blocks, &mut code_block_language);
                current_block_typ = BlockTyp::Misc;
            } else {
                match line.chars().next().expect("string empty") {
                    _ if line.starts_with("---") | line.starts_with("___") | line.starts_with("***") => {
                        if current_block_typ != BlockTyp::Misc {
                            Self::end_block(&mut current_block_typ, &mut active_block, &mut blocks, &mut code_block_language);
                        }
                        current_block_typ = BlockTyp::HorizontalLine;
                    }
                    '-' | '*' => {
                        if current_block_typ != BlockTyp::UnorderedList {
                            Self::end_block(&mut current_block_typ, &mut active_block, &mut blocks, &mut code_block_language);
                        }
                        current_block_typ = BlockTyp::UnorderedList;
                        let line = line[1..].trim();
                        active_block.push(line);
                    }
                    a if a.is_numeric() && line.split(' ').next().expect("empty").ends_with('.') => {
                        if current_block_typ != BlockTyp::OrderedList {
                            Self::end_block(&mut current_block_typ, &mut active_block, &mut blocks, &mut code_block_language);
                        }
                        current_block_typ = BlockTyp::OrderedList;
                        let line = line.split(' ').nth(1).expect("empty").trim();
                        active_block.push(line);
                    }
                    '>' => {
                        if current_block_typ != BlockTyp::BlockQuote {
                            Self::end_block(&mut current_block_typ, &mut active_block, &mut blocks, &mut code_block_language);
                        }
                        current_block_typ = BlockTyp::BlockQuote;
                        if line.len() > 2 {
                            let line = line[2..].trim();
                            active_block.push(line);
                        } else {
                            active_block.push("");
                        }
                    }
                    '|' => {
                        if current_block_typ != BlockTyp::Table {
                            Self::end_block(&mut current_block_typ, &mut active_block, &mut blocks, &mut code_block_language);
                        }
                        current_block_typ = BlockTyp::Table;
                        active_block.push(line);
                    }

                    '#' => {
                        if current_block_typ != BlockTyp::Misc {
                            Self::end_block(&mut current_block_typ, &mut active_block, &mut blocks, &mut code_block_language);
                        }
                        current_block_typ = BlockTyp::Misc;

                        let level = line.chars().take_while(|&c| c == '#').count();
                        let content = line[level..].trim();

                        blocks.push(MarkDownBlock::Heading { level: level as u8, content });
                    }

                    _ if line.starts_with("```") => {
                        if current_block_typ == BlockTyp::CodeBlockBlock {
                            Self::end_block(&mut current_block_typ, &mut active_block, &mut blocks, &mut code_block_language);
                            current_block_typ = BlockTyp::Misc;
                        } else {
                            current_block_typ = BlockTyp::CodeBlockBlock;
                            if let Some(item) = &line.split(' ').next()
                                && let Some(lang) = item.strip_prefix("```")
                            {
                                code_block_language = lang
                            }
                        }
                    }
                    _ if (untrimmed_line.starts_with("  ") | untrimmed_line.starts_with("    ")) && current_block_typ != BlockTyp::CodeBlockBlock => {
                        if current_block_typ != BlockTyp::Misc {
                            Self::end_block(&mut current_block_typ, &mut active_block, &mut blocks, &mut code_block_language);
                        } else {
                            current_block_typ = BlockTyp::CodeBlockLine;
                            let line = if untrimmed_line.starts_with("  ") { line } else { &line[5..] };
                            active_block.push(line);
                        }
                    }
                    _ => {
                        if current_block_typ != BlockTyp::CodeBlockBlock {
                            current_block_typ = BlockTyp::Paragraph;
                        }
                        active_block.push(line);
                    }
                }
            }
        }
        if current_block_typ != BlockTyp::CodeBlockBlock {
            Self::end_block(&mut current_block_typ, &mut active_block, &mut blocks, &mut code_block_language);
        }

        // for i in blocks.clone() {
        //     println!("{:?}", i);
        // }

        MarkdownNode::Document(blocks.into_iter().map(Self::parse_block).collect())
    }

    fn parse_block(block: MarkDownBlock<'a>) -> MarkdownNode<'a> {
        match block {
            MarkDownBlock::Heading { level, content } => MarkdownNode::Heading {
                level,
                children: Self::parse_inline(content),
            },
            MarkDownBlock::Paragraph { content } => MarkdownNode::Paragraph(content.iter().flat_map(|line| Self::parse_inline(line)).collect()),
            MarkDownBlock::OrderedList { content } => {
                MarkdownNode::OrderedList(content.iter().map(|item| MarkdownNode::ListItem(Self::parse_inline(item))).collect())
            }
            MarkDownBlock::UnorderedList { content } => {
                MarkdownNode::UnorderedList(content.iter().map(|item| MarkdownNode::ListItem(Self::parse_inline(item))).collect())
            }
            MarkDownBlock::BlockQuote { content } => MarkdownNode::BlockQuote(content.iter().flat_map(|item| Self::parse_inline(item)).collect()),
            MarkDownBlock::Table { content } => MarkdownNode::Table,
            MarkDownBlock::CodeBlock { language, content } => MarkdownNode::CodeBlock {
                language: if language.is_empty() { None } else { Some(language) },
                content,
            },
            MarkDownBlock::BreakLine => MarkdownNode::HorizontalLine,
        }
    }

    fn parse_inline(input: &'a str) -> Vec<MarkdownNode<'a>> {
        let mut res = Vec::new();
        let mut stack: Vec<(char, usize, usize)> = Vec::new();
        let mut cursor = 0;

        let chars: Vec<(usize, char)> = input.char_indices().collect();
        let mut i = 0;

        while i < chars.len() {
            let (idx, ch) = chars[i];

            match ch {
                '*' | '_' => {
                    let mut count = 1;
                    while i + count < chars.len() && chars[i + count].1 == ch {
                        count += 1;
                    }
                    if let Some((top_ch, start_idx, top_count)) = stack.last() {
                        if *top_ch == ch && *top_count <= count {
                            let inner = &input[start_idx + count..idx];

                            if *start_idx > cursor {
                                res.push(MarkdownNode::Text(&input[cursor..*start_idx]));
                            }

                            let inner_nodes = Self::parse_inline(inner);
                            let node = match count {
                                1 => MarkdownNode::Italic(inner_nodes),
                                2 => MarkdownNode::Bold(inner_nodes),
                                3 => MarkdownNode::Italic(vec![MarkdownNode::Bold(inner_nodes)]),
                                _ => MarkdownNode::Text(&input[*start_idx..idx + count]),
                            };
                            res.push(node);

                            cursor = idx + count;
                            stack.pop();
                            i += count - 1;
                        } else {
                            stack.push((ch, idx, count));
                            i += count - 1;
                        }
                    } else {
                        stack.push((ch, idx, count));
                        i += count - 1;
                    }
                }

                '`' => {
                    let mut count = 1;
                    while i + count < chars.len() && chars[i + count].1 == '`' {
                        count += 1;
                    }

                    if let Some((top_ch, start_idx, top_count)) = stack.last() {
                        if *top_ch == '`' && *top_count == count {
                            let inner = &input[start_idx + count..idx];
                            if *start_idx > cursor {
                                res.push(MarkdownNode::Text(&input[cursor..*start_idx]));
                            }
                            res.push(MarkdownNode::InlineCode(inner));

                            stack.pop();
                            cursor = idx + count;
                            i += count - 1;
                        } else {
                            stack.push(('`', idx, count));
                            i += count - 1;
                        }
                    } else {
                        stack.push(('`', idx, count));
                        i += count - 1;
                    }
                }
                _ => {}
            }
            i += 1;
        }

        if cursor < input.len() {
            res.push(MarkdownNode::Text(&input[cursor..]));
        }

        res
    }
    fn end_block<'b>(
        current_block_typ: &mut BlockTyp,
        active_block: &mut Vec<&'b str>,
        blocks: &mut Vec<MarkDownBlock<'b>>,
        code_block_language: &mut &'b str,
    ) {
        // println!("Ending block {:?}", current_block_typ);
        blocks.push(match current_block_typ {
            BlockTyp::Paragraph => MarkDownBlock::Paragraph {
                content: std::mem::take(active_block),
            },
            BlockTyp::UnorderedList => MarkDownBlock::UnorderedList {
                content: std::mem::take(active_block),
            },
            BlockTyp::OrderedList => MarkDownBlock::OrderedList {
                content: std::mem::take(active_block),
            },
            BlockTyp::BlockQuote => MarkDownBlock::BlockQuote {
                content: std::mem::take(active_block),
            },
            BlockTyp::Table => MarkDownBlock::Table {
                content: std::mem::take(active_block),
            },
            BlockTyp::CodeBlockBlock => MarkDownBlock::CodeBlock {
                language: code_block_language,
                content: std::mem::take(active_block),
            },
            BlockTyp::CodeBlockLine => MarkDownBlock::CodeBlock {
                language: "",
                content: std::mem::take(active_block),
            },
            BlockTyp::HorizontalLine => MarkDownBlock::BreakLine,
            BlockTyp::Misc => return,
        });
        *code_block_language = "";
    }

    fn html(node: MarkdownNode) -> String {
        let mut html = String::new();
        Self::html_helper(&node, &mut html);
        html
    }

    fn html_helper(node: &MarkdownNode, builder: &mut String) {
        // print!("{:?}", node);
        match node {
            MarkdownNode::Document(nodes) => {
                nodes.iter().for_each(|n| Self::html_helper(n, builder));
            }
            MarkdownNode::Paragraph(children) => {
                builder.push_str("<p>");
                for (idx, child) in children.iter().enumerate() {
                    Self::html_helper(child, builder);
                    if idx < children.len() - 1 {
                        builder.push('\n');
                    }
                }
                builder.push_str("</p>\n");
            }
            MarkdownNode::Text(text) => {
                builder.push_str(text);
            }
            MarkdownNode::Bold(children) => {
                builder.push_str("<strong>");
                children.iter().for_each(|n| Self::html_helper(n, builder));
                builder.push_str("</strong>");
            }
            MarkdownNode::Italic(children) => {
                builder.push_str("<em>");
                children.iter().for_each(|n| Self::html_helper(n, builder));
                builder.push_str("</em>");
            }

            MarkdownNode::Heading { level, children } => {
                let header_level = match level {
                    0 => panic!("Should not be parsed"),
                    1 => "h1",
                    2 => "h2",
                    3 => "h3",
                    4 => "h4",
                    5 => "h5",
                    _ => "h6",
                };

                builder.push('<');
                builder.push_str(header_level);
                builder.push('>');
                children.iter().for_each(|n| Self::html_helper(n, builder));
                builder.push_str("</");
                builder.push_str(header_level);
                builder.push_str(">\n");
                if *level < 3 {
                    builder.push_str("<hr/>\n");
                }
            }
            MarkdownNode::InlineCode(code) => {
                builder.push_str("<code>");
                builder.push_str(code);
                builder.push_str("</code>");
            }
            MarkdownNode::CodeBlock { language, content } => {
                builder.push_str("<pre><code>\n");
                for (idx, child) in content.iter().enumerate() {
                    builder.push_str(child);
                    if idx < content.len() - 1 {
                        builder.push('\n');
                    }
                }
                builder.push_str("</code></pre>\n");
            }
            MarkdownNode::OrderedList(nodes) => {
                builder.push_str("<ol type=\"1\">\n");
                nodes.iter().for_each(|n| Self::html_helper(n, builder));
                builder.push_str("</ol>\n");
            }
            MarkdownNode::UnorderedList(nodes) => {
                builder.push_str("<ul>\n");
                nodes.iter().for_each(|n| Self::html_helper(n, builder));
                builder.push_str("</ul>\n");
            }
            MarkdownNode::ListItem(nodes) => {
                builder.push_str("  <li> ");
                nodes.iter().for_each(|n| Self::html_helper(n, builder));
                builder.push('\n');
            }
            MarkdownNode::BlockQuote(nodes) => {
                builder.push_str("<blockquote>\n");
                for child in nodes {
                    Self::html_helper(child, builder);
                    builder.push('\n');
                }
                builder.push_str("</blockquote>\n");
            }
            MarkdownNode::HorizontalLine => {
                builder.push_str("<hr/>\n");
            }
            MarkdownNode::Table => {}
            MarkdownNode::Link { text, url } => {
                builder.push('(');
                text.iter().for_each(|n| Self::html_helper(n, builder));
                builder.push(')');

                builder.push('[');
                builder.push_str(url);
                builder.push(']');
            }
        }
    }
}
