#![feature(tcp_linger)]
#![feature(if_let_guard)]
#![feature(hash_map_macro)]
#![feature(slice_split_once)]
#![allow(unused)]
// #![allow(unused_mut)]

use std::borrow::Cow;
use std::cmp::{max, min};
use std::collections::{HashMap, HashSet};
use std::env;
use std::error::Error;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::fmt::{Debug, Display};
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::iter::{Peekable, zip};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf, StripPrefixError};
use std::process::Command;
use std::ptr::{null, null_mut};
use std::slice;
use std::str::{CharIndices, FromStr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::vec::IntoIter;
use std::{char, fmt, fs, vec};

const SOCKET_ADDR: &str = "127.0.0.1:4000";
const ASSETS_PATH: &str = "./assets/";
const TEMPLATES_PATH: &str = "./templates/";

#[cfg(generated)]
include!(concat!(env!("OUT_DIR"), "/generated.rs"));

fn main() -> Result<(), Box<dyn Error>> {
    if std::env::args().any(|arg| arg.contains("build-script-build")) {
        println!("cargo:warning=Running in build script");
        comptime()
    } else {
        println!("Running normally");
        #[cfg(generated)] // Marks everything deadcode during build time
        runtime()?;

        Ok(())
    }
}

fn runtime() -> Result<(), Box<dyn Error>> {
    register_signal_handlers();

    let mut db = Db::init()?;
    println!("Initialized db");
    db.test_counter()?;
    db.sync()?;

    let content = Content::load_embedded()?;

    println!(
        "Static/Generated asset count: {:?}/{:?}",
        content.assets.len(),
        content.templates.len()
    );
    let context = Context::load_intial(&content);

    // println!("{context:#?}");

    let router = Router::new(content, context, db)
        .route_static_hidden("/layout", "layout.html")
        .route_static_hidden("/home", "pages/home.html")
        .route_static_page("/posts", "pages/posts.html")
        .route_static_page("/about", "pages/about.html")
        .route_static_page("/qoutes", "pages/quotes.html")
        .route_static_page("/stats", "pages/stats.html")
        .route_dynamic_pages("/posts/:post", "pages/post.html", "posts")?
        .fallback("/home");

    let listener: TcpListener = TcpListener::bind(SOCKET_ADDR).expect("Unable to bind to socket");
    println!("Started listening on socket http://{SOCKET_ADDR}");

    HttpServer::serve(listener, router)?;
    Ok(())
}

impl Context {
    fn load_intial(content: &Content) -> Context {
        let mut context = Context::new();

        context.update_posts(content);
        context.insert_global("copyright_start", TemplateValue::Text("2026".to_string()));
        context.insert_global("copyright_end", TemplateValue::Text("2026".to_string())); // TODO make dynamic

        #[cfg(generated)]
        {
            context.insert_global(
                "git_hash_short",
                TemplateValue::Text(GIT_HASH_SHORT.to_string()),
            );
            context.insert_global(
                "git_hash_long",
                TemplateValue::Text(GIT_HASH_LONG.to_string()),
            );
        }

        #[cfg(debug_assertions)]
        let hotreload = true;
        #[cfg(not(debug_assertions))]
        let hotreload = false;
        context.insert_global("hotreload", hotreload.to_template_value());

        context
    }
}

const DEBUG_BIN_PATH: &str = "./target/debug/webber";
const RELEASE_BIN_PATH: &str = "./target/release/webber";

fn comptime() -> Result<(), Box<dyn Error>> {
    println!("cargo:rustc-cfg=generated");
    println!("cargo:rerun-if-changed=./assets");
    println!("cargo:rerun-if-changed=./templates");
    println!("cargo:rerun-if-changed={DEBUG_BIN_PATH}");
    println!("cargo:rerun-if-changed={RELEASE_BIN_PATH}");

    // === Init ===
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let last_bin_path = Path::new(&out_dir).join("prev_bin");
    let generated_code_path = Path::new(&out_dir).join("generated.rs");
    let cwd = std::env::current_dir().expect("current dir");
    let cwd = cwd.to_string_lossy();

    let asset_paths = walk_dir(ASSETS_PATH);

    let mut out = String::new();

    //  === Assets ===

    out.push_str("fn load_embedded_assets() -> Result<Trie<Asset>, io::Error>{\n");
    out.push_str("\tlet mut assets = Trie::new();\n");

    out.push_str("\tlet paths = vec![\n");
    for asset_path in asset_paths {
        let global_path = format!("{cwd}/{}", asset_path.to_string_lossy());
        let str_path = asset_path
            .strip_prefix(ASSETS_PATH)
            .expect("Failed to strip prefix")
            .to_string_lossy()
            .into_owned();
        let content_str = match asset_path.extension().and_then(|s| s.to_str()) {
            Some("png") => &format!("AssetData::Png(include_bytes!({global_path:?}).to_vec())"),
            Some("ico") => &format!("AssetData::Png(include_bytes!({global_path:?}).to_vec())"),
            Some("woff2") => &format!("AssetData::Woff2(include_bytes!({global_path:?}).to_vec())"),
            Some("md") => &format!(
                "AssetData::MdParsed(MarkdownParser::parse(include_str!({global_path:?})))"
            ),
            Some("html") => &format!("AssetData::Html(include_str!({global_path:?}))"),
            Some("txt") => &format!("AssetData::Text(include_str!({global_path:?}).to_string())"),
            Some("css") => &format!("AssetData::Css(include_str!({global_path:?}).to_string())"),
            Some("js") => &format!("AssetData::Js(include_str!({global_path:?}).to_string())"),
            _ => &format!("AssetData::Unknown(include_str!({global_path:?}))"),
        };

        out.push_str(&format!(
            "\t\t(\"/{str_path}\".to_string(),{content_str}),\n"
        ));
    }
    out.push_str("\t];\n");

    out.push_str("\tfor (key, content) in paths {\n");
    out.push_str("\t\tassets.insert(key,Asset::new(content));\n");
    out.push_str("\t}\n");

    out.push_str("\tOk(assets)\n");
    out.push_str("}\n");

    out.push('\n');

    // === Templates ===

    let template_paths = walk_dir(TEMPLATES_PATH);

    out.push_str(
        "fn load_embedded_templates() -> Result<HashMap<String, Template>,TemplateError> {\n",
    );
    out.push_str("\tlet mut templates = HashMap::new();\n");

    out.push_str("\tlet paths = vec![\n");
    for template_path in template_paths {
        let path_key = template_path.to_string_lossy();
        let global_path = format!("{cwd}/{path_key}");
        let stripped_key = path_key
            .strip_prefix(TEMPLATES_PATH)
            .expect("Failed to find prefix");

        let content_str = match template_path.extension().and_then(|s| s.to_str()) {
            Some("html") => &format!("include_str!({global_path:?})"),
            _ => continue,
        };
        out.push_str(&format!(
            "\t\t({path_key:?},{stripped_key:?},{content_str}),\n"
        ));
    }
    out.push_str("\t];\n");

    out.push_str("\tfor (origin_file, key, template_str) in paths {\n");
    out.push_str(
        "\t\tlet template = Template::from_str(origin_file.to_string(), template_str)?;\n",
    );

    out.push_str("\t\ttemplates.insert(key.to_string(),template);\n");
    out.push_str("\t}\n");

    out.push_str("\tOk(templates)\n");
    out.push_str("}\n");

    // Db
    let debug_path = PathBuf::from(DEBUG_BIN_PATH);
    let release_path = PathBuf::from(RELEASE_BIN_PATH);

    let bin_tupple = match (debug_path.exists(), release_path.exists()) {
        (true, false) => Some((debug_path, true)),
        (false, true) => Some((release_path, false)),

        (true, true) => {
            if fs::metadata(&debug_path)?.modified()? > fs::metadata(&release_path)?.modified()? {
                Some((debug_path, true))
            } else {
                Some((release_path, false))
            }
        }

        (false, false) => None,
    };

    match bin_tupple {
        Some((prev_bin_path, is_debug)) => {
            fs::copy(&prev_bin_path, &last_bin_path)?;

            println!(
                "cargo:warning=embedding binary path: {}",
                prev_bin_path.display()
            );

            if is_debug {
                out.push_str("static PREV_BIN_TYPE: Option<&str> = Some(\"debug\");\n");
            } else {
                out.push_str("static PREV_BIN_TYPE: Option<&str> = Some(\"release\");\n");
            }

            out.push_str(&format!(
                "static PREV_BIN_PATH: Option<&str> = Some({last_bin_path:?});\n"
            ));
        }

        None => {
            println!("cargo:warning=no existing selfmod binary found");

            out.push_str("static PREV_BIN_TYPE: Option<&str> = None;\n");
            out.push_str("static PREV_BIN_PATH: Option<&str> = None;\n");
        }
    };

    // === Git ===
    let (short, long) = get_commit_hash();

    out.push_str(&format!("const GIT_HASH_SHORT:&str = {short:?};\n"));
    out.push_str(&format!("const GIT_HASH_LONG:&str = {long:?};\n"));

    fs::write(&generated_code_path, out).unwrap();
    println!("cargo:warning=End of build script");
    Ok(())
}

fn get_commit_hash() -> (String, String) {
    let short = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|s| s.trim().to_string())
        .expect("unable to get git hash");

    let long = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|s| s.trim().to_string())
        .expect("unable to get git hash");

    (short, long)
}

// === Templating ===

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

impl ToTemplateValue for SystemTime {
    fn to_template_value(&self) -> TemplateValue {
        TemplateValue::Text(format!("{:?}", self.duration_since(SystemTime::UNIX_EPOCH)))
    }
}

impl<T: ToTemplateValue> ToTemplateValue for Vec<T> {
    fn to_template_value(&self) -> TemplateValue {
        TemplateValue::List(self.iter().map(|item| item.to_template_value()).collect())
    }
}
impl ToTemplateValue for AssetData {
    fn to_template_value(&self) -> TemplateValue {
        match self {
            AssetData::Png(b) | AssetData::Ico(b) | AssetData::Woff2(b) => {
                todo!("Cant embed binary assets yet")
            }
            AssetData::Empty => todo!("not sure what to do with this"),
            AssetData::Text(s)
            | AssetData::Html(s)
            | AssetData::Css(s)
            | AssetData::Js(s)
            | AssetData::JsPrism(s, _)
            | AssetData::MdRaw(s)
            | AssetData::Unknown(s) => TemplateValue::Text(s.to_string()),
            AssetData::MdParsed(ParsedMarkdown {
                html,
                metadata,
                highlighted_langs,
            }) => {
                let mut obj = HashMap::new();

                obj.insert("content".to_string(), TemplateValue::Text(html.to_string()));

                obj.insert(
                    "title".to_string(),
                    TemplateValue::Text(metadata.title.to_string()),
                );
                obj.insert(
                    "slug".to_string(),
                    TemplateValue::Text(metadata.slug.to_string()),
                );
                obj.insert(
                    "published".to_string(),
                    TemplateValue::Text(metadata.published.to_string()),
                );
                obj.insert("draft".to_string(), TemplateValue::Bool(metadata.draft));
                obj.insert("tags".to_string(), metadata.tags.to_template_value());

                let highlighted_langs =
                    SyntaxHighlightLang::include_dependencies(highlighted_langs);

                obj.insert(
                    "highlighted_langs".to_string(),
                    highlighted_langs.to_template_value(),
                );

                TemplateValue::Object(obj)
            }
        }
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

#[derive(Debug, Clone)]
struct TemplateNode {
    data: TemplateNodeData,
    pos: TemplatePositionData,
}

#[derive(Debug, Clone)]
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
    Block {
        ident: String,
        body: Vec<TemplateNode>,
    },
}

#[derive(Clone, Debug)]
enum TemplateNodeKind {
    Text,
    Variable,
    If,
    For,
    Block,
}

impl TemplateNodeData {
    fn kind(&self) -> TemplateNodeKind {
        match self {
            TemplateNodeData::Text(_) => TemplateNodeKind::Text,
            TemplateNodeData::Variable(_) => TemplateNodeKind::Variable,
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
            TemplateNodeData::Variable(parts) => {
                write!(f, "{}", parts.join("."))
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

                write!(
                    f,
                    "if {} then {{\n \t{}\n}} else {{\n\t{}\n}}",
                    condition.join("."),
                    then_branch_str,
                    else_branch_str
                )
            }
            TemplateNodeData::For {
                iter_bind,
                iter_src,
                body,
            } => {
                let body_str = body
                    .iter()
                    .map(|n| format!("{}", n.data))
                    .collect::<Vec<_>>()
                    .join("\n");

                write!(
                    f,
                    "for {} in {} {{\n{}\n}}",
                    iter_bind,
                    iter_src.join("."),
                    body_str
                )
            }
            TemplateNodeData::Block { ident, body } => {
                let body_str = body
                    .iter()
                    .map(|n| format!("{}", n.data))
                    .collect::<Vec<_>>()
                    .join("\n");
                write!(f, "block {ident} {{\n{body_str}\n}}")
            } // TemplateNodeData::Extends { path } => {
              //     write!(f, "extends \"{path}\"")
              // }
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
    Path(String),
    Dot,
    If,
    Else,
    For,
    In,
    EndIf,
    EndElse,
    EndFor,
    NewLine,
    Block,
    EndBlock,
    Extends,
    // ParenOpen(PositionData),
    // ParenClose(PositionData),
}

#[derive(Debug, Clone)]
struct TemplatePositionData {
    file: Arc<String>,
    start_pos: Position,
    end_pos: Position,
}

impl Default for TemplatePositionData {
    fn default() -> Self {
        Self {
            file: Arc::new("".to_owned()),
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
struct TemplateParseError {
    typ: TemplateParseErrorMsg,
    pos: Option<TemplatePositionData>,
}

impl TemplatePositionData {
    fn merge(&self, other: &TemplatePositionData) -> Result<Self, TemplateParseError> {
        if self.file != other.file {
            Err(TemplateParseError::no_info(
                TemplateParseErrorMsg::MergingSpansFromDifferentFiles(
                    self.file.to_string(),
                    other.file.to_string(),
                ),
            ))
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
    ExtendsNotFirstLine,
    UnexpectedEOF,
}

#[derive(Debug)]
struct TemplateRenderError {
    typ: TemplateRenderErrorMsg,
    pos: TemplatePositionData,
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
impl Error for TemplateError {}

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
        TemplateError::Parse(TemplateParseError::no_info(
            TemplateParseErrorMsg::GenericError(e.to_string()),
        ))
    }
}

impl<T> From<std::sync::PoisonError<T>> for TemplateError {
    fn from(e: std::sync::PoisonError<T>) -> Self {
        TemplateError::Parse(TemplateParseError::no_info(
            TemplateParseErrorMsg::GenericError(e.to_string()),
        ))
    }
}

impl From<StripPrefixError> for TemplateError {
    fn from(e: StripPrefixError) -> Self {
        TemplateError::Parse(TemplateParseError::no_info(
            TemplateParseErrorMsg::GenericError(e.to_string()),
        ))
    }
}

impl TemplateParseError {
    fn new(typ: TemplateParseErrorMsg, pos: TemplatePositionData) -> Self {
        Self {
            typ,
            pos: Some(pos),
        }
    }
    fn no_info(typ: TemplateParseErrorMsg) -> Self {
        Self { typ, pos: None }
    }
    fn only_file(typ: TemplateParseErrorMsg, file: &str) -> Self {
        Self {
            typ,
            pos: Some(TemplatePositionData {
                file: Arc::new(file.to_owned()),
                start_pos: Position { line: 0, column: 0 },
                end_pos: Position { line: 0, column: 0 },
            }),
        }
    }
}

impl TemplateRenderError {
    fn new(typ: TemplateRenderErrorMsg, pos: TemplatePositionData) -> Self {
        Self { typ, pos }
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

        // println!("File: {}", path_string);
        // for i in &lexed {
        //     println!("\t{:?}", i.kind);
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
            file: Arc::new(file_path.to_owned()),
            start_pos: Position { line: 0, column: 0 },
            end_pos: Position { line: 0, column: 0 },
        };

        while cursor < input_len {
            let rest = &input[cursor..];

            // if rest.starts_with(char::is_whitespace) {
            //   cursor += 1;
            //   metadata.end_pos.column += 1;
            //   continue;
            // }

            if rest.starts_with("\n") {
                metadata.end_pos.line += 1;
                metadata.end_pos.column = 0;
            }

            if rest.starts_with("{{") {
                if !in_block && cursor != 0 {
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
                    let mut lexed_code = Self::lex_code(code_text, &mut metadata);
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

        if start_block < input_len {
            let text = input[start_block..].to_string();

            if !text.is_empty() {
                lexed.push(TemplateToken {
                    kind: TemplateTokenKind::Text(text),
                    metadata: metadata.clone(),
                });
            }
        }
        lexed
    }

    fn lex_code(input: &str, metadata: &mut TemplatePositionData) -> Vec<TemplateToken> {
        use TemplateTokenKind::*;

        let mut lexed = vec![];

        let mut cursor = 0;
        let input_len = input.len();

        let mut start_ident = 0;
        while cursor < input_len {
            let rest = &input[cursor..];
            let end_ident = cursor;

            if rest.starts_with("\"") {
                if start_ident != cursor {
                    let ident = input[start_ident..cursor].trim().to_string();
                    if !ident.is_empty() {
                        lexed.push(TemplateToken {
                            kind: Identifier(ident),
                            metadata: metadata.clone(),
                        });
                    }
                }
                cursor += 1;
                metadata.end_pos.column += 1;

                let start_path = cursor;
                while cursor < input.len() && !input[cursor..cursor + 1].starts_with("\"") {
                    cursor += 1;
                    metadata.end_pos.column += 1;
                }
                let path_str = input[start_path..cursor].to_string();

                cursor += 1;
                metadata.end_pos.column += 1;

                lexed.push(TemplateToken {
                    kind: TemplateTokenKind::Path(path_str),
                    metadata: metadata.clone(),
                });
                start_ident = cursor;
                continue;
            }

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
            } else if rest.starts_with("block") {
                Some((Block, 5, false))
            } else if rest.starts_with("endBlock") {
                Some((EndBlock, 8, false))
            } else if rest.starts_with("extends") {
                Some((Extends, 7, false))
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
                    metadata.end_pos.column = 0;
                }

                if start_ident != end_ident {
                    let ident = input[start_ident..end_ident].trim().to_string();
                    if !ident.is_empty() {
                        lexed.push(TemplateToken {
                            kind: Identifier(ident),
                            metadata: metadata.clone(),
                        });
                    }
                }
                lexed.push(TemplateToken {
                    kind: tok,
                    metadata: metadata.clone(),
                });
                start_ident = cursor;
            }

            cursor += 1;
        }
        if start_ident + 1 != cursor {
            let ident = input[start_ident..].trim().to_string();

            if !ident.is_empty() {
                lexed.push(TemplateToken {
                    kind: Identifier(ident),
                    metadata: metadata.clone(),
                });
            }
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
                    Err(TemplateParseError::new(
                        TemplateParseErrorMsg::UnexpectedEOF,
                        prev.metadata.clone(),
                    ))?
                } else {
                    Err(TemplateParseError::no_info(
                        TemplateParseErrorMsg::UnexpectedEOF,
                    ))?
                }
            }
        }
    }

    fn peek(&mut self) -> Option<&TemplateToken> {
        self.tokens.peek()
    }

    fn consume(
        &mut self,
        expected_token_kind: TemplateTokenKind,
    ) -> Result<TemplateToken, TemplateError> {
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
                Err(TemplateParseError::new(
                    TemplateParseErrorMsg::ExpectButEOF(expected_token_kind),
                    pos,
                ))?
            }
        }
    }

    fn parse(&mut self) -> Result<(Option<String>, Vec<TemplateNode>), TemplateError> {
        Ok((self.parse_extends()?, self.parse_until(&[])?))
    }

    fn parse_until(
        &mut self,
        stop: &[TemplateTokenKind],
    ) -> Result<Vec<TemplateNode>, TemplateError> {
        use TemplateTokenKind::*;
        let mut parsed = vec![];

        while let Some(next_token) = &self.tokens.peek() {
            if stop.contains(&next_token.kind) {
                break;
            }
            match &next_token.kind {
                If => {
                    parsed.push(self.parse_if()?);
                }
                Identifier(_) => {
                    parsed.push(self.parse_var()?);
                }
                For => {
                    parsed.push(self.parse_for()?);
                }
                Block => {
                    parsed.push(self.parse_block()?);
                }
                Extends => {
                    return Err(TemplateParseError::new(
                        TemplateParseErrorMsg::ExtendsNotFirstLine,
                        next_token.metadata.clone(),
                    ))?;
                }
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

    fn parse_extends(&mut self) -> Result<Option<String>, TemplateError> {
        use TemplateTokenKind::*;
        // self.show_next_n_tokens(10);

        match self.peek() {
            Some(token) if token.kind == Extends => {
                self.consume(Extends)?;

                let token = self.next_token()?;
                match token.kind {
                    Path(path) => Ok(Some(path)),
                    other => Err(TemplateParseError::new(
                        TemplateParseErrorMsg::UnexpectedToken(
                            other,
                            Identifier("<path>".to_string()),
                        ),
                        token.metadata,
                    ))?,
                }
            }
            _ => Ok(None),
        }
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
                    TemplateParseErrorMsg::UnexpectedTemplateValueType(
                        TemplateNodeKind::Variable,
                        node.kind(),
                    ),
                    cond_node.pos,
                ))?;
            }
        };

        let then_branch = self.parse_until(&[Else, EndIf])?;

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

    fn parse_block(&mut self) -> Result<TemplateNode, TemplateError> {
        use TemplateTokenKind::*;

        let start_block = self.consume(Block)?;
        let ident_node = self.parse_var()?;

        let ident = match ident_node.data {
            ref node @ TemplateNodeData::Variable(ref var) if var.len() > 1 => {
                return Err(TemplateParseError::new(
                    TemplateParseErrorMsg::GenericError(format!(
                        "blocks can only contain single level identifiers {node}"
                    )),
                    ident_node.pos,
                ))?;
            }
            TemplateNodeData::Variable(var) => var.first().expect("invariant").clone(),
            node => {
                return Err(TemplateParseError::new(
                    TemplateParseErrorMsg::UnexpectedTemplateValueType(
                        TemplateNodeKind::Variable,
                        node.kind(),
                    ),
                    ident_node.pos,
                ))?;
            }
        };

        let body = self.parse_until(&[EndBlock])?;
        let end_block = self.consume(EndBlock)?;

        Ok(TemplateNode {
            data: TemplateNodeData::Block {
                ident: ident.to_string(),
                body,
            },
            pos: start_block.metadata.merge(&end_block.metadata)?,
        })
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
                    TemplateParseErrorMsg::UnexpectedTemplateValueType(
                        TemplateNodeKind::Variable,
                        node.kind(),
                    ),
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
                    self.consume(Dot)?;
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

#[derive(Debug)]
struct Template {
    template: Vec<TemplateNode>,
    parent: Option<String>,
    blocks: HashMap<String, Vec<TemplateNode>>,
    required_variables: Vec<String>,
    origin_file: String,
    last_modified: SystemTime,
}

impl Template {
    fn from_path<P: AsRef<Path> + Debug + Copy>(path: P) -> Result<Self, TemplateError> {
        let path_string = path.as_ref().to_string_lossy().to_string();

        let template_str = match fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                return Err(TemplateParseError::only_file(
                    TemplateParseErrorMsg::GenericError(e.to_string()),
                    &path_string,
                ))?;
            }
        };

        Self::from_str(path_string, &template_str)
    }

    fn update_from_path<P: AsRef<Path> + Debug + Copy>(
        template: &mut Template,
        path: P,
    ) -> Result<(), TemplateError> {
        let path_string = path.as_ref().to_string_lossy().to_string();

        let template_str = match fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                return Err(TemplateParseError::only_file(
                    TemplateParseErrorMsg::GenericError(e.to_string()),
                    &path_string,
                ))?;
            }
        };

        let (extends, new_template) = TemplateParser::lex(&template_str, &path_string).parse()?;
        let required_variables = Self::get_required_vars(&new_template);

        template.blocks = Self::get_blocks(&new_template);
        template.template = new_template;
        template.parent = extends;
        template.required_variables = required_variables;
        template.last_modified = SystemTime::now();

        Ok(())
    }

    fn from_str(path_string: String, template_str: &str) -> Result<Self, TemplateError> {
        let (extends, template_nodes) = TemplateParser::lex(template_str, &path_string).parse()?;

        // for i in &parsed {
        //     print!("{}", i.data);
        // }
        let required_variables = Self::get_required_vars(&template_nodes);
        let blocks = Self::get_blocks(&template_nodes);
        Ok(Template {
            template: template_nodes,
            parent: extends,
            required_variables,
            origin_file: path_string,
            last_modified: SystemTime::now(),
            blocks,
        })
    }

    fn render(&self, context: &mut Context) -> Result<String, TemplateError> {
        Self::render_helper(&self.template, context, &HashMap::new())
    }

    fn render_with_blocks(
        &self,
        context: &mut Context,
        blocks: &HashMap<String, Vec<TemplateNode>>,
    ) -> Result<String, TemplateError> {
        Self::render_helper(&self.template, context, blocks)
    }

    fn render_helper(
        nodes: &Vec<TemplateNode>,
        context: &mut Context,
        blocks: &HashMap<String, Vec<TemplateNode>>,
    ) -> Result<String, TemplateError> {
        use TemplateNodeData::*;
        let mut res = String::new();
        for node in nodes {
            match &node.data {
                Text(text) => res.push_str(text),
                Variable(ident_fields) => {
                    if let TemplateValue::Text(text) =
                        Self::resolve_var(ident_fields, context, &node.pos)?
                    {
                        res.push_str(text);
                    } else {
                        return Err(TemplateRenderError::new(
                            TemplateRenderErrorMsg::NodeNotOfExpectedType(
                                ident_fields.concat(),
                                TemplateNodeKind::Text,
                            ),
                            node.pos.clone(),
                        ))?;
                    }
                }
                If {
                    condition,
                    then_branch,
                    else_branch,
                } => match Self::resolve_var(condition, context, &node.pos)? {
                    TemplateValue::Bool(cond) => {
                        let cond_str = if *cond {
                            Self::render_helper(then_branch, context, blocks)?
                        } else {
                            Self::render_helper(else_branch, context, blocks)?
                        };
                        res.push_str(&cond_str);
                    }
                    TemplateValue::List(template_values) => {
                        let cond_str = if !template_values.is_empty() {
                            Self::render_helper(then_branch, context, blocks)?
                        } else {
                            Self::render_helper(else_branch, context, blocks)?
                        };
                        res.push_str(&cond_str);
                    }
                    _ => {
                        return Err(TemplateRenderError::new(
                            TemplateRenderErrorMsg::VariableNotOfExpectedType(
                                condition.concat(),
                                TemplateValueKind::Bool,
                            ),
                            node.pos.clone(),
                        ))?;
                    }
                },
                For {
                    iter_bind,
                    iter_src,
                    body,
                } => {
                    if let TemplateValue::List(iter) =
                        Self::resolve_var(iter_src, context, &node.pos)?.clone()
                    {
                        let mut for_res = String::new();
                        for it in iter {
                            context.push();
                            context.insert_local(iter_bind, it.clone());
                            for_res.push_str(&Self::render_helper(body, context, blocks)?);
                            context.pop();
                        }
                        res.push_str(&for_res);
                    } else {
                        return Err(TemplateRenderError::new(
                            TemplateRenderErrorMsg::VariableNotOfExpectedType(
                                iter_src.concat(),
                                TemplateValueKind::List,
                            ),
                            node.pos.clone(),
                        ))?;
                    }
                }
                Block { ident, body } => {
                    if let Some(override_body) = blocks.get(ident) {
                        let body_str = Self::render_helper(override_body, context, blocks)?;
                        res.push_str(&body_str);
                    } else {
                        let body_str = Self::render_helper(body, context, blocks)?;
                        res.push_str(&body_str);
                    }
                }
            };
        }
        Ok(res)
    }

    fn resolve_var<'a>(
        ident_fields: &[String],
        context: &'a Context,
        pos: &TemplatePositionData,
    ) -> Result<&'a TemplateValue, TemplateRenderError> {
        let mut current = if let Some(current) = context.lookup(&ident_fields[0]) {
            current
        } else {
            return Err(TemplateRenderError::new(
                TemplateRenderErrorMsg::VariableNotFound(ident_fields[0].to_string()),
                pos.clone(),
            ));
        };

        let mut idx = 1;
        for field in &ident_fields[1..] {
            current = match current {
                TemplateValue::Object(map) => {
                    if let Some(obj) = map.get(field.as_str()) {
                        obj
                    } else {
                        return Err(TemplateRenderError::new(
                            TemplateRenderErrorMsg::FieldNotFoundOnVariable(
                                ident_fields[1..idx].concat(),
                                field.to_string(),
                            ),
                            pos.clone(),
                        ));
                    }
                }
                _ => Err(TemplateRenderError::new(
                    TemplateRenderErrorMsg::VariableNotOfExpectedType(
                        field.to_string(),
                        TemplateValueKind::List,
                    ),
                    pos.clone(),
                ))?,
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

    fn get_blocks(ast: &[TemplateNode]) -> HashMap<String, Vec<TemplateNode>> {
        ast.iter()
            .filter_map(|node| {
                if let TemplateNodeData::Block { ident, body } = &node.data {
                    Some((ident.clone(), body.clone()))
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
#[derive(Debug)]
struct Context {
    global_context: HashMap<String, TemplateValue>,
    local_context: Vec<HashMap<String, TemplateValue>>,
}

impl Context {
    fn new() -> Self {
        Context {
            global_context: HashMap::new(),
            local_context: vec![HashMap::new()],
        }
    }

    fn push(&mut self) {
        self.local_context.push(HashMap::new());
    }

    fn pop(&mut self) {
        if self.local_context.len() > 1 {
            self.local_context.pop();
        } else {
            self.local_context = vec![HashMap::new()]
        }
    }

    fn insert_local(&mut self, key: &str, value: TemplateValue) {
        self.local_context
            .last_mut()
            .expect("invariant")
            .insert(key.to_owned(), value);
    }
    fn insert_global(&mut self, key: &str, value: TemplateValue) {
        self.global_context.insert(key.to_owned(), value);
    }

    fn lookup(&self, key: &str) -> Option<&TemplateValue> {
        if let Some(val) = self.global_context.get(key) {
            Some(val)
        } else {
            for context in &self.local_context {
                if let Some(val) = context.get(key) {
                    return Some(val);
                }
            }
            None
        }
    }

    fn lookup_mut(&mut self, key: &str) -> Option<&mut TemplateValue> {
        if let Some(val) = self.global_context.get_mut(key) {
            Some(val)
        } else {
            for context in &mut self.local_context {
                if let Some(val) = context.get_mut(key) {
                    return Some(val);
                }
            }
            None
        }
    }

    fn update_posts(&mut self, content: &Content) {
        let posts: Vec<AssetData> = content
            .assets
            .get_partial("/posts/")
            .into_iter()
            .cloned()
            .map(|p| p.data)
            .collect();

        let post_values = posts.to_template_value();

        let mut posts_by_slug = HashMap::new();

        if let TemplateValue::List(list) = &post_values {
            for post in list {
                if let TemplateValue::Object(object) = post
                    && let Some(TemplateValue::Text(slug)) = object.get("slug")
                {
                    posts_by_slug.insert(slug.clone(), post.clone());
                }
            }
        }

        self.global_context.insert("posts".to_string(), post_values);

        self.global_context.insert(
            "posts_by_slug".to_string(),
            TemplateValue::Object(posts_by_slug),
        );
    }
}

impl ToTemplateValue for Duration {
    fn to_template_value(&self) -> TemplateValue {
        TemplateValue::Text(format!("{:.2?}", self))
    }
}
impl ToTemplateValue for u64 {
    fn to_template_value(&self) -> TemplateValue {
        TemplateValue::Text(format!("{:.2?}", self))
    }
}

#[derive(Debug)]
struct DynamicRoute {
    _base_url: String,
    _page_list_name: String,
    page_var_name: String,
    template_path: String,
    cached_page: Option<String>,
    slug: String,
}

#[derive(Debug, Clone)]
struct StaticRoute {
    path: String,
    cached_page: Option<String>,
    hidden: bool,
}

impl StaticRoute {
    fn new(path: &str, hidden: bool) -> Self {
        Self {
            path: path.to_owned(),
            cached_page: None,
            hidden,
        }
    }
}

#[derive(Debug)]
struct Router {
    content: Content,
    context: Context,
    db: Db,
    static_routes: HashMap<String, StaticRoute>,
    dynamic_routes: HashMap<String, DynamicRoute>,

    fallback: Option<String>,
}

impl Router {
    fn new(content: Content, context: Context, db: Db) -> Self {
        Router {
            content,
            context,
            db,
            static_routes: HashMap::new(),
            dynamic_routes: HashMap::new(),
            fallback: None,
        }
    }

    fn route_static_page(mut self, path: &str, template: &str) -> Self {
        let route = StaticRoute::new(template, false);
        self.static_routes.insert(path.into(), route.clone());
        let name = path.split("/").last().expect("valid path");

        let obj = TemplateValue::Object(hash_map! {
          "url".to_string() => TemplateValue::Text(path.to_string()),
          "hidden".to_string() => TemplateValue::Bool(route.hidden),
          "name".to_string() => TemplateValue::Text(name.to_string()),
        });

        if let Some(pages) = self.context.lookup_mut("pages-static") {
            if let TemplateValue::List(list) = pages {
                list.push(obj);
            } else {
                panic!("overwrote \"pages-static\" with something")
            }
        } else {
            let page_list = TemplateValue::List(vec![obj]);

            self.context.insert_global("pages-static", page_list);
        }

        self
    }

    fn route_static_hidden(mut self, path: &str, template: &str) -> Self {
        self.static_routes
            .insert(path.into(), StaticRoute::new(template, true));
        self
    }

    fn route_dynamic_pages(
        mut self,
        path: &str,
        base_template_path: &str,
        list_name: &str,
    ) -> Result<Self, TemplateError> {
        let (base_path, key) = path.rsplit_once(':').expect("expected path to contain ':'");

        let template_value = self
            .context
            .lookup(list_name)
            .unwrap_or_else(|| panic!("Failed to find var {} in context", list_name))
            .clone();

        let TemplateValue::List(page_list) = template_value else {
            todo!("dynamic page source must be a list");
        };

        for page in page_list {
            if let TemplateValue::Object(ref object) = page
                && let Some(TemplateValue::Text(slug)) = object.get("slug")
            {
                let url = format!("{base_path}{slug}");

                let dyn_route = DynamicRoute {
                    _base_url: base_path.to_owned(),
                    _page_list_name: list_name.to_owned(),
                    page_var_name: key.to_owned(),
                    template_path: base_template_path.to_owned(),
                    slug: slug.to_string(),
                    cached_page: None,
                };

                self.dynamic_routes.insert(url, dyn_route);
            }
        }

        Ok(self)
    }

    fn fallback(mut self, page: &str) -> Self {
        self.fallback = Some(page.to_string());
        self
    }

    fn serve_page(
        &mut self,
        header: &HttpRequestHeader,
        _body: AssetData,
    ) -> Result<AssetData, HttpServerError> {
        match self.static_routes.get(&header.path) {
            Some(route) if let Some(cached) = &route.cached_page => {
                println!("Serving cached page {}", header.path);

                Ok(AssetData::Html(cached.to_string()))
            }

            Some(route) if header.path == "/stats" => {
                self.context.push();
                let stats = self
                    .db
                    .load_stats()
                    .expect("TOPO improve error handeling to make this work");

                self.context
                    .insert_local("stats", stats.to_template_value());

                let page =
                    Self::render_template(&self.content.templates, &mut self.context, &route.path)?;
                self.context.pop();
                Ok(AssetData::Html(page))
            }
            Some(route) => {
                self.context.push();
                let page =
                    Self::render_template(&self.content.templates, &mut self.context, &route.path)?;
                self.context.pop();
                Ok(AssetData::Html(page))
            }
            _ => match self.dynamic_routes.get(&header.path) {
                Some(dyn_route) if let Some(cached) = &dyn_route.cached_page => {
                    println!("Serving cached dynamic page {}", header.path);

                    Ok(AssetData::Html(cached.to_string()))
                }
                Some(dyn_route) => {
                    println!("Serving dynamic page {}", header.path);

                    let page_context_var = if let Some(TemplateValue::Object(posts_by_slug)) =
                        self.context.lookup("posts_by_slug")
                        && let Some(template_value) = posts_by_slug.get(&dyn_route.slug).cloned()
                    {
                        template_value
                    } else {
                        todo!("slug not found");
                    };

                    self.context.push();
                    self.context
                        .insert_local(&dyn_route.page_var_name, page_context_var);

                    // println!("Context {:#?}", self.context);
                    let page = Self::render_template(
                        &self.content.templates,
                        &mut self.context,
                        &dyn_route.template_path,
                    )?;
                    self.context.pop();
                    Ok(AssetData::Html(page))
                }

                None if let Some(fallback) = &self.fallback => {
                    println!("Path {} not found, redirecting to {fallback}", header.path);

                    Err(HttpServerError::Redirect(fallback.to_string()))
                }
                _ => Ok(AssetData::Text(
                    HttpResponseCode::NotFound.to_string().to_owned(),
                )),
            },
        }
    }

    fn render_template(
        templates: &HashMap<String, Template>,
        context: &mut Context,
        path: &str,
    ) -> Result<String, TemplateError> {
        let template = templates.get(path).expect("template not found");
        if let Some(parent_path) = &template.parent {
            let parent = templates
                .get(parent_path)
                .expect("Parent template not found: {parent_path}");
            if parent.parent.is_some() {
                return Err(TemplateParseError::only_file(
                    TemplateParseErrorMsg::GenericError(format!(
                        "Nested extends are not allowed: {parent_path} extends {parent_path}, but {parent_path} also extends another template"
                    )),
                    parent_path,
                ))?;
            }

            Ok(parent.render_with_blocks(context, &template.blocks)?)
        } else {
            Ok(template.render(context)?)
        }
    }

    fn serve_api(
        &self,
        _header: &HttpRequestHeader,
        _body: AssetData,
    ) -> Result<AssetData, HttpServerError> {
        Err(HttpServerError::Todo)
    }
}

#[derive(Debug)]
enum HttpServerError {
    Redirect(String),
    LockFailed,
    StreamWriteFailed,
    TemplatingError(TemplateError),
    Todo,
}

impl Error for HttpServerError {}

impl Display for HttpServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Redirect(location) => write!(f, "redirect to {location}"),
            Self::LockFailed => write!(f, "failed to acquire lock"),
            Self::StreamWriteFailed => write!(f, "failed to write to stream"),
            Self::TemplatingError(error) => write!(f, "templating error: {error}"),
            Self::Todo => write!(f, "operation not implemented"),
        }
    }
}

impl<T> From<std::sync::PoisonError<T>> for HttpServerError {
    fn from(_e: std::sync::PoisonError<T>) -> Self {
        HttpServerError::LockFailed
    }
}

impl From<std::io::Error> for HttpServerError {
    fn from(_value: std::io::Error) -> Self {
        HttpServerError::StreamWriteFailed
    }
}

impl From<TemplateError> for HttpServerError {
    fn from(err: TemplateError) -> Self {
        HttpServerError::TemplatingError(err)
    }
}

#[derive(Debug)]
enum HttpResponseCode {
    Ok,
    RedirectOther(String),
    BadRequest,
    NotFound,
    InternalServer,
}

impl fmt::Display for HttpResponseCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpResponseCode::Ok => write!(f, "200 OK"),
            HttpResponseCode::RedirectOther(redirect) => {
                write!(f, "303 See Other\r\nLocation: {redirect}")
            }
            HttpResponseCode::NotFound => write!(f, "404 Not Found"),
            HttpResponseCode::BadRequest => write!(f, "400 Bad Request"),
            HttpResponseCode::InternalServer => write!(f, "500 Internal Server Error"),
        }
    }
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
    content_typ: AssetTyp,
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
            let websocket_accept =
                base64(&sha1(format!("{}{magic_string}", sec_websocket_key.trim())));
            format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {websocket_accept}\r\n\r\n"
            )
            .as_bytes()
            .to_vec()
        } else {
            println!("Failed");
            Self::build_response(
                HttpResponseCode::BadRequest,
                &AssetData::Text("Invalid websocket upgrade request".to_owned()),
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

    fn parse_request(buffer: &[u8]) -> Result<(HttpRequestHeader, AssetData), io::Error> {
        if let Some(pos) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            let header = Self::parse_header(String::from_utf8_lossy(&buffer[..pos]).to_string())
                .expect("Unable to parse header");
            let content = AssetData::from_asset_type(&buffer[pos + 4..], &header.content_typ);

            Ok((header, content))
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "could not find header/body separator",
            ))
        }
    }

    fn build_response(code: HttpResponseCode, content: &AssetData) -> Vec<u8> {
        let status = code.to_string();

        let body = content.as_bytes();

        let cache_control = match content {
            AssetData::Png(_) | AssetData::Ico(_) | AssetData::Css(_) | AssetData::Js(_) => {
                "Cache-Control: public, max-age=3600\r\n"
            }
            _ => "",
        };

        let mut res = format!(
            "HTTP/1.1 {status}\r\nContent-Type: {}\r\nContent-Length: {}\r\n{cache_control}Connection: close\r\n\r\n",
            content.typ(),
            body.len()
        )
        .as_bytes()
        .to_vec();

        res.extend_from_slice(body);
        res
    }

    fn parse_header(header_str: String) -> Result<HttpRequestHeader, io::Error> {
        let mut lines = header_str.lines();

        let first_line = lines.next().expect("Unable to get next line");
        let mut first_line_words = first_line.split_ascii_whitespace();

        let request_type = match first_line_words.next() {
            Some("GET") => HttpRequestType::GET,
            invalid => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid request type {invalid:?}"),
                ));
            }
        };

        let path = if let Some(path) = first_line_words.next() {
            Self::clean_path(path)
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid request path",
            ));
        };

        let mut origin = None;
        let mut sec_websocket_key = None;
        let mut sec_websocket_version = None;
        let mut user_agent = None;
        let mut upgrade = None;
        let mut content_typ = AssetTyp::Unknown;

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
                            "text/plain" => AssetTyp::Text,
                            "text/html" => AssetTyp::Html,
                            "text/css" => AssetTyp::Css,
                            "text/javascript" => AssetTyp::Js,
                            "image/png" => AssetTyp::Png,
                            _ => AssetTyp::Unknown,
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

    fn clean_path(path: &str) -> &str {
        let end = path.find(['?', '#', '%']).unwrap_or(path.len());

        &path[..end]
    }

    fn serve(listener: TcpListener, mut router: Router) -> Result<(), Box<dyn Error>> {
        let mut buffer: [u8; 8192] = [0; 8192]; // 8kb buffer
        let mut active_streams: Vec<TcpStream> = vec![];
        let mut check_alive_timer = Instant::now();
        let mut check_fs_timer = Instant::now();
        let mut check_db_sync_timer = Instant::now();

        let mut it = 0;

        println!("Static Routes:");
        for (route, page) in &router.static_routes {
            println!(" {route}\t\t->\t{}", page.path);
        }
        println!("Dynamic Routes:");
        for (route, page) in &router.dynamic_routes {
            println!(" {route}\t\t->\t{}", page.template_path);
        }
        println!("Assets");
        for (route, asset) in &router.content.assets.collect_kv_mut() {
            println!(" {route:?}\t\t->\t{}", asset.data.typ());
        }

        println!(" Fallback\t->\t{:?}", router.fallback);
        listener
            .set_nonblocking(true)
            .expect("Unable to set socket to nonblocking mode");

        'main: while !SHUTDOWN.load(Ordering::Relaxed) {
            print!("Loop it {it}\r");
            it += 1;

            if let Ok((mut stream, peer_addr)) = listener.accept() {
                stream
                    .set_nonblocking(true)
                    .expect("Failed to change blocking of stream");

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
                let start_timer = Instant::now();
                let (header, body) =
                    HttpServer::parse_request(&buffer[..n]).expect("Unable to parse request");

                // println!(
                //     "[{peer_addr}] Received {:?} request for {:?} of length {}",
                //     header.typ,
                //     header.path,
                //     body.len()
                // );

                let mut is_ws = false;

                match header.path.as_str() {
                    #[cfg(debug_assertions)]
                    "/ws" => {
                        // print!("[{peer_addr:?}] Upgrading websocket ... ");
                        let response = HttpServer::upgrade_websocket(header);
                        stream
                            .write_all(&response)
                            .expect("Failed to write to stream");
                        stream.flush().expect("Failed to flush stream");
                        is_ws = true;
                    }
                    path => {
                        let res: Result<Cow<'_, AssetData>, HttpServerError> = if path
                            .starts_with("/api")
                        {
                            router.serve_api(&header, body).map(Cow::Owned)
                        } else {
                            match router.content.assets.get_ref(&header.path) {
                                Some(asset) if !asset.internal => Ok(Cow::Borrowed(&asset.data)),
                                _ => router.serve_page(&header, body).map(Cow::Owned),
                            }
                        };

                        let bytes = match res {
                            Ok(content) => Self::build_response(HttpResponseCode::Ok, &content),
                            Err(HttpServerError::Redirect(redirect_path)) => Self::build_response(
                                HttpResponseCode::RedirectOther(redirect_path),
                                &AssetData::Empty,
                            ),
                            Err(err) => {
                                println!("Server error {err:#?}");
                                Self::build_response(
                                    HttpResponseCode::InternalServer,
                                    &AssetData::Empty,
                                )
                            }
                        };
                        stream.write_all(&bytes).expect("Failed to write to stream");
                        let end_timer = Instant::now();
                        let duration = end_timer - start_timer;
                        // router.stats.add_hit(path, duration);
                        // println!("served request in {duration:?}");
                        router.db.save_page_hit(path, duration)?;
                    }
                };

                #[cfg(debug_assertions)]
                {
                    if is_ws {
                        active_streams.push(stream);
                        // println!("Active connections {}", active_streams.len());
                    }
                }
            }

            if check_db_sync_timer.elapsed() > Duration::from_secs(10) {
                router.db.sync()?;
                check_db_sync_timer = Instant::now();
            }

            #[cfg(debug_assertions)]
            {
                let reload = if check_fs_timer.elapsed() > Duration::from_millis(50) {
                    check_fs_timer = Instant::now();

                    match router.content.check_update(&mut router.context) {
                        Ok(reload) => reload,
                        Err(err) => {
                            println!("Error while reloading: {err}");
                            false
                        }
                    }
                } else {
                    false
                };

                if reload || check_alive_timer.elapsed() > Duration::from_secs(1) {
                    check_alive_timer = Instant::now();
                    active_streams.retain(|mut stream| {
                        let connection_is_alive = match stream.read(&mut [0]) {
                            Ok(0) => false,
                            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => true,
                            _ => false,
                        };

                        if connection_is_alive && let Ok(peer_addr) = stream.peer_addr() {
                            if reload {
                                let _ = HttpServer::send_ws_message(stream, "reload");
                                println!("[{peer_addr:?}] Reloaded");
                            }
                            // println!("[{peer_addr:?}] Connection still alive");
                            true
                        } else {
                            // println!("Closing connection");
                            let _ = stream.shutdown(std::net::Shutdown::Both);

                            false
                        }
                    });
                }
            }
        }

        // Exit routine
        router.db.sync()
    }
}

#[derive(Clone, Debug, Copy, PartialEq, Eq)]
enum SyntaxHighlightLang {
    Bash,
    C,
    Clike,
    Css,
    Haskell,
    Nix,
    Rust,
    Markdown,
    Markup,
    Elixir,
    Html,
    Javascript,
    Typescript,
}

impl SyntaxHighlightLang {
    fn from_str(input: &str) -> Option<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "bash" => Some(Self::Bash),
            "c" => Some(Self::C),
            "clike" => Some(Self::Clike),
            "css" => Some(Self::Css),
            "haskell" => Some(Self::Haskell),
            "nix" => Some(Self::Nix),
            "rust" => Some(Self::Rust),
            "markdown" => Some(Self::Markdown),
            "markup" => Some(Self::Markup),
            "elixir" => Some(Self::Elixir),
            "html" => Some(Self::Html),
            "javascript" => Some(Self::Javascript),
            "typescript" => Some(Self::Typescript),
            _ => None,
        }
    }
    fn to_str(self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::C => "c",
            Self::Clike => "clike",
            Self::Css => "css",
            Self::Haskell => "haskell",
            Self::Nix => "nix",
            Self::Rust => "rust",
            Self::Markdown => "markdown",
            Self::Markup => "markup",
            Self::Elixir => "elixir",
            Self::Html => "html",
            Self::Javascript => "javascript",
            Self::Typescript => "typescript",
        }
    }

    fn include_dependencies(langs: &[SyntaxHighlightLang]) -> Vec<SyntaxHighlightLang> {
        use SyntaxHighlightLang::*;
        let mut result = vec![];

        for &lang in langs {
            let dependency = match lang {
                Javascript | Typescript => Clike,
                Html => Markup,
                _ => continue,
            };
            if !result.contains(&dependency) {
                result.push(dependency);
            }
        }

        result.extend_from_slice(langs);
        result
    }
}

impl ToTemplateValue for SyntaxHighlightLang {
    fn to_template_value(&self) -> TemplateValue {
        match self {
            SyntaxHighlightLang::Bash => TemplateValue::Text(self.to_str().to_string()),
            SyntaxHighlightLang::C => TemplateValue::Text(self.to_str().to_string()),
            SyntaxHighlightLang::Clike => TemplateValue::Text(self.to_str().to_string()),
            SyntaxHighlightLang::Css => TemplateValue::Text(self.to_str().to_string()),
            SyntaxHighlightLang::Haskell => TemplateValue::Text(self.to_str().to_string()),
            SyntaxHighlightLang::Nix => TemplateValue::Text(self.to_str().to_string()),
            SyntaxHighlightLang::Rust => TemplateValue::Text(self.to_str().to_string()),
            SyntaxHighlightLang::Markdown => TemplateValue::Text(self.to_str().to_string()),
            SyntaxHighlightLang::Markup => TemplateValue::Text(self.to_str().to_string()),
            SyntaxHighlightLang::Elixir => TemplateValue::Text(self.to_str().to_string()),
            SyntaxHighlightLang::Html => TemplateValue::Text(self.to_str().to_string()),
            SyntaxHighlightLang::Javascript => TemplateValue::Text(self.to_str().to_string()),
            SyntaxHighlightLang::Typescript => TemplateValue::Text(self.to_str().to_string()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum AssetTyp {
    Text,
    Html,
    Css,
    Js,
    Png,
    MdRaw,
    MdParsed,
    Ico,
    Woff2,
    Unknown,
}

impl AssetTyp {
    fn is_text(&self) -> bool {
        use AssetTyp::*;
        matches!(self, Text | Html | Css | Js | MdRaw)
    }
    fn from_path(path: &Path) -> AssetTyp {
        match path.extension().and_then(|s| s.to_str()) {
            Some("html") => AssetTyp::Html,
            Some("txt") => AssetTyp::Text,
            Some("css") => AssetTyp::Css,
            Some("js") => AssetTyp::Js,
            Some("png") => AssetTyp::Png,
            Some("md") => AssetTyp::MdRaw,
            Some("ico") => AssetTyp::Ico,
            Some("woff2") => AssetTyp::Woff2,
            _ => AssetTyp::Unknown,
        }
    }
}

#[derive(Clone, Debug)]
struct Asset {
    last_modified: SystemTime,
    data: AssetData,
    internal: bool,
}

impl Asset {
    fn new(content: AssetData) -> Self {
        Self {
            last_modified: SystemTime::now(),
            data: content,
            internal: false,
        }
    }
}

#[derive(Clone, Debug)]
enum AssetData {
    Text(String),
    Html(String),
    Css(String),
    Js(String),
    JsPrism(String, SyntaxHighlightLang),
    Png(Vec<u8>),
    Ico(Vec<u8>),
    MdRaw(String),
    MdParsed(ParsedMarkdown),
    Woff2(Vec<u8>),
    Unknown(String),
    Empty,
}

impl AssetData {
    fn len(&self) -> usize {
        match self {
            AssetData::Text(s)
            | AssetData::Html(s)
            | AssetData::Css(s)
            | AssetData::Js(s)
            | AssetData::JsPrism(s, _)
            | AssetData::MdRaw(s)
            | AssetData::MdParsed(ParsedMarkdown { html: s, .. })
            | AssetData::Unknown(s) => s.len(),
            AssetData::Png(bytes) | AssetData::Ico(bytes) | AssetData::Woff2(bytes) => bytes.len(),
            AssetData::Empty => 0,
        }
    }
    fn read_asset(path: &Path) -> Result<AssetData, io::Error> {
        let content = match path.extension().and_then(|s| s.to_str()) {
            Some("png") => AssetData::Png(fs::read(path)?),
            Some("ico") => AssetData::Ico(fs::read(path)?),
            Some("md") => {
                let markdown = fs::read_to_string(path)?;
                let parsed = MarkdownParser::parse(&markdown);
                AssetData::MdParsed(parsed)
            }
            Some("html") => AssetData::Html(fs::read_to_string(path)?),
            Some("txt") => AssetData::Text(fs::read_to_string(path)?),
            Some("css") => AssetData::Css(fs::read_to_string(path)?),
            Some("js")
                if let Some(filename) = path.file_name()
                    && let Some(filename) = filename.to_str()
                    && filename.starts_with("prism-")
                    && let Some(stripped) = filename.strip_prefix("prism-")
                    && let Some(stripped) = stripped.strip_suffix("js")
                    && let Some(prism_lang) = SyntaxHighlightLang::from_str(stripped) =>
            {
                AssetData::JsPrism(fs::read_to_string(path)?, prism_lang)
            }
            Some("js") => AssetData::Js(fs::read_to_string(path)?),
            _ => AssetData::Unknown(fs::read_to_string(path)?),
        };
        Ok(content)
    }

    fn typ(&self) -> &str {
        match self {
            AssetData::Text(_) => "text/plain; charset=utf-8",
            AssetData::Html(_) => "text/html; charset=utf-8",
            AssetData::Css(_) => "text/css",
            AssetData::Js(_) => "text/javascript",
            AssetData::JsPrism(_, _) => "text/javascript",
            AssetData::Png(_) => "image/png",
            AssetData::Ico(_) => "image/ico",
            AssetData::MdRaw(_) => "text/plain; charset=utf-8",
            AssetData::MdParsed(_) => "text/html; charset=utf-8",
            AssetData::Woff2(_) => "font/woff2",
            AssetData::Unknown(_) => "text/plain; charset=utf-8",
            AssetData::Empty => "",
        }
    }

    fn from_asset_type(buffer: &[u8], content_typ: &AssetTyp) -> AssetData {
        match content_typ {
            AssetTyp::Png => AssetData::Png(buffer.to_vec()),
            AssetTyp::Ico => AssetData::Ico(buffer.to_vec()),
            AssetTyp::Woff2 => AssetData::Woff2(buffer.to_vec()),
            AssetTyp::Html => AssetData::Html(String::from_utf8_lossy(buffer).to_string()),
            AssetTyp::Css => AssetData::Css(String::from_utf8_lossy(buffer).to_string()),
            AssetTyp::Js => AssetData::Js(String::from_utf8_lossy(buffer).to_string()),
            AssetTyp::MdRaw => AssetData::MdRaw(String::from_utf8_lossy(buffer).to_string()),
            AssetTyp::Text => AssetData::Text(String::from_utf8_lossy(buffer).to_string()),
            AssetTyp::Unknown => AssetData::Unknown(String::from_utf8_lossy(buffer).to_string()),
            AssetTyp::MdParsed => todo!(),
        }
    }

    fn as_bytes(&self) -> &[u8] {
        match self {
            AssetData::Png(b) | AssetData::Ico(b) | AssetData::Woff2(b) => b,
            AssetData::Text(s)
            | AssetData::Html(s)
            | AssetData::Css(s)
            | AssetData::Js(s)
            | AssetData::JsPrism(s, _)
            | AssetData::MdRaw(s)
            | AssetData::MdParsed(ParsedMarkdown { html: s, .. })
            | AssetData::Unknown(s) => s.as_bytes(),
            AssetData::Empty => &[],
        }
    }
}

#[derive(Debug)]
struct Content {
    assets: Trie<Asset>,
    templates: HashMap<String, Template>,
}

impl Content {
    fn load_embedded() -> Result<Self, TemplateError> {
        #[cfg(generated)]
        let mut assets = load_embedded_assets()?;
        #[cfg(generated)]
        let templates = load_embedded_templates()?;
        #[cfg(not(generated))]
        // Stub to make the compiler happy
        let assets = Trie::new();
        #[cfg(not(generated))]
        let templates = HashMap::new();
        // assets
        Ok(Self { assets, templates })
    }

    fn check_update(&mut self, context: &mut Context) -> Result<bool, TemplateError> {
        let assets_changed = match self.update_assets() {
            Ok(assets_changed) => {
                if assets_changed {
                    context.update_posts(self);
                }
                assets_changed
            }
            err => return err,
        };
        let templates_changed = match self.update_templates() {
            Ok(templates_changed) => templates_changed,
            err => return err,
        };
        Ok(templates_changed || assets_changed)
    }

    fn update_templates(&mut self) -> Result<bool, TemplateError> {
        let paths = walk_dir(TEMPLATES_PATH);
        let mut is_new = true;
        let mut changed = false;
        for path in &paths {
            let last_modified = path.metadata()?.modified()?;
            let path_str = path.to_string_lossy().to_string();

            for (key, template) in self.templates.iter_mut() {
                if template.origin_file == path_str {
                    is_new = false;
                    if template.last_modified < last_modified {
                        Template::update_from_path(template, path)?;
                        changed = true;

                        println!("Updated template {:?}, for page: {key:?}", path_str,);
                    }
                }
            }

            if is_new {
                let template = Template::from_path(path)?;
                println!("Added template {path_str:?}");
                self.templates.insert(path_str.clone(), template);
                changed = true;
            }
        }
        Ok(changed)
    }

    fn update_assets(&mut self) -> Result<bool, TemplateError> {
        let paths = walk_dir(ASSETS_PATH);
        let mut changed = false;

        for path in &paths {
            let last_modified = path.metadata()?.modified()?;
            let key_path = format!(
                "/{}",
                path.strip_prefix(ASSETS_PATH)
                    .expect("Failed to strip prefix")
                    .to_string_lossy()
            );

            match self.assets.get_ref_mut(&key_path) {
                Some(existing_asset) if last_modified > existing_asset.last_modified => {
                    existing_asset.data = AssetData::read_asset(path)?;
                    existing_asset.last_modified = last_modified;
                    changed = true;

                    println!(
                        "Updated file {:?}, edited {} minutes ago",
                        path,
                        last_modified.elapsed().unwrap().as_secs() / 60
                    );
                }
                Some(_) => {} // File not changed
                None => {
                    let asset = AssetData::read_asset(path)?;
                    self.assets.insert(
                        key_path.clone(),
                        Asset {
                            last_modified,
                            data: asset,
                            internal: false,
                        },
                    );
                    changed = true;

                    println!("Added file {:?}", key_path);
                }
            }
        }
        let str_paths = paths
            .iter()
            .map(|p| {
                format!(
                    "/{}",
                    p.strip_prefix(ASSETS_PATH)
                        .expect("Failed to strip prefix")
                        .to_string_lossy()
                )
            })
            .collect(); // Todo unfuck
        if self.assets.remove_other_than_except_generated(str_paths) {
            changed = true;
        }
        Ok(changed)
    }
}

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

#[derive(Debug)]
struct TrieNode<T> {
    asset: Option<T>,
    children: HashMap<String, TrieNode<T>>,
}

impl<T> Default for TrieNode<T> {
    fn default() -> Self {
        Self {
            asset: None,
            children: HashMap::new(),
        }
    }
}

#[derive(Default, Debug)]
struct Trie<T> {
    root: TrieNode<T>,
    paths: HashSet<String>,
}

impl<T> Trie<T>
where
    T: Clone,
{
    fn new() -> Self {
        Trie {
            root: TrieNode::default(),
            paths: HashSet::new(),
        }
    }

    fn insert(&mut self, path: String, asset: T) {
        let mut current_node = &mut self.root;

        for component in PathBuf::from(path.clone()).components() {
            let key = component.as_os_str().to_string_lossy().to_string();
            current_node = current_node.children.entry(key).or_default();
        }
        current_node.asset = Some(asset);
        self.paths.insert(path);
    }

    fn get_ref_mut(&mut self, path: &String) -> Option<&mut T> {
        let mut current_node = &mut self.root;

        for component in PathBuf::from(path).components() {
            let key = component.as_os_str().to_string_lossy().to_string();
            match current_node.children.get_mut(&key) {
                Some(node) => current_node = node,
                None => return None,
            }
        }

        current_node.asset.as_mut()
    }

    fn get_ref(&self, path: &String) -> Option<&T> {
        let mut current_node = &self.root;

        for component in PathBuf::from(path).components() {
            let key = component.as_os_str().to_string_lossy().to_string();
            match current_node.children.get(&key) {
                Some(node) => current_node = node,
                None => return None,
            }
        }

        current_node.asset.as_ref()
    }

    // gets everything from path downwards
    fn get_partial(&self, path: &str) -> Vec<&T> {
        let mut current_node = &self.root;

        for component in PathBuf::from(path).components() {
            let key = component.as_os_str().to_string_lossy();

            match current_node.children.get(key.as_ref()) {
                Some(node) => current_node = node,
                None => return vec![],
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
    fn collect_kv_mut(&mut self) -> Vec<(PathBuf, &mut T)> {
        let mut result = Vec::new();

        Self::dfs(&mut self.root, &mut PathBuf::new(), &mut result);

        result
    }

    fn dfs<'a>(
        node: &'a mut TrieNode<T>,
        path: &mut PathBuf,
        result: &mut Vec<(PathBuf, &'a mut T)>,
    ) {
        if let Some(asset) = node.asset.as_mut() {
            result.push((path.clone(), asset));
        }

        for (key, child) in node.children.iter_mut() {
            path.push(key);
            Self::dfs(child, path, result);
            path.pop();
        }
    }

    fn contains(&self, path: &String) -> bool {
        let mut current_node = &self.root;

        for component in PathBuf::from(path).components() {
            let key = component.as_os_str().to_string_lossy().to_string();
            match current_node.children.get(&key) {
                Some(node) => current_node = node,
                None => return false,
            }
        }

        current_node.asset.is_some()
    }

    fn remove(&mut self, path: &String) -> bool {
        let mut current_node = &mut self.root;

        for component in PathBuf::from(path).components() {
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
    fn remove_other_than_except_generated(&mut self, current_paths: Vec<String>) -> bool {
        let current_paths_set: HashSet<String> = current_paths.into_iter().collect();

        let paths_to_delete: Vec<String> =
            self.paths.difference(&current_paths_set).cloned().collect();

        let mut changed = false;

        for path in &paths_to_delete {
            if path.starts_with("/generated") {
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
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
    'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '+', '/',
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
            words[i] = ((chunk[4 * i] as u32) << 24)
                | ((chunk[4 * i + 1] as u32) << 16)
                | ((chunk[4 * i + 2] as u32) << 8)
                | (chunk[4 * i + 3] as u32);
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

            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*word);

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

#[derive(Clone, Debug)]

struct ParsedMarkdown {
    html: String,
    metadata: MarkdownMetadata,
    highlighted_langs: Vec<SyntaxHighlightLang>,
}

#[derive(Clone, Debug)]
struct MarkdownMetadata {
    title: String,
    slug: String,
    published: String,
    tags: Vec<String>,
    draft: bool,
}

impl MarkdownMetadata {
    fn parse_metadata(input: &str) -> (Self, &str) {
        let mut cursor: usize = 0;

        let first_line_end = input[cursor..]
            .find('\n')
            .map(|i| cursor + i)
            .unwrap_or(input.len());

        let first_line = &input[cursor..first_line_end];

        if !first_line.starts_with("::::") {
            panic!("markdown must have metadata");
        }

        cursor = if first_line_end < input.len() {
            first_line_end + 1
        } else {
            first_line_end
        };

        let mut metadata_lines = vec![];

        loop {
            let line_end = input[cursor..]
                .find('\n')
                .map(|i| cursor + i)
                .unwrap_or(input.len());

            let line = &input[cursor..line_end];

            if line.starts_with("::::") {
                cursor = if line_end < input.len() {
                    line_end + 1
                } else {
                    line_end
                };

                break;
            }
            metadata_lines.push(line);
            if line_end == input.len() {
                return (
                    MarkdownMetadata::parse_metadata_content(metadata_lines),
                    input,
                );
            }

            cursor = line_end + 1;
        }
        (
            MarkdownMetadata::parse_metadata_content(metadata_lines),
            &input[cursor..],
        )
    }

    fn parse_metadata_content(lines: Vec<&str>) -> MarkdownMetadata {
        let mut title: Option<String> = None;
        let mut slug: Option<String> = None;
        let mut published: Option<String> = None;
        let mut tags: Vec<String> = Vec::new();
        let mut draft: bool = false;

        for line in lines {
            let line = line.trim();

            if line.is_empty() {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let key = key.trim();
            let value = value.trim();

            match key {
                "title" => title = Self::parse_string(value),
                "slug" => slug = Self::parse_string(value),
                "published" => published = Self::parse_date(value),
                "tags" => tags = Self::parse_tags(value),
                "draft" => match value {
                    "true" => draft = true,
                    "false" => draft = false,
                    _ => continue,
                },
                _ => continue,
            }
        }

        let title_str = title.unwrap_or("untitled".to_owned());
        MarkdownMetadata {
            slug: slug.unwrap_or(title_str.replace(" ", "-").to_lowercase()),
            title: title_str,
            published: published.unwrap_or("data unknown".to_owned()),
            tags,
            draft,
        }
    }

    fn parse_string(value: &str) -> Option<String> {
        let value = value.trim();
        if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
            Some(value[1..value.len() - 1].to_string())
        } else {
            None
        }
    }

    fn parse_date(value: &str) -> Option<String> {
        let value = value.trim();

        if !value.is_empty() {
            Some(value.to_string())
        } else {
            None
        }
    }
    fn parse_tags(value: &str) -> Vec<String> {
        if !value.starts_with('[') || !value.ends_with(']') {
            return vec![];
        }

        let inner = &value[1..value.len() - 1];

        if inner.trim().is_empty() {
            return vec![];
        }

        let mut tags = vec![];
        for tag in inner.split(',') {
            if let Some(tag) = Self::parse_string(tag.trim()) {
                tags.push(tag);
            } else {
                return vec![];
            }
        }
        tags
    }
}

#[derive(Debug)]
enum MarkdownNode<'a> {
    Document(Vec<MarkdownNode<'a>>),

    // Block
    Paragraph(Vec<MarkdownNode<'a>>),
    Heading {
        level: usize,
        children: Vec<MarkdownNode<'a>>,
    },
    CodeBlock {
        language: Option<SyntaxHighlightLang>,
        content: Vec<&'a str>,
    },
    OrderedList(Vec<MarkdownNode<'a>>),
    UnorderedList(Vec<MarkdownNode<'a>>),
    BlockQuote(Vec<MarkdownNode<'a>>),
    ListItem(Vec<MarkdownNode<'a>>),
    HorizontalLine,
    _Table,
    BreakLine,

    // Inline
    Text(&'a str),
    Italic(Vec<MarkdownNode<'a>>),
    Bold(Vec<MarkdownNode<'a>>),
    StrikeThrough(Vec<MarkdownNode<'a>>),
    InlineCode(&'a str),
    Link {
        text: Vec<MarkdownNode<'a>>,
        url: &'a str,
    },
    Image {
        alt: &'a str,
        path: &'a str,
    },
}

#[derive(Debug, Clone)]
enum MarkdownBlock<'a> {
    Heading {
        level: usize,
        content: &'a [MarkdownToken],
    },
    Paragraph {
        content: &'a [MarkdownToken],
    },
    OrderedList {
        content: Vec<&'a [MarkdownToken]>,
    },
    UnorderedList {
        content: Vec<&'a [MarkdownToken]>,
    },
    BlockQuote {
        content: Vec<&'a [MarkdownToken]>,
    },
    _Table {
        content: Vec<&'a [MarkdownToken]>,
    },
    CodeBlock {
        language: Option<SyntaxHighlightLang>,
        content: &'a [MarkdownToken],
    },
    _BreakLine,
    HorizontalLine,
}

#[derive(Debug, Clone)]
enum MarkdownToken {
    NewLine(Span),
    BracketOpen(Span),
    BracketClose(Span),
    ParenOpen(Span),
    ParenClose(Span),

    HeadingMarker(Span),    // #, ##, ### ...
    BlockQuoteMarker(Span), // > or >> maybe
    Whitespace(Span),
    Asterisk(Span),
    Tilde(Span),
    Underscore(Span),
    Backtick(Span),
    Dash(Span),
    Plus(Span),
    Exclamation(Span),

    TextRaw(Span),
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum MarkdownTokenTyp {
    NewLine,
    BracketOpen,
    BracketClose,
    ParenOpen,
    ParenClose,

    HeadingMarker(usize),    // #, ##, ### ...
    BlockQuoteMarker(usize), // > or >> maybe
    Whitespace(usize),
    Asterisk(usize),
    Underscore(usize),
    Backtick(usize),
    Dash(usize),
    Plus(usize),
    Tilde(usize),
    Exclamation(usize),

    TextRaw,
}

impl MarkdownToken {
    fn typ(&self) -> MarkdownTokenTyp {
        match self {
            MarkdownToken::NewLine(_) => MarkdownTokenTyp::NewLine,
            MarkdownToken::BracketOpen(_) => MarkdownTokenTyp::BracketOpen,
            MarkdownToken::BracketClose(_) => MarkdownTokenTyp::BracketClose,
            MarkdownToken::ParenOpen(_) => MarkdownTokenTyp::ParenOpen,
            MarkdownToken::ParenClose(_) => MarkdownTokenTyp::ParenClose,
            MarkdownToken::HeadingMarker(span) => MarkdownTokenTyp::HeadingMarker(span.len()),
            MarkdownToken::BlockQuoteMarker(span) => MarkdownTokenTyp::BlockQuoteMarker(span.len()),
            MarkdownToken::Whitespace(span) => MarkdownTokenTyp::Whitespace(span.len()),
            MarkdownToken::Asterisk(span) => MarkdownTokenTyp::Asterisk(span.len()),
            MarkdownToken::Underscore(span) => MarkdownTokenTyp::Underscore(span.len()),
            MarkdownToken::Backtick(span) => MarkdownTokenTyp::Backtick(span.len()),
            MarkdownToken::Dash(span) => MarkdownTokenTyp::Dash(span.len()),
            MarkdownToken::Tilde(span) => MarkdownTokenTyp::Tilde(span.len()),
            MarkdownToken::Plus(span) => MarkdownTokenTyp::Plus(span.len()),
            MarkdownToken::Exclamation(span) => MarkdownTokenTyp::Exclamation(span.len()),
            MarkdownToken::TextRaw(_) => MarkdownTokenTyp::TextRaw,
        }
    }

    fn span(&self) -> &Span {
        match self {
            MarkdownToken::NewLine(span)
            | MarkdownToken::BracketOpen(span)
            | MarkdownToken::BracketClose(span)
            | MarkdownToken::ParenOpen(span)
            | MarkdownToken::ParenClose(span)
            | MarkdownToken::HeadingMarker(span)
            | MarkdownToken::BlockQuoteMarker(span)
            | MarkdownToken::Whitespace(span)
            | MarkdownToken::Asterisk(span)
            | MarkdownToken::Underscore(span)
            | MarkdownToken::Backtick(span)
            | MarkdownToken::Dash(span)
            | MarkdownToken::Tilde(span)
            | MarkdownToken::Plus(span)
            | MarkdownToken::Exclamation(span)
            | MarkdownToken::TextRaw(span) => span,
        }
    }

    fn start(&self) -> usize {
        self.span().start
    }

    fn end(&self) -> usize {
        self.span().end
    }
}

#[derive(Debug, Clone)]
struct Span {
    start: usize,
    end: usize,
}

impl Span {
    fn len(&self) -> usize {
        self.end - self.start
    }
    fn from_single(idx: usize) -> Self {
        Self {
            start: idx,
            end: idx + 1,
        }
    }
    fn from_double(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    fn to_str<'a>(&self, input: &'a str) -> &'a str {
        &input[self.start..self.end]
    }
}

struct MarkdownListLine<'a> {
    _indent: usize,
    content: &'a [MarkdownToken],
    list_marker: ListMarker,
}

#[derive(PartialEq, Eq, Debug, Copy, Clone)]
enum ListMarker {
    Numbered,
    Dash,
    Asterisk,
    Plus,
}

impl<'a> MarkdownListLine<'a> {
    fn parse_line(tokens: &'a [MarkdownToken], input: &str) -> Option<MarkdownListLine<'a>> {
        use MarkdownToken::*;

        let (indent, rest) = match tokens {
            [Whitespace(span), rest @ ..] => (span.len(), rest),
            rest => (0, rest),
        };
        let (list_marker, content) = match rest {
            [Dash(span), Whitespace(_), content @ ..] if span.len() == 1 => {
                (ListMarker::Dash, content)
            }
            [Asterisk(span), Whitespace(_), content @ ..] if span.len() == 1 => {
                (ListMarker::Asterisk, content)
            }
            [Plus(span), Whitespace(_), content @ ..] if span.len() == 1 => {
                (ListMarker::Plus, content)
            }
            [TextRaw(text), Whitespace(_), content @ ..]
                if text
                    .to_str(input)
                    .strip_suffix('.')
                    .is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit())) =>
            {
                (ListMarker::Numbered, content)
            }
            _ => return None,
        };

        Some(MarkdownListLine {
            _indent: indent,
            content,
            list_marker,
        })
    }
}
struct MarkdownParser {}

impl MarkdownParser {
    fn parse(input: &str) -> ParsedMarkdown {
        let (metadata, markdown_input) = MarkdownMetadata::parse_metadata(input);

        let lex = Self::lex(markdown_input);
        // println!("{lex:#?}");

        let blocks: Vec<MarkdownBlock<'_>> = Self::parse_blocks(&lex, markdown_input);
        // println!("{blocks:#?}");
        let ast = Self::parse_block_content(&blocks, markdown_input);
        let highlighted_langs = Self::get_highlighted_langs(&blocks);
        // println!("{ast:#?}");
        let html = Self::to_html(ast);
        ParsedMarkdown {
            html,
            metadata,
            highlighted_langs,
        }
    }

    fn get_highlighted_langs(blocks: &Vec<MarkdownBlock<'_>>) -> Vec<SyntaxHighlightLang> {
        let mut langs = vec![];
        for block in blocks {
            match block {
                MarkdownBlock::CodeBlock { language: Some(language), .. } => {
                    langs.push(*language)
                }
                _ => continue,
            }
        }

        langs
    }

    fn lex(input: &str) -> Vec<MarkdownToken> {
        use MarkdownToken::*;

        let mut tokens = vec![];
        let mut chars = input.char_indices().peekable();

        let mut start_text_idx = 0;
        let mut text_len = 0;
        while let Some((i, c)) = chars.next() {
            let token = match c {
                '\n' => Some((NewLine(Span::from_single(i)), 1)),
                '[' => Some((BracketOpen(Span::from_single(i)), 1)),
                ']' => Some((BracketClose(Span::from_single(i)), 1)),
                '(' => Some((ParenOpen(Span::from_single(i)), 1)),
                ')' => Some((ParenClose(Span::from_single(i)), 1)),
                '!' => Some((Exclamation(Span::from_single(i)), 1)),

                c if ['#', '-', ' ', '_', '+', '>', '`', '*', '~'].contains(&c) => {
                    let repeated = Self::count_repeated(&mut chars, c);
                    match c {
                        '#' => Some((HeadingMarker(Span::from_double(i, i + repeated)), repeated)),
                        '-' => Some((Dash(Span::from_double(i, i + repeated)), repeated)),
                        ' ' => Some((Whitespace(Span::from_double(i, i + repeated)), repeated)),
                        '_' => Some((Underscore(Span::from_double(i, i + repeated)), repeated)),
                        '+' => Some((Plus(Span::from_double(i, i + repeated)), repeated)),
                        '>' => Some((
                            BlockQuoteMarker(Span::from_double(i, i + repeated)),
                            repeated,
                        )),
                        '`' => Some((Backtick(Span::from_double(i, i + repeated)), repeated)),
                        '*' => Some((Asterisk(Span::from_double(i, i + repeated)), repeated)),
                        '~' => Some((Tilde(Span::from_double(i, i + repeated)), repeated)),
                        _ => panic!("invariant"),
                    }
                }
                _ => None,
            };

            if let Some((token, repeated_non_text)) = token {
                if text_len > 0 {
                    tokens.push(TextRaw(Span::from_double(
                        start_text_idx,
                        start_text_idx + text_len,
                    )));
                    start_text_idx += text_len;
                    text_len = 0;
                }

                start_text_idx += repeated_non_text;
                tokens.push(token);
            } else {
                text_len += 1;
            }
        }

        if text_len != 0 {
            tokens.push(TextRaw(Span::from_double(
                start_text_idx,
                start_text_idx + text_len,
            )));
        }

        tokens
    }

    fn count_repeated(chars: &mut Peekable<CharIndices<'_>>, expected: char) -> usize {
        let mut count = 1;
        while let Some((_, c)) = chars.peek() {
            if *c != expected {
                break;
            }
            chars.next();
            count += 1;
        }
        count
    }

    fn parse_blocks<'tok: 'src, 'src>(
        tokens: &'tok [MarkdownToken],
        input: &'src str,
    ) -> Vec<MarkdownBlock<'src>> {
        use MarkdownBlock::*;
        use MarkdownToken::*;

        let mut blocks = vec![];
        let mut tokens = tokens;

        while let [first, rest @ ..] = tokens {
            tokens = match first {
                NewLine(_) => rest,
                Dash(span) if span.len() >= 3 => {
                    blocks.push(HorizontalLine);
                    rest
                }
                HeadingMarker(span) if span.len() <= 6 => {
                    let (content, rest) = Self::until_tok(rest, MarkdownTokenTyp::NewLine, false);
                    blocks.push(Heading {
                        level: span.len(),
                        content,
                    });
                    rest
                }
                BlockQuoteMarker(_) if let Some((content, after)) = Self::parse_quote(tokens) => {
                    blocks.push(content);
                    after
                }
                Backtick(span)
                    if span.len() == 3
                        && let Some((content, after)) = Self::parse_codeblock(tokens, input) =>
                {
                    blocks.push(content);
                    after
                }
                _ if let Some((content, after)) = Self::parse_list(tokens, input) => {
                    blocks.push(content);
                    after
                }
                _ => {
                    let (content, after) =
                        Self::until_tok(tokens, MarkdownTokenTyp::NewLine, false);

                    blocks.push(Paragraph { content });
                    after
                }
            }
        }
        blocks
    }

    fn parse_codeblock<'a>(
        tokens: &'a [MarkdownToken],
        input: &'a str,
    ) -> Option<(MarkdownBlock<'a>, &'a [MarkdownToken])> {
        use MarkdownBlock::*;
        use MarkdownToken::*;

        if let [Backtick(span), rest @ ..] = tokens
            && span.len() == 3
        {
            let (rest, language) = if let [TextRaw(lang), NewLine { .. }, inner_rest @ ..] = rest {
                (inner_rest, Some(lang.to_str(input)))
            } else {
                (rest, None)
            };
            let (content, rest) = Self::until_tok(rest, MarkdownTokenTyp::Backtick(3), false);
            if !content.is_empty() {
                Some((
                    CodeBlock {
                        language: language.and_then(SyntaxHighlightLang::from_str),
                        content,
                    },
                    rest,
                ))
            } else {
                None
            }
        } else {
            None
        }
    }

    fn parse_list<'a>(
        mut tokens: &'a [MarkdownToken],
        input: &'a str,
    ) -> Option<(MarkdownBlock<'a>, &'a [MarkdownToken])> {
        let mut content = vec![];
        let mut marker = None;

        while !tokens.is_empty() {
            let (line, rest) = Self::until_tok(tokens, MarkdownTokenTyp::NewLine, false);
            let line = if let Some(line) = MarkdownListLine::parse_line(line, input) {
                line
            } else {
                break;
            };

            if marker.is_none() {
                marker = Some(line.list_marker);
            }

            if let Some(marker) = marker
                && line.list_marker != marker
            {
                break;
            }

            content.push(line.content);
            tokens = rest;
        }

        match marker {
            Some(ListMarker::Numbered) => Some((MarkdownBlock::OrderedList { content }, tokens)),
            Some(ListMarker::Dash | ListMarker::Asterisk | ListMarker::Plus) => {
                Some((MarkdownBlock::UnorderedList { content }, tokens))
            }
            None => None,
        }
    }

    fn parse_quote<'a>(
        mut tokens: &'a [MarkdownToken],
    ) -> Option<(MarkdownBlock<'a>, &'a [MarkdownToken])> {
        use MarkdownBlock::*;
        use MarkdownToken::*;

        let mut content = vec![];

        while !tokens.is_empty() {
            let (line, rest) = Self::until_tok(tokens, MarkdownTokenTyp::NewLine, false);
            match line {
                [BlockQuoteMarker(span), Whitespace(_), quote_content @ ..]
                | [BlockQuoteMarker(span), quote_content @ ..]
                    if span.len() > 0 =>
                {
                    content.push(quote_content);
                    tokens = rest;
                }
                _ => break,
            }
        }

        if content.is_empty() {
            None
        } else {
            Some((BlockQuote { content }, tokens))
        }
    }

    // With split inc;lludes split in rest
    fn until_tok(
        tokens: &[MarkdownToken],
        until: MarkdownTokenTyp,
        include_split: bool,
    ) -> (&[MarkdownToken], &[MarkdownToken]) {
        let split = if let Some(pos) = tokens.iter().position(|token| token.typ() == until) {
            pos
        } else {
            return (tokens, &tokens[0..0]);
        };

        let (content, rest) = tokens.split_at(split);

        let rest = match (rest, &until) {
            (with_split @ [tok, ..], _) if tok.typ() == until && include_split => with_split,
            ([tok, rest_without_split @ ..], _) if tok.typ() == until => rest_without_split,
            _ => rest,
        };

        (content, rest)
    }

    fn tokens_to_string<'a>(mut tokens: &'a [MarkdownToken], input: &'a str) -> Vec<&'a str> {
      let Some(first) = tokens.first() else {
        return Vec::new();
      };

      let last = tokens.last().expect("invariant");
      let content = &input[first.start()..last.end()];

      content.split('\n').collect() 
    }

    fn parse_block_content<'a>(blocks: &'a Vec<MarkdownBlock>, input: &'a str) -> MarkdownNode<'a> {
        let mut nodes = vec![];

        for block in blocks {
            match block {
                MarkdownBlock::Heading { level, content } => {
                    nodes.push(MarkdownNode::Heading {
                        level: *level,
                        children: Self::parse_inline_helper(content, input),
                    });
                }
                MarkdownBlock::Paragraph { content } => {
                    nodes.push(MarkdownNode::Paragraph(Self::parse_inline_helper(
                        content, input,
                    )));
                }
                MarkdownBlock::OrderedList { content } => {
                    let lines = content
                        .iter()
                        .map(|line| MarkdownNode::ListItem(Self::parse_inline_helper(line, input)))
                        .collect();
                    nodes.push(MarkdownNode::OrderedList(lines));
                }
                MarkdownBlock::UnorderedList { content } => {
                    let lines = content
                        .iter()
                        .map(|line| MarkdownNode::ListItem(Self::parse_inline_helper(line, input)))
                        .collect();
                    nodes.push(MarkdownNode::UnorderedList(lines));
                }
                MarkdownBlock::BlockQuote { content } => {
                    let lines = content
                        .iter()
                        .map(|line| MarkdownNode::Paragraph(Self::parse_inline_helper(line, input)))
                        .collect();
                    nodes.push(MarkdownNode::BlockQuote(lines));
                }
                MarkdownBlock::_Table { content } => {
                    todo!()
                }
                MarkdownBlock::CodeBlock { language, content } => {
                    nodes.push(MarkdownNode::CodeBlock {
                        language: *language,
                        content: Self::tokens_to_string(content, input),
                    });
                }
                MarkdownBlock::_BreakLine => nodes.push(MarkdownNode::BreakLine),
                MarkdownBlock::HorizontalLine => nodes.push(MarkdownNode::HorizontalLine),
            }
        }

        MarkdownNode::Document(nodes)
    }

    fn parse_inline_helper<'a>(
        mut tokens: &'a [MarkdownToken],
        input: &'a str,
    ) -> Vec<MarkdownNode<'a>> {
        use MarkdownNode::*;
        use MarkdownToken::*;
        let mut nodes = vec![];
        while !tokens.is_empty() {
            match &tokens {
                [Backtick(open), rest @ ..] if open.len() == 1 => {
                    if let Some(close_index) = rest
                        .iter()
                        .position(|token| matches!(token, Backtick(span) if span.len() == 1))
                    {
                        let Backtick(close) = &rest[close_index] else {
                            unreachable!();
                        };

                        nodes.push(InlineCode(&input[open.end..close.start]));

                        tokens = &rest[close_index + 1..];
                    } else {
                        nodes.push(Text(&input[open.start..open.end]));
                        tokens = rest;
                    }
                }
                [Underscore(open), rest @ ..]
                    if open.len() == 1 && Self::delimiter_can_open(tokens) =>
                {
                    let close_index = tokens.iter().enumerate().position(|(idx, token)| {
                        matches!(token, Underscore(_)) && Self::delimiter_can_close(tokens, idx)
                    });
                    if let Some(close_index) = close_index {
                        nodes.push(Italic(Self::parse_inline_helper(
                            &tokens[1..close_index],
                            input,
                        )));

                        tokens = &tokens[close_index + 1..];
                    } else {
                        nodes.push(Text(open.to_str(input)));
                        tokens = &tokens[1..];
                    }
                }
                [Asterisk(open), rest @ ..]
                    if open.len() == 1 && Self::delimiter_can_open(tokens) =>
                {
                    let close_index = tokens.iter().enumerate().position(|(idx, token)| {
                        matches!(token, Asterisk(_)) && Self::delimiter_can_close(tokens, idx)
                    });
                    if let Some(close_index) = close_index {
                        nodes.push(Bold(Self::parse_inline_helper(
                            &tokens[1..close_index],
                            input,
                        )));

                        tokens = &tokens[close_index + 1..];
                    } else {
                        nodes.push(Text(open.to_str(input)));
                        tokens = &tokens[1..];
                    }
                }
                [Tilde(open), rest @ ..] if open.len() == 1 && Self::delimiter_can_open(tokens) => {
                    let close_index = tokens.iter().enumerate().position(|(idx, token)| {
                        matches!(token, Tilde(_)) && Self::delimiter_can_close(tokens, idx)
                    });
                    if let Some(close_index) = close_index {
                        nodes.push(StrikeThrough(Self::parse_inline_helper(
                            &tokens[1..close_index],
                            input,
                        )));

                        tokens = &tokens[close_index + 1..];
                    } else {
                        nodes.push(Text(open.to_str(input)));
                        tokens = &tokens[1..];
                    }
                }
                [Asterisk(count), after @ ..] | [Underscore(count), after @ ..] => {
                    if count.len() >= 3 {
                        nodes.push(HorizontalLine);
                        tokens = after
                    } else {
                        nodes.push(Text(count.to_str(input)));
                        tokens = after
                    }
                }
                [first @ BracketOpen { .. }, after_open @ ..] => {
                    if let Some((node, rest)) = Self::try_parse_link(after_open, input) {
                        nodes.push(node);
                        tokens = rest;
                    } else {
                        nodes.push(Text(first.span().to_str(input)));
                        tokens = after_open;
                    }
                }
                [
                    first @ Exclamation { .. },
                    second @ BracketOpen { .. },
                    after_open @ ..,
                ] => {
                    if let Some((node, rest)) = Self::try_parse_image(after_open, input) {
                        nodes.push(node);
                        tokens = rest;
                    } else {
                        nodes.push(Text(&input[first.start()..second.end()]));
                        tokens = after_open;
                    }
                }
                _ => {
                    let mut text_token_count = 0;

                    while let [first, ..] = &tokens[text_token_count..] {
                        if Self::is_inline_special(first) {
                            break;
                        }

                        text_token_count += 1;
                    }

                    if text_token_count == 0 {
                        let first = &tokens[0];

                        nodes.push(Text(&input[first.start()..first.end()]));
                        tokens = &tokens[1..];
                    } else {
                        let plain = &tokens[..text_token_count];
                        let start = plain.first().unwrap().start();
                        let end = plain.last().unwrap().end();

                        nodes.push(Text(&input[start..end]));
                        tokens = &tokens[text_token_count..];
                    }
                }
            }
        }

        nodes
    }

    fn try_parse_link<'a>(
        tokens: &'a [MarkdownToken],
        input: &'a str,
    ) -> Option<(MarkdownNode<'a>, &'a [MarkdownToken])> {
        use MarkdownNode::*;
        use MarkdownToken::*;

        let close_bracket = tokens
            .iter()
            .position(|token| matches!(token, BracketClose { .. }))?;

        let text_tokens = &tokens[..close_bracket];
        let after_bracket = &tokens[close_bracket + 1..];

        let [ParenOpen { .. }, TextRaw(url), ParenClose { .. }, rest @ ..] = after_bracket else {
            return None;
        };

        Some((
            Link {
                text: Self::parse_inline_helper(text_tokens, input),
                url: url.to_str(input),
            },
            rest,
        ))
    }
    fn try_parse_image<'a>(
        tokens: &'a [MarkdownToken],
        input: &'a str,
    ) -> Option<(MarkdownNode<'a>, &'a [MarkdownToken])> {
        use MarkdownNode::*;
        use MarkdownToken::*;

        let close_bracket = tokens
            .iter()
            .position(|token| matches!(token, BracketClose { .. }))?;

        let text_tokens = &tokens[..close_bracket];
        let after_bracket = &tokens[close_bracket + 1..];

        let [ParenOpen { .. }, TextRaw(url), ParenClose { .. }, rest @ ..] = after_bracket else {
            return None;
        };

        let first = text_tokens.first().unwrap().start();
        let last = text_tokens.last().unwrap().end();
        let title = &input[first..last];

        Some((
            Image {
                alt: title,
                path: url.to_str(input),
            },
            rest,
        ))
    }
    fn is_inline_special(token: &MarkdownToken) -> bool {
        matches!(
            token,
            MarkdownToken::BracketOpen { .. }
                | MarkdownToken::Backtick(_)
                | MarkdownToken::Underscore(_)
                | MarkdownToken::Asterisk(_)
        )
    }
    fn delimiter_can_open(tokens: &[MarkdownToken]) -> bool {
        tokens.first().is_some_and(|token| {
            !matches!(
                token,
                MarkdownToken::Whitespace(_) | MarkdownToken::NewLine(_)
            )
        })
    }

    fn delimiter_can_close(tokens: &[MarkdownToken], index: usize) -> bool {
        index
            .checked_sub(1)
            .and_then(|index| tokens.get(index))
            .is_some_and(|token| {
                !matches!(
                    token,
                    MarkdownToken::Whitespace(_) | MarkdownToken::NewLine(_)
                )
            })
    }

    fn to_html(node: MarkdownNode) -> String {
        let mut html = String::new();
        Self::html_helper(&node, &mut html);
        html
    }

    fn html_helper(node: &MarkdownNode, builder: &mut String) {
        match node {
            MarkdownNode::BreakLine => {
                builder.push_str("<br>");
            }
            MarkdownNode::Document(nodes) => {
                nodes.iter().for_each(|n| Self::html_helper(n, builder));
            }
            MarkdownNode::Paragraph(children) => {
                builder.push_str("<p>");
                children.iter().for_each(|n| Self::html_helper(n, builder));

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
            MarkdownNode::StrikeThrough(children) => {
                builder.push_str("<s>");
                children.iter().for_each(|n| Self::html_helper(n, builder));
                builder.push_str("</s>");
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
                if let Some(language) = language {
                    builder.push_str("<pre><code class=\"language-");
                    builder.push_str(language.to_str());
                    builder.push_str("\">\n");
                } else {
                    builder.push_str("<pre><code>\n");
                }

                for (idx, line) in content.iter().enumerate() {
                    if idx != 0 {
                        builder.push('\n');
                    }
                    Self::push_escaped_code(builder, line);
                }
                builder.push_str("</code></pre>\n");
            }
            MarkdownNode::OrderedList(nodes) => {
                builder.push_str("<ol>\n");
                nodes.iter().for_each(|n| Self::html_helper(n, builder));
                builder.push_str("</ol>\n");
            }
            MarkdownNode::UnorderedList(nodes) => {
                builder.push_str("<ul>\n");
                nodes.iter().for_each(|n| Self::html_helper(n, builder));
                builder.push_str("</ul>\n");
            }
            MarkdownNode::ListItem(nodes) => {
                builder.push_str("<li>");
                nodes.iter().for_each(|n| Self::html_helper(n, builder));
                builder.push_str("</li>\n");
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
            MarkdownNode::Link { text, url } => {
                builder.push_str("<a class=\"link\" href=\"");
                builder.push_str(url);
                builder.push_str("\">");

                text.iter().for_each(|n| Self::html_helper(n, builder));
                builder.push_str("</a>");
            }
            MarkdownNode::Image { alt, path } => {
                builder.push_str("<img class=\"image\" src=\"");
                builder.push_str(path);
                builder.push_str(" alt=\"");
                builder.push_str(alt);
                builder.push_str("\">");
            }
            MarkdownNode::_Table => todo!("tabble"),
        }
    }

    fn push_escaped_code(builder: &mut String, input: &str) {
        for character in input.chars() {
            match character {
                '&' => builder.push_str("&amp;"),
                '<' => builder.push_str("&lt;"),
                '>' => builder.push_str("&gt;"),
                _ => builder.push(character),
            }
        }
    }
}

const SQLITE_OK: c_int = 0;
const SQLITE_ROW: c_int = 100;
const SQLITE_DONE: c_int = 101;

const SQLITE_DESERIALIZE_FLAG_FREEONCLOSE: u32 = 1;
const SQLITE_DESERIALIZE_FLAG_RESIZEABLE: u32 = 2;

const BLOB_MAGIC: &[u8; 11] = b"SQLITEBLOB\0";
const BLOB_FOOTER_SIZE: usize = 8 + BLOB_MAGIC.len();

#[repr(C)]
#[allow(non_camel_case_types)]
struct sqlite3_stmt {
    _private: [u8; 0],
}

#[repr(C)]
#[allow(non_camel_case_types)]
struct sqlite3_handle {
    _private: [u8; 0],
}

#[allow(non_camel_case_types)]
type sqlite3_destructor = Option<unsafe extern "C" fn(*mut c_void)>;

#[link(name = "sqlite3")]
unsafe extern "C" {
    fn sqlite3_open(
        filename: *const c_char,         /* Database filename (UTF-8) */
        pp_db: *mut *mut sqlite3_handle, /* OUT: SQLite db handle */
    ) -> c_int;

    fn sqlite3_close(db: *mut sqlite3_handle) -> c_int;
    fn sqlite3_prepare_v2(
        db: *mut sqlite3_handle,                  /* Database handle */
        sql: *const c_char,                       /* SQL statement, UTF-8 encoded */
        max_sql_len: c_int,                       /* Maximum length of zSql in bytes. */
        statement_handle: *mut *mut sqlite3_stmt, /* OUT: Statement handle */
        unused_sql: *mut *const c_char,           /* OUT: Pointer to unused portion of zSql */
    ) -> c_int;
    fn sqlite3_step(statement_handle: *mut sqlite3_stmt) -> c_int;
    fn sqlite3_finalize(statement_handle: *mut sqlite3_stmt) -> c_int;

    fn sqlite3_bind_blob(
        statement_handle: *mut sqlite3_stmt,
        index: c_int,
        value: *const c_void,
        value_len: c_int,
        destructor: sqlite3_destructor,
    ) -> c_int;
    fn sqlite3_bind_text(
        statement_handle: *mut sqlite3_stmt,
        index: c_int,
        value: *const i8,
        value_len: c_int,
        destructor: sqlite3_destructor,
    ) -> c_int;

    fn sqlite3_bind_int64(statement_handle: *mut sqlite3_stmt, index: c_int, value: i64) -> c_int;

    fn sqlite3_column_blob(
        statement_handle: *mut sqlite3_stmt,
        column_index: c_int,
    ) -> *const c_void;
    fn sqlite3_column_int64(statement_handle: *mut sqlite3_stmt, column_index: c_int) -> i64;
    fn sqlite3_column_text(statement_handle: *mut sqlite3_stmt, column_index: c_int) -> *const u8;
    fn sqlite3_column_bytes(statement_handle: *mut sqlite3_stmt, column_index: c_int) -> c_int;

    fn sqlite3_serialize(
        db: *mut sqlite3_handle, /* The database connection */
        target: *const i8,       /* Which DB to serialize. ex: "main", "temp", ... */
        result_size: *mut u64,   /* Write size of the DB here, if not NULL */
        flags: u32,              /* Zero or more SQLITE_SERIALIZE_* flags */
    ) -> *const u8;

    fn sqlite3_deserialize(
        db: *mut sqlite3_handle,  /* The database connection */
        target: *const i8,        /* Which DB to reopen with the deserialization */
        content: *const u8,       /* The serialized database content */
        content_len: u64,         /* Number of bytes in the deserialization */
        content_bufffer_len: u64, /* Total size of content buffer */
        flags: u32,               /* Zero or more SQLITE_SERIALIZE_* flags */
    ) -> c_int;
    fn sqlite3_malloc64(size: u64) -> *mut c_void;
    fn sqlite3_free(ptr: *mut c_void);
    fn sqlite3_errmsg(db: *mut sqlite3_handle) -> *const i8;
}

struct Statement {
    handle: *mut sqlite3_stmt,
}

impl Statement {
    fn step(&mut self) -> Result<bool, Box<dyn Error>> {
        let status = unsafe { sqlite3_step(self.handle) };

        match status {
            SQLITE_ROW => Ok(true),
            SQLITE_DONE => Ok(false),
            code => Err(format!(
                "sqlite3_step failed with code {}",
                Connection::to_sqlite_err(code, None)
            )
            .into()),
        }
    }
    fn bind_all(&self, binds: Vec<Bind>) -> Result<(), Box<dyn Error>> {
        for (i, bind) in binds.iter().enumerate() {
            bind.apply(self, i)?;
            // println!("Bound: {bind:?}")
        }
        Ok(())
    }
}

impl Drop for Statement {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                sqlite3_finalize(self.handle);
            }
        }
    }
}

#[derive(Debug)]
enum Bind<'a> {
    Text(&'a str),
    Int(i64),
    Blob(&'a [u8]),
}

impl Bind<'_> {
    fn apply(&self, statement: &Statement, index: usize) -> Result<(), Box<dyn Error>> {
        let statement = statement.handle;
        let index = index as c_int + 1; // Stinky sqlite is 1 indexed
        let status = match self {
            Bind::Text(value) => unsafe {
                sqlite3_bind_text(
                    statement,
                    index,
                    value.as_ptr().cast(),
                    value.len().try_into()?,
                    None,
                )
            },

            Bind::Int(value) => unsafe { sqlite3_bind_int64(statement, index, *value) },
            Bind::Blob(value) => unsafe {
                sqlite3_bind_blob(
                    statement,
                    index,
                    value.as_ptr().cast(),
                    value.len().try_into()?,
                    None,
                )
            },
        };

        match status {
            SQLITE_OK => {
                // println!("Bound: {self:?}");
                Ok(())
            }
            code => Err(format!(
                "binding parameter {index} failed with code {} for {self:?}",
                Connection::to_sqlite_err(code, None)
            )
            .into()),
        }
    }
}

#[derive(Debug)]
struct SqlResult {
    inner: Vec<Vec<ColumnValue>>,
}

impl SqlResult {
    fn get_text_column(&self, idx: usize) -> Result<Vec<&str>, Box<dyn Error>> {
        self.inner[idx]
            .iter()
            .map(|v| match v {
                ColumnValue::Text(s) => Ok(s.as_str()),
                ColumnValue::Null => Err("Null".into()),
                _ => Err("wrong type".into()),
            })
            .collect()
    }

    fn get_int_column(&self, idx: usize) -> Result<Vec<i64>, Box<dyn Error>> {
        self.inner[idx]
            .iter()
            .map(|v| match v {
                ColumnValue::Int(i) => Ok(*i),
                ColumnValue::Null => Err("Null".into()),
                _ => Err("wrong type".into()),
            })
            .collect()
    }

    fn get_blob_column(&self, idx: usize) -> Result<Vec<&[u8]>, Box<dyn Error>> {
        self.inner[idx]
            .iter()
            .map(|v| match v {
                ColumnValue::Blob(b) => Ok(b.as_slice()),
                ColumnValue::Null => Err("Null".into()),
                _ => Err("wrong type".into()),
            })
            .collect()
    }
}

enum ColumnTyp {
    Text,
    Int,
    Blob,
}

#[derive(Debug, Clone)]
enum ColumnValue {
    Text(String),
    Int(i64),
    Blob(Vec<u8>),
    Null,
}

impl ColumnTyp {
    fn get_from_statement(
        &self,
        statement: &Statement,
        column_index: usize,
    ) -> Result<ColumnValue, Box<dyn Error>> {
        let statement = statement.handle;
        let column_index = column_index.try_into()?;
        match self {
            ColumnTyp::Text => {
                let ptr = unsafe { sqlite3_column_text(statement, column_index) };

                if ptr.is_null() {
                    return Ok(ColumnValue::Null);
                }

                let len: usize =
                    unsafe { sqlite3_column_bytes(statement, column_index) }.try_into()?;

                let bytes = unsafe { slice::from_raw_parts(ptr, len) };

                Ok(ColumnValue::Text(str::from_utf8(bytes)?.to_owned()))
            }

            ColumnTyp::Int => Ok(ColumnValue::Int(unsafe {
                sqlite3_column_int64(statement, column_index)
            })),

            ColumnTyp::Blob => {
                let ptr = unsafe { sqlite3_column_blob(statement, column_index) };

                let len: usize =
                    unsafe { sqlite3_column_bytes(statement, column_index) }.try_into()?;

                if len == 0 {
                    return Ok(ColumnValue::Blob(Vec::new()));
                }

                if ptr.is_null() {
                    return Err("null blob pointer".into());
                }

                let bytes = unsafe { slice::from_raw_parts(ptr.cast(), len) };

                Ok(ColumnValue::Blob(bytes.to_vec()))
            }
        }
    }
}

#[derive(Debug)]
struct Connection {
    handle: *mut sqlite3_handle,
}

impl Connection {
    fn open(path: &str) -> Result<Self, Box<dyn Error>> {
        let c_string = CString::from_str(path)?;
        let mut handle: *mut sqlite3_handle = null_mut();

        let status = unsafe { sqlite3_open(c_string.as_ptr(), &mut handle) };

        match status {
            SQLITE_OK => Ok(Self { handle }),
            code => Err(format!("Opening db at {path} failed with code {code}").into()),
        }
    }

    fn prepare(&self, sql: &str) -> Result<Statement, Box<dyn Error>> {
        let sql = CString::new(sql)?;
        let mut statement_handle: *mut sqlite3_stmt = null_mut();

        let status = unsafe {
            sqlite3_prepare_v2(
                self.handle,
                sql.as_ptr(),
                -1,
                &mut statement_handle,
                null_mut(),
            )
        };

        match status {
            SQLITE_OK => Ok(Statement {
                handle: statement_handle,
            }),
            code => Err(format!(
                "sqlite3_prepare_v2 failed with code {}",
                Self::to_sqlite_err(code, Some(self))
            )
            .into()),
        }
    }

    fn execute(&self, sql: &str) -> Result<(), Box<dyn Error>> {
        let mut statement = self.prepare(sql)?;
        // println!("Executing query: {sql}");

        match statement.step()? {
            false => Ok(()),
            true => Err("execute unexpectedly returned a row".into()),
        }
    }

    fn insert(&self, sql: &str, binds: Vec<Bind>) -> Result<(), Box<dyn Error>> {
        let mut statement = self.prepare(sql)?;
        statement.bind_all(binds)?;

        // println!("Executing query: {sql}");

        match statement.step()? {
            false => Ok(()),
            true => Err("execute unexpectedly returned a row".into()),
        }
    }

    fn querry(
        &self,
        sql: &str,
        binds: Vec<Bind>,
        return_typ: Vec<ColumnTyp>,
    ) -> Result<SqlResult, Box<dyn Error>> {
        let mut statement = self.prepare(sql)?;

        statement.bind_all(binds)?;

        let mut res = vec![vec![]; return_typ.len()];

        while statement.step()? {
            for (i, typ) in return_typ.iter().enumerate() {
                let value = typ.get_from_statement(&statement, i)?;

                res.get_mut(i).expect("invariant").push(value);
            }
        }

        Ok(SqlResult { inner: res })
    }
    fn serialize(&self) -> Result<&[u8], Box<dyn Error>> {
        let serialized_db_size = &mut 0;
        let flags = 0;

        let bytes: &[u8] = unsafe {
            let serialized_db_ptr =
                sqlite3_serialize(self.handle, null(), serialized_db_size, flags);

            let bytes =
                slice::from_raw_parts(serialized_db_ptr.cast(), (*serialized_db_size) as usize);

            sqlite3_free(serialized_db_ptr.cast_mut().cast());
            bytes
        };

        Ok(bytes)
    }

    fn deserialize(content: &[u8]) -> Result<Connection, Box<dyn Error>> {
        let content_len = content.len() as u64;

        let buffer = unsafe { sqlite3_malloc64(content_len) }.cast::<u8>();

        unsafe {
            std::ptr::copy_nonoverlapping(content.as_ptr(), buffer, content.len());
        }

        let conn = Connection::open(":memory:")?; // Temp empty db in memory
        let flags = SQLITE_DESERIALIZE_FLAG_FREEONCLOSE | SQLITE_DESERIALIZE_FLAG_RESIZEABLE;

        let status = unsafe {
            sqlite3_deserialize(conn.handle, null(), buffer, content_len, content_len, flags)
        };
        // println!("Deserialized db");

        match status {
            SQLITE_OK => Ok(conn),
            code => Err(format!(
                "Deserializing db failed with code {}",
                Self::to_sqlite_err(code, None)
            )
            .into()),
        }
    }

    fn export_db(&self, path: PathBuf) -> Result<(), Box<dyn Error>> {
        let bytes = self.serialize()?;

        println!("Exported db to {path:?}");
        fs::write(path, bytes)?;
        Ok(())
    }

    fn import_db(path: PathBuf) -> Result<Connection, Box<dyn Error>> {
        let bytes = fs::read(&path)?;

        let conn = Connection::deserialize(&bytes)?;
        println!("Imported db from {path:?}");
        Ok(conn)
    }

    fn sqlite_error_msg(conn: &Connection) -> String {
        unsafe {
            CStr::from_ptr(sqlite3_errmsg(conn.handle))
                .to_string_lossy()
                .into_owned()
        }
    }

    fn to_sqlite_err(code: i32, conn: Option<&Connection>) -> String {
        match code & 0xff {
            0 => "SQLITE_OK: operation completed successfully",
            1 if conn.is_none() => "SQLITE_ERROR: generic SQL error: {}",
            1 if let Some(conn) = conn => {
                return format!(
                    "SQLITE_ERROR: generic SQL error: {}",
                    Self::sqlite_error_msg(conn)
                );
            }
            2 => "SQLITE_INTERNAL: internal SQLite error",
            5 => "SQLITE_BUSY: database is busy",
            9 => "SQLITE_INTERRUPT: operation was interrupted",
            10 => "SQLITE_IOERR: disk I/O error",
            11 => "SQLITE_CORRUPT: database is corrupted",
            12 => "SQLITE_NOTFOUND: unknown operation or object",
            14 => "SQLITE_CANTOPEN: unable to open database file",
            17 => "SQLITE_SCHEMA: database schema changed",
            18 => "SQLITE_TOOBIG: string or blob is too large",
            19 => "SQLITE_CONSTRAINT: constraint violation",
            20 => "SQLITE_MISMATCH: datatype mismatch",
            21 => "SQLITE_MISUSE: SQLite API used incorrectly",
            25 => "SQLITE_RANGE: bind parameter or column index out of range",
            26 => "SQLITE_NOTADB: file is not a valid SQLite database",
            27 => "SQLITE_NOTICE: SQLite notice",
            28 => "SQLITE_WARNING: SQLite warning",
            100 => "SQLITE_ROW: sqlite3_step produced another row",
            101 => "SQLITE_DONE: sqlite3_step finished",
            _ => return format!("unknown SQLite result code {code}"),
        }
        .to_owned()
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                sqlite3_close(self.handle);
            }

            self.handle = null_mut();
        }
    }
}

struct Blob {}

impl Blob {
    fn read_blob(bytes: &[u8]) -> Result<Option<&[u8]>, Box<dyn Error>> {
        if bytes.len() < BLOB_FOOTER_SIZE {
            return Ok(None);
        }

        let magic_offset = bytes.len() - BLOB_MAGIC.len();

        if &bytes[magic_offset..] != BLOB_MAGIC {
            return Ok(None);
        }

        let length_offset = magic_offset - 8;

        let blob_len = u64::from_le_bytes(bytes[length_offset..magic_offset].try_into()?) as usize;

        let blob_offset = length_offset - blob_len;

        Ok(Some(&bytes[blob_offset..length_offset]))
    }

    fn write_blob(bytes: &mut Vec<u8>, blob: &[u8]) -> Result<(), Box<dyn Error>> {
        // Replace the existing blob rather than appending another blob each time.
        Blob::remove_blob(bytes)?;

        bytes.extend_from_slice(blob);
        bytes.extend_from_slice(&(blob.len() as u64).to_le_bytes());
        bytes.extend_from_slice(BLOB_MAGIC);

        Ok(())
    }

    fn remove_blob(bytes: &mut Vec<u8>) -> Result<(), Box<dyn Error>> {
        if bytes.len() < BLOB_FOOTER_SIZE {
            // Binary to small
            return Ok(());
        }

        let magic_offset = bytes.len() - BLOB_MAGIC.len();

        if &bytes[magic_offset..] != BLOB_MAGIC {
            return Ok(());
        }

        let length_offset = magic_offset - 8;

        let blob_len = u64::from_le_bytes(bytes[length_offset..magic_offset].try_into()?) as usize;

        let blob_offset = length_offset - blob_len;

        bytes.truncate(blob_offset);

        Ok(())
    }

    fn self_modify(
        path: &PathBuf,
        bytes: &mut Vec<u8>,
        conn: &Connection,
    ) -> Result<(), Box<dyn Error>> {
        let start_time = Instant::now();
        let serialized = conn.serialize()?;

        Blob::write_blob(bytes, serialized)?;

        let tmp = path.with_extension("tmp");

        fs::write(&tmp, bytes)?;

        let perms = fs::metadata(path)?.permissions();
        fs::set_permissions(&tmp, perms)?;

        // renames the executable, doesnt affect the currently running process
        fs::rename(&tmp, path)?;

        let end_time = Instant::now() - start_time;
        println!(
            "Serialized db into {} bytes in {:?}",
            serialized.len(),
            end_time
        );

        Ok(())
    }
}

#[derive(Debug)]
struct Db {
    connection: Connection,
    executable_bytes: Vec<u8>,
    executable_path: PathBuf,
    unsynced: bool,
}

impl Db {
    fn init() -> Result<Self, Box<dyn Error>> {
        let current_executable_path = env::current_exe()?;

        let mut executable_bytes = fs::read(&current_executable_path)?;

        let conn = match Blob::read_blob(&executable_bytes)? {
            Some(blob) => {
                let conn = Connection::deserialize(blob)?;
                println!(
                    "Blob of length {} found in own binary and serialized into db",
                    blob.len()
                );
                conn
            }
            None => {
                #[cfg(generated)] // PREV_BIN_PATH and PREV_BIN_TYPE dont exist during build time
                if let Some(prev_bin_path) = &PREV_BIN_PATH
                    && let Ok(prev_bin) = fs::read(prev_bin_path)
                    && let Ok(Some(blob)) = Blob::read_blob(&prev_bin)
                    && let Some(prev_bin_type) = &PREV_BIN_TYPE
                {
                    println!(
                        "Blob of length {} found in previous {prev_bin_type} binary and serialized into db",
                        blob.len()
                    );

                    Connection::deserialize(blob)?
                } else {
                    println!("No blob found, creating new db");
                    let conn = Connection::open(":memory:")?;
                    Self::init_schema(&conn)?;
                    conn
                }
                #[cfg(not(generated))]
                unreachable!();
            }
        };
        let mut db = Self {
            connection: conn,
            executable_bytes,
            executable_path: current_executable_path,
            unsynced: false,
        };
        db.sync()?;
        Ok(db)
    }

    fn sync(&mut self) -> Result<(), Box<dyn Error>> {
        if self.unsynced {
            Blob::self_modify(
                &self.executable_path,
                &mut self.executable_bytes,
                &self.connection,
            )?;
            self.unsynced = false;
            Ok(())
        } else {
            Ok(())
        }
    }

    fn init_counter(conn: &Connection) -> Result<(), Box<dyn Error>> {
        conn.execute(
            "
            CREATE TABLE counter (
              count INTEGER NOT NULL
            );",
        )?;
        conn.insert(
            "
            INSERT INTO counter (count)
            VALUES (?);",
            vec![Bind::Int(0)],
        )?;
        Ok(())
    }
    fn init_schema(conn: &Connection) -> Result<(), Box<dyn Error>> {
        Self::init_counter(conn)?;

        conn.execute(
            "
            CREATE TABLE page_metrics (
              id INTEGER PRIMARY KEY,
              page TEXT,
              load_time INTEGER,
              timestamp TIMESTAMP
            );",
        )?;
        conn.execute(
            "
          CREATE TABLE global_stats (
            id INTEGER PRIMARY KEY,
            start_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
          );",
        )?;
        conn.execute(
            "
        INSERT INTO global_stats (id) VALUES (1)",
        )?;
        Ok(())
    }

    fn test_counter(&mut self) -> Result<(), Box<dyn Error>> {
        let conn = &self.connection;

        let res = conn.querry("SELECT count FROM counter", vec![], vec![ColumnTyp::Int])?;

        let counter_col = res.get_int_column(0).unwrap();
        let counter = *counter_col.first().unwrap();

        println!("Counter: {counter:?}");

        conn.insert(
            "
            UPDATE counter
            SET count = ?;",
            vec![Bind::Int(counter + 1)],
        )?;
        self.unsynced = true;
        Ok(())
    }

    fn save_page_hit(&mut self, page: &str, loadtime: Duration) -> Result<(), Box<dyn Error>> {
        let conn = &self.connection;
        let timestamp = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        let loadtime_nanos = i64::from(loadtime.subsec_nanos());

        conn.insert(
            "
            INSERT INTO page_metrics (page, load_time, timestamp) VALUES (?,?,?)",
            vec![
                Bind::Text(page),
                Bind::Int(loadtime_nanos),
                Bind::Int(timestamp),
            ],
        )?;
        self.unsynced = true;

        Ok(())
    }

    fn load_stats(&self) -> Result<Stats, Box<dyn Error>> {
        let conn = &self.connection;

        let res = conn.querry(
            "
              SELECT start_time
              FROM global_stats",
            vec![],
            vec![ColumnTyp::Text],
        )?;
        let col = res.get_text_column(0)?;
        let start_time = col.first().ok_or("Start time not found")?.to_string();

        let res = conn.querry(
            "
                SELECT page, AVG(load_time) AS average_load_time, COUNT(*) AS total_count
                FROM page_metrics
                GROUP BY page",
            vec![],
            vec![ColumnTyp::Text, ColumnTyp::Int, ColumnTyp::Int],
        )?;

        let pages = res.get_text_column(0)?;
        let average_loadtimes = res.get_int_column(1)?;
        let counts = res.get_int_column(2)?;

        let metrics = zip(pages, zip(average_loadtimes, counts))
            .map(|(page, (average_loadtime_nanos, count))| PageMetric {
                page: page.to_owned(),
                avg_loadtime: Duration::from_nanos(average_loadtime_nanos as u64),
                count: count as u64,
            })
            .collect();

        Ok(Stats {
            pages: metrics,
            start_time,
        })
    }
}

#[derive(Debug)]
struct Stats {
    start_time: String,
    pages: Vec<PageMetric>,
}

impl ToTemplateValue for Stats {
    fn to_template_value(&self) -> TemplateValue {
        TemplateValue::Object(hash_map! {
          "pages".to_string() => self.pages.to_template_value(),
          "start_time".to_string() => self.start_time.to_template_value(),
        })
    }
}

#[derive(Debug)]
struct PageMetric {
    page: String,
    avg_loadtime: Duration,
    count: u64,
}

impl ToTemplateValue for PageMetric {
    fn to_template_value(&self) -> TemplateValue {
        TemplateValue::Object(hash_map! {
          "path".to_string() => TemplateValue::Text(self.page.to_string()),
          "avg".to_string() =>  self.avg_loadtime.to_template_value(),
          "count".to_string() => self.count.to_template_value(),
        })
    }
}

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

const SIGINT: c_int = 2;
const SIGTERM: c_int = 15;
const SIG_ERR: usize = usize::MAX;

extern "C" fn handle_signal(_: c_int) {
    SHUTDOWN.store(true, Ordering::Relaxed);
}

unsafe extern "C" {
    fn signal(signal: c_int, handler: extern "C" fn(c_int)) -> usize;
}

fn register_signal_handlers() {
    unsafe {
        assert_ne!(signal(SIGINT, handle_signal), SIG_ERR);
        assert_ne!(signal(SIGTERM, handle_signal), SIG_ERR);
    }
}
