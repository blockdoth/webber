#![feature(tcp_linger)]
#![feature(if_let_guard)]
#![feature(hash_map_macro)]
#![allow(unused)]

// #![warn(clippy::pedantic)]
// #![allow(clippy::similar_names)]
// #![allow(clippy::cast_possible_truncation)]
// #![allow(clippy::cast_sign_loss)]
// #![allow(clippy::cast_possible_wrap)]
// #![allow(clippy::enum_glob_use)]

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::env;
use std::error::Error;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::fmt::Write as FmtWrite;
use std::fmt::{Debug, Display};
use std::io::{self, Read, Write};
use std::iter::{Peekable, zip};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf, StripPrefixError};
use std::process::Command;
use std::ptr::{null, null_mut};
use std::slice;
use std::str::{CharIndices, FromStr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};
use std::{char, fmt, fs, vec};

const SOCKET_ADDR: &str = "127.0.0.1:4000";
const ASSETS_PATH: &str = "./assets/";
const TEMPLATES_PATH: &str = "./templates/";

const DEBUG_BIN_PATH: &str = "./target/debug/webber";
const RELEASE_BIN_PATH: &str = "./target/release/webber";

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

#[cfg(generated)]
include!(concat!(env!("OUT_DIR"), "/generated.rs"));

fn main() -> Result<(), Box<dyn Error>> {
    if std::env::args().any(|arg| arg.contains("build-script-build")) {
        // println!("cargo:warning=Running in build script");
        comptime()
    } else {
        // println!("Running normally");
        #[cfg(generated)] // Marks everything deadcode during build time
        runtime()?;

        Ok(())
    }
}

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

    out.push_str("fn load_embedded_assets() -> Trie<Asset>{\n");
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
            Some("png") | Some("ico") => {
                &format!("AssetData::Png(include_bytes!({global_path:?}).to_vec())")
            }
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

    out.push_str("\tassets\n");
    out.push_str("}\n");

    out.push('\n');

    // === Templates ===

    let template_paths = walk_dir(TEMPLATES_PATH);

    out.push_str(
        "fn load_embedded_templates() -> HashMap<String, Result<Template,TemplateError>> {\n",
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
    out.push_str("\t\tlet template = TemplateParser::parse(template_str, origin_file);\n");

    out.push_str("\t\ttemplates.insert(key.to_string(),template);\n");
    out.push_str("\t}\n");

    out.push_str("\ttemplates\n");
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

    if let Some((prev_bin_path, is_debug)) = bin_tupple {
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
    } else {
        println!("cargo:warning=no existing selfmod binary found");

        out.push_str("static PREV_BIN_TYPE: Option<&str> = None;\n");
        out.push_str("static PREV_BIN_PATH: Option<&str> = None;\n");
    };

    // === Git ===
    let (short, long) = get_commit_hash();

    out.push_str(&format!("const GIT_HASH_SHORT:&str = {short:?};\n"));
    out.push_str(&format!("const GIT_HASH_LONG:&str = {long:?};\n"));

    fs::write(&generated_code_path, out).unwrap();
    // println!("cargo:warning=End of build script");
    Ok(())
}

fn runtime() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args();

    if let Some(first_arg) = args.nth(1) {
        match first_arg.as_str() {
            "dumpdb" => {
                let db = Db::init()?;
                let path = if let Some(path) = args.next() {
                    PathBuf::from(path)
                } else {
                    PathBuf::from("./webber.db")
                };
                return db.export_db(&path);
            }
            "exportdb" => {
                let mut db = Db::init()?;
                let path = if let Some(path) = args.next() {
                    PathBuf::from(path)
                } else {
                    PathBuf::from("./webber.db")
                };
                return db.export_db_serialized(path);
            }
            "loaddb" => {
                let path = if let Some(path) = args.next() {
                    PathBuf::from(path)
                } else {
                    PathBuf::from("./webber.db")
                };
                return Db::import_db(path);
            }
            _ => return Err(format!("unknown arg: {}", first_arg).into()),
        }
    }

    run_server()
}

fn run_server() -> Result<(), Box<dyn Error>> {
    register_signal_handlers();

    let mut db = Db::init()?;
    println!("Initialized db");
    db.test_counter()?;
    db.sync()?;

    let content = Content::load_embedded();

    let context = Context::load_intial(&content);

    let router = Router::new(content, context, db)
        .route_static_hidden("/layout", "layout.html")
        .route_static_hidden("/home", "pages/home.html")
        .route_static_hidden("/rss", "rss.html")
        .route_static_page("/posts", "pages/posts.html")
        .route_static_page("/quotes", "pages/quotes.html")
        .route_static_page("/stats", "pages/stats.html")
        .route_static_page("/about", "pages/about.html")
        .route_dynamic_pages("/posts/:post", "pages/post.html", "posts")
        .fallback("/home")
        .error_page("error.html");

    let listener: TcpListener = TcpListener::bind(SOCKET_ADDR).expect("Unable to bind to socket");
    println!("Started listening on socket http://{SOCKET_ADDR}");

    HttpServer::serve(listener, router)
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

        context.insert_global("hotreload", cfg!(debug_assertions).to_template_value());

        context
    }
}

// === Http Server ===

#[derive(Debug)]
struct HttpRequestHeader {
    _typ: HttpRequestType,
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
            let websocket_accept = base64(&sha1(&format!(
                "{}{magic_string}",
                sec_websocket_key.trim()
            )));
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
            _typ: request_type,
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
        let end = path
            .as_bytes()
            .iter()
            .position(|&b| b == b'?' || b == b'#')
            .unwrap_or(path.len());

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
            // print!("Loop it {it}\r");
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
                        _ => {}
                    };
                };
                let start_timer = Instant::now();
                let (header, body) =
                    HttpServer::parse_request(&buffer[..n]).expect("Unable to parse request");

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
                            Err(HttpServerError::TemplatingError(err)) => {
                                let error_template = if let Some(error_page_path) =
                                    &router.error_page
                                    && let Some(Ok(template)) =
                                        router.content.templates.get(error_page_path)
                                {
                                    Some(template)
                                } else {
                                    None
                                };

                                Self::build_response(
                                    HttpResponseCode::Ok,
                                    &AssetData::Html(err.render_error(error_template)),
                                )
                            }
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

                        router.db.save_page_hit(path, duration)?;
                    }
                };

                #[cfg(debug_assertions)]
                {
                    if is_ws {
                        active_streams.push(stream);
                    }
                }
            }

            if check_db_sync_timer.elapsed() > Duration::from_secs(60) {
                router.db.sync()?;
                check_db_sync_timer = Instant::now();
            }

            #[cfg(debug_assertions)]
            {
                let reload = if check_fs_timer.elapsed() > Duration::from_millis(50) {
                    check_fs_timer = Instant::now();

                    router.content.check_update(&mut router.context)?
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
                            true
                        } else {
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

#[derive(Debug)]
enum HttpServerError {
    Redirect(String),
    TemplatingError(TemplateError),
    StreamWriteFailed,
    Todo,
}

impl Error for HttpServerError {}

impl Display for HttpServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Redirect(location) => write!(f, "redirect to {location}"),
            Self::StreamWriteFailed => write!(f, "failed to write to stream"),
            Self::TemplatingError(error) => write!(f, "templating error: {error}"),
            Self::Todo => write!(f, "operation not implemented"),
        }
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

// === Router ===

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
    error_page: Option<String>,
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
            error_page: None,
        }
    }

    fn route_static_page(mut self, path: &str, template: &str) -> Self {
        let route = StaticRoute::new(template, false);
        self.static_routes.insert(path.into(), route.clone());
        let name = path.split('/').next_back().expect("valid path");

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
    ) -> Self {
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

        self
    }

    fn fallback(mut self, page: &str) -> Self {
        self.fallback = Some(page.to_string());
        self
    }

    fn error_page(mut self, template: &str) -> Self {
        match self.content.templates.get(template) {
            None => panic!("Error page: \"{template}\" must be in the templates"),
            Some(Err(err)) => {
                panic!("Error page: \"{template}\" has a render or parsing error: {err:?}")
            }
            Some(Ok(_)) => self.error_page = Some(template.to_owned()),
        }
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
                let stats = self
                    .db
                    .load_stats()
                    .expect("TOPO improve error handeling to make this work");
                let stats = stats.to_template_value();
                let local_context = LocalContext::new(&self.context, "stats", &stats);

                let page =
                    Self::render_template(&self.content.templates, &local_context, &route.path)?;

                Ok(AssetData::Html(page))
            }
            Some(route) => {
                let page =
                    Self::render_template(&self.content.templates, &self.context, &route.path)?;
                Ok(AssetData::Html(page))
            }
            _ => match self.dynamic_routes.get(&header.path) {
                Some(dyn_route) if let Some(cached) = &dyn_route.cached_page => {
                    println!("Serving cached dynamic page {}", header.path);

                    Ok(AssetData::Html(cached.to_string()))
                }
                Some(dyn_route) => {
                    // println!("Serving dynamic page {}", header.path);

                    let page_context_var = if let Some(TemplateValue::Object(posts_by_slug)) =
                        self.context.lookup("posts_by_slug")
                        && let Some(template_value) = posts_by_slug.get(&dyn_route.slug).cloned()
                    {
                        template_value
                    } else {
                        todo!("slug not found");
                    };
                    let local_context = LocalContext::new(
                        &self.context,
                        &dyn_route.page_var_name,
                        &page_context_var,
                    );

                    let page = Self::render_template(
                        &self.content.templates,
                        &local_context,
                        &dyn_route.template_path,
                    )?;

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
        templates: &HashMap<String, Result<Template, TemplateError>>,
        context: &dyn TemplateContext,
        path: &str,
    ) -> Result<String, TemplateError> {
        //TODO unfuck
        let mut slug = path.strip_suffix(".html").unwrap_or(path);
        slug = slug.strip_prefix("pages").unwrap_or(slug);
        let url = &slug.to_template_value();

        let context = LocalContext::new(context, "current_page_url", url);

        match templates.get(path).expect("template not found") {
            Ok(template) => {
                if let Some(parent_path) = &template.parent {
                    match templates
                        .get(parent_path)
                        .expect("Parent template not found: {parent_path}")
                    {
                        Ok(parent_template) => {
                            if parent_template.parent.is_some() {
                                todo!("nested parents")
                            } else {
                                template.render_with_parent(&context, parent_template)
                            }
                        }
                        Err(err) => Err(template.enhance_error(err.clone())),
                    }
                } else {
                    template.render(&context)
                }
            }
            Err(template_error) => Err(template_error.clone()),
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

// === Templates ===

#[derive(Debug)]
struct Template {
    template: Vec<TemplateNode>,
    parent: Option<String>,
    blocks: HashMap<String, Vec<TemplateNode>>,
    required_variables: Vec<Vec<String>>,
    origin_file: String,
    last_modified: SystemTime,
    input: String,
    newlines: Vec<usize>,
}

impl Template {
    fn from_path<P: AsRef<Path> + Debug + Copy>(path: P) -> Result<Self, TemplateError> {
        let path_string = path.as_ref().to_string_lossy().to_string();

        let template_str = fs::read_to_string(path).expect("invariant");

        TemplateParser::parse(&template_str, &path_string)
    }

    fn update_from_path<P: AsRef<Path> + Debug + Copy>(
        template: &mut Result<Template, TemplateError>,
        path: P,
    ) {
        let path_string = path.as_ref().to_string_lossy().to_string();

        *template = match fs::read_to_string(path) {
            Ok(template_str) => TemplateParser::parse(&template_str, &path_string),
            Err(e) => Err(TemplateError::only_file(
                TemplateErrorMsg::GenericError(e.to_string()),
                &path_string,
            )),
        };
    }

    fn render(&self, context: &dyn TemplateContext) -> Result<String, TemplateError> {
        let mut out = String::new();
        Self::render_helper(&self.template, context, &HashMap::new(), &mut out)
            .map_err(|e| self.enhance_error(e));
        Ok(out)
    }

    fn render_with_parent(
        &self,
        context: &dyn TemplateContext,
        parent: &Template,
    ) -> Result<String, TemplateError> {
        let mut out = String::new();
        Self::render_helper(&parent.template, context, &self.blocks, &mut out).map_err(
            |e| match &e.pos {
                Some(pos) => {
                    if pos.file == self.origin_file {
                        self.enhance_error(e)
                    } else if pos.file == parent.origin_file {
                        parent.enhance_error(e)
                    } else {
                        panic!("cosmic ray type event")
                    }
                }
                None => self.enhance_error(e),
            },
        );
        Ok(out)
    }

    fn render_helper(
        template: &[TemplateNode],
        context: &dyn TemplateContext,
        blocks: &HashMap<String, Vec<TemplateNode>>,
        out: &mut String,
    ) -> Result<(), TemplateError> {
        use TemplateNodeData::*;
        for node in template {
            match &node.data {
                Text(text) => out.push_str(text),
                Variable(ident_fields) => {
                    match Self::resolve_var(ident_fields, context, &node.pos)? {
                        TemplateValue::Text(text) => out.push_str(text),
                        TemplateValue::Bool(bool_val) => write!(out, "{bool_val}")?,
                        TemplateValue::List(list) => write!(out, "{list:?}")?,
                        TemplateValue::Object(object) => write!(out, "{object:?}")?,
                    }
                }
                If {
                    condition,
                    then_branch,
                    else_branch,
                } => {
                    let cond = match condition {
                        ConditionExpr::Literal(bool_lit) => *bool_lit,
                        ConditionExpr::Var(var) => Self::resolve_bool(var, context, node)?,
                        ConditionExpr::VarComp(var_1, var_2) => {
                            let var_1 = Self::resolve_var(var_1, context, &node.pos)?;
                            let var_2 = Self::resolve_var(var_2, context, &node.pos)?;

                            match (var_1, var_2) {
                                (TemplateValue::Text(text_1), TemplateValue::Text(text_2)) => {
                                    text_1 == text_2
                                }
                                _ => {
                                    return Err(TemplateError::new(
                                        TemplateErrorMsg::CantCompareTemplateValues(
                                            var_1.kind(),
                                            var_2.kind(),
                                        ),
                                        node.pos.clone(),
                                    ));
                                }
                            }
                        }
                        ConditionExpr::LiteralComp(var, literal) => {
                            let var = Self::resolve_var(var, context, &node.pos)?;
                            match var {
                                TemplateValue::Text(var_text) => var_text == literal,
                                _ => {
                                    return Err(TemplateError::new(
                                        TemplateErrorMsg::CantCompareWithLiteral(var.kind()),
                                        node.pos.clone(),
                                    ));
                                }
                            }
                        }
                    };

                    if cond {
                        Self::render_helper(then_branch, context, blocks, out)?
                    } else {
                        Self::render_helper(else_branch, context, blocks, out)?
                    };
                }
                For {
                    iter_bind,
                    iter_src,
                    body,
                } => {
                    // Todo remove clone
                    if let TemplateValue::List(iter) =
                        Self::resolve_var(iter_src, context, &node.pos)?
                    {
                        let mut for_res = String::new();
                        for it in iter {
                            let child_context = LocalContext::new(context, iter_bind, it);

                            Self::render_helper(body, &child_context, blocks, &mut for_res)?;
                        }
                        out.push_str(&for_res);
                    } else {
                        return Err(TemplateError::new(
                            TemplateErrorMsg::VariableNotOfExpectedType(
                                iter_src.concat(),
                                TemplateValueKind::List,
                            ),
                            node.pos.clone(),
                        ));
                    }
                }
                Block { ident, body } => {
                    if let Some(override_body) = blocks.get(ident) {
                        Self::render_helper(override_body, context, blocks, out)?;
                    } else {
                        Self::render_helper(body, context, blocks, out)?;
                    }
                }
            };
        }
        Ok(())
    }

    fn resolve_var<'a>(
        ident_fields: &[String],
        context: &'a dyn TemplateContext,
        pos: &TemplatePositionData,
    ) -> Result<&'a TemplateValue, TemplateError> {
        let Some(mut current) = context.lookup(&ident_fields[0]) else {
            let field = ident_fields[0].to_string();
            let mut pos = pos.clone();

            if let Some(span) = &mut pos.span {
                span.end = span.start + field.len();
            }

            return Err(TemplateError::new(
                TemplateErrorMsg::VariableNotFound(field),
                pos,
            ));
        };

        let mut field_idx = 1;

        let node_span = pos.span.as_ref().expect("pretty sure this is always true");
        let mut start_field = node_span.start
            + ident_fields
                .first()
                .expect("pretty sure this is always true")
                .len();

        for field in &ident_fields[1..] {
            start_field += 1;
            current = match current {
                TemplateValue::Object(map) => {
                    if let Some(obj) = map.get(field.as_str()) {
                        obj
                    } else {
                        return Err(TemplateError::new(
                            TemplateErrorMsg::FieldNotFoundOnVariable(
                                ident_fields[0..field_idx].concat(),
                                field.to_string(),
                            ),
                            TemplatePositionData {
                                file: pos.file.clone(),
                                span: Some(Span::from_double(start_field, node_span.end)),
                            },
                        ));
                    }
                }
                _ => Err(TemplateError::new(
                    TemplateErrorMsg::VariableNotOfExpectedType(
                        field.to_string(),
                        TemplateValueKind::List,
                    ),
                    TemplatePositionData {
                        file: pos.file.clone(),
                        span: Some(Span::from_double(start_field, node_span.end)),
                    },
                ))?,
            };
            start_field += field.len();

            field_idx += 1;
        }
        Ok(current)
    }

    fn resolve_bool(
        condition: &[String],
        context: &dyn TemplateContext,
        node: &TemplateNode,
    ) -> Result<bool, TemplateError> {
        match Self::resolve_var(condition, context, &node.pos)? {
            TemplateValue::Bool(cond) => Ok(*cond),
            TemplateValue::List(template_values) => Ok(!template_values.is_empty()),
            _ => Err(TemplateError::new(
                TemplateErrorMsg::VariableNotOfExpectedType(
                    condition.concat(),
                    TemplateValueKind::Bool,
                ),
                node.pos.clone(),
            ))?,
        }
    }

    fn enhance_error(&self, err: TemplateError) -> TemplateError {
        TemplateError {
            typ: err.typ,
            pos: err.pos,
            info: Some(Box::new(TemplateInfo {
                input: self.input.clone(),
                newlines: self.newlines.clone(),
                last_modified: self.last_modified,
            })),
        }
    }
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
        TemplateValue::Text((*self).to_string())
    }
}

impl ToTemplateValue for String {
    fn to_template_value(&self) -> TemplateValue {
        TemplateValue::Text((*self).to_string())
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
        TemplateValue::List(
            self.iter()
                .map(ToTemplateValue::to_template_value)
                .collect(),
        )
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

impl ToTemplateValue for PageMetric {
    fn to_template_value(&self) -> TemplateValue {
        TemplateValue::Object(hash_map! {
          "path".to_string() => TemplateValue::Text(self.page.to_string()),
          "avg".to_string() =>  self.avg_loadtime.to_template_value(),
          "count".to_string() => self.count.to_template_value(),
        })
    }
}

impl ToTemplateValue for Stats {
    fn to_template_value(&self) -> TemplateValue {
        TemplateValue::Object(hash_map! {
          "pages".to_string() => self.pages.to_template_value(),
          "start_time".to_string() => self.start_time.to_template_value(),
        })
    }
}

impl ToTemplateValue for SyntaxHighlightLang {
    fn to_template_value(&self) -> TemplateValue {
        use SyntaxHighlightLang::*;
        use TemplateValue::*;
        match self {
            Bash | C | Clike | Css | Haskell | Nix | Rust | Markdown | Markup | Elixir | Html
            | Javascript | Typescript => Text(self.to_str().to_string()),
        }
    }
}

impl ToTemplateValue for AssetData {
    fn to_template_value(&self) -> TemplateValue {
        use AssetData::*;
        use TemplateValue::*;
        match self {
            Png(_) | Ico(_) | Woff2(_) => {
                todo!("Cant isnert binary assets into context yet")
            }
            Empty => todo!("not sure what to do with this"),
            AssetData::Text(s) | Html(s) | Css(s) | Js(s) | MdRaw(s) | Unknown(s) => {
                TemplateValue::Text(s.to_string())
            }
            MdParsed(ParsedMarkdown {
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
                obj.insert("draft".to_string(), Bool(metadata.draft));
                obj.insert("tags".to_string(), metadata.tags.to_template_value());

                let highlighted_langs =
                    SyntaxHighlightLang::include_dependencies(highlighted_langs);

                obj.insert(
                    "highlighted_langs".to_string(),
                    highlighted_langs.to_template_value(),
                );

                Object(obj)
            }
        }
    }
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
        condition: ConditionExpr,
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

#[derive(Debug, Clone)]
enum ConditionExpr {
    Var(Vec<String>),
    VarComp(Vec<String>, Vec<String>),
    LiteralComp(Vec<String>, String),
    Literal(bool),
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

                match condition {
                    ConditionExpr::Var(ident_1) => write!(
                        f,
                        "if {} then {{\n \t{then_branch_str}\n}} else {{\n\t{else_branch_str}\n}}",
                        ident_1.join(".")
                    ),
                    ConditionExpr::VarComp(ident_1, ident_2) => write!(
                        f,
                        "if {} == {} then {{\n \t{then_branch_str}\n}} else {{\n\t{else_branch_str}\n}}",
                        ident_1.join("."),
                        ident_2.join("."),
                    ),
                    ConditionExpr::LiteralComp(ident_1, literal) => write!(
                        f,
                        "if {} == \"{}\" then {{\n \t{then_branch_str}\n}} else {{\n\t{else_branch_str}\n}}",
                        ident_1.join("."),
                        literal
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
            }
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
enum TemplateToken {
    Text(Span),
    Identifier(Span),
    Literal(Span),
    Dot(Span),
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
}

#[derive(Debug, PartialEq, Clone)]
enum TemplateTokenTyp {
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
    Equals,
}

impl TemplateToken {
    fn typ(&self) -> TemplateTokenTyp {
        use TemplateToken as Token;
        use TemplateTokenTyp as Typ;

        match self {
            Token::Text(_) => Typ::Text,
            Token::Identifier(_) => Typ::Identifier,
            Token::If(_) => Typ::If,
            Token::Else(_) => Typ::Else,
            Token::For(_) => Typ::For,
            Token::In(_) => Typ::In,
            Token::EndIf(_) => Typ::EndIf,
            Token::EndElse(_) => Typ::EndElse,
            Token::EndFor(_) => Typ::EndFor,
            Token::Block(_) => Typ::Block,
            Token::EndBlock(_) => Typ::EndBlock,
            Token::Extends(_) => Typ::Extends,
            Token::NewLine(_) => Typ::NewLine,
            Token::Whitespace(_) => Typ::Whitespace,
            Token::Dot(_) => Typ::Dot,
            Token::Equals(_) => Typ::Equals,
            Token::Literal(_) => Typ::Literal,
        }
    }

    fn span(&self) -> &Span {
        match self {
            Self::Text(span)
            | Self::Identifier(span)
            | Self::Dot(span)
            | Self::Equals(span)
            | Self::Whitespace(span)
            | Self::If(span)
            | Self::Else(span)
            | Self::For(span)
            | Self::In(span)
            | Self::EndIf(span)
            | Self::EndElse(span)
            | Self::EndFor(span)
            | Self::NewLine(span)
            | Self::Block(span)
            | Self::EndBlock(span)
            | Self::Extends(span)
            | Self::Literal(span) => span,
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
struct TemplatePositionData {
    file: String,
    span: Option<Span>,
}

#[derive(Clone, Debug)]
struct Position {
    line: usize,
    column: usize,
}

#[derive(Debug, Clone)]
struct TemplateError {
    typ: TemplateErrorMsg,
    pos: Option<TemplatePositionData>,
    info: Option<Box<TemplateInfo>>, // Box because otherwise clippy complains about Result size
}

#[derive(Debug, Clone)]
struct TemplateInfo {
    input: String,
    newlines: Vec<usize>,
    last_modified: SystemTime,
}

impl TemplateError {
    fn new(typ: TemplateErrorMsg, pos: TemplatePositionData) -> TemplateError {
        TemplateError {
            typ,
            pos: Some(pos),
            info: None,
        }
    }

    fn no_info(typ: TemplateErrorMsg) -> Self {
        Self {
            typ,
            pos: None,
            info: None,
        }
    }
    fn only_file(typ: TemplateErrorMsg, file: &str) -> Self {
        Self {
            typ,
            pos: Some(TemplatePositionData {
                file: file.to_owned(),
                span: None,
            }),
            info: None,
        }
    }

    fn render_error(&self, error_template: Option<&Template>) -> String {
        let (file_info, code_snippet) = self.render_error_info();

        if let Some(error_template) = error_template {
            let mut context = Context::new();

            context.insert_global("hotreload", cfg!(debug_assertions).to_template_value());
            context.insert_global("file", file_info.to_template_value());
            context.insert_global("code_snippet", code_snippet.to_template_value());
            context.insert_global("error_msg", self.typ.to_string().to_template_value());

            error_template.render(&context).expect("needs to work")
        } else {
            format!("{file_info}\n{code_snippet}")
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

                let file_str = format!("{}:{}:{}", pos.file, start_pos.line, start_pos.column,);
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
            " ".repeat(start_col),
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

#[derive(Debug, Clone)]
enum TemplateErrorMsg {
    VariableNotFound(String),
    FieldNotFoundOnVariable(String, String),
    NodeNotOfExpectedType(String, TemplateNodeKind),
    VariableNotOfExpectedType(String, TemplateValueKind),
    UnexpectedToken(TemplateTokenTyp, TemplateTokenTyp),
    DidNotExpectToken(TemplateTokenTyp),
    UnexpectedTokenOptions(TemplateTokenTyp, Vec<TemplateTokenTyp>),
    GenericError(String),
    MultiLevelForLoopBind(Vec<String>),
    UnexpectedTemplateValueType(TemplateNodeKind, TemplateNodeKind),
    CantCompareTemplateValues(TemplateValueKind, TemplateValueKind),
    CantCompareWithLiteral(TemplateValueKind),
    ExtendsNotFirstLine,
    UnexpectedEOF,
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

impl TemplateErrorMsg {
    fn kind(&self) -> TemplateErrorKind {
        use TemplateErrorKind::*;
        use TemplateErrorMsg::*;

        match self {
            VariableNotFound(_)
            | FieldNotFoundOnVariable(_, _)
            | NodeNotOfExpectedType(_, _)
            | VariableNotOfExpectedType(_, _)
            | CantCompareTemplateValues(_, _)
            | CantCompareWithLiteral(_) => Render,

            UnexpectedToken(_, _)
            | DidNotExpectToken(_)
            | UnexpectedTokenOptions(_, _)
            | MultiLevelForLoopBind(_)
            | UnexpectedTemplateValueType(_, _)
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
            NodeNotOfExpectedType(node, expected) => {
                write!(
                    f,
                    "{error_kind}: Node '{node}' is not of expected type {expected:?}"
                )
            }
            VariableNotOfExpectedType(var, expected) => {
                write!(
                    f,
                    "{error_kind}: Variable '{var}' is not of expected type {expected:?}"
                )
            }

            UnexpectedToken(found, expected) => {
                write!(
                    f,
                    "{error_kind}: Unexpected token: {found:?}, expected: {expected:?}"
                )
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
            MultiLevelForLoopBind(path) => {
                write!(
                    f,
                    "{error_kind}: For-loop binding must be a single identifier, found '{}'",
                    path.join(".")
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

// === Context ===

#[derive(Debug)]
struct Context {
    global_context: HashMap<String, TemplateValue>,
}

impl Context {
    fn new() -> Self {
        Context {
            global_context: HashMap::new(),
        }
    }

    fn insert_global(&mut self, key: &str, value: TemplateValue) {
        self.global_context.insert(key.to_owned(), value);
    }

    fn lookup_mut(&mut self, key: &str) -> Option<&mut TemplateValue> {
        self.global_context.get_mut(key)
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

trait TemplateContext {
    fn lookup(&self, key: &str) -> Option<&TemplateValue>;
}

impl TemplateContext for Context {
    fn lookup(&self, key: &str) -> Option<&TemplateValue> {
        self.global_context.get(key)
    }
}

struct LocalContext<'a> {
    parent: &'a dyn TemplateContext,
    key: &'a str,
    value: &'a TemplateValue,
}

impl<'a> LocalContext<'a> {
    fn new(parent: &'a dyn TemplateContext, key: &'a str, value: &'a TemplateValue) -> Self {
        Self { parent, key, value }
    }
}

impl TemplateContext for LocalContext<'_> {
    fn lookup(&self, key: &str) -> Option<&TemplateValue> {
        if self.key == key {
            Some(self.value)
        } else {
            self.parent.lookup(key)
        }
    }
}

// === Content ===

#[derive(Debug)]
struct Content {
    assets: Trie<Asset>,
    templates: HashMap<String, Result<Template, TemplateError>>,
}

impl Content {
    fn load_embedded() -> Self {
        #[cfg(generated)]
        let assets = load_embedded_assets();
        #[cfg(generated)]
        let templates = load_embedded_templates();
        #[cfg(not(generated))]
        // Stub to make the compiler happy
        let assets = Trie::new();
        #[cfg(not(generated))]
        let templates = HashMap::new();
        // assets
        Self { assets, templates }
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

            for (key, template_res) in &mut self.templates {
                match template_res {
                    Ok(template) => {
                        if template.origin_file == path_str {
                            is_new = false;
                            if template.last_modified < last_modified {
                                Template::update_from_path(template_res, path);
                                changed = true;

                                println!("Updated template {:?}, for page: {key:?}", path_str,);
                            }
                        }
                    }
                    Err(template_err) => {
                        if let Some(pos) = &template_err.pos
                            && let Some(info) = &template_err.info
                            && pos.file == path_str
                        {
                            is_new = false;
                            if info.last_modified < last_modified {
                                Template::update_from_path(template_res, path);
                                changed = true;

                                println!("Updated template {:?}, for page: {key:?}", path_str,);
                            }
                        }
                    }
                }
            }

            if is_new {
                let template = Template::from_path(path)?;
                println!("Added template {path_str:?}");
                self.templates.insert(path_str.to_string(), Ok(template));
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
                        key_path.to_string(),
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

#[derive(Clone, Debug)]
struct Asset {
    last_modified: SystemTime,
    data: AssetData,
    internal: bool,
}

impl Asset {
    // Used by build script
    #[allow(unused)]
    fn new(content: AssetData) -> Self {
        Self {
            last_modified: SystemTime::now(),
            data: content,
            internal: false,
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

#[derive(Clone, Debug)]
enum AssetData {
    Text(String),
    Html(String),
    Css(String),
    Js(String),
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
            Some("js") => AssetData::Js(fs::read_to_string(path)?),
            _ => AssetData::Unknown(fs::read_to_string(path)?),
        };
        Ok(content)
    }

    fn typ(&self) -> &str {
        match self {
            AssetData::Html(_) => "text/html; charset=utf-8",
            AssetData::Css(_) => "text/css",
            AssetData::Js(_) => "text/javascript",
            AssetData::Png(_) => "image/png",
            AssetData::Ico(_) => "image/ico",
            AssetData::Woff2(_) => "font/woff2",
            AssetData::MdParsed(_) => "text/html; charset=utf-8",
            AssetData::Text(_) | AssetData::MdRaw(_) | AssetData::Unknown(_) => {
                "text/plain; charset=utf-8"
            }
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
            | AssetData::MdRaw(s)
            | AssetData::MdParsed(ParsedMarkdown { html: s, .. })
            | AssetData::Unknown(s) => s.as_bytes(),
            AssetData::Empty => &[],
        }
    }
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

        for component in PathBuf::from(&path).components() {
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
            result.push((path.to_owned(), asset));
        }

        for (key, child) in &mut node.children {
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
            }
            println!("Removed file {path:?}");
            changed |= self.remove(path);
        }
        self.paths = current_paths_set;

        changed
    }

    fn len(&self) -> usize {
        self.paths.len()
    }
}

// === Template lexer
struct TemplateLexer<'a> {
    file_path: &'a str,
    input: &'a str,
    newlines: Vec<usize>,
}

type LookupTable<'a> = &'a [(&'a str, fn(Span) -> TemplateToken)];

impl<'a> TemplateLexer<'a> {
    fn lex(file_path: &'a str, input: &'a str) -> TemplateParser<'a> {
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

                cursor += 1;
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
            required_variables: vec![],
            tokens,
            cursor: 0,
        }
    }

    fn lex_code(&mut self, start: usize, end: usize) -> Vec<TemplateToken> {
        use TemplateToken::*;

        const KEYWORDS: LookupTable = &[
            ("endBlock", EndBlock),
            ("endElse", EndElse),
            ("extends", Extends),
            ("endFor", EndFor),
            ("endIf", EndIf),
            ("block", Block),
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
                Self::flush_ident(&mut tokens, start_ident, cursor);

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
                    if let Some(c) = input[keyword_end..].chars().next()
                        && c != ' '
                        && c != '\n'
                        && c != '{'
                        && c != '}'
                    {
                        return None;
                    }

                    Some((make_token, keyword_end))
                })
            {
                Self::flush_ident(&mut tokens, start_ident, cursor);

                tokens.push(make_token(Span::from_double(cursor, keyword_end)));
                cursor = keyword_end;
                start_ident = cursor;
            } else {
                cursor += 1;
            }
        }
        Self::flush_ident(&mut tokens, start_ident, end);

        tokens
    }

    fn flush_ident(tokens: &mut Vec<TemplateToken>, start: usize, end: usize) {
        if start < end && start > 0 {
            tokens.push(TemplateToken::Identifier(Span::from_double(start, end)));
        }
    }
}

// === Template parser

struct TemplateParser<'a> {
    file_path: &'a str,
    input: &'a str,
    newlines: Vec<usize>,
    blocks: HashMap<String, Vec<TemplateNode>>,
    required_variables: Vec<Vec<String>>,
    tokens: Vec<TemplateToken>,
    cursor: usize,
}

impl TemplateParser<'_> {
    fn parse(input: &str, file_path: &str) -> Result<Template, TemplateError> {
        let mut parser = TemplateLexer::lex(file_path, input);

        let parent = parser.parse_parent();
        let template = parser.parse_until(&[])?;
        Ok(Template {
            template,
            parent,
            blocks: parser.blocks,
            required_variables: parser.required_variables,
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
        use TemplateToken::*;

        let start_span = self.next_token()?.span().start - 1;

        let mut ident = Vec::new();

        let input = self.input;

        loop {
            let span = self.consume(TemplateTokenTyp::Identifier)?;

            ident.push(span.to_str(input).to_owned());
            let end_span = span.end - 1;
            if let Some(Dot(_)) = self.tokens.get(self.cursor) {
                self.consume(TemplateTokenTyp::Dot)?;
            } else {
                self.required_variables.push(ident.clone());
                return Ok(TemplateNode {
                    data: TemplateNodeData::Variable(ident),
                    pos: self.span_to_position(&Span::from_double(start_span, end_span)),
                });
            }
        }
    }

    fn parse_for(&mut self) -> Result<TemplateNode, TemplateError> {
        use TemplateTokenTyp::*;
        let start_tok = self.consume(For)?;
        let whitespace_tok = self.consume(Whitespace)?;

        let node = self.parse_var()?;
        let node_span = node.pos.span.expect("msg");
        let bind = if let TemplateNodeData::Variable(var) = node.data {
            if var.len() == 1
                && let Some(bind) = var.first()
            {
                bind.to_string()
            } else {
                return Err(self.error(
                    TemplateErrorMsg::MultiLevelForLoopBind(var),
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

        // Self::show_next_n_tokens(tokens, 3);
        let body: Vec<TemplateNode> = self.parse_until(&[EndFor])?;
        let end_tok = self.consume(EndFor)?;

        Ok(TemplateNode {
            data: TemplateNodeData::For {
                iter_bind: bind,
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
        let ident_node = self.parse_var()?;
        let ident = match ident_node.data {
            ref node @ TemplateNodeData::Variable(ref var) if var.len() > 1 => {
                return Err(self.error(
                    TemplateErrorMsg::GenericError(format!(
                        "blocks can only contain single level identifiers {node}"
                    )),
                    ident_node.pos,
                ));
            }
            TemplateNodeData::Variable(var) => var.first().expect("invariant").clone(),
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

// Markdown parser

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
            .map_or(input.len(), |i| cursor + i);

        let first_line = &input[cursor..first_line_end];

        assert!(
            first_line.starts_with("::::"),
            "markdown must have metadata"
        );

        cursor = if first_line_end < input.len() {
            first_line_end + 1
        } else {
            first_line_end
        };

        let mut metadata_lines = vec![];

        loop {
            let line_end = input[cursor..]
                .find('\n')
                .map_or(input.len(), |i| cursor + i);

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
            slug: slug.unwrap_or(title_str.replace(' ', "-").to_lowercase()),
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

        if value.is_empty() {
            None
        } else {
            Some(value.to_string())
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

    HeadingMarker(Span),
    BlockQuoteMarker(Span),
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

    HeadingMarker(usize),
    BlockQuoteMarker(usize),
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
        use MarkdownToken::*;
        match self {
            NewLine(_) => MarkdownTokenTyp::NewLine,
            BracketOpen(_) => MarkdownTokenTyp::BracketOpen,
            BracketClose(_) => MarkdownTokenTyp::BracketClose,
            ParenOpen(_) => MarkdownTokenTyp::ParenOpen,
            ParenClose(_) => MarkdownTokenTyp::ParenClose,
            HeadingMarker(span) => MarkdownTokenTyp::HeadingMarker(span.len()),
            BlockQuoteMarker(span) => MarkdownTokenTyp::BlockQuoteMarker(span.len()),
            Whitespace(span) => MarkdownTokenTyp::Whitespace(span.len()),
            Asterisk(span) => MarkdownTokenTyp::Asterisk(span.len()),
            Underscore(span) => MarkdownTokenTyp::Underscore(span.len()),
            Backtick(span) => MarkdownTokenTyp::Backtick(span.len()),
            Dash(span) => MarkdownTokenTyp::Dash(span.len()),
            Tilde(span) => MarkdownTokenTyp::Tilde(span.len()),
            Plus(span) => MarkdownTokenTyp::Plus(span.len()),
            Exclamation(span) => MarkdownTokenTyp::Exclamation(span.len()),
            TextRaw(_) => MarkdownTokenTyp::TextRaw,
        }
    }

    fn span(&self) -> &Span {
        use MarkdownToken::*;
        match self {
            NewLine(span)
            | BracketOpen(span)
            | BracketClose(span)
            | ParenOpen(span)
            | ParenClose(span)
            | HeadingMarker(span)
            | BlockQuoteMarker(span)
            | Whitespace(span)
            | Asterisk(span)
            | Underscore(span)
            | Backtick(span)
            | Dash(span)
            | Tilde(span)
            | Plus(span)
            | Exclamation(span)
            | TextRaw(span) => span,
        }
    }

    fn start(&self) -> usize {
        self.span().start
    }

    fn end(&self) -> usize {
        self.span().end
    }
}

#[derive(Debug, PartialEq, Clone)]
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

    fn to_line<'a>(&self, input: &'a str, newlines: &[usize]) -> &'a str {
        let line_start = match newlines.partition_point(|&newline| newline < self.start) {
            0 => 0,
            index => newlines[index - 1] + 1,
        };

        let line_end = match newlines.partition_point(|&newline| newline < self.end) {
            index if index < newlines.len() => newlines[index] - 1,
            _ => input.len(),
        };

        &input[line_start..line_end]
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

        let blocks: Vec<MarkdownBlock<'_>> = Self::parse_blocks(&lex, markdown_input);
        let ast = Self::parse_block_content(&blocks, markdown_input);
        let highlighted_langs = Self::get_highlighted_langs(&blocks);
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
                MarkdownBlock::CodeBlock {
                    language: Some(language),
                    ..
                } => langs.push(*language),
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

                '#' | '-' | ' ' | '_' | '+' | '>' | '`' | '*' | '~' => {
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

            if content.is_empty() {
                None
            } else {
                Some((
                    CodeBlock {
                        language: language.and_then(SyntaxHighlightLang::from_str),
                        content,
                    },
                    rest,
                ))
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
            let Some(line) = MarkdownListLine::parse_line(line, input) else {
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

    fn parse_quote(
        mut tokens: &'_ [MarkdownToken],
    ) -> Option<(MarkdownBlock<'_>, &[MarkdownToken])> {
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
        let Some(split) = tokens.iter().position(|token| token.typ() == until) else {
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

    fn tokens_to_string<'a>(tokens: &'a [MarkdownToken], input: &'a str) -> Vec<&'a str> {
        let Some(first) = tokens.first() else {
            return Vec::new();
        };

        let last = tokens.last().expect("invariant");
        let content = &input[first.start()..last.end()];

        content.split('\n').collect()
    }

    fn parse_block_content<'a>(blocks: &'a [MarkdownBlock], input: &'a str) -> MarkdownNode<'a> {
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
                MarkdownBlock::_Table { .. } => {
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
                [Underscore(open), _] if open.len() == 1 && Self::delimiter_can_open(tokens) => {
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
                [Asterisk(open), _] if open.len() == 1 && Self::delimiter_can_open(tokens) => {
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
                [Tilde(open), _] if open.len() == 1 && Self::delimiter_can_open(tokens) => {
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
                        tokens = after;
                    } else {
                        nodes.push(Text(count.to_str(input)));
                        tokens = after;
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

                for n in text.iter() {
                    Self::html_helper(n, builder);
                }
                builder.push_str("</a>");
            }
            MarkdownNode::Image { alt, path } => {
                builder.push_str("<img class=\"image\" src=\"");
                builder.push_str(path);
                // builder.push_str(" alt=\"");
                // builder.push_str(alt);
                // builder.push_str("\"");
                builder.push('>');
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

// === Database ===

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
    fn sqlite3_reset(statement_handle: *mut sqlite3_stmt) -> c_int;
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
    fn bind_all(&self, binds: &[Bind]) -> Result<(), Box<dyn Error>> {
        for (i, bind) in binds.iter().enumerate() {
            bind.apply(self, i)?;
        }
        Ok(())
    }

    fn reset_binds(&self) -> Result<(), Box<dyn Error>> {
        let status = unsafe { sqlite3_reset(self.handle) };

        match status {
            SQLITE_OK => Ok(()),
            code => Err(format!(
                "sqlite3_step failed with code {}",
                Connection::to_sqlite_err(code, None)
            )
            .into()),
        }
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
            SQLITE_OK => Ok(()),
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

        let status = unsafe { sqlite3_open(c_string.as_ptr(), &raw mut handle) };

        match status {
            SQLITE_OK => Ok(Self { handle }),
            code => Err(format!("Opening db at {path} failed with code {code}").into()),
        }
    }

    fn transaction<F>(&self, query_fn: F) -> Result<(), Box<dyn Error>>
    where
        F: FnOnce() -> Result<(), Box<dyn Error>>,
    {
        self.execute("BEGIN TRANSACTION;")?;

        match query_fn() {
            Ok(()) => {
                self.execute("COMMIT;")?;
                Ok(())
            }
            Err(error) => {
                let _ = self.execute("ROLLBACK;");
                Err(error)
            }
        }
    }

    fn transaction_multi<F>(&self, query_fns: Vec<F>) -> Result<(), Box<dyn Error>>
    where
        F: FnOnce() -> Result<(), Box<dyn Error>>,
    {
        self.execute("BEGIN TRANSACTION;")?;

        for query in query_fns {
            match query() {
                Ok(()) => continue,
                Err(error) => {
                    self.execute("ROLLBACK;")?;
                    return Err(error);
                }
            }
        }

        self.execute("COMMIT;")?;
        Ok(())
    }
    fn prepare(&self, sql: &str) -> Result<Statement, Box<dyn Error>> {
        let sql = CString::new(sql)?;
        let mut statement_handle: *mut sqlite3_stmt = null_mut();

        let status = unsafe {
            sqlite3_prepare_v2(
                self.handle,
                sql.as_ptr(),
                -1,
                &raw mut statement_handle,
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

        if statement.step()? {
            Err("execute unexpectedly returned a row".into())
        } else {
            Ok(())
        }
    }

    fn insert(&self, sql: &str, binds: &[Bind]) -> Result<(), Box<dyn Error>> {
        let mut statement = self.prepare(sql)?;
        statement.bind_all(binds)?;

        if statement.step()? {
            Err(format!("insertion unexpectedly returned a row {sql}").into())
        } else {
            Ok(())
        }
    }

    fn insert_rows(&self, sql: &str, multi_binds: Vec<Vec<Bind>>) -> Result<(), Box<dyn Error>> {
        self.transaction(|| self.insert_rows_unchecked(sql, multi_binds))
    }

    fn insert_rows_unchecked(
        &self,
        sql: &str,
        multi_binds: Vec<Vec<Bind>>,
    ) -> Result<(), Box<dyn Error>> {
        let mut statement = self.prepare(sql)?;

        for binds in multi_binds {
            statement.bind_all(&binds)?;

            if statement.step()? {
                return Err(format!("insertion unexpectedly returned a row {sql}").into());
            }

            statement.reset_binds()?;
        }
        Ok(())
    }

    fn querry(
        &self,
        sql: &str,
        binds: &[Bind],
        return_typ: &[ColumnTyp],
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
    fn serialize(&self) -> Vec<u8> {
        let serialized_db_size = &mut 0;
        let flags = 0;

        unsafe {
            let serialized_db_ptr =
                sqlite3_serialize(self.handle, null(), serialized_db_size, flags);

            let bytes =
                slice::from_raw_parts(serialized_db_ptr.cast(), (*serialized_db_size) as usize)
                    .to_vec();

            sqlite3_free(serialized_db_ptr.cast_mut().cast());
            bytes
        }
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

        match status {
            SQLITE_OK => Ok(conn),
            code => Err(format!(
                "Deserializing db failed with code {}",
                Self::to_sqlite_err(code, None)
            )
            .into()),
        }
    }

    fn export_db_serialized(&self, path: PathBuf) -> Result<(), Box<dyn Error>> {
        let bytes = self.serialize();

        println!(
            "Exported db of size {} to {path:?}",
            Blob::pretty_bytes(bytes.len())
        );
        fs::write(path, bytes)?;
        Ok(())
    }

    fn import_db(path: PathBuf) -> Result<Connection, Box<dyn Error>> {
        let bytes = fs::read(&path)?;

        let conn = Connection::deserialize(&bytes)?;
        println!(
            "Imported db of size {} from {path:?}",
            Blob::pretty_bytes(bytes.len())
        );

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

        let blob_len = usize::from_le_bytes(bytes[length_offset..magic_offset].try_into()?);

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

        let blob_len = usize::from_le_bytes(bytes[length_offset..magic_offset].try_into()?);

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
        let serialized = conn.serialize();

        Blob::write_blob(bytes, &serialized)?;

        let tmp = path.with_extension("tmp");

        fs::write(&tmp, bytes)?;

        let perms = fs::metadata(path)?.permissions();
        fs::set_permissions(&tmp, perms)?;

        // renames the executable, doesnt affect the currently running process
        fs::rename(&tmp, path)?;

        let end_time = start_time.elapsed();
        println!(
            "Serialized db into {} bytes in {:?}",
            Self::pretty_bytes(serialized.len()),
            end_time
        );

        Ok(())
    }

    fn pretty_bytes(bytes: usize) -> String {
        const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];

        if bytes < 1024 {
            return format!("{bytes} B");
        }

        let exponent = ((bytes as f64).log2() / 10.0).floor() as usize;
        let exponent = exponent.min(UNITS.len() - 1);
        let value = bytes as f64 / 1024_f64.powi(exponent as i32);

        format!("{value:.2} {}", UNITS[exponent])
    }
}

#[derive(Debug)]
struct Db {
    connection: Connection,
    executable_bytes: Vec<u8>,
    executable_path: PathBuf,
    unsynced: bool,
    metric_cache: Vec<CachedPageHit>,
}

impl Db {
    fn init() -> Result<Self, Box<dyn Error>> {
        let current_executable_path = env::current_exe()?;

        let executable_bytes = fs::read(&current_executable_path)?;

        let conn = match Blob::read_blob(&executable_bytes)? {
            Some(blob) => {
                let conn = Connection::deserialize(blob)?;
                println!(
                    "Blob of length {} found in own binary and serialized into db",
                    Blob::pretty_bytes(blob.len())
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
                        Blob::pretty_bytes(blob.len())
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
            unsynced: true,
            metric_cache: vec![],
        };
        db.sync()?;
        Ok(db)
    }

    fn sync(&mut self) -> Result<(), Box<dyn Error>> {
        if !self.metric_cache.is_empty() {
            self.sync_metric_cache()?;
        }

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
            &[Bind::Int(0)],
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
          CREATE TABLE page_metrics_aggregate (
            page TEXT PRIMARY KEY,
            total_load_time INTEGER,
            total_hits INTEGER
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

        let res = conn.querry("SELECT count FROM counter", &[], &[ColumnTyp::Int])?;

        let counter_col = res.get_int_column(0).unwrap();
        let counter = *counter_col.first().unwrap();

        println!("Counter: {counter:?}");

        conn.insert(
            "
            UPDATE counter
            SET count = ?;",
            &[Bind::Int(counter + 1)],
        )?;
        self.unsynced = true;
        Ok(())
    }

    fn save_page_hit(&mut self, page: &str, loadtime: Duration) -> Result<(), Box<dyn Error>> {
        let timestamp = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs()
            .cast_signed();

        let loadtime_nanos = i64::from(loadtime.subsec_nanos());

        self.metric_cache.push(CachedPageHit {
            page: page.to_string(),
            loadtime: loadtime_nanos,
            timestamp,
        });
        self.unsynced = true;

        if self.metric_cache.len() >= 1000 {
            self.sync_metric_cache()?;
        }

        Ok(())
    }

    // TODO wrap both inserts into transaction
    fn sync_metric_cache(&mut self) -> Result<(), Box<dyn Error>> {
        let start = Instant::now();
        let conn = &self.connection;

        let multi_binds_metrics = self
            .metric_cache
            .iter()
            .map(|b| {
                vec![
                    Bind::Text(&b.page),
                    Bind::Int(b.loadtime),
                    Bind::Int(b.timestamp),
                ]
            })
            .collect();

        let mut sorted: Vec<_> = self.metric_cache.iter().collect();
        sorted.sort_unstable_by(|a, b| a.page.cmp(&b.page));

        let aggregates =
            sorted
                .into_iter()
                .fold(Vec::<(&str, i64, i64)>::new(), |mut aggregates, hit| {
                    match aggregates.last_mut() {
                        Some((page, total_load_time, total_hits)) if *page == hit.page.as_str() => {
                            *total_load_time += hit.loadtime;
                            *total_hits += 1;
                        }

                        _ => aggregates.push((hit.page.as_str(), hit.loadtime, 1)),
                    }

                    aggregates
                });

        let multi_binds_metrics_aggregate = aggregates
            .iter()
            .map(|b| vec![Bind::Text(b.0), Bind::Int(b.1), Bind::Int(b.2)])
            .collect();

        conn.transaction(|| {
            conn.insert_rows_unchecked(
                "INSERT INTO page_metrics (page, load_time, timestamp) VALUES (?,?,?)",
                multi_binds_metrics,
            )?;
            conn.insert_rows_unchecked(
                "
                INSERT INTO page_metrics_aggregate (
                  page,
                  total_load_time,
                  total_hits
                )
                VALUES (?, ?, ?)
                ON CONFLICT(page)
                  DO UPDATE SET
                    total_load_time = total_load_time + excluded.total_load_time,
                    total_hits = total_hits + excluded.total_hits;",
                multi_binds_metrics_aggregate,
            )
        })?;

        let metric_entries = self.metric_cache.len();
        self.metric_cache = vec![];
        self.unsynced = true;
        let duration = start.elapsed();
        // println!("Synced {metric_entries} entries in metric cache in {duration:?}",);

        Ok(())
    }

    fn load_stats(&self) -> Result<Stats, Box<dyn Error>> {
        let conn = &self.connection;

        let res = conn.querry(
            "
              SELECT start_time
              FROM global_stats",
            &[],
            &[ColumnTyp::Text],
        )?;
        let col = res.get_text_column(0)?;
        let start_time = (*col.first().ok_or("Start time not found")?).to_string();

        let res = conn.querry(
            "
                SELECT page, total_load_time, total_hits
                FROM page_metrics_aggregate",
            &[],
            &[ColumnTyp::Text, ColumnTyp::Int, ColumnTyp::Int],
        )?;

        let pages = res.get_text_column(0)?;
        let total_loadtimes = res.get_int_column(1)?;
        let counts = res.get_int_column(2)?;

        let mut metrics_by_page: HashMap<&str, (i64, i64)> = HashMap::new();

        for (page, (total_loadtime, count)) in zip(pages, zip(total_loadtimes, counts)) {
            metrics_by_page.insert(page, (total_loadtime, count));
        }

        for hit in &self.metric_cache {
            if let Some(entry) = metrics_by_page.get_mut(hit.page.as_str()) {
                entry.0 += hit.loadtime;
                entry.1 += 1;
            } else {
                metrics_by_page.insert(&hit.page, (hit.loadtime, 1));
            }
        }

        let mut metrics: Vec<PageMetric> = metrics_by_page
            .into_iter()
            .map(|(page, (total_loadtime, count))| {
                let average_nanos = total_loadtime / count;

                PageMetric {
                    page: page.to_owned(),
                    avg_loadtime: Duration::from_nanos(average_nanos as u64),
                    count: count as u64,
                }
            })
            .collect();

        metrics.sort_unstable_by(|a, b| a.avg_loadtime.cmp(&b.avg_loadtime));
        Ok(Stats {
            pages: metrics,
            start_time,
        })
    }

    fn import_db(path: PathBuf) -> Result<(), Box<dyn Error>> {
        let executable_path = env::current_exe()?;

        let executable_bytes = fs::read(&executable_path)?;

        let connection = Connection::import_db(path)?;
        let mut db = Db {
            connection,
            executable_bytes,
            executable_path,
            unsynced: true,
            metric_cache: vec![],
        };

        db.sync()?;
        Ok(())
    }

    fn export_db_serialized(&mut self, path: PathBuf) -> Result<(), Box<dyn Error>> {
        self.connection.export_db_serialized(path)?;
        self.sync()
    }
    fn export_db(&self, path: &PathBuf) -> Result<(), Box<dyn Error>> {
        if path.exists() {
            return Err(format!("Path {path:?} already exists").into());
        }
        let path_str = path.to_string_lossy();
        self.connection
            .insert("VACUUM INTO ?;", &[Bind::Text(&path_str)])
    }
}

#[derive(Debug, Clone)]
struct CachedPageHit {
    page: String,
    loadtime: i64,
    timestamp: i64,
}

#[derive(Debug)]
struct Stats {
    start_time: String,
    pages: Vec<PageMetric>,
}

#[derive(Debug)]
struct PageMetric {
    page: String,
    avg_loadtime: Duration,
    count: u64,
}

// === Utils ===

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
                }
                let file_path = file.path();
                asset_paths.push(file_path);
            }
        }
    }
    asset_paths
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
        let merged =
            u32::from(bytes[i]) << 16 | u32::from(bytes[i + 1]) << 8 | u32::from(bytes[i + 2]);

        encoded.push(BASE64_CONVERSION[((merged >> 18) & 0b111111) as usize]);
        encoded.push(BASE64_CONVERSION[((merged >> 12) & 0b111111) as usize]);
        encoded.push(BASE64_CONVERSION[((merged >> 6) & 0b111111) as usize]);
        encoded.push(BASE64_CONVERSION[(merged & 0b111111) as usize]);
        i += 3;
    }

    match bytes.len() - i {
        2 => {
            let merged = u32::from(bytes[i]) << 16 | u32::from(bytes[i + 1]) << 8;

            encoded.push(BASE64_CONVERSION[((merged >> 18) & 0b111111) as usize]);
            encoded.push(BASE64_CONVERSION[((merged >> 12) & 0b111111) as usize]);
            encoded.push(BASE64_CONVERSION[((merged >> 6) & 0b111111) as usize]);
            encoded.push('=');
        }
        1 => {
            let merged = u32::from(bytes[i]) << 16;

            encoded.push(BASE64_CONVERSION[((merged >> 18) & 0b111111) as usize]);
            encoded.push(BASE64_CONVERSION[((merged >> 12) & 0b111111) as usize]);
            encoded.push('=');
            encoded.push('=');
        }
        _ => {}
    }

    encoded
}

// Inspired by:
// https://en.wikipedia.org/wiki/SHA-1
// https://www.thespatula.io/rust/rust_sha1/
fn sha1(input: &str) -> [u8; 20] {
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
            words[i] = (u32::from(chunk[4 * i]) << 24)
                | (u32::from(chunk[4 * i + 1]) << 16)
                | (u32::from(chunk[4 * i + 2]) << 8)
                | (u32::from(chunk[4 * i + 3]));
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
