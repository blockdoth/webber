#![feature(tcp_linger)]
#![allow(unexpected_cfgs)]
#![allow(dead_code, unused, unused_mut)]

use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Display, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime};
use std::{char, fmt, fs, thread, vec};

const SOCKET_ADDR: &str = "127.0.0.1:4000";
const ASSETS_PATH: &str = "./assets/";

#[cfg(generated)]
include!(concat!(env!("OUT_DIR"), "/generated.rs"));

fn main() {
    if std::env::args().any(|arg| arg.contains("build-script-build")) {
        println!("cargo:warning=Running in build script");
        comptime();
    } else {
        println!("Running normally");
        // runtime();

        let html_template = fs::read_to_string("./assets/templates/test.html").expect("Cant find template");

        let template = Template::new(html_template);
        let mut context: HashMap<String, &dyn TemplateValue> = HashMap::new();

        context.insert("body".to_string(), &"");

        let html_string = template.populate(context);
        println!("{html_string}");
    }
}

struct SimpleTemplate {
    html: String,
}

impl SimpleTemplate {
    fn populate(&self, content: Vec<(String, String)>) -> String {
        let mut res = self.html.clone();
        for (key, value) in content {
            res = res.replace(&format!("{{{{{key}}}}}"), &value)
        }
        res
    }
}

trait TemplateValue {
    fn get_field(&self) -> Option<&dyn TemplateValue>;
    fn to_str(&self) -> String;
}

impl TemplateValue for &str {
    fn get_field(&self) -> Option<&dyn TemplateValue> {
        Some(self)
    }

    fn to_str(&self) -> String {
        self.to_string()
    }
}
enum TemplateNode {
    Text(String),
}

struct Template {
    ast: Vec<TemplateNode>,
}

enum TemplateToken {
    Text(&str),
    StartBlock,
    EndBlock,
    Identifier,
    Dot,
    If,
    For,
    In,
}

impl Template {
    fn new(template_str: &str) -> Self {
        let lexed = Self::lex(template_str);

        Template {
            ast: TemplateNode::Text(template_str),
        }
    }

    fn lex(input: &str) -> Vec<TemplateToken> {
        use TemplateNode::*;
        let lexed = vec![];

        let mut cursor = 0;

        let mut in_block = false;
        let mut last_block = 0;

        while cursor < input.len() {
            let rest = input[cursor..];

            if rest.starts_with("{{") {
                cursor += 2;
                lexed.push(StartBlock);

                if !in_block {
                    let prev_text = input[last_block..cursor];
                    lexed.push(Text(prev_text));
                }
                in_block = true;
            }

            if rest.starts_with("}}") {
                cursor += 2;
                lexed.push(StartBlock);
                in_block = false;
            }

            rest
        }

        lexed
    }

    fn populate<'a>(&self, context: HashMap<String, &'a dyn TemplateValue>) -> String {
        String::new()
    }
}

fn comptime() {
    println!("cargo:rerun-if-changed=none");
    println!("cargo:rustc-cfg=generated");

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let file_path = Path::new(&out_dir).join("generated.rs");

    let asset_paths = walk_dir(ASSETS_PATH);

    let mut assets_str = String::new();
    assets_str.push_str("fn get_assets() -> PathTrie {\n");
    assets_str.push_str("\tlet mut assets = PathTrie::new();\n");

    for asset_path in asset_paths {
        let path_key = asset_path.to_string_lossy();
        let full_path = format!("{}/{}", std::env::current_dir().expect("current dir").to_string_lossy(), path_key);

        assets_str.push_str(&format!("\tlet path = PathBuf::from(\"{}\");\n", path_key));
        assets_str.push_str(&format!("\tlet asset_typ = AssetType::from_path(&PathBuf::from(\"{}\"));\n", full_path));
        assets_str.push_str("\tlet content = Content::from_path(&path, &asset_typ);\n");
        assets_str.push_str("\tlet asset = Asset { content, asset_typ, last_modified: SystemTime::now()};\n");
        assets_str.push_str("\tassets.insert(path,asset);\n");
        println!("cargo:warning=Loaded {asset_path:?}");
    }
    assets_str.push_str("\tassets\n");
    assets_str.push_str("}\n");

    fs::write(&file_path, assets_str).unwrap();
    println!("cargo:warning=End of build script");
}

fn runtime() {
    #[cfg(generated)]
    let assets: Arc<Mutex<PathTrie>> = Arc::new(Mutex::new(get_assets()));
    #[cfg(not(generated))]
    let assets: Arc<Mutex<PathTrie>> = Arc::new(Mutex::new(PathTrie::new()));
    println!("Asset count: {:?}", assets.lock().unwrap().len());
    let listener = TcpListener::bind(SOCKET_ADDR).expect("Unable to bind socket");
    println!("Started listening on socket http://{SOCKET_ADDR}");

    let reload_assets = Arc::new(AtomicBool::new(false));
    #[cfg(debug_assertions)]
    {
        hot_reloading(assets.clone(), ASSETS_PATH, reload_assets.clone());
    }

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

            let (header, body) = parse_request(&buffer[..n]).expect("Unable to parse request");

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
                    let response = upgrade_websocket(header);
                    stream.write_all(&response).expect("Failed to write to stream");
                    stream.flush().expect("Failed to flush stream");
                    is_ws = true;
                }
                path => {
                    let asset = match header.typ {
                        HttpRequestType::GET => {
                            let key = PathBuf::from(format!("./assets{}", path));
                            // println!("{key:?}");
                            let guard = assets.lock().expect("Cant get lock");
                            guard.get(&key)
                        }
                    };
                    // println!("{:?}", asset);
                    let response = if let Some(asset) = asset {
                        let response_content = if asset.asset_typ == AssetType::Md
                            && let Content::Text(content) = asset.content
                        {
                            let main_template = {
                                #[cfg(debug_assertions)]
                                let template_path = PathBuf::from("./assets/templates/main-hotreload.html");
                                #[cfg(not(debug_assertions))]
                                let template_path = PathBuf::from("./assets/templates/main.html");

                                let guard = assets.lock().expect("unable to unlock");
                                let asset = guard.get(&template_path).expect("Failed to find main template");

                                match (&asset.asset_typ, asset.content.clone()) {
                                    (AssetType::Html, Content::Text(html)) => SimpleTemplate { html },
                                    _ => panic!("Main template must be html"),
                                }
                            };
                            Content::Text(main_template.populate(vec![("body".to_string(), content)]))
                        } else {
                            asset.content
                        };
                        println!("{:?}", response_content);

                        build_response(HttpResponseCode::Ok, asset.asset_typ, response_content)
                    } else {
                        let body = Content::Text(format!("resource at {} not found", path));
                        build_response(HttpResponseCode::NotFound, AssetType::Text, body)
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
            let should_reload = reload_assets.load(Ordering::Relaxed);

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
                            let _ = send_ws_message(stream, "reload");
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
                    reload_assets.store(false, Ordering::Relaxed);
                }
            }
        }
    }
}

fn upgrade_websocket(header: HttpRequestHeader) -> Vec<u8> {
    if let Some(_) = header.upgrade
        && let Some(sec_websocket_key) = header.sec_websocket_key
        && let Some(_) = header.sec_websocket_version
    {
        let magic_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        let websocket_accept = base64(&sha1(format!("{}{magic_string}", sec_websocket_key.trim())));
        println!("Succeeded");
        format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {websocket_accept}\r\n\r\n")
            .as_bytes()
            .to_vec()
    } else {
        println!("Failed");
        build_response(
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
        let header = parse_header(String::from_utf8_lossy(&buffer[..pos]).to_string()).expect("Unable to parse header");

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

fn parse_header(header_str: String) -> Result<HttpRequestHeader, io::Error> {
    let mut lines = header_str.lines();

    let first_line = lines.next().expect("Unable to get next line");
    let mut first_line_words = first_line.split_ascii_whitespace();

    let request_type = match first_line_words.next() {
        Some("GET") => HttpRequestType::GET,
        invalid => return Err(io::Error::new(io::ErrorKind::InvalidData, format!("invalid request type {invalid:?}"))),
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
    fn from_path(path: &Path, content_typ: &AssetType) -> Content {
        match content_typ {
            AssetType::Png | AssetType::Unknown => Content::Binary(fs::read(path).expect("Unable to read file into binary")),
            AssetType::Md => {
                let markdown = fs::read_to_string(path).expect("Unable read file into string");
                let html = Parser::html(Parser::parse(&markdown));
                Content::Text(html)
            }
            _ => Content::Text(fs::read_to_string(path).expect("Unable read file into string")),
        }
    }
}

fn walk_dir(dir_path: &'static str) -> Vec<PathBuf> {
    let rootdir: PathBuf = PathBuf::from(dir_path);

    let mut asset_paths = vec![];
    let mut stack = vec![rootdir];

    while let Some(dir_path) = stack.pop() {
        let dir = match fs::read_dir(&dir_path) {
            Ok(dir) => dir,
            Err(error) => {
                println!("Error while trying to open asset dir at {dir_path:?}: {error}");
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

fn hot_reloading(asset_map: Arc<Mutex<PathTrie>>, dir_path: &'static str, changed: Arc<AtomicBool>) {
    let _ = thread::spawn(move || {
        println!("Started file watcher thread");
        loop {
            let asset_paths = walk_dir(dir_path);
            let asset_set: HashSet<PathBuf> = asset_paths.iter().cloned().collect();

            let mut map = asset_map.lock().expect("Unable to acquire lock");
            for path in &asset_paths {
                let metadata = match path.metadata() {
                    Ok(m) => m,
                    Err(_) => continue,
                };

                let last_modified = match metadata.modified() {
                    Ok(t) => t,
                    Err(_) => continue,
                };

                match map.get_mut(path) {
                    Some(existing_asset) => {
                        if last_modified > existing_asset.last_modified {
                            existing_asset.content = Content::from_path(path, &existing_asset.asset_typ);
                            existing_asset.last_modified = last_modified;
                            changed.store(true, Ordering::Release);

                            println!(
                                "Updated file {:?}, edited {} minutes ago",
                                path,
                                last_modified.elapsed().unwrap().as_secs() / 60
                            );
                        }
                    }
                    None => {
                        let content_typ = AssetType::from_path(path);
                        map.insert(
                            path.clone(),
                            Asset {
                                last_modified,
                                content: Content::from_path(path, &content_typ),
                                asset_typ: content_typ,
                            },
                        );
                        changed.store(true, Ordering::Release);
                        println!(
                            "Added file {:?}, edited {:?} minutes ago",
                            path,
                            last_modified.elapsed().expect("Unable to get time elapsed").as_secs() / 60
                        );
                    }
                }
            }
            if map.remove_other_than(asset_paths) {
                changed.store(true, Ordering::Release);
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

#[derive(Default, Debug, Clone)]
struct PathTrie {
    root: TrieNode,
    paths: HashSet<PathBuf>,
}

impl PathTrie {
    fn new() -> Self {
        PathTrie {
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

    fn get_mut(&mut self, path: &Path) -> Option<&mut Asset> {
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
    fn remove_other_than(&mut self, current_paths: Vec<PathBuf>) -> bool {
        let current_paths_set: HashSet<PathBuf> = current_paths.into_iter().collect();

        let paths_to_delete: Vec<PathBuf> = self.paths.difference(&current_paths_set).cloned().collect();

        let mut changed = false;

        for path in &paths_to_delete {
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
struct Parser<'a> {
    ast: MarkdownNode<'a>,
}

impl<'a> Parser<'a> {
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
