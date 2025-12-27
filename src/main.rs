#![feature(tcp_linger)]
#![allow(unexpected_cfgs)]
#![allow(dead_code, unused, unused_mut)]

use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Display, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime};
use std::{fmt, fs, thread, vec};

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
        runtime();
    }
}

fn comptime() {
    println!("cargo:rerun-if-changed=none");
    println!("cargo:rustc-cfg=generated");

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let file_path = Path::new(&out_dir).join("generated.rs");

    let asset_paths = walk_dir(ASSETS_PATH);

    let mut assets_str = String::new();
    assets_str.push_str("fn get_assets() -> HashMap<PathBuf, Asset> {\n");
    assets_str.push_str("\tlet mut assets = HashMap::new();\n");

    for asset_path in asset_paths {
        let path_key = asset_path.to_string_lossy();
        let full_path = format!("{}/{}", std::env::current_dir().expect("current dir").to_string_lossy(), path_key);

        assets_str.push_str(&format!("\tlet path = PathBuf::from(\"{}\");\n", path_key));
        assets_str.push_str(&format!("\tlet asset_typ = AssetType::from_path(&PathBuf::from(\"{}\"));\n", full_path));
        assets_str.push_str(&format!("\tlet content_raw = include_bytes!(\"{}\").to_vec();\n", full_path));
        assets_str.push_str(
            "\tlet content = if asset_typ.is_text() {
                Content::Text(String::from_utf8(content_raw).expect(\"Failed to convert to utf8\"))
            } else {
                Content::Binary(content_raw)
            };\n",
        );
        assets_str.push_str("\tlet asset = Asset { content, asset_typ, last_modified: SystemTime::now()};\n");
        assets_str.push_str("\tassets.insert(path,asset);\n");
    }
    assets_str.push_str("\tassets\n");
    assets_str.push_str("}\n");

    fs::write(&file_path, assets_str).unwrap();
    println!("cargo:warning=End of build script");
}

fn runtime() {
    #[cfg(generated)]
    let assets: Arc<Mutex<HashMap<PathBuf, Asset>>> = Arc::new(Mutex::new(get_assets()));
    #[cfg(not(generated))]
    let assets: Arc<Mutex<HashMap<PathBuf, Asset>>> = Arc::new(Mutex::new(HashMap::new()));

    let listener = TcpListener::bind(SOCKET_ADDR).expect("Unable to bind socket");
    println!("Started listening on socket {SOCKET_ADDR}");

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
                            assets.lock().expect("Cant get lock").get(&key).cloned()
                        }
                    };
                    let response = if let Some(asset) = asset {
                        build_response(HttpResponseCode::Ok, asset.asset_typ, asset.content)
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

#[derive(Clone, Debug)]
enum AssetType {
    Text = 1,
    Html = 2,
    Css = 3,
    Js = 4,
    Png = 5,
    Unknown = 6,
}

impl AssetType {
    fn is_text(&self) -> bool {
        use AssetType::*;
        matches!(self, Text | Html | Css | Js)
    }
    fn from_path(path: &Path) -> AssetType {
        match path.extension().and_then(|s| s.to_str()) {
            Some("html") => AssetType::Html,
            Some("txt") => AssetType::Text,
            Some("css") => AssetType::Css,
            Some("js") => AssetType::Js,
            Some("png") => AssetType::Png,
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
    pub fn len(&self) -> usize {
        match self {
            Content::Binary(bytes) => bytes.len(),
            Content::Text(text) => text.len(),
        }
    }
    fn from_path(path: &Path, content_typ: &AssetType) -> Content {
        match content_typ {
            AssetType::Png | AssetType::Unknown => Content::Binary(fs::read(path).expect("Unable to read file into binary")),
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

fn hot_reloading(asset_map: Arc<Mutex<HashMap<PathBuf, Asset>>>, dir_path: &'static str, changed: Arc<AtomicBool>) {
    let _ = thread::spawn(move || {
        println!("Started file watcher thread");
        loop {
            let asset_paths = walk_dir(dir_path);
            let asset_set: HashSet<PathBuf> = asset_paths.iter().cloned().collect();

            let mut map = asset_map.lock().expect("Unable to acquire lock");
            for path in asset_paths {
                let metadata = match path.metadata() {
                    Ok(m) => m,
                    Err(_) => continue,
                };

                let last_modified = match metadata.modified() {
                    Ok(t) => t,
                    Err(_) => continue,
                };

                match map.get_mut(&path) {
                    Some(existing_asset) => {
                        if last_modified > existing_asset.last_modified {
                            existing_asset.content = Content::from_path(&path, &existing_asset.asset_typ);
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
                        let content_typ = AssetType::from_path(&path);
                        map.insert(
                            path.clone(),
                            Asset {
                                last_modified,
                                content: Content::from_path(&path, &content_typ),
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
            map.retain(|path, _| {
                if asset_set.contains(path) {
                    true
                } else {
                    println!("Removed file {:?}", path);
                    changed.store(true, Ordering::Release);
                    false
                }
            });

            sleep(Duration::from_millis(100));
        }
    });
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
