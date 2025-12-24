use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::{Duration, SystemTime};
use std::{fs, thread};

const SOCKET_ADDR: &str = "127.0.0.1:4000";
const ASSETS_PATH: &str = "./assets/";

fn main() {
    let listener = TcpListener::bind(SOCKET_ADDR).unwrap();
    println!("Started listening on socket {SOCKET_ADDR}");

    let assets = Arc::new(Mutex::new(HashMap::new()));

    let changed = AtomicBool::new(false);
    #[cfg(debug_assertions)]
    {
        hot_reloading(assets.clone(), ASSETS_PATH, changed);
    }

    for stream in listener.incoming() {
        let handle_asset_map = assets.clone();
        thread::spawn(|| {
            let _ = handle_stream(stream.unwrap(), handle_asset_map);
        });
    }
}

fn handle_stream(mut stream: TcpStream, asset_map: Arc<Mutex<HashMap<PathBuf, Asset>>>) -> Result<(), io::Error> {
    let peer_ip = stream.peer_addr()?;
    println!("[{peer_ip}] Connected");

    let mut buffer: [u8; 8192] = [0; 8192]; // 8kb buffer

    let connection_is_http = true;

    loop {
        let n = stream.read(&mut buffer)?;
        // println!("{:?}", &buffer[..n]);
        if connection_is_http {
            if let Some(pos) = buffer[..n].windows(4).position(|window| window == b"\r\n\r\n") {
                let header_str = String::from_utf8_lossy(&buffer[..pos]);
                let body_str = String::from_utf8_lossy(&buffer[pos + 4..n]);
                let header = parse_header(header_str.to_string())?;
                println!(
                    "[{peer_ip}] Received {:?} request for {:?} of length {}",
                    header.typ,
                    header.path,
                    body_str.len()
                );

                let response = handle_request(header, &body_str, asset_map.clone());
                let _ = stream.write(&response);
                let _ = stream.flush();
            }
        } else {
            // Connection is websocket
            let response = vec![];
            let _ = stream.write(&response);
            let _ = stream.flush();
        }
    }
}

fn handle_request(header: HttpRequestHeader, _body: &str, asset_map: Arc<Mutex<HashMap<PathBuf, Asset>>>) -> Vec<u8> {
    match header.path.as_str() {
        "/ws" => upgrade_websocket(header),
        _ => {
            let asset = match header.typ {
                HttpRequestType::GET => {
                    let key = PathBuf::from(format!("./assets{}", header.path));
                    // println!("{key:?}");
                    asset_map.lock().unwrap().get(&key).cloned()
                }
            };
            if let Some(asset) = asset {
                build_response(HttpResponseCode::Ok, asset.asset_typ, asset.content)
            } else {
                let body = Content::Text(format!("resource at {} not found", header.path));
                build_response(HttpResponseCode::NotFound, ContentType::Text, body)
            }
        }
    }
}

fn upgrade_websocket(header: HttpRequestHeader) -> Vec<u8> {
    println!("upgrading connection to websocket");
    if let Some(_) = header.upgrade
        && let Some(sec_websocket_key) = header.sec_websocket_key
        && let Some(_) = header.sec_websocket_version
    {
        let magic_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        let websocket_accept = base64(&sha1(format!("{sec_websocket_key}{magic_string}")));
        format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {websocket_accept}\r\n\r\n")
            .as_bytes()
            .to_vec()
    } else {
        build_response(
            HttpResponseCode::BadRequest,
            ContentType::Text,
            Content::Text("Invalid websocket upgrade request".to_owned()),
        )
    }
}

fn build_response(code: HttpResponseCode, content_typ: ContentType, content: Content) -> Vec<u8> {
    let status = match code {
        HttpResponseCode::Ok => "200 Ok",
        HttpResponseCode::NotFound => "404 Not Found",
        HttpResponseCode::BadRequest => "400 Bad Request",
    };

    let content_typ = match content_typ {
        ContentType::Text => "text/plain",
        ContentType::Html => "text/html",
        ContentType::Css => "text/css",
        ContentType::Js => "text/javascript",
        ContentType::Unknown => "text/plain",
        ContentType::Png => "image/png",
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

#[derive(Clone, Debug)]
enum ContentType {
    Text = 1,
    Html = 2,
    Css = 3,
    Js = 4,
    Png = 5,
    Unknown = 6,
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
}

#[derive(Debug)]
#[allow(clippy::upper_case_acronyms)]
enum HttpRequestType {
    GET,
}

fn parse_header(header_str: String) -> Result<HttpRequestHeader, io::Error> {
    let mut lines = header_str.lines();

    let first_line = lines.next().unwrap();
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

    for line in lines {
        if let Some((key, value)) = line.split_once(':') {
            let value = value.to_string();
            match key.to_ascii_lowercase().as_str() {
                "origin" => origin = Some(value),
                "sec-websocket-key" => sec_websocket_key = Some(value),
                "sec-websocket-version" => sec_websocket_version = Some(value),
                "user-agent" => user_agent = Some(value),
                "upgrade" => upgrade = Some(value),
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
    })
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

type AssetPath = PathBuf;

#[derive(Clone, Debug)]
struct Asset {
    last_modified: SystemTime,
    content: Content,
    asset_typ: ContentType,
}

#[derive(Clone, Debug)]
enum Content {
    Binary(Vec<u8>),
    Text(String),
}

fn hot_reloading(asset_map: Arc<Mutex<HashMap<AssetPath, Asset>>>, dir_path: &'static str, changed: AtomicBool) {
    let _handle = thread::spawn(move || {
        loop {
            let rootdir: PathBuf = PathBuf::from(dir_path);

            let mut asset_file_paths = HashSet::new();

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
                        && let Ok(last_edited) = metadata.accessed()
                    {
                        if metadata.is_dir() {
                            stack.push(file.path());
                            continue;
                        };
                        let file_path = file.path();

                        let asset_typ = match file_path.extension().and_then(|s| s.to_str()) {
                            Some("html") => ContentType::Html,
                            Some("txt") => ContentType::Text,
                            Some("css") => ContentType::Css,
                            Some("js") => ContentType::Js,
                            Some("png") => ContentType::Png,
                            _ => ContentType::Unknown,
                        };

                        let content = match asset_typ {
                            ContentType::Png | ContentType::Unknown => Content::Binary(fs::read(&file_path).unwrap()),
                            _ => Content::Text(fs::read_to_string(&file_path).unwrap()),
                        };

                        asset_file_paths.insert(file_path.clone());

                        if let Some(asset) = asset_map.lock().unwrap().get_mut(&file_path) {
                            if asset.last_modified < last_edited {
                                asset.content = content;
                                asset.last_modified = last_edited;
                                changed.store(true, Ordering::Release);
                                println!(
                                    "Updated file {file_path:?}, edited {:?} minutes ago",
                                    last_edited.elapsed().unwrap().as_secs() / 60
                                );
                            }
                        } else {
                            asset_map.lock().unwrap().insert(
                                file_path.clone(),
                                Asset {
                                    last_modified: last_edited,
                                    content,
                                    asset_typ,
                                },
                            );
                            changed.store(true, Ordering::Release);
                            println!(
                                "Added file {file_path:?}, edited {:?} minutes ago",
                                last_edited.elapsed().unwrap().as_secs() / 60
                            );
                        }
                    }
                }
            }

            let keys_set: HashSet<_> = asset_map.lock().unwrap().keys().cloned().collect();
            let asset_difference = keys_set.difference(&asset_file_paths);
            // println!("{keys_set:?} {asset_file_paths:?} {asset_difference:?}");

            let mut map = asset_map.lock().unwrap();
            for key in asset_difference {
                map.remove(key);
                println!("Removed file {key:?}");
            }

            sleep(Duration::from_millis(100));
        }
    });
}
