use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{fs, thread};

const SOCKET_ADDR: &str = "127.0.0.1:4000";
const ASSETS_PATH: &str = "./assets/";
const STATE_PATH: &str = "./state/state";

fn main() {
    let listener = TcpListener::bind(SOCKET_ADDR).unwrap();
    println!("Started listening on socket {SOCKET_ADDR}");

    let asset_map = Arc::new(Mutex::new(match deserialize_asset_map(STATE_PATH) {
        Ok(hm) => {
            println!("Loaded {} assets from state", hm.len());
            for asset in hm.keys() {
                println!("{}", asset.to_string_lossy());
            }
            hm
        }
        Err(err) => {
            println!("Failed to restore state, {err:?}");
            HashMap::new()
        }
    }));

    let watch_asset_map = asset_map.clone();
    let _handle = thread::spawn(|| {
        watch_assets(watch_asset_map, ASSETS_PATH);
    });

    for stream in listener.incoming() {
        let handle_asset_map = asset_map.clone();
        thread::spawn(|| {
            let _ = handle_stream(stream.unwrap(), handle_asset_map);
        });
    }
}

fn handle_stream(mut stream: TcpStream, asset_map: Arc<Mutex<HashMap<PathBuf, Asset>>>) -> Result<(), io::Error> {
    let peer_ip = stream.peer_addr()?;
    println!("[{peer_ip}] Connected");

    let mut buffer: [u8; 8192] = [0; 8192]; // 8kb buffer

    loop {
        let n = stream.read(&mut buffer)?;
        // println!("{:?}", &buffer[..n]);

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

            let asset = match header.typ {
                HttpRequestType::GET => {
                    let key = PathBuf::from(format!("./assets{}", header.path));
                    // println!("{key:?}");
                    asset_map.lock().unwrap().get(&key).cloned()
                }
            };

            if let Some(asset) = asset {
                let body = asset.content;
                let header = build_response_header(HttpResponseCode::Ok, HttpContentType::Text, body.len());

                stream.write_all(header.as_bytes())?;
                stream.write_all(body.as_bytes())?;
            } else {
                let body = format!("resource at {} not found", header.path);
                let header = build_response_header(HttpResponseCode::NotFound, HttpContentType::Text, body.len());

                stream.write_all(header.as_bytes())?;
                stream.write_all(body.as_bytes())?;
            }
            let _ = stream.flush();
        }
    }
}

fn build_response_header(code: HttpResponseCode, content_typ: HttpContentType, content_length: usize) -> String {
    let status = match code {
        HttpResponseCode::Ok => "200 Ok",
        HttpResponseCode::NotFound => "404 Not Found",
    };

    let content_typ = match content_typ {
        HttpContentType::Text => "text/plain",
    };

    format!("HTTP/1.1 {status}\r\nContent-Type: {content_typ}\r\nContent-Length: {content_length}\r\n\r\n")
}

enum HttpResponseCode {
    Ok = 200,
    NotFound = 404,
}
enum HttpContentType {
    Text,
}

#[derive(Debug)]
struct HttpRequestHeader {
    typ: HttpRequestType,
    path: String,
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

    Ok(HttpRequestHeader {
        typ: request_type,
        path: path.to_owned(),
    })
}


// const base64Conversion:[char;64] = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z','a', 'b', 'd', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'];

// fn base64(bytes:&[u8]) -> String {
//   let count = bytes.len() * 8;
  
//   let pad = count % 3;
//   let bits = bytes.bit

//   for _ in 0..pad {
//     bytes. ('');
//   }


//   ""

  
// }

// fn sha1(input:String) -> String{
//   let h0:u32 = 0x67452301;
//   let h1:u32 = 0xEFCDAB89;
//   let h2:u32 = 0x98BADCFE;
//   let h3:u32 = 0x10325476;
//   let h4:u32 = 0xC3D2E1F0;

//   let message = input.as_bytes();
//   let ml = message.len() * 8;

//   "".to_owned()
// }


type AssetPath = PathBuf;

#[derive(Clone)]
struct Asset {
    last_modified: SystemTime,
    content: String,
}

const MAGIC_VALUE: u8 = 255;

fn serialize_asset_map(asset_map: &HashMap<AssetPath, Asset>, save_path: &str) -> Result<(), io::Error> {
    let mut bin: Vec<u8> = vec![];
    bin.push(MAGIC_VALUE);

    for key_value in asset_map.iter() {
        let key_bin = key_value.0.as_os_str().as_encoded_bytes();
        let last_modified_duration = key_value.1.last_modified.duration_since(UNIX_EPOCH).unwrap();
        let asset_last_modified_secs_bin = last_modified_duration.as_secs();
        let asset_last_modified_nanos_bin = last_modified_duration.subsec_nanos();
        let asset_content_bin = key_value.1.content.as_bytes();

        // Key
        bin.extend((key_bin.len() as u64).to_be_bytes()); // Length of path string in u8's
        bin.extend_from_slice(key_bin);

        // Value
        // Unix timestamp
        bin.extend(asset_last_modified_secs_bin.to_be_bytes()); // unix time stamp is of constant length
        bin.extend(asset_last_modified_nanos_bin.to_be_bytes());

        // Content
        bin.extend((asset_content_bin.len() as u64).to_be_bytes()); // Length of path string in u8's
        bin.extend_from_slice(asset_content_bin);
    }

    fs::write(save_path, bin)
}

fn deserialize_asset_map(load_path: &str) -> Result<HashMap<AssetPath, Asset>, io::Error> {
    let bin = fs::read(load_path)?;
    let mut hm = HashMap::new();

    if bin[0] != MAGIC_VALUE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "File is not a valid serialization"));
    }

    let mut idx = 1;
    let bin_length = bin.len();
    while idx < bin_length {
        // println!("{:?}", bin[idx..].to_vec());
        let key_length = u64::from_be_bytes(bin[idx..idx + 8].try_into().unwrap()) as usize;
        idx += 8;
        let key = PathBuf::from(OsString::from_vec(bin[idx..idx + key_length].to_vec()));
        idx += key_length;

        let timestamp_secs = u64::from_be_bytes(bin[idx..idx + 8].try_into().unwrap());
        idx += 8;
        let timestamp_nanos = u32::from_be_bytes(bin[idx..idx + 4].try_into().unwrap());
        idx += 4;
        let last_modified = UNIX_EPOCH + Duration::new(timestamp_secs, timestamp_nanos);

        let content_length = u64::from_be_bytes(bin[idx..idx + 8].try_into().unwrap()) as usize;
        idx += 8;

        let content = String::from_utf8(bin[idx..idx + content_length].to_vec()).unwrap();
        idx += content_length;
        // println!("Inserting {key:?} {last_modified:?} {content:?}");

        hm.insert(key, Asset { last_modified, content });
    }

    Ok(hm)
}

fn watch_assets(asset_map: Arc<Mutex<HashMap<AssetPath, Asset>>>, dir_path: &str) {
    let mut state_changed = true;
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
                    let content = fs::read_to_string(&file_path).unwrap();

                    asset_file_paths.insert(file_path.clone());

                    if let Some(asset) = asset_map.lock().unwrap().get_mut(&file_path) {
                        // println!("{:?} {:?}", asset.last_modified, last_edited);

                        if asset.last_modified < last_edited {
                            asset.content = content;
                            asset.last_modified = last_edited;
                            println!(
                                "Updated file {file_path:?}, edited {:?} minutes ago",
                                last_edited.elapsed().unwrap().as_secs() / 60
                            );
                            state_changed = true;
                        }
                    } else {
                        asset_map.lock().unwrap().insert(
                            file_path.clone(),
                            Asset {
                                last_modified: last_edited,
                                content,
                            },
                        );

                        println!(
                            "Added file {file_path:?}, edited {:?} minutes ago",
                            last_edited.elapsed().unwrap().as_secs() / 60
                        );
                        state_changed = true;
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
            state_changed = true;
        }

        if state_changed {
            match serialize_asset_map(&map, STATE_PATH) {
                Ok(_) => {
                    // println!("Saved state to file");
                }
                Err(err) => {
                    println!("Error while saving state to file {err:?}");
                }
            }
            state_changed = false;
        }

        sleep(Duration::from_millis(100));
    }
}
