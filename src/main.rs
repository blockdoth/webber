use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::io::{self, Write};
use std::net::TcpListener;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{fs, thread};

const SOCKET_ADDR: &str = "127.0.0.1:9123";
const ASSETS_PATH: &str = "./assets/";
const STATE_PATH: &str = "./state/state";

fn main() {
    let listener = TcpListener::bind(SOCKET_ADDR).unwrap();
    println!("Started listening on socket {SOCKET_ADDR}");

    let asset_map = Arc::new(Mutex::new(match deserialize_asset_map(STATE_PATH) {
        Ok(hm) => {
            println!("Loaded {} assets from state", hm.len());
            hm
        }
        Err(err) => {
            println!("Failed to restore state, {err:?}");
            HashMap::new()
        }
    }));

    let _handle = thread::spawn(|| {
        watch_assets(asset_map, ASSETS_PATH);
    });

    for stream in listener.incoming() {
        thread::spawn(|| {
            let mut stream = stream.unwrap();
            let _ = stream.write(b"Hello World\r\n").unwrap();
        });
    }
}

type AssetPath = PathBuf;
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
    loop {
        let dir = match fs::read_dir(Path::new(dir_path)) {
            Ok(dir) => dir,
            Err(error) => {
                println!("Error while trying to open asset dir at {dir_path}: {error}");
                return;
            }
        };

        let mut asset_file_paths = HashSet::new();
        for file in dir {
            if let Ok(file) = file
                && let Ok(metadata) = file.metadata()
                && let Ok(last_edited) = metadata.accessed()
            {
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
        match serialize_asset_map(&map, STATE_PATH) {
            Ok(_) => {
                // println!("Saved state to file");
            }
            Err(err) => {
                println!("Error while saving state to file {err:?}");
            }
        }

        sleep(Duration::from_millis(500));
    }
}
