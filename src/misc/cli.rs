use std::env::{self, Args};
use std::error::Error;
use std::path::PathBuf;

use crate::runtime::db::db::Db;

pub struct Config {
    pub host: String,
    pub port: String,
    pub domain: String,
}

impl Config {
    pub fn from_env() -> Self {
        let host = env::var("WEBBER_HOST").unwrap_or_else(|_| "127.0.0.1".to_owned());

        let port = env::var("WEBBER_PORT").unwrap_or_else(|_| "4000".to_owned());

        let domain = env::var("WEBBER_DOMAIN").unwrap_or_else(|_| format!("{host}:{port}"));

        Self { host, port, domain }
    }

    pub fn bind_address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

pub fn run_arg_tools(mut args: Args) -> Result<bool, Box<dyn Error>> {
    if let Some(first_arg) = args.nth(1) {
        match first_arg.as_str() {
            "dumpdb" => {
                let db = Db::init()?;
                let path = if let Some(path) = args.next() {
                    PathBuf::from(path)
                } else {
                    PathBuf::from("./webber.db")
                };
                db.export_db(&path)?;
                Ok(true)
            }
            "exportdb" => {
                let mut db = Db::init()?;
                let path = if let Some(path) = args.next() {
                    PathBuf::from(path)
                } else {
                    PathBuf::from("./webber.db")
                };
                db.export_db_serialized(path)?;
                Ok(true)
            }
            "loaddb" => {
                let path = if let Some(path) = args.next() {
                    PathBuf::from(path)
                } else {
                    PathBuf::from("./webber.db")
                };
                Db::import_db(path)?;
                Ok(true)
            }
            _ => Err(format!("unknown arg: {}", first_arg).into()),
        }
    } else {
        Ok(false)
    }
}
