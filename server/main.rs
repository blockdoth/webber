#![feature(hash_map_macro)]
#![allow(clippy::module_inception)]
#![allow(dead_code)]

use crate::runtime::server::error::ServerError;

pub const DEBUG_BIN_PATH: &str = "./target/debug/webber";
pub const RELEASE_BIN_PATH: &str = "./target/release/webber";

pub const CONFIG_PATH: &str = "./server.tomlish";
pub const API_DYN_LIB_PATH: &str = "target/debug/libapi.so";

#[path = "src/comptime.rs"]
mod comptime;

#[path = "src/runtime.rs"]
mod runtime;

fn main() -> Result<(), ServerError> {
    if std::env::args().any(|arg| arg.contains("build_script_build")) {
        comptime::comptime()
    } else {
        // #[cfg(generated)] // Marks everything deadcode during build time
        runtime::runtime()?;
        Ok(())
    }
}
