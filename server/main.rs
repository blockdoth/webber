#![feature(tcp_linger)]
#![feature(if_let_guard)]
#![feature(hash_map_macro)]
#![feature(allocator_api)]
#![allow(clippy::module_inception)]
#![allow(unused)]
#![allow(dead_code)]

// #![warn(clippy::pedantic)]
// #![allow(clippy::similar_names)]
// #![allow(clippy::cast_possible_truncation)]
// #![allow(clippy::cast_sign_loss)]
// #![allow(clippy::cast_possible_wrap)]
// #![allow(clippy::enum_glob_use)]

use crate::runtime::server::error::ServerError;
use std::env;

pub const DEBUG_BIN_PATH: &str = "./target/debug/webber";
pub const RELEASE_BIN_PATH: &str = "./target/release/webber";

pub const CONFIG_PATH: &str = "./server.tomlish";

#[path = "src/comptime.rs"]
mod comptime;

#[path = "src/runtime.rs"]
mod runtime;

fn main() -> Result<(), ServerError> {
    if std::env::args().any(|arg| arg.contains("build-script-build")) {
        comptime::comptime()
    } else {
        #[cfg(generated)] // Marks everything deadcode during build time
        runtime::runtime()?;
        Ok(())
    }
}
