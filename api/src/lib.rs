#![feature(tcp_linger)]
#![feature(if_let_guard)]
#![feature(hash_map_macro)]
#![feature(allocator_api)]
#![allow(clippy::module_inception)]
#![allow(unused)]
#![allow(dead_code)]
#![allow(clippy::should_implement_trait)]
#![allow(clippy::len_without_is_empty)]

#[cfg(debug_assertions)]
pub const CONFIG_PATH: &str =
    "placeholder, because it is defined in main.rs and required as import for runtime.rs";

#[cfg(debug_assertions)]
pub const API_DYN_LIB_PATH: &str = "same as above";

#[cfg(debug_assertions)]
#[path = "../../server/src/runtime.rs"]
pub mod runtime;

#[cfg(debug_assertions)]
pub mod api;
