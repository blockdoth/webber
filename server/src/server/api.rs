use crate::API_DYN_LIB_PATH;
use crate::runtime::{
    assets::asset::AssetData,
    db::db::Db,
    server::{error::HttpServerError, server::HttpRequestHeader},
};
use std::process::Command;
use std::{collections::HashMap, error::Error};

use std::{
    ffi::{CString, c_char, c_int, c_void},
    mem::transmute,
};

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn dlclose(handle: *mut c_void) -> c_int;
}

const RTLD_NOW: c_int = 2;

pub type ApiHandlerFn =
    fn(header: &HttpRequestHeader, body: AssetData, db: &Db) -> Result<AssetData, HttpServerError>;
pub type GetApiHandlersFn = fn() -> HashMap<String, ApiHandlerFn>;

#[derive(Debug)]
pub struct Api {
    handlers: HashMap<String, ApiHandlerFn>,
    api_lib_handle: Option<*mut c_void>,
    api_version: usize,
}

impl Api {
    pub fn new(lib_path: &str, version: usize) -> Self {
        #[cfg(debug_assertions)]
        let (mut handlers, api_lib_handle) = unsafe {
            let path = CString::new(lib_path).unwrap();
            let handlers_str = CString::new("register_handlers").unwrap();

            let api_lib_handle = dlopen(path.as_ptr(), RTLD_NOW);
            assert!(!api_lib_handle.is_null(), "Failed to load plugin");

            let get_handler = dlsym(api_lib_handle, handlers_str.as_ptr());

            assert!(
                !get_handler.is_null(),
                "Failed to find \"register_handlers\""
            );

            let register_handlers: GetApiHandlersFn = transmute(get_handler);

            let mut handlers = register_handlers();
            (handlers, Some(api_lib_handle))
        };
        #[cfg(not(debug_assertions))]
        let (mut handlers, api_lib_handle) = {
            mod external_api {
                include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../api/src/api.rs"));
            }
            let handlers = external_api::register_handlers();
            (handlers, None)
        };

        handlers.extend(Self::default_handlers());
        println!("Registered handlers {:#?}", handlers.keys());
        Self {
            handlers,
            api_lib_handle,
            api_version: version,
        }
    }

    pub fn default_handlers() -> HashMap<String, ApiHandlerFn> {
        hash_map! {
            // "/api/test".to_owned() => Api::test_handler as ApiHandlerFn,
        }
    }

    pub fn handle_api(
        &self,
        header: &HttpRequestHeader,
        body: AssetData,
        db: &Db,
    ) -> Result<AssetData, HttpServerError> {
        if let Some(handler) = self.handlers.get(header.path) {
            handler(header, body, db)
        } else {
            Ok(AssetData::Empty)
        }
    }

    pub fn test_handler(
        header: &HttpRequestHeader,
        body: AssetData,
        db: &Db,
    ) -> Result<AssetData, HttpServerError> {
        println!("ran test handler");
        Ok(AssetData::Empty)
    }

    pub fn reload_api(&mut self) {
        let status = Command::new("cargo")
            .args(["build", "-p", "api"])
            .status()
            .expect("Failed to start Cargo");

        if status.success() {
            println!("API rebuilt succesfully");
            let new_path = &format!("target/debug/libapi_new{}.so", self.api_version);

            std::fs::copy(API_DYN_LIB_PATH, new_path).expect("Failed to copy API library");

            *self = Api::new(new_path, self.api_version + 1);
        } else {
            println!("failed to rebuild API, reusing old API");
        }
    }
}

impl Drop for Api {
    fn drop(&mut self) {
        unsafe {
            if let Some(handle) = self.api_lib_handle {
                dlclose(handle);
            }
        }
    }
}
