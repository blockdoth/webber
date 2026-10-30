use crate::runtime::{
    assets::asset::AssetData,
    db::db::Db,
    server::{error::HttpServerError, server::HttpRequestHeader},
};
use std::{collections::HashMap, error::Error};

// #[path = "../../content/api/mod.rs"]
// mod api;

pub type ApiHandlerFn =
    fn(header: &HttpRequestHeader, body: AssetData, db: &Db) -> Result<AssetData, HttpServerError>;
pub type GetApiHandlersFn = fn() -> HashMap<String, ApiHandlerFn>;

#[derive(Debug)]
pub struct Api {
    handlers: HashMap<String, ApiHandlerFn>,
    api_lib_handle: Option<*mut c_void>,
}

impl Default for Api {
    fn default() -> Self {
        Self::new()
    }
}

impl Api {
    pub fn new() -> Self {
        #[cfg(debug_assertions)]
        let (mut handlers, api_lib_handle) = unsafe {
            let path = CString::new("target/debug/libapi.so").unwrap();
            let handlers_str = CString::new("register_handlers").unwrap();
            let api_lib_handle = dlopen(path.as_ptr(), RTLD_NOW);
            assert!(!api_lib_handle.is_null(), "Failed to load plugin");

            let get_handler = dlsym(api_lib_handle, handlers_str.as_ptr());

            assert!(!get_handler.is_null(), "Failed to find get_handlers");

            let register_handlers: GetApiHandlersFn = transmute(get_handler);

            let mut handlers = register_handlers();
            (handlers, Some(api_lib_handle))
        };
        #[cfg(not(debug_assertions))]
        let (mut handlers, api_lib_handle) = {
            mod external_api {
                // use crate::runtime::server::api::Api;
                // use crate::runtime::server::server::HttpRequestHeader;
                // use crate::runtime::server::error::HttpServerError;
                // use crate::runtime::assets::asset::AssetData;
                // use crate::runtime::db::db::Db;
                // use crate::runtime::server::api::ApiHandlerFn;

                include!(concat!(env!("CARGO_MANIFEST_DIR"), "/../api/src/api.rs"));
            }
            let handlers = external_api::register_handlers();

            (handlers, None)
        };

        handlers.insert("/api/test".to_owned(), Api::test_handler as ApiHandlerFn);
        Self {
            handlers,
            api_lib_handle,
        }
    }

    pub fn handle(
        &self,
        header: &HttpRequestHeader,
        body: AssetData,
        db: &Db,
    ) -> Result<AssetData, HttpServerError> {
        if let Some(handler) = self.handlers.get(header.path) {
            handler(header, body, db)?;
        }

        Ok(AssetData::Empty)
    }

    pub fn test_handler(
        header: &HttpRequestHeader,
        body: AssetData,
        db: &Db,
    ) -> Result<AssetData, HttpServerError> {
        println!("ran test handler");
        Ok(AssetData::Empty)
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
