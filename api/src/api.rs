use std::collections::HashMap;

use crate::runtime::assets::asset::AssetData;
use crate::runtime::db::db::Db;
use crate::runtime::server::api::Api;
use crate::runtime::server::api::ApiHandlerFn;
use crate::runtime::server::error::HttpServerError;
use crate::runtime::server::server::HttpRequestHeader;

#[unsafe(no_mangle)]
pub fn register_handlers() -> HashMap<String, ApiHandlerFn> {
    hash_map! {
        "/api/balls".to_owned() => imported_handler_1 as ApiHandlerFn,
        "/api/rocks".to_owned() => imported_handler_2 as ApiHandlerFn,
    }
}

pub fn imported_handler_1(
    header: &HttpRequestHeader,
    body: AssetData,
    db: &Db,
) -> Result<AssetData, HttpServerError> {
    println!("handler 1");

    Ok(AssetData::Empty)
}

pub fn imported_handler_2(
    header: &HttpRequestHeader,
    body: AssetData,
    db: &Db,
) -> Result<AssetData, HttpServerError> {
    println!("handler 2");

    Ok(AssetData::Empty)
}
