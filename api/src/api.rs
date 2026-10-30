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
        "/api/testos".to_owned() => imported_handler as ApiHandlerFn,
    }
}

pub fn imported_handler(
    header: &HttpRequestHeader,
    body: AssetData,
    db: &Db,
) -> Result<AssetData, HttpServerError> {
    println!("ran imported handler");

    Ok(AssetData::Empty)
}
