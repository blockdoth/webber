pub mod assets;
pub mod config;
pub mod db;
pub mod jpeg;
pub mod markdown;
pub mod misc;
pub mod server;
pub mod templating;

use std::{clone, error::Error, net::TcpListener, time::SystemTime};

use crate::{
    CONFIG_PATH,
    runtime::{
        assets::content::Content,
        config::{config::Config, parser::TomlishValue},
        db::db::Db,
        misc::{
            cli::{self},
            date::Date,
            sighandlers::{self},
        },
        server::{error::ServerError, router::Router, server::HttpServer},
        templating::context::Context,
    },
};

#[cfg(generated)]
use crate::comptime::GIT_HASH_LONG;
#[cfg(generated)]
use crate::comptime::GIT_HASH_SHORT;
#[cfg(generated)]
use crate::comptime::last_build_date;

pub fn runtime() -> Result<(), ServerError> {
    let args = std::env::args();
    if cli::run_arg_tools(args)? {
        return Ok(());
    }
    #[cfg(generated)]
    let mut config = Config::load_embeded_config();
    #[cfg(not(generated))]
    let mut config = Config::default();

    // println!("Config:\n{config:#?}");

    sighandlers::register_signal_handlers();

    loop {
        match start_server(config.populate_env()) {
            Err(ServerError::ReloadConfig(new_config)) => config = *new_config,
            e => return e,
        }
    }
}

pub fn start_server(config: Config) -> Result<(), ServerError> {
    let mut db = Db::init()?;
    // db.test_counter()?;
    // db.sync()?;

    let content = Content::load_embedded();

    let context = construct_context(&content, &config);
    let socket_addr = format!("{}:{}", config.host, config.port);

    let router = Router::from_config(config, content, context, db);

    let listener: TcpListener = TcpListener::bind(&socket_addr).expect("Unable to bind to socket");
    println!("Started listening on socket http://{socket_addr}");
    // panic!();
    HttpServer::new().serve(listener, router)
}

fn construct_context(content: &Content, config: &Config) -> Context {
    let mut context = Context::new();

    for (var_name, tomlish_value) in &config.variables {
        let templates_value = tomlish_value.clone().resolve(content, &config.assets_path);
        match tomlish_value {
            TomlishValue::Path(path, _) | TomlishValue::ContentPath(path, _) => {
                context
                    .generated_to_asset_map
                    .insert(path.clone(), var_name.clone());
            }
            _ => {}
        }

        context.insert_global(var_name, templates_value); // TODO remove clone
    }
    #[cfg(generated)]
    {
        context.insert_global(
            "last_build_date",
            Date::from_systemtime(last_build_date()).expect("invariant"),
        );
        context.insert_global("git_hash_short", GIT_HASH_SHORT.to_string());
        context.insert_global("git_hash_long", GIT_HASH_LONG.to_string());
    }

    context.insert_global("hotreload", cfg!(debug_assertions));

    context
}
