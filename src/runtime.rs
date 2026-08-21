pub mod assets;
pub mod db;
pub mod jpeg;
pub mod markdown;
pub mod misc;
pub mod server;
pub mod templating;

use std::{error::Error, net::TcpListener, time::SystemTime};

use crate::runtime::{
    assets::content::Content,
    db::db::Db,
    misc::{
        cli::{self, Config},
        date::Date,
        sighandlers::{self},
    },
    server::{router::Router, server::HttpServer},
    templating::context::Context,
};

#[cfg(generated)]
use crate::comptime::GIT_HASH_LONG;
#[cfg(generated)]
use crate::comptime::GIT_HASH_SHORT;

pub fn runtime() -> Result<(), Box<dyn Error>> {
    let args = std::env::args();
    if cli::run_arg_tools(args)? {
        return Ok(());
    }

    let config = Config::from_env();
    start_server(config.bind_address(), config.domain)
}

pub fn start_server(socket_addr: String, domain: String) -> Result<(), Box<dyn Error>> {
    sighandlers::register_signal_handlers();

    let mut db = Db::init()?;
    // db.test_counter()?;
    // db.sync()?;

    let content = Content::load_embedded();

    let context = construct_context(&content, domain);

    let router = Router::new(content, context, db)
        .route_static_hidden("/layout", "layout.html")
        .route_static_hidden("/home", "pages/home.html")
        .route_static_page("/posts", "pages/posts.html")
        .route_static_page("/quotes", "pages/quotes.html")
        .route_static_page("/gallery", "pages/gallery.html")
        .route_static_page("/stats", "pages/stats.html")
        .route_static_page("/about", "pages/about.html")
        .route_dynamic_pages("/posts", "posts", "post", "pages/post.html")
        .fallback("/home")
        .error_page("error.html")
        .rss("rss.html");

    let listener: TcpListener = TcpListener::bind(&socket_addr).expect("Unable to bind to socket");
    println!("Started listening on socket http://{socket_addr}");

    HttpServer::new().serve(listener, router)
}

fn construct_context(content: &Content, domain: String) -> Context {
    let mut context = Context::new();

    let last_build_date = Date::from_systemtime(SystemTime::now()).expect("failed to parse date");

    content.update_asset_content(&mut context, None);

    context.insert_global("random_quote_index", 0);
    context.insert_global("basedate", Date::default());
    context.insert_global("copyright_start", "2026".to_string());
    context.insert_global(
        "copyright_end",
        Date::from_systemtime(SystemTime::now()).expect("invariant"),
    ); // TODO make dynamic
    context.insert_global("domain", domain);
    context.insert_global("last_build_date", last_build_date);

    #[cfg(generated)]
    {
        context.insert_global("git_hash_short", GIT_HASH_SHORT.to_string());
        context.insert_global("git_hash_long", GIT_HASH_LONG.to_string());
    }

    context.insert_global("hotreload", cfg!(debug_assertions));

    context
}
