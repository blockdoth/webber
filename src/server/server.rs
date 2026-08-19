use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Debug, Display};
use std::io::{self, ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use std::{fmt, vec};

use crate::runtime::assets::asset::{AssetData, AssetDataRef, AssetTyp};
use crate::runtime::db::db::DB_SYNC_INTERVAL;
use crate::runtime::misc::byte_stuff::{base64, sha1};
use crate::runtime::misc::date::Date;
use crate::runtime::misc::sighandlers::SHUTDOWN;
use crate::runtime::server::router::Router;
use crate::runtime::templating::error::TemplateError;

// === Http Server ===

#[derive(Debug)]
pub struct HttpRequestHeader<'a> {
    _typ: HttpRequestType,
    pub path: &'a str,
    _origin: Option<&'a str>,
    _user_agent: Option<&'a str>,
    pub sec_websocket_key: Option<&'a str>,
    pub sec_websocket_version: Option<&'a str>,
    pub upgrade: Option<&'a str>,
    pub content_typ: AssetTyp,
}

#[derive(Debug)]
#[allow(clippy::upper_case_acronyms)]
pub enum HttpRequestType {
    GET,
}

pub struct HttpServer {
    response_buffer: Vec<u8>,
    render_buffer: String,
    #[cfg(debug_assertions)]
    active_streams: Vec<TcpStream>,
}

impl HttpServer {
    pub fn new() -> Self {
        Self {
            response_buffer: Vec::with_capacity(64 * 1024),
            render_buffer: String::with_capacity(64 * 1024),
            #[cfg(debug_assertions)]
            active_streams: vec![],
        }
    }

    pub fn serve(
        &mut self,
        listener: TcpListener,
        mut router: Router,
    ) -> Result<(), Box<dyn Error>> {
        let mut read_buffer: [u8; 8192] = [0; 8192]; // 8kb buffer,
        let mut template_cache: HashMap<String, String> = HashMap::new();

        #[cfg(debug_assertions)]
        let mut check_alive_timer = Instant::now();
        #[cfg(debug_assertions)]
        let mut check_fs_timer = Instant::now();

        let mut check_db_sync_timer = Instant::now();
        let mut last_day = 0;

        println!("Static Routes:");
        for (route, page) in &router.static_routes {
            println!(" {route}\t\t->\t{}", page.path);
        }
        println!("Dynamic Routes:");
        for (route, page) in &router.dynamic_routes {
            println!(" {route}\t\t->\t{}", page.template_path);
        }
        // println!("Assets");
        // for (route, asset) in &router.content.assets.collect_kv_mut() {
        //     println!(" {route:?}\t\t->\t{}", asset.data.html_typ_string());
        // }

        println!(" Fallback\t->\t{:?}", router.fallback);

        #[cfg(debug_assertions)]
        listener
            .set_nonblocking(true)
            .expect("Unable to set socket to nonblocking mode");

        'main: while !SHUTDOWN.load(Ordering::Relaxed) {
            match listener.accept() {
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    if check_db_sync_timer.elapsed() > Duration::from_secs(DB_SYNC_INTERVAL) {
                        router.db.sync()?;
                        check_db_sync_timer = Instant::now();
                    }
                }
                Err(e) => return Err(e.into()),
                Ok((mut stream, peer_addr)) => {
                    stream
                        .set_nonblocking(true)
                        .expect("Failed to change blocking of stream");

                    let n = loop {
                        match stream.read(&mut read_buffer) {
                            Ok(0) => {
                                println!("[{peer_addr}] Disconnected");
                                continue 'main;
                            }
                            Ok(n) => break n,
                            Err(ref error) if error.kind() == ErrorKind::WouldBlock => {
                                std::hint::spin_loop();
                            }
                            Err(error) => return Err(error.into()),
                        };
                    };

                    let start_timer = Instant::now();

                    let (header, body) = match HttpServer::parse_request(&read_buffer[..n]) {
                        Ok(request) => request,
                        Err(err) => {
                            eprintln!("Failed to parse request: {err}");
                            continue;
                        }
                    };
                    // println!("Allocs request parsing {alloc}\t{}", header.path);
                    // println!("{:?}", header.path);
                    let mut is_ws = false;
                    match header.path {
                        #[cfg(debug_assertions)]
                        "/ws" => {
                            // print!("[{peer_addr:?}] Upgrading websocket ... ");
                            self.upgrade_websocket(header, &mut stream)?;
                            is_ws = true;
                        }
                        path => {
                            let result = if path.starts_with("/api") {
                                match router.serve_api(&header, body) {
                                    Ok(content) => Self::send_response(
                                        HttpResponseCode::Ok,
                                        content.as_ref(),
                                        &mut self.response_buffer,
                                        &mut stream,
                                    ),
                                    Err(err) => {
                                        self.build_error_response(&router, err, &mut stream)
                                    }
                                }
                            } else if let Some(asset) = router.content.assets.get_ref(header.path)
                                && !asset.internal
                            {
                                Self::send_response(
                                    HttpResponseCode::Ok,
                                    asset.data.as_ref(),
                                    &mut self.response_buffer,
                                    &mut stream,
                                )
                            } else {
                                match router.serve_page(
                                    &header,
                                    body,
                                    &mut self.render_buffer,
                                    &mut template_cache,
                                ) {
                                    Ok(content) => Self::send_response(
                                        HttpResponseCode::Ok,
                                        content,
                                        &mut self.response_buffer,
                                        &mut stream,
                                    ),
                                    Err(err) => {
                                        self.build_error_response(&router, err, &mut stream)
                                    }
                                }
                            };

                            if let Err(err) = result {
                                match err {
                                    HttpServerError::StreamWriteFailed(ref io_err)
                                        if matches!(
                                            io_err.kind(),
                                            ErrorKind::BrokenPipe
                                                | ErrorKind::ConnectionReset
                                                | ErrorKind::ConnectionAborted
                                        ) =>
                                    {
                                        // browser/client disappeared.
                                        continue 'main;
                                    }

                                    err => {
                                        eprintln!("[{peer_addr}] request failed: {err}");
                                        continue 'main;
                                    }
                                }
                            }

                            let end_timer = Instant::now();
                            let duration = end_timer - start_timer;

                            router.db.save_page_hit(path, duration).expect("in measure");
                        }
                    };

                    #[cfg(debug_assertions)]
                    {
                        if is_ws {
                            self.active_streams.push(stream);
                        }
                    }
                }
            };

            let day = Date::days();
            if day != last_day {
                last_day = day;
                router.content.update_random_quote(&mut router.context, day);
            }

            #[cfg(debug_assertions)]
            {
                let reload = if check_fs_timer.elapsed() > Duration::from_millis(50) {
                    check_fs_timer = Instant::now();

                    template_cache.clear();
                    router.content.check_update(&mut router.context)?
                } else {
                    false
                };

                if reload || check_alive_timer.elapsed() > Duration::from_secs(1) {
                    check_alive_timer = Instant::now();
                    self.active_streams.retain(|mut stream| {
                        let connection_is_alive = match stream.read(&mut [0]) {
                            Ok(0) => false,
                            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => true,
                            _ => false,
                        };

                        if connection_is_alive && let Ok(_peer_addr) = stream.peer_addr() {
                            if reload {
                                let _ = HttpServer::send_ws_message(stream, "reload");
                                // println!("[{peer_addr:?}] Reloaded");
                            }
                            true
                        } else {
                            let _ = stream.shutdown(std::net::Shutdown::Both);

                            false
                        }
                    });
                }
            }
            std::hint::spin_loop();
        }

        // Exit routine

        router.db.sync()?;
        Ok(())
    }

    fn upgrade_websocket(
        &mut self,
        header: HttpRequestHeader,
        stream: &mut TcpStream,
    ) -> Result<(), HttpServerError> {
        if let Some(_) = header.upgrade
            && let Some(sec_websocket_key) = header.sec_websocket_key
            && let Some(_) = header.sec_websocket_version
        {
            let magic_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
            let websocket_accept = base64(&sha1(&format!(
                "{}{magic_string}",
                sec_websocket_key.trim()
            )));

            self.response_buffer.clear();
            write!(self.response_buffer,
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {websocket_accept}\r\n\r\n"
            ).expect("writing in a Vec<u8> can not fail");
            stream.write_all(&self.response_buffer)?;
        } else {
            println!("Failed");
            Self::send_response(
                HttpResponseCode::BadRequest,
                AssetDataRef::Text("Invalid websocket upgrade request"),
                &mut self.response_buffer,
                stream,
            )?;
        }
        Ok(())
    }

    fn send_ws_message(mut stream: &TcpStream, msg: &str) -> Result<(), HttpServerError> {
        let mut frame = Vec::new();
        frame.push(0x81); // first bit for FIN frame and 8th bit for message type text 
        frame.push(msg.len() as u8); // should technically u7, but not needed for my use case
        frame.extend_from_slice(msg.as_bytes());
        stream.write_all(&frame)?;
        stream.flush()?;
        Ok(())
    }

    fn parse_request<'a>(
        buffer: &'a [u8],
    ) -> Result<(HttpRequestHeader<'a>, AssetData), HttpServerError> {
        if let Some(pos) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            let header_str = str::from_utf8(&buffer[..pos])
                .map_err(|_| HttpServerError::MalformedRequest)
                .expect("fix after 0 alloc");

            let header = Self::parse_header(header_str).expect("Unable to parse header");

            let content = AssetData::from_asset_type(&buffer[pos + 4..], &header.content_typ);

            Ok((header, content))
        } else {
            Err(HttpServerError::MalformedRequest)
        }
    }

    fn send_response<'a>(
        code: HttpResponseCode,
        content: AssetDataRef<'a>,
        response_buffer: &'a mut Vec<u8>,
        stream: &mut TcpStream,
    ) -> Result<(), HttpServerError> {
        let cache_control = match content {
            AssetDataRef::Png(_)
            | AssetDataRef::Ico(_)
            | AssetDataRef::Css(_)
            | AssetDataRef::Js(_) => "Cache-Control: public, max-age=3600\r\n",
            _ => "",
        };

        let body = content.as_bytes();
        response_buffer.clear();
        write!(
            response_buffer,
            "HTTP/1.1 {code}\r\n\
            Content-Type: {}\r\n\
            Content-Length: {}\r\n\
            {cache_control}\
            Connection: close\r\n\r\n",
            content.html_typ_string(),
            body.len(),
        )
        .expect("writing to Vec<u8> cannot fail");

        response_buffer.extend_from_slice(body);
        Self::write_all_nonblocking(stream, response_buffer)?;
        Ok(())
    }

    // Required to transmit larger payloads that dont fit into the kernel buffer
    fn write_all_nonblocking(stream: &mut TcpStream, mut buffer: &[u8]) -> io::Result<()> {
        while !buffer.is_empty() {
            match stream.write(buffer) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write response",
                    ));
                }
                Ok(n) => buffer = &buffer[n..],
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::hint::spin_loop();
                }
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }
    fn build_error_response(
        &mut self,
        router: &Router,
        err: HttpServerError,
        stream: &mut TcpStream,
    ) -> Result<(), HttpServerError> {
        match err {
            HttpServerError::Redirect(redirect_path) => Self::send_response(
                HttpResponseCode::Redirect(&redirect_path),
                AssetDataRef::Empty,
                &mut self.response_buffer,
                stream,
            ),

            HttpServerError::TemplatingError(err) => {
                let error_template = router
                    .error_page
                    .as_ref()
                    .and_then(|path| router.content.templates.get(path))
                    .and_then(|result| result.as_ref().ok());
                let err_str = err.render_error(error_template, &mut self.render_buffer);

                Self::send_response(
                    HttpResponseCode::Ok,
                    AssetDataRef::Html(&err_str),
                    &mut self.response_buffer,
                    stream,
                )
            }

            err => {
                println!("Server error {err:#?}");

                Self::send_response(
                    HttpResponseCode::InternalServer,
                    AssetDataRef::Empty,
                    &mut self.response_buffer,
                    stream,
                )
            }
        }
    }

    fn parse_header<'a>(header_str: &'a str) -> Result<HttpRequestHeader<'a>, HttpServerError> {
        let mut lines = header_str.lines();

        let first_line = lines.next().expect("Unable to get next line");
        let mut first_line_words = first_line.split_ascii_whitespace();

        let request_type = match first_line_words.next() {
            Some("GET") => HttpRequestType::GET,
            Some(invalid) => return Err(HttpServerError::InvalidRequestType(invalid.to_string())),
            None => return Err(HttpServerError::MalformedRequest),
        };

        let path = if let Some(path) = first_line_words.next() {
            Self::clean_path(path)
        } else {
            return Err(HttpServerError::MalformedRequest);
        };

        let mut origin = None;
        let mut sec_websocket_key = None;
        let mut sec_websocket_version = None;
        let mut user_agent = None;
        let mut upgrade = None;
        let mut content_typ = AssetTyp::Unknown;

        for line in lines {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };

            let value = value.trim_ascii_start();
            match key {
                k if k.eq_ignore_ascii_case("origin") => origin = Some(value),
                k if k.eq_ignore_ascii_case("user-agent") => user_agent = Some(value),
                k if k.eq_ignore_ascii_case("content-type") => {
                    content_typ = match value {
                        "text/plain" => AssetTyp::Text,
                        "text/html" => AssetTyp::Html,
                        "text/css" => AssetTyp::Css,
                        "text/javascript" => AssetTyp::Js,
                        "image/png" => AssetTyp::Png,
                        _ => AssetTyp::Unknown,
                    }
                }

                #[cfg(debug_assertions)]
                k if k.eq_ignore_ascii_case("sec-websocket-key") => sec_websocket_key = Some(value),
                #[cfg(debug_assertions)]
                k if k.eq_ignore_ascii_case("sec-websocket-version") => {
                    sec_websocket_version = Some(value)
                }
                #[cfg(debug_assertions)]
                k if k.eq_ignore_ascii_case("upgrade") => upgrade = Some(value),

                _ => {}
            }
        }

        Ok(HttpRequestHeader {
            _typ: request_type,
            path,
            _origin: origin,
            _user_agent: user_agent,
            sec_websocket_key,
            sec_websocket_version,
            upgrade,
            content_typ,
        })
    }

    fn clean_path(path: &str) -> &str {
        let end = path
            .as_bytes()
            .iter()
            .position(|&b| b == b'?' || b == b'#')
            .unwrap_or(path.len());

        &path[..end]
    }
}

#[derive(Debug)]
pub enum HttpServerError {
    Redirect(String),
    TemplatingError(TemplateError),
    StreamWriteFailed(std::io::Error),
    MalformedRequest,
    InvalidRequestType(String),
    Todo,
}

impl Error for HttpServerError {}

impl Display for HttpServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Redirect(location) => write!(f, "redirect to {location}"),
            Self::StreamWriteFailed(error) => write!(f, "failed to write to stream {error}"),
            Self::TemplatingError(error) => write!(f, "templating error: {error}"),
            Self::InvalidRequestType(request) => write!(f, "invalid request type {request}"),
            Self::Todo => write!(f, "operation not implemented"),
            Self::MalformedRequest => write!(f, "Malformed request"),
        }
    }
}

impl From<std::io::Error> for HttpServerError {
    fn from(value: std::io::Error) -> Self {
        HttpServerError::StreamWriteFailed(value)
    }
}

impl From<TemplateError> for HttpServerError {
    fn from(err: TemplateError) -> Self {
        HttpServerError::TemplatingError(err)
    }
}

#[derive(Debug)]
pub enum HttpResponseCode<'a> {
    Ok,
    Redirect(&'a str),
    BadRequest,
    NotFound,
    InternalServer,
}

impl HttpResponseCode<'_> {
    pub const fn status_line(&self) -> &'static str {
        match self {
            Self::Ok => "200 OK",
            Self::Redirect(_) => "303 See Other",
            Self::BadRequest => "400 Bad Request",
            Self::NotFound => "404 Not Found",
            Self::InternalServer => "500 Internal Server Error",
        }
    }
}

impl fmt::Display for HttpResponseCode<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpResponseCode::Ok => write!(f, "200 OK"),
            HttpResponseCode::Redirect(redirect) => {
                write!(f, "303 See Other\r\nLocation: {redirect}")
            }
            HttpResponseCode::NotFound => write!(f, "404 Not Found"),
            HttpResponseCode::BadRequest => write!(f, "400 Bad Request"),
            HttpResponseCode::InternalServer => write!(f, "500 Internal Server Error"),
        }
    }
}
