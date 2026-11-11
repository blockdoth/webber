use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Debug, Display};
use std::io::{self, ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::IntoRawFd;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use std::{fmt, vec};
use std::{os::fd::AsRawFd, os::raw::c_int};

use crate::runtime::assets::asset::{AssetData, AssetDataRef, AssetTyp};
use crate::runtime::assets::content::Content;
use crate::runtime::db::db::DB_SYNC_INTERVAL;
use crate::runtime::misc::byte_stuff::{base64, sha1};
use crate::runtime::misc::date::Date;
use crate::runtime::server::error::{HttpResponseCode, HttpServerError, ServerError};
use crate::runtime::server::eventloop::Connection;
use crate::runtime::server::router::Router;
use crate::runtime::templating::error::TemplateError;

unsafe extern "C" {
    fn listen(fd: c_int, backlog: c_int) -> c_int;
}

pub struct HttpServer {
    pub response_buffer: Vec<u8>,
    pub render_buffer: String,
    #[cfg(debug_assertions)]
    pub active_streams: Vec<TcpStream>,
}

impl Default for HttpServer {
    fn default() -> Self {
        Self::new()
    }
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
    pub fn set_backlog(listener: &TcpListener, backlog: c_int) -> io::Result<()> {
        if unsafe { listen(listener.as_raw_fd(), backlog) } == -1 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn increase_max_fds() -> std::io::Result<()> {
        #[repr(C)]
        struct RLimit {
            current: u64,
            maximum: u64,
        }

        unsafe extern "C" {
            fn getrlimit(resource: i32, limit: *mut RLimit) -> i32;
            fn setrlimit(resource: i32, limit: *const RLimit) -> i32;
        }

        const RLIMIT_NOFILE: i32 = 7;

        unsafe {
            let mut limit = RLimit {
                current: 0,
                maximum: 0,
            };

            if getrlimit(RLIMIT_NOFILE, &mut limit) != 0 {
                return Err(io::Error::last_os_error());
            }

            limit.current = limit.maximum;

            if setrlimit(RLIMIT_NOFILE, &limit) != 0 {
                return Err(io::Error::last_os_error());
            }
        }

        Ok(())
    }
    pub fn upgrade_websocket(
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

    pub fn send_ws_message(mut stream: &TcpStream, msg: &str) -> Result<(), HttpServerError> {
        let mut frame = Vec::new();
        frame.push(0x81); // first bit for FIN frame and 8th bit for message type text
        frame.push(msg.len() as u8); // should technically u7, but not needed for my use case
        frame.extend_from_slice(msg.as_bytes());
        stream.write_all(&frame)?;
        stream.flush()?;
        Ok(())
    }

    pub fn parse_request<'a>(
        buffer: &'a [u8],
    ) -> Result<(HttpRequestHeader<'a>, AssetData), HttpServerError> {
        if let Some(pos) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            let header_str = str::from_utf8(&buffer[..pos])
                .map_err(|_| HttpServerError::MalformedRequest)
                .expect("fix after 0 alloc");

            let header = HttpRequestHeader::parse(header_str).expect("Unable to parse header");

            let content = AssetData::from_asset_type(&buffer[pos + 4..], &header.content_typ);

            Ok((header, content))
        } else {
            Err(HttpServerError::MalformedRequest)
        }
    }

    pub fn send_response<'a>(
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

    pub fn build_error_response(
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
}

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

impl<'a> HttpRequestHeader<'a> {
    fn parse(header_str: &'a str) -> Result<HttpRequestHeader<'a>, HttpServerError> {
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
