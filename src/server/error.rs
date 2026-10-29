use core::fmt;
use std::{error::Error, fmt::Display};

use crate::runtime::{
    config::config::Config, jpeg::errors::ImageParseError, templating::error::TemplateError,
};

#[derive(Debug)]
pub enum ServerError {
    ReloadConfig(Box<Config>),
    TemplateError(TemplateError),
    ImageParseError(ImageParseError),
    HttpServerError(HttpServerError),
    Other(String),
}

impl From<Box<dyn Error>> for ServerError {
    fn from(error: Box<dyn Error>) -> Self {
        Self::Other(error.to_string())
    }
}

impl From<Box<dyn Error + Send + Sync>> for ServerError {
    fn from(error: Box<dyn Error + Send + Sync>) -> Self {
        Self::Other(error.to_string())
    }
}

impl From<std::io::Error> for ServerError {
    fn from(error: std::io::Error) -> Self {
        Self::Other(error.to_string())
    }
}

impl Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServerError::ReloadConfig(new_config) => {
                f.write_str(&format!("Server config has changed {new_config:?}"))
            }
            ServerError::TemplateError(error) => Display::fmt(error, f),
            ServerError::HttpServerError(error) => Display::fmt(error, f),
            ServerError::ImageParseError(error) => Display::fmt(error, f),
            ServerError::Other(message) => f.write_str(message),
        }
    }
}

impl From<TemplateError> for ServerError {
    fn from(error: TemplateError) -> Self {
        Self::TemplateError(error)
    }
}

impl From<HttpServerError> for ServerError {
    fn from(error: HttpServerError) -> Self {
        Self::HttpServerError(error)
    }
}

impl From<ImageParseError> for ServerError {
    fn from(error: ImageParseError) -> Self {
        Self::ImageParseError(error)
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
