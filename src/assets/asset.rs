use std::borrow::Cow;
use std::fmt::Debug;
use std::fs;
use std::io::{self};
use std::path::Path;
use std::time::SystemTime;

use crate::runtime::markdown::parser::{MarkdownParser, ParsedMarkdown};

#[derive(Clone, Debug)]
pub struct Asset {
    pub last_modified: SystemTime,
    pub data: AssetData,
    pub internal: bool,
}

impl Asset {
    // Used by build script
    #[allow(unused)]
    pub fn new(content: AssetData) -> Self {
        Self {
            last_modified: SystemTime::now(),
            data: content,
            internal: false,
        }
    }
}

#[derive(Clone, Debug)]
pub enum AssetData {
    Text(Cow<'static, str>),
    Html(Cow<'static, str>),
    Css(Cow<'static, str>),
    Js(Cow<'static, str>),
    Png(Cow<'static, [u8]>),
    Jpeg(Cow<'static, [u8]>),
    Ico(Cow<'static, [u8]>),
    Markdown(Cow<'static, ParsedMarkdown>),
    Woff2(Cow<'static, [u8]>),
    Otf(Cow<'static, [u8]>),
    UnknownText(Cow<'static, str>),
    Unknown(Cow<'static, [u8]>),
    Empty,
}
#[derive(Clone, Debug)]
pub enum AssetDataRef<'a> {
    Text(&'a str),
    Html(&'a str),
    Css(&'a str),
    Js(&'a str),
    MdRaw(&'a str),
    Unknown(&'a [u8]),
    UnknownText(&'a str),
    Png(&'a [u8]),
    Jpeg(&'a [u8]),
    Ico(&'a [u8]),
    Woff2(&'a [u8]),
    Otf(&'a [u8]),
    Markdown(&'a ParsedMarkdown),
    Empty,
}

impl AssetDataRef<'_> {
    pub fn html_typ_string(&self) -> &str {
        match self {
            AssetDataRef::Html(_) => "text/html; charset=utf-8",
            AssetDataRef::Css(_) => "text/css",
            AssetDataRef::Js(_) => "text/javascript",
            AssetDataRef::Png(_) => "image/png",
            AssetDataRef::Jpeg(_) => "image/jpeg",
            AssetDataRef::Ico(_) => "image/ico",
            AssetDataRef::Woff2(_) => "font/woff2",
            AssetDataRef::Otf(_) => "font/otf",
            AssetDataRef::Markdown(_) => "text/html; charset=utf-8",
            AssetDataRef::Text(_) | AssetDataRef::MdRaw(_) | AssetDataRef::UnknownText(_) => {
                "text/plain; charset=utf-8"
            }
            AssetDataRef::Unknown(_) => todo!(),
            AssetDataRef::Empty => "",
        }
    }
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            AssetDataRef::Png(b)
            | AssetDataRef::Jpeg(b)
            | AssetDataRef::Ico(b)
            | AssetDataRef::Woff2(b)
            | AssetDataRef::Otf(b)
            | AssetDataRef::Unknown(b) => b,
            AssetDataRef::Text(s)
            | AssetDataRef::Html(s)
            | AssetDataRef::Css(s)
            | AssetDataRef::Js(s)
            | AssetDataRef::MdRaw(s)
            | AssetDataRef::UnknownText(s) => s.as_bytes(),
            AssetDataRef::Markdown(m) => m.as_bytes(),
            AssetDataRef::Empty => &[],
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            AssetDataRef::Png(_)
            | AssetDataRef::Jpeg(_)
            | AssetDataRef::Ico(_)
            | AssetDataRef::Woff2(_)
            | AssetDataRef::Otf(_)
            | AssetDataRef::Unknown(_) => None,
            AssetDataRef::Text(s)
            | AssetDataRef::Html(s)
            | AssetDataRef::Css(s)
            | AssetDataRef::Js(s)
            | AssetDataRef::MdRaw(s)
            | AssetDataRef::UnknownText(s) => Some(s),
            AssetDataRef::Markdown(m) => Some(m.as_str()),
            AssetDataRef::Empty => None,
        }
    }
}

impl AssetData {
    pub fn read_asset(path: &Path) -> Result<AssetData, io::Error> {
        let content = match path.extension().and_then(|s| s.to_str()) {
            Some("png") => AssetData::Png(Cow::Owned(fs::read(path)?)),
            Some("jpg") | Some("jpeg") | Some("JPG") | Some("JPEG") => {
                AssetData::Jpeg(Cow::Owned(fs::read(path)?))
            }
            Some("ico") => AssetData::Ico(Cow::Owned(fs::read(path)?)),
            Some("md") => AssetData::Markdown(Cow::Owned(MarkdownParser::parse(
                &fs::read_to_string(path)?,
            ))),
            Some("html") => AssetData::Html(Cow::Owned(fs::read_to_string(path)?)),
            Some("txt") => AssetData::Text(Cow::Owned(fs::read_to_string(path)?)),
            Some("otf") => AssetData::Otf(Cow::Owned(fs::read(path)?)),
            Some("woff2") => AssetData::Woff2(Cow::Owned(fs::read(path)?)),
            Some("css") => AssetData::Css(Cow::Owned(fs::read_to_string(path)?)),
            Some("js") => AssetData::Js(Cow::Owned(fs::read_to_string(path)?)),
            _ => {
                if let Ok(text) = fs::read_to_string(path) {
                    AssetData::Text(Cow::Owned(text))
                } else {
                    AssetData::Unknown(Cow::Owned(fs::read(path)?))
                }
            }
        };
        Ok(content)
    }

    pub fn as_ref(&self) -> AssetDataRef<'_> {
        match self {
            AssetData::Text(text) => AssetDataRef::Text(text),
            AssetData::Html(html) => AssetDataRef::Html(html),
            AssetData::Css(css) => AssetDataRef::Css(css),
            AssetData::Js(js) => AssetDataRef::Js(js),
            AssetData::Png(bytes) => AssetDataRef::Png(bytes),
            AssetData::Jpeg(bytes) => AssetDataRef::Jpeg(bytes),
            AssetData::Ico(bytes) => AssetDataRef::Ico(bytes),
            AssetData::Markdown(parsed_markdown) => AssetDataRef::Markdown(parsed_markdown),
            AssetData::Woff2(bytes) => AssetDataRef::Woff2(bytes),
            AssetData::Otf(bytes) => AssetDataRef::Otf(bytes),
            AssetData::Unknown(value) => AssetDataRef::Unknown(value),
            AssetData::UnknownText(value) => AssetDataRef::UnknownText(value),
            AssetData::Empty => AssetDataRef::Empty,
        }
    }

    pub fn html_typ_string(&self) -> &str {
        match self {
            AssetData::Html(_) => "text/html; charset=utf-8",
            AssetData::Css(_) => "text/css",
            AssetData::Js(_) => "text/javascript",
            AssetData::Png(_) => "image/png",
            AssetData::Jpeg(_) => "image/jpeg",
            AssetData::Ico(_) => "image/ico",
            AssetData::Woff2(_) => "font/woff2",
            AssetData::Otf(_) => "font/otf",
            AssetData::Markdown(_) => "text/html; charset=utf-8",
            AssetData::Text(_) | AssetData::Unknown(_) => "text/plain; charset=utf-8",
            AssetData::UnknownText(_) => todo!(),
            AssetData::Empty => "",
        }
    }

    pub fn from_asset_type(buffer: &[u8], content_typ: &AssetTyp) -> AssetData {
        match content_typ {
            AssetTyp::Png => AssetData::Png(Cow::Owned(buffer.to_owned())),
            AssetTyp::Ico => AssetData::Ico(Cow::Owned(buffer.to_owned())),
            AssetTyp::Woff2 => AssetData::Woff2(Cow::Owned(buffer.to_owned())),
            AssetTyp::Otf => AssetData::Otf(Cow::Owned(buffer.to_owned())),
            AssetTyp::Js => AssetData::Js(Cow::Owned(String::from_utf8_lossy(buffer).into_owned())),
            AssetTyp::Empty => AssetData::Empty,
            AssetTyp::Md => todo!(),
            AssetTyp::Html => {
                AssetData::Html(Cow::Owned(String::from_utf8_lossy(buffer).into_owned()))
            }
            AssetTyp::Css => {
                AssetData::Css(Cow::Owned(String::from_utf8_lossy(buffer).into_owned()))
            }
            AssetTyp::Text => {
                AssetData::Text(Cow::Owned(String::from_utf8_lossy(buffer).into_owned()))
            }
            AssetTyp::UnknownText
                if let s = String::from_utf8_lossy(buffer)
                    && !s.is_empty() =>
            {
                AssetData::UnknownText(Cow::Owned(s.into_owned()))
            }
            AssetTyp::UnknownText | AssetTyp::Unknown => {
                AssetData::Unknown(Cow::Owned(buffer.to_vec()))
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AssetTyp {
    Text,
    Html,
    Css,
    Js,
    Png,
    Md,
    Ico,
    Woff2,
    Otf,
    UnknownText,
    Empty,
    Unknown,
}
