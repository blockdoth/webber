use std::borrow::Cow;
use std::collections::HashMap;

use std::fmt::Debug;
use std::hash::BuildHasher;
use std::time::{Duration, SystemTime};

use crate::runtime::assets::asset::AssetData;
use crate::runtime::assets::content::GalleryImage;
use crate::runtime::assets::content::Quote;
use crate::runtime::db::db::{PageMetric, Stats};
use crate::runtime::jpeg::exif::ExifMetadata;
use crate::runtime::markdown::parser::{MarkdownFile, MarkdownPost, ParsedMarkdown};
use crate::runtime::markdown::syntax::SyntaxHighlightLang;
use crate::runtime::misc::date::Date;

#[derive(Clone, Debug)]
pub enum TemplateValue {
    Text(String),
    Number(i64),
    Date(Date),
    Bool(bool),
    List(Vec<TemplateValue>),
    Object(HashMap<String, TemplateValue>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TemplateValueKind {
    Text,
    Number,
    Bool,
    Date,
    List,
    Object,
}

impl TemplateValue {
    pub fn kind(&self) -> TemplateValueKind {
        match self {
            TemplateValue::Text(_) => TemplateValueKind::Text,
            TemplateValue::Number(_) => TemplateValueKind::Number,
            TemplateValue::Bool(_) => TemplateValueKind::Bool,
            TemplateValue::Date(_) => TemplateValueKind::Date,
            TemplateValue::List(_) => TemplateValueKind::List,
            TemplateValue::Object(_) => TemplateValueKind::Object,
        }
    }
}

pub trait ToTemplateValue: Sized {
    fn to_template_value(self) -> TemplateValue;
}

impl ToTemplateValue for TemplateValue {
    fn to_template_value(self) -> TemplateValue {
        self
    }
}

impl ToTemplateValue for String {
    fn to_template_value(self) -> TemplateValue {
        TemplateValue::Text(self)
    }
}

impl ToTemplateValue for bool {
    fn to_template_value(self) -> TemplateValue {
        TemplateValue::Bool(self)
    }
}

impl ToTemplateValue for SystemTime {
    fn to_template_value(self) -> TemplateValue {
        TemplateValue::Text(format!("{:?}", self.duration_since(SystemTime::UNIX_EPOCH)))
    }
}

impl<T: ToTemplateValue> ToTemplateValue for Vec<T> {
    fn to_template_value(self) -> TemplateValue {
        TemplateValue::List(
            self.into_iter()
                .map(ToTemplateValue::to_template_value)
                .collect(),
        )
    }
}

impl<K, V, S> ToTemplateValue for HashMap<K, V, S>
where
    K: Into<String>,
    V: ToTemplateValue,
    S: BuildHasher,
{
    fn to_template_value(self) -> TemplateValue {
        TemplateValue::Object(
            self.into_iter()
                .map(|(key, value)| (key.into(), value.to_template_value()))
                .collect(),
        )
    }
}

impl ToTemplateValue for Duration {
    fn to_template_value(self) -> TemplateValue {
        format!("{:.2?}", self).to_template_value()
    }
}
impl ToTemplateValue for i64 {
    fn to_template_value(self) -> TemplateValue {
        TemplateValue::Number(self)
    }
}

impl ToTemplateValue for PageMetric {
    fn to_template_value(self) -> TemplateValue {
        hash_map! {
          "path".to_string() => self.page.to_string().to_template_value(),
          "avg".to_string() =>  self.avg_loadtime.to_template_value(),
          "count".to_string() => self.count.to_template_value(),
        }
        .to_template_value()
    }
}

impl ToTemplateValue for Quote {
    fn to_template_value(self) -> TemplateValue {
        hash_map! {
          "quote".to_string() => self.quote.to_template_value(),
          "author".to_string() =>  self.author.to_template_value(),
          "description".to_string() => self.description.to_template_value(),
        }
        .to_template_value()
    }
}

impl ToTemplateValue for Stats {
    fn to_template_value(self) -> TemplateValue {
        hash_map! {
          "pages".to_string() => self.pages.to_template_value(),
          "start_time".to_string() => self.start_time.to_template_value(),
        }
        .to_template_value()
    }
}

impl ToTemplateValue for SyntaxHighlightLang {
    fn to_template_value(self) -> TemplateValue {
        use SyntaxHighlightLang::*;

        match self {
            Bash | C | Clike | Css | Haskell | Nix | Rust | Markdown | Markup | Elixir | Html
            | Javascript | Typescript => self.to_str().to_owned().to_template_value(),
        }
    }
}

impl ToTemplateValue for AssetData {
    fn to_template_value(self) -> TemplateValue {
        use AssetData::*;
        match self {
            Png(_) | Jpeg(_) | Ico(_) | Woff2(_) | Otf(_) | Unknown(_) => {
                todo!("Cant insert binary assets into context yet")
            }
            Empty => todo!("not sure what to do with this"),
            AssetData::Text(s) | Html(s) | Css(s) | Js(s) | UnknownText(s) => s.to_template_value(),

            Markdown(parsed) => parsed.to_template_value(),
        }
    }
}

impl<T> ToTemplateValue for Cow<'static, T>
where
    T: ToOwned + ?Sized,
    T::Owned: ToTemplateValue,
{
    fn to_template_value(self) -> TemplateValue {
        match self {
            Cow::Borrowed(inner) => inner.to_owned().to_template_value(),
            Cow::Owned(inner) => inner.to_template_value(),
        }
    }
}

impl ToTemplateValue for MarkdownPost {
    fn to_template_value(self) -> TemplateValue {
        let published = match self.metadata.published {
            Ok(date) => date.to_template_value(),
            Err(err) => (*err).to_owned().to_template_value(),
        };

        let summary = self
            .metadata
            .summary
            .clone()
            .unwrap_or("No summary provided".to_owned())
            .to_template_value();

        let highlighted_langs = SyntaxHighlightLang::include_dependencies(&self.highlighted_langs);

        hash_map! {
          "title" => self.metadata.title.to_template_value(),
          "slug" => self.metadata.slug.to_template_value(),
          "published" => published,
          "tags" => self.metadata.tags.to_template_value(),
          "images" => self.images.to_template_value(),
          "summary" => summary,
          "draft" => self.metadata.draft.to_template_value(),
          "content" => self.html.to_template_value(),
          "highlighted_langs" => highlighted_langs.to_template_value(),
        }
        .to_template_value()
    }
}

impl ToTemplateValue for MarkdownFile {
    fn to_template_value(self) -> TemplateValue {
        let highlighted_langs = SyntaxHighlightLang::include_dependencies(&self.highlighted_langs);
        hash_map! {
          "content" => self.html.to_template_value(),
          "highlighted_langs" => highlighted_langs.to_template_value(),
        }
        .to_template_value()
    }
}

impl ToTemplateValue for ParsedMarkdown {
    fn to_template_value(self) -> TemplateValue {
        match self {
            ParsedMarkdown::Post(markdown_post) => markdown_post.to_template_value(),
            ParsedMarkdown::File(markdown_file) => markdown_file.to_template_value(),
        }
    }
}
impl ToTemplateValue for Date {
    fn to_template_value(self) -> TemplateValue {
        TemplateValue::Date(self)
    }
}

impl ToTemplateValue for GalleryImage {
    fn to_template_value(self) -> TemplateValue {
        let mut base = hash_map! {
          "path" =>  self.path.to_template_value(),
          "height" => (self.height as i64).to_template_value(),
          "width" => (self.width as i64).to_template_value(),
        };

        if let Some(metadata) = self.metadata {
            base.insert("metadata", metadata.to_template_value());
        }

        base.to_template_value()
    }
}

impl ToTemplateValue for ExifMetadata {
    fn to_template_value(self) -> TemplateValue {
        let mut obj = HashMap::new();

        if let Some(value) = self.orientation {
            obj.insert("orientation".to_owned(), (value as i64).to_template_value());
        }
        if let Some(value) = self.model {
            obj.insert("model".to_owned(), value.to_template_value());
        }

        if let Some(value) = self.datetime_original {
            obj.insert("datetime_original".to_owned(), value.to_template_value());
        }
        if let Some(value) = self.iso {
            obj.insert("iso".to_owned(), (value as i64).to_template_value());
        }
        if let Some(value) = self.exposure_time {
            obj.insert(
                "exposure_time".to_owned(),
                format!("1/{}", 1.0 / value).to_template_value(),
            );
        }
        if let Some(value) = self.f_number {
            obj.insert(
                "f_number".to_owned(),
                format!("{value:.1}").to_template_value(),
            );
        }
        if let Some(value) = self.focal_length {
            obj.insert(
                "focal_length".to_owned(),
                format!("{value:.1}").to_template_value(),
            );
        }

        TemplateValue::Object(obj)
    }
}
