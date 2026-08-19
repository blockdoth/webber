use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt::Debug;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::vec;

use crate::comptime::{ASSETS_PATH, TEMPLATES_PATH};
#[cfg(generated)]
use crate::comptime::{load_embedded_assets, load_embedded_templates};
use crate::runtime::assets::asset::{Asset, AssetData};
use crate::runtime::assets::trie::Trie;
use crate::runtime::jpeg::errors::ImageParseError;
use crate::runtime::jpeg::errors::JpegError;
use crate::runtime::jpeg::exif::ExifMetadata;
use crate::runtime::jpeg::jpeg::Jpeg;
use crate::runtime::markdown::parser::ParsedMarkdown;
use crate::runtime::misc::byte_stuff::split_mix_64_hash;
use crate::runtime::misc::date::Date;
use crate::runtime::templating::context::Context;
use crate::runtime::templating::context::TemplateContext;
use crate::runtime::templating::error::TemplateError;
use crate::runtime::templating::template::Template;
use crate::runtime::templating::values::{TemplateValue, ToTemplateValue};

// === Content ===

#[derive(Debug)]
pub struct Content {
    pub assets: Trie<Asset>,
    pub templates: HashMap<String, Result<Template, TemplateError>>,
}

impl Content {
    pub fn load_embedded() -> Self {
        #[cfg(generated)]
        let assets = load_embedded_assets();
        #[cfg(generated)]
        let templates = load_embedded_templates();
        #[cfg(not(generated))]
        // Stub to make the compiler happy
        let assets = Trie::new();
        #[cfg(not(generated))]
        let templates = HashMap::new();
        // assets
        Self { assets, templates }
    }
    pub fn update_asset_content(&self, context: &mut Context) {
        self.update_posts(context);
        self.update_quotes(context);
        self.update_pages(context);
        self.update_blogs(context);
        self.update_gallery(context);
    }
    pub fn check_update(&mut self, context: &mut Context) -> Result<bool, TemplateError> {
        let assets_changed = match self.update_assets() {
            Ok(assets_changed) => {
                if assets_changed {
                    self.update_asset_content(context);
                }
                assets_changed
            }
            err => return err,
        };
        let templates_changed = match self.update_templates() {
            Ok(templates_changed) => templates_changed,
            err => return err,
        };
        Ok(templates_changed || assets_changed)
    }

    pub fn update_templates(&mut self) -> Result<bool, TemplateError> {
        let paths = walk_dir(TEMPLATES_PATH);
        let mut is_new = true;
        let mut changed = false;
        for path in &paths {
            let last_modified = path.metadata()?.modified()?;
            let path_str = path.to_string_lossy();

            for (key, template_res) in &mut self.templates {
                match template_res {
                    Ok(template) => {
                        if template.origin_file == path_str {
                            is_new = false;
                            if template.last_modified < last_modified {
                                Template::update_from_path(template_res, path);
                                changed = true;

                                println!("Updated template {:?}, for page: {key:?}", path_str,);
                            }
                        }
                    }
                    Err(template_err) => {
                        if let Some(pos) = &template_err.pos
                            && let Some(info) = &template_err.info
                            && pos.file == path_str
                        {
                            is_new = false;
                            if info.last_modified < last_modified {
                                Template::update_from_path(template_res, path);
                                changed = true;

                                println!("Updated template {:?}, for page: {key:?}", path_str,);
                            }
                        }
                    }
                }
            }

            if is_new {
                let template = Template::from_path(path)?;
                println!("Added template {path_str:?}");
                self.templates.insert(path_str.to_string(), Ok(template));
                changed = true;
            }
        }
        Ok(changed)
    }

    pub fn update_assets(&mut self) -> Result<bool, TemplateError> {
        let paths = walk_dir(ASSETS_PATH);
        let mut changed = false;

        for path in &paths {
            let last_modified = path.metadata()?.modified()?;
            let key_path = format!(
                "/{}",
                path.strip_prefix(ASSETS_PATH)
                    .expect("Failed to strip prefix")
                    .to_string_lossy()
            );

            match self.assets.get_ref_mut(&key_path) {
                Some(existing_asset) if last_modified > existing_asset.last_modified => {
                    existing_asset.data = AssetData::read_asset(path)?;
                    existing_asset.last_modified = last_modified;
                    changed = true;

                    println!(
                        "Updated file {:?}, edited {} minutes ago",
                        path,
                        last_modified.elapsed().unwrap().as_secs() / 60
                    );
                }
                Some(_) => {} // File not changed
                None => {
                    let asset = AssetData::read_asset(path)?;
                    self.assets.insert(
                        key_path.to_string(),
                        Asset {
                            last_modified,
                            data: asset,
                            internal: false,
                        },
                    );
                    changed = true;

                    println!("Added file {:?}", key_path);
                }
            }
        }
        let str_paths = paths
            .iter()
            .map(|p| {
                format!(
                    "/{}",
                    p.strip_prefix(ASSETS_PATH)
                        .expect("Failed to strip prefix")
                        .to_string_lossy()
                )
            })
            .collect(); // Todo unfuck
        if self.assets.remove_other_than_except_generated(str_paths) {
            changed = true;
        }
        Ok(changed)
    }

    pub fn update_posts(&self, context: &mut Context) {
        fn publish_date(asset: &AssetData) -> Option<&Date> {
            match asset {
                AssetData::Markdown(Cow::Owned(ParsedMarkdown::Post(post)))
                | AssetData::Markdown(Cow::Borrowed(ParsedMarkdown::Post(post))) => {
                    post.metadata.published.as_ref().ok()
                }
                _ => None,
            }
        }

        let mut posts: Vec<AssetData> = self
            .assets
            .get_partial("/posts/")
            .into_iter()
            .map(|(_, p)| p.data.clone())
            .collect();

        posts.sort_by(|a, b| publish_date(b).cmp(&publish_date(a)));

        let post_values = posts.to_template_value();

        let mut posts_by_slug = HashMap::new();

        if let TemplateValue::List(list) = &post_values {
            for post in list {
                if let TemplateValue::Object(object) = post
                    && let Some(TemplateValue::Text(slug)) = object.get("slug")
                {
                    posts_by_slug.insert(slug.clone(), post.clone());
                }
            }
        }

        context
            .global_context
            .insert("posts".to_string(), post_values);

        context.global_context.insert(
            "posts_by_slug".to_string(),
            TemplateValue::Object(posts_by_slug),
        );
    }

    pub fn update_quotes(&self, context: &mut Context) {
        let quotes_asset = self
            .assets
            .get_ref("/quotes_collection")
            .expect("quotes asset must exist")
            .data
            .as_ref();

        let quotes_str = quotes_asset
            .as_str()
            .expect("quotes asset must contain text");

        let mut quotes = vec![];

        let mut rest = quotes_str;

        while let Some(quote_start) = rest.find('"') {
            rest = &rest[quote_start + 1..];

            let Some(quote_end) = rest.find('"') else {
                break;
            };

            let quote = rest[..quote_end].trim();
            rest = &rest[quote_end + 1..];

            let metadata = rest.trim_start();

            let Some(metadata) = metadata.trim_start().strip_prefix('~') else {
                continue;
            };

            let metadata_end = metadata.find('\n').unwrap_or(metadata.len());
            let metadata_line = metadata[..metadata_end].trim();

            let author;
            let description;

            if let Some((parsed_author, parsed_description)) = metadata_line.split_once(',') {
                author = parsed_author.trim();
                description = parsed_description.trim();
            } else {
                author = metadata_line.trim();
                description = "";
            }

            quotes.push(Quote {
                quote: quote.to_string(),
                author: author.to_string(),
                description: description.to_string(),
            });

            rest = &metadata[metadata_end..];
        }

        context
            .global_context
            .insert("quotes".to_owned(), quotes.to_template_value());
    }

    pub fn update_random_quote(&self, context: &mut Context, day: i64) {
        let quote_count = if let Some(TemplateValue::List(quotes)) = context.lookup("quotes") {
            quotes.len() as u64
        } else {
            return;
        };

        if quote_count == 0 {
            return;
        }

        if let Some(TemplateValue::Number(number)) = context.lookup_mut("random_quote_index") {
            *number = (split_mix_64_hash(day as u64) % quote_count) as i64;
        }
    }

    pub fn update_pages(&self, context: &mut Context) {
        let pages = self.assets.get_partial("/pages/");

        for (path, page) in pages {
            if let AssetData::Markdown(..) = page.data
                && let Some(stripped_path) = path.strip_suffix(".md")
                && let Some(stripped_path) = stripped_path.strip_prefix("/")
            {
                println!("{stripped_path}");
                let page_value = page.data.clone().to_template_value();
                context
                    .global_context
                    .insert(stripped_path.to_owned(), page_value);
            }
        }
    }
    pub fn update_blogs(&self, context: &mut Context) {
        if let Some(blogs) = self.assets.get_ref("cool_blogs")
            && let AssetData::Text(blogs) = &blogs.data
        {
            let blogs: Vec<String> = blogs.lines().map(str::to_owned).collect();
            context
                .global_context
                .insert("cool_blogs".to_owned(), blogs.to_template_value());
        }
    }
    pub fn update_gallery(&self, context: &mut Context) {
        let gallery_assets = self.assets.get_partial("/gallery/");

        let mut grouped: HashMap<String, Vec<GalleryImage>> = HashMap::new();

        for (path, image) in gallery_assets {
            let img = match &image.data {
                AssetData::Png(bin) => match GalleryImage::from_png(&path, bin) {
                    Ok(img) => img,
                    Err(err) => {
                        println!("{err:?}");
                        continue;
                    }
                },
                AssetData::Jpeg(bin) => match GalleryImage::from_jpg(&path, bin) {
                    Ok(img) => img,
                    Err(err) => {
                        println!("{err:?}");
                        continue;
                    }
                },
                _ => continue,
            };

            let path_buf = PathBuf::from(&path);

            let label = path_buf
                .parent()
                .and_then(|p| p.file_name())
                .and_then(|p| p.to_str())
                .unwrap_or("unlabelled")
                .to_owned();

            grouped.entry(label).or_default().push(img);
        }

        let mut gallery = vec![];

        for (label, photos) in grouped {
            let label = label.split('_').next_back().unwrap_or(&label).to_string();
            gallery.push(hash_map! {
                "label" => label.to_template_value(),
                "photos" => photos.to_template_value(),
            });
        }

        context
            .global_context
            .insert("gallery".to_owned(), gallery.to_template_value());
    }
}
pub fn walk_dir<P: AsRef<Path> + Debug>(rootdir: P) -> Vec<PathBuf> {
    let mut asset_paths = vec![];
    let mut stack = vec![rootdir.as_ref().to_path_buf()];

    while let Some(dir_path) = stack.pop() {
        let dir = match fs::read_dir(&dir_path) {
            Ok(dir) => dir,
            Err(error) => {
                println!("Error while trying to open asset dir at {rootdir:?}: {error}");
                continue;
            }
        };

        for file in dir {
            if let Ok(file) = file
                && let Ok(metadata) = file.metadata()
            {
                if metadata.is_dir() {
                    stack.push(file.path());
                    continue;
                }
                let file_path = file.path();
                asset_paths.push(file_path);
            }
        }
    }
    asset_paths
}

#[derive(Debug)]
pub struct GalleryImage {
    pub path: String,
    pub width: usize,
    pub height: usize,
    pub metadata: Option<ExifMetadata>,
}

impl GalleryImage {
    pub fn from_png(path: &str, bin: &[u8]) -> Result<Self, ImageParseError> {
        // println!("{:?}", &bin[..32]);
        use crate::runtime::jpeg::errors::ImageParseError::*;
        if bin.len() < 24 {
            return Err(BinaryBlobToShort);
        }

        if &bin[0..8] != b"\x89PNG\r\n\x1a\n" {
            return Err(InvalidPngSignature);
        }

        if &bin[12..16] != b"IHDR" {
            return Err(MissingIhdrChunk);
        }

        let width = u32::from_be_bytes(bin[16..20].try_into().expect("invariant")) as usize;

        let height = u32::from_be_bytes(bin[20..24].try_into().expect("invariant")) as usize;

        Ok(Self {
            path: path.to_owned(),
            width,
            height,
            metadata: None,
        })
    }

    pub fn from_jpg(path: &str, bytes: &[u8]) -> Result<Self, JpegError> {
        let (metadata, mut width, mut height) = Jpeg::decode_metadata(bytes)?;

        if let Some(metadata) = &metadata
            && matches!(metadata.orientation, Some(5..=8))
        {
            std::mem::swap(&mut width, &mut height)
        }

        Ok(GalleryImage {
            path: path.to_owned(),
            width,
            height,
            metadata,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Quote {
    pub quote: String,
    pub author: String,
    pub description: String,
}
