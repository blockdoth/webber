use std::borrow::Cow;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt::Debug;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::vec;

#[cfg(generated)]
use crate::comptime::{load_embedded_assets, load_embedded_templates};
use crate::runtime::assets::asset::{Asset, AssetData};
use crate::runtime::assets::image::GalleryImage;
use crate::runtime::assets::trie::Trie;
use crate::runtime::jpeg::errors::ImageParseError;
use crate::runtime::jpeg::errors::JpegError;
use crate::runtime::jpeg::exif::ExifMetadata;
use crate::runtime::jpeg::jpeg::Jpeg;
use crate::runtime::markdown;
use crate::runtime::markdown::parser::MarkdownPost;
use crate::runtime::markdown::parser::ParsedMarkdown;
use crate::runtime::misc::byte_stuff::split_mix_64_hash;
use crate::runtime::misc::date::Date;
use crate::runtime::server::router::DynamicRoute;
use crate::runtime::server::router::Router;
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
    // pub generated: Trie<TemplateValue>,
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
    pub fn update_asset_content(
        &self,
        context: &mut Context,
        dynamic_routes: Option<&mut HashMap<String, DynamicRoute>>,
    ) {
        self.update_gallery(context);
    }
    pub fn check_update(
        &mut self,
        context: &mut Context,
        dynamic_routes: &mut HashMap<String, DynamicRoute>,
        asset_path: &str,
        template_path: &str,
        generated_path: &str,
    ) -> Result<bool, TemplateError> {
        let assets_changed = match self.update_assets(asset_path, generated_path) {
            Ok(assets_changed) => {
                // if assets_changed {
                //     self.update_asset_content(context, Some(dynamic_routes));
                // }
                assets_changed
            }
            err => return err,
        };
        let templates_changed = match self.update_templates(template_path) {
            Ok(templates_changed) => templates_changed,
            err => return err,
        };

        Ok(templates_changed || assets_changed)
    }

    pub fn update_templates(&mut self, template_path: &str) -> Result<bool, TemplateError> {
        // TODO Delete and new logic
        let paths = walk_dir(template_path);
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

    pub fn update_assets(
        &mut self,
        asset_path: &str,
        generated_path: &str,
    ) -> Result<bool, TemplateError> {
        let mut paths = walk_dir(asset_path);
        paths.extend(walk_dir(generated_path));
        let mut changed = false;
        // println!("{paths:?}");
        for path in &paths {
            let last_modified = path.metadata()?.modified()?;
            let key_path = format!("{}", path.to_string_lossy());

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

        let current_paths_set: HashSet<String> = paths
            .into_iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect();

        let paths_to_delete: Vec<String> = self
            .assets
            .paths
            .difference(&current_paths_set)
            .cloned()
            .collect();

        for path in &paths_to_delete {
            println!("Removed file {path:?}");
            changed |= self.assets.remove(path);
        }
        self.assets.paths = current_paths_set;

        Ok(changed)
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

        let mut grouped: Vec<_> = grouped.into_iter().collect();

        grouped.sort_by_key(|(label, _)| {
            label
                .split_once('_')
                .and_then(|(n, _)| n.parse::<u32>().ok())
                .unwrap_or(u32::MAX)
        });

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
