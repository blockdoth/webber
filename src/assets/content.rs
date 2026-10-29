use std::borrow::Cow;
use std::collections::HashMap;
use std::collections::HashSet;
use std::error::Error;
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
use crate::runtime::config::parser::insert_nested;
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

        Self { assets, templates }
    }

    pub fn check_update(
        &mut self,
        context: &mut Context,
        dynamic_routes: &mut HashMap<String, DynamicRoute>,
        asset_path: &str,
        template_path: &str,
        generated_path: &str,
    ) -> Result<bool, TemplateError> {
        let (assets_changed, updated) = self.update_assets(asset_path, generated_path)?;

        if assets_changed {
            self.update_asset_content(context, &updated, asset_path)
                .expect("fix later");
        }

        let templates_changed = self.update_templates(template_path)?;

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
    ) -> Result<(bool, Vec<PathBuf>), TemplateError> {
        let mut paths = walk_dir(asset_path);
        paths.extend(walk_dir(generated_path));

        let current_paths_set: HashSet<String> = paths
            .iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect();

        let mut changed = false;
        let mut updated = vec![];

        for path in paths {
            let last_modified = path.metadata()?.modified()?;
            let key_path = format!("{}", path.to_string_lossy());

            match self.assets.get_ref_mut(&key_path) {
                Some(existing_asset) if last_modified > existing_asset.last_modified => {
                    existing_asset.data = AssetData::read_asset(&path)?;
                    existing_asset.last_modified = last_modified;
                    changed = true;

                    println!(
                        "Updated file {:?}, edited {} minutes ago",
                        path,
                        last_modified.elapsed().unwrap().as_secs() / 60
                    );
                    updated.push(path);
                }
                Some(_) => {} // File not changed
                None => {
                    let asset = AssetData::read_asset(&path)?;
                    self.assets.insert(
                        key_path.to_string(),
                        Asset {
                            last_modified,
                            data: asset,
                            internal: false,
                        },
                    );
                    changed = true;
                    updated.push(path);

                    println!("Added file {:?}", key_path);
                }
            }
        }

        let paths_to_delete: Vec<String> = self
            .assets
            .paths
            .difference(&current_paths_set)
            .cloned()
            .collect();

        for path in &paths_to_delete {
            updated.push(PathBuf::from(path));
            println!("Removed file {path:?}");
            changed |= self.assets.remove(path);
        }
        self.assets.paths = current_paths_set;

        Ok((changed, updated))
    }

    pub fn update_asset_content(
        &self,
        context: &mut Context,
        updated: &[PathBuf],
        asset_path: &str,
    ) -> Result<(), ImageParseError> {
        for (var_asset_path_str, var_name) in &context.generated_to_asset_map.clone() {
            // TODO remove very bad clone
            let var_asset_path = Path::new(var_asset_path_str);
            let candidates: Vec<&PathBuf> = updated
                .iter()
                .filter(|path| path.starts_with(var_asset_path) || var_asset_path.starts_with(path))
                .collect();

            if !candidates.is_empty()
                && let Some(mut var) = context.lookup_mut(var_name)
            {
                let assets = self.assets.get_partial(var_asset_path_str);

                if let [(path, new)] = assets.as_slice() {
                    *var = new
                        .data
                        .clone()
                        .to_template_value_with_path(path, asset_path)?;
                } else {
                    let mut object = HashMap::new();
                    for (path, asset) in assets {
                        if let Some(stripped) = path.strip_prefix(var_asset_path_str) {
                            let components: Vec<String> = Path::new(stripped)
                                .components()
                                .map(|component| {
                                    component.as_os_str().to_string_lossy().into_owned()
                                })
                                .collect();

                            insert_nested(
                                &mut object,
                                &components,
                                asset
                                    .data
                                    .clone()
                                    .to_template_value_with_path(&path, asset_path)?,
                            );
                        }
                    }
                    *var = object.to_template_value();
                }
            }
        }
        Ok(())
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
