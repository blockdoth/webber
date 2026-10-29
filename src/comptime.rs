use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

use crate::CONFIG_PATH;
use crate::runtime::assets::content::walk_dir;
use crate::runtime::config::config::Config;
use crate::runtime::config::parser::TomlishValue;
use crate::runtime::misc::date::Date;
use crate::runtime::templating::values::TemplateValue;

#[cfg(generated)]
include!(concat!(env!("OUT_DIR"), "/generated.rs"));

pub const DEBUG_BIN_PATH: &str = "./target/debug/webber";
pub const RELEASE_BIN_PATH: &str = "./target/release/webber";

pub fn comptime() -> Result<(), Box<dyn Error>> {
    let config = Config::default().populate_file(CONFIG_PATH)?;
    cargo_flags(&config);

    // === Init ===
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let last_bin_path = Path::new(&out_dir).join("prev_bin");
    let generated_code_path = Path::new(&out_dir).join("generated.rs");
    let cwd = std::env::current_dir().expect("current dir");
    let cwd = cwd.to_string_lossy();

    let mut out = String::new();

    gen_imports(&mut out);
    gen_load_embedded_assets(&mut out, &cwd, &config);
    gen_load_embedded_templates(&mut out, &cwd, &config);
    prev_binary_discovery(&mut out, &last_bin_path)?;
    gen_git_commit_hash(&mut out);
    gen_build_info(&mut out);

    gen_config(&mut out, &config);

    fs::write(&generated_code_path, out).unwrap();
    Ok(())
}

fn cargo_flags(config: &Config) {
    println!("cargo:rustc-cfg=generated");

    println!("cargo:rerun-if-changed={DEBUG_BIN_PATH}");
    println!("cargo:rerun-if-changed={RELEASE_BIN_PATH}");
    println!("cargo:rerun-if-changed={}", config.assets_path);
    println!("cargo:rerun-if-changed={}", config.templates_path);
}

fn gen_config(out: &mut String, config: &Config) {
    let static_routes = config
        .static_routes
        .iter()
        .map(|(a, b)| format!("({a:?}.into(), {b:?}.into())"))
        .collect::<Vec<_>>()
        .join(", ");

    fn tomlish_value_to_owned_str(value: &TomlishValue) -> String {
        match value {
            TomlishValue::String(s) => format!("TomlishValue::String({s:?}.into())"),
            TomlishValue::Number(n) => format!("TomlishValue::Number({n})"),
            TomlishValue::Boolean(b) => format!("TomlishValue::Boolean({b})"),
            TomlishValue::Array(values) => {
                let values = values
                    .iter()
                    .map(tomlish_value_to_owned_str)
                    .collect::<Vec<_>>()
                    .join(", ");

                format!("TomlishValue::Array(vec![{values}])")
            }
            TomlishValue::Object(entries) => {
                let entries = entries
                    .iter()
                    .map(|(key, value)| {
                        format!(
                            "({key:?}.into(), vec![{}])",
                            value
                                .iter()
                                .map(tomlish_value_to_owned_str)
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ");

                format!("TomlishValue::Object([{entries}].into_iter().collect())")
            }
            TomlishValue::Path(path, flag) => {
                format!("TomlishValue::Path({path:?}.into(), {flag})")
            }
            TomlishValue::ContentPath(path, flag) => {
                format!("TomlishValue::ContentPath({path:?}.into(), {flag})")
            }
            TomlishValue::Route(route) => format!("TomlishValue::Route({route:?}.into())"),
        }
    }

    let variables = config
        .variables
        .iter()
        .map(|(key, value)| format!("({key:?}.into(), {})", tomlish_value_to_owned_str(value)))
        .collect::<Vec<_>>()
        .join(", ");

    let dynamic_routes =
        config.dynamic_routes.iter()
            .map(|(a, b)| {
                    let route = format!("{b:?}");
                    format!("({a:?}.into(), DynamicRouteConfig {{ template: {:?}.into(), context_var: {:?}.into(), bind: {:?}.into()}})", b.template, b.context_var, b.bind)
                }
            )
            .collect::<Vec<_>>()
            .join(", ");

    out.push_str("impl Config {\n");
    out.push_str("\tpub fn load_embeded_config() -> Self {\n");
    out.push_str("\t#[allow(clippy::unnecessary_map_on_constructor)]\n");
    out.push_str(&format!(
        "\t\tConfig {{
            host: {:?}.into(),
            port: {},
            domain: {:?}.into(),
            content_path: {:?}.into(),
            templates_path: {:?}.into(),
            assets_path: {:?}.into(),
            generated_path: {:?}.into(),
            fallback_route: {:?}.map(Into::into),
            error_template: {:?}.map(Into::into),
            rss_template: {:?}.map(Into::into),
            variables: vec![{}],
            static_routes: vec![{}],
            dynamic_routes: vec![{}],
        }}\n",
        config.host,
        config.port,
        config.domain,
        config.content_path,
        config.templates_path,
        config.assets_path,
        config.generated_path,
        config.fallback_route,
        // layout_template: {:?}.map(Into::into),

        // config.layout_template,
        config.error_template,
        config.rss_template,
        variables,
        static_routes,
        dynamic_routes,
    ));

    out.push_str("\t}\n");

    out.push_str("}\n");
    out.push('\n');
}

fn gen_imports(out: &mut String) {
    out.push_str("use crate::runtime::templating::parser::TemplateParser;\n");
    out.push_str("use crate::runtime::assets::asset::AssetData;\n");
    out.push_str("use crate::runtime::assets::asset::Asset;\n");
    out.push_str("use crate::runtime::assets::trie::Trie;\n");
    out.push_str("use crate::runtime::templating::template::Template;\n");
    out.push_str("use crate::runtime::templating::error::TemplateError;\n");
    out.push_str("use crate::runtime::markdown::parser::MarkdownParser;\n");
    out.push_str("use crate::runtime::config::config::DynamicRouteConfig;\n");
    out.push_str("use std::collections::HashMap;\n");
    out.push_str("use std::borrow::Cow;\n");
    out.push_str("use std::time::{UNIX_EPOCH, Duration};\n");
    out.push('\n');
}

fn gen_load_embedded_assets(out: &mut String, cwd: &str, config: &Config) {
    let asset_paths = walk_dir(&config.assets_path);

    out.push_str("pub fn load_embedded_assets() -> Trie<Asset>{\n");
    out.push_str("\tlet mut assets = Trie::new();\n");

    out.push_str("\tlet paths: Vec<(String, AssetData)> = vec![\n");
    for asset_path in asset_paths {
        let str_path = asset_path.to_string_lossy().into_owned();
        let global_path = format!("{cwd}/{}", str_path);
        let content_str = extension_to_asset_str(asset_path, &global_path);

        out.push_str(&format!(
            "\t\t(\"{str_path}\".to_string(),{content_str}),\n"
        ));
    }
    out.push_str("\t];\n");

    out.push_str("\tpaths.into_iter().for_each(|(key, content)| assets.insert(key, Asset::new(content, false)));\n");

    let mut generated_paths = walk_dir(&config.generated_path);

    out.push_str("\tlet paths: Vec<(String, AssetData)> = vec![\n");
    for generated_path in generated_paths {
        let str_path = generated_path.to_string_lossy().into_owned();
        let global_path = format!("{cwd}/{}", str_path);

        let content_str = extension_to_asset_str(generated_path, &global_path);

        out.push_str(&format!(
            "\t\t(\"{str_path}\".to_string(),{content_str}),\n"
        ));
    }
    out.push_str("\t];\n");

    out.push_str("\tpaths.into_iter().for_each(|(key, content)| assets.insert(key, Asset::new(content, true)));\n");

    let generated_paths = walk_dir(&config.generated_path);

    out.push_str("\tassets\n");
    out.push_str("}\n\n");
}

fn gen_load_embedded_templates(out: &mut String, cwd: &str, config: &Config) {
    let template_paths = walk_dir(&config.templates_path);

    out.push_str(
        "pub fn load_embedded_templates() -> HashMap<String, Result<Template,TemplateError>> {\n",
    );
    out.push_str("\tlet mut templates = HashMap::new();\n");

    out.push_str("\tlet paths: Vec<(&str, &str)>  = vec![\n");
    for template_path in template_paths {
        let path_key = template_path.to_string_lossy();
        let global_path = format!("{cwd}/{path_key}");
        let stripped_key = &path_key
            .strip_prefix(&config.templates_path)
            .expect("Failed to find prefix");

        let content_str = match template_path.extension().and_then(|s| s.to_str()) {
            Some("html") => &format!("include_str!({global_path:?})"),
            _ => continue,
        };
        out.push_str(&format!("\t\t({path_key:?},{content_str}),\n"));
    }
    out.push_str("\t];\n");

    out.push_str("\tpaths.into_iter().for_each(|(origin_file, template_str)| {templates.insert(origin_file.to_string(), TemplateParser::parse(template_str, origin_file));});\n");
    out.push_str("\ttemplates\n");
    out.push_str("}\n\n");
}

fn extension_to_asset_str(asset_path: PathBuf, global_path: &str) -> String {
    match asset_path.extension().and_then(|s| s.to_str()) {
        Some("png") => {
            format!("AssetData::Png(Cow::Borrowed(include_bytes!({global_path:?})))")
        }
        Some("ico") => {
            format!("AssetData::Ico(Cow::Borrowed(include_bytes!({global_path:?})))")
        }
        Some("jpg") | Some("jpeg") | Some("JPG") | Some("JPEG") => {
            format!("AssetData::Jpeg(Cow::Borrowed(include_bytes!({global_path:?})))")
        }
        Some("woff2") => {
            format!("AssetData::Woff2(Cow::Borrowed(include_bytes!({global_path:?})))")
        }
        Some("otf") => {
            format!("AssetData::Otf(Cow::Borrowed(include_bytes!({global_path:?})))")
        }
        Some("md") => {
            format!(
                "AssetData::Markdown(Cow::Owned(MarkdownParser::parse(include_str!({global_path:?}))))"
            )
        }
        Some("html") => {
            format!("AssetData::Html(Cow::Borrowed(include_str!({global_path:?})))")
        }
        Some("txt") => {
            format!("AssetData::Text(Cow::Borrowed(include_str!({global_path:?})))")
        }
        Some("css") => {
            format!("AssetData::Css(Cow::Borrowed(include_str!({global_path:?})))")
        }
        Some("js") => {
            format!("AssetData::Js(Cow::Borrowed(include_str!({global_path:?})))")
        }
        _ => {
            format!("AssetData::Text(Cow::Borrowed(include_str!({global_path:?})))")
        }
    }
}

fn prev_binary_discovery(out: &mut String, last_bin_path: &PathBuf) -> Result<(), Box<dyn Error>> {
    // Db
    let debug_path = PathBuf::from(DEBUG_BIN_PATH);
    let release_path = PathBuf::from(RELEASE_BIN_PATH);

    let bin_tupple = match (debug_path.exists(), release_path.exists()) {
        (true, false) => Some((debug_path, true)),
        (false, true) => Some((release_path, false)),

        (true, true) => {
            if fs::metadata(&debug_path)?.modified()? > fs::metadata(&release_path)?.modified()? {
                Some((debug_path, true))
            } else {
                Some((release_path, false))
            }
        }

        (false, false) => None,
    };

    if let Some((prev_bin_path, is_debug)) = bin_tupple {
        fs::copy(&prev_bin_path, last_bin_path)?;

        println!(
            "cargo:warning=embedded db from previous binary: \"{}\"",
            prev_bin_path.display()
        );

        if is_debug {
            out.push_str("pub const PREV_BIN_TYPE: Option<&str> = Some(\"debug\");\n");
        } else {
            out.push_str("pub const PREV_BIN_TYPE: Option<&str> = Some(\"release\");\n");
        }

        out.push_str(&format!(
            "pub const PREV_BIN_PATH: Option<&str> = Some({last_bin_path:?});\n"
        ));
    } else {
        println!("cargo:warning=no existing selfmod binary found");

        out.push_str("pub const PREV_BIN_TYPE: Option<&str> = None;\n");
        out.push_str("pub const PREV_BIN_PATH: Option<&str> = None;\n");
    };
    out.push('\n');
    Ok(())
}

fn gen_git_commit_hash(out: &mut String) {
    let long = if let Ok(hash) = env::var("WEBBER_GIT_REV") {
        hash
    } else {
        Command::new("git")
            .args(["rev-parse", "HEAD"])
            .output()
            .ok()
            .and_then(|out| String::from_utf8(out.stdout).ok())
            .map(|s| s.trim().to_string())
            .expect("unable to get git hash")
    };

    let short: String = long.chars().take(7).collect();

    out.push_str(&format!("pub const GIT_HASH_SHORT:&str = {short:?};\n"));
    out.push_str(&format!("pub const GIT_HASH_LONG:&str = {long:?};\n"));
    out.push('\n');
}

fn gen_build_info(out: &mut String) {
    let unix_timestamp = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    out.push_str("pub fn last_build_date() -> SystemTime {\n");
    out.push_str(&format!(
        "\tUNIX_EPOCH + Duration::from_secs({unix_timestamp})\n"
    ));
    out.push_str("}\n");
    out.push('\n');
}
