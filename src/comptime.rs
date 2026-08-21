use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::runtime::assets::content::walk_dir;

#[cfg(generated)]
include!(concat!(env!("OUT_DIR"), "/generated.rs"));

pub const DEBUG_BIN_PATH: &str = "./target/debug/webber";
pub const RELEASE_BIN_PATH: &str = "./target/release/webber";
pub const ASSETS_PATH: &str = "./assets/";
pub const TEMPLATES_PATH: &str = "./templates/";

pub fn comptime() -> Result<(), Box<dyn Error>> {
    println!("cargo:rustc-cfg=generated");
    println!("cargo:rerun-if-changed={ASSETS_PATH}");
    println!("cargo:rerun-if-changed={TEMPLATES_PATH}");
    println!("cargo:rerun-if-changed={DEBUG_BIN_PATH}");
    println!("cargo:rerun-if-changed={RELEASE_BIN_PATH}");

    // === Init ===
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let last_bin_path = Path::new(&out_dir).join("prev_bin");
    let generated_code_path = Path::new(&out_dir).join("generated.rs");
    let cwd = std::env::current_dir().expect("current dir");
    let cwd = cwd.to_string_lossy();

    let asset_paths = walk_dir(ASSETS_PATH);

    let mut out = String::new();

    //  === Assets ===
    out.push_str("use crate::runtime::templating::parser::TemplateParser;\n");
    out.push_str("use crate::runtime::assets::asset::AssetData;\n");
    out.push_str("use crate::runtime::assets::asset::Asset;\n");
    out.push_str("use crate::runtime::assets::trie::Trie;\n");
    out.push_str("use crate::runtime::templating::template::Template;\n");
    out.push_str("use crate::runtime::markdown::parser::MarkdownParser;\n");
    out.push_str("use crate::runtime::templating::error::TemplateError;\n");
    out.push_str("use std::collections::HashMap;\n");
    out.push_str("use std::borrow::Cow;\n");

    out.push_str("pub fn load_embedded_assets() -> Trie<Asset>{\n");
    out.push_str("\tlet mut assets = Trie::new();\n");

    out.push_str("\tlet paths = vec![\n");
    for asset_path in asset_paths {
        let global_path = format!("{cwd}/{}", asset_path.to_string_lossy());
        let str_path = asset_path
            .strip_prefix(ASSETS_PATH)
            .expect("Failed to strip prefix")
            .to_string_lossy()
            .into_owned();

        let content_str = match asset_path.extension().and_then(|s| s.to_str()) {
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
        };

        out.push_str(&format!(
            "\t\t(\"/{str_path}\".to_string(),{content_str}),\n"
        ));
    }
    out.push_str("\t];\n");

    out.push_str("\tfor (key, content) in paths {\n");
    out.push_str("\t\tassets.insert(key,Asset::new(content));\n");
    out.push_str("\t}\n");

    out.push_str("\tassets\n");
    out.push_str("}\n");

    out.push('\n');

    // === Templates ===

    let template_paths = walk_dir(TEMPLATES_PATH);

    out.push_str(
        "pub fn load_embedded_templates() -> HashMap<String, Result<Template,TemplateError>> {\n",
    );
    out.push_str("\tlet mut templates = HashMap::new();\n");

    out.push_str("\tlet paths = vec![\n");
    for template_path in template_paths {
        let path_key = template_path.to_string_lossy();
        let global_path = format!("{cwd}/{path_key}");
        let stripped_key = path_key
            .strip_prefix(TEMPLATES_PATH)
            .expect("Failed to find prefix");

        let content_str = match template_path.extension().and_then(|s| s.to_str()) {
            Some("html") => &format!("include_str!({global_path:?})"),
            _ => continue,
        };
        out.push_str(&format!(
            "\t\t({path_key:?},{stripped_key:?},{content_str}),\n"
        ));
    }
    out.push_str("\t];\n");

    out.push_str("\tfor (origin_file, key, template_str) in paths {\n");
    out.push_str("\t\tlet template = TemplateParser::parse(template_str, origin_file);\n");

    out.push_str("\t\ttemplates.insert(key.to_string(),template);\n");
    out.push_str("\t}\n");

    out.push_str("\ttemplates\n");
    out.push_str("}\n");

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
        fs::copy(&prev_bin_path, &last_bin_path)?;

        println!(
            "cargo:warning=embedded db from previous binary: \"{}\"",
            prev_bin_path.display()
        );

        if is_debug {
            out.push_str("pub static PREV_BIN_TYPE: Option<&str> = Some(\"debug\");\n");
        } else {
            out.push_str("pub static PREV_BIN_TYPE: Option<&str> = Some(\"release\");\n");
        }

        out.push_str(&format!(
            "pub static PREV_BIN_PATH: Option<&str> = Some({last_bin_path:?});\n"
        ));
    } else {
        println!("cargo:warning=no existing selfmod binary found");

        out.push_str("pub static PREV_BIN_TYPE: Option<&str> = None;\n");
        out.push_str("pub static PREV_BIN_PATH: Option<&str> = None;\n");
    };

    // === Git ===
    let (short, long) = get_commit_hash();

    out.push_str(&format!("pub const GIT_HASH_SHORT:&str = {short:?};\n"));
    out.push_str(&format!("pub const GIT_HASH_LONG:&str = {long:?};\n"));

    fs::write(&generated_code_path, out).unwrap();
    // println!("cargo:warning=End of build script");
    Ok(())
}

fn get_commit_hash() -> (String, String) {
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

    let short = long.chars().take(7).collect();

    (short, long)
}
