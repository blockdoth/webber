use std::{collections::HashMap, env, error::Error, fs};

use crate::runtime::{
    assets::content::Content,
    config::parser::{Tomlish, TomlishValue},
    templating::values::{TemplateValue, ToTemplateValue},
};

#[derive(Debug)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub domain: String,

    pub content_path: String,
    pub templates_path: String,
    pub assets_path: String,
    pub generated_path: String,

    pub fallback_route: Option<String>,
    // pub layout_template: Option<String>,
    pub error_template: Option<String>,
    pub rss_template: Option<String>,

    pub variables: Vec<(String, TomlishValue)>,
    pub static_routes: Vec<(String, String)>,
    pub dynamic_routes: Vec<(String, DynamicRouteConfig)>,
}

#[derive(Debug)]
pub struct DynamicRouteConfig {
    pub template: String,
    pub context_var: String,
    pub bind: String,
}

impl Config {
    pub fn populate_env(mut self) -> Self {
        if let Ok(host) = env::var("WEBBER_HOST") {
            self.host = host;
        }

        if let Some(port) = env::var("WEBBER_PORT")
            .ok()
            .and_then(|p| p.parse::<u16>().ok())
        {
            self.port = port;
        }

        if let Ok(domain) = env::var("WEBBER_DOMAIN") {
            self.domain = domain;
        } else {
            self.domain = format!("{}:{}", self.host, self.port);
        }
        self
    }

    pub fn default() -> Self {
        let host = "127.0.0.1".into();
        let port = 4000;
        Self {
            domain: format!("{host}:{port}"),
            host,
            port,
            content_path: "content".into(),
            templates_path: "content/templates".into(),
            assets_path: "content/assets".into(),
            generated_path: "content/gen".into(),
            fallback_route: None,
            // layout_template: None,
            error_template: None,
            rss_template: None,
            variables: vec![],
            static_routes: vec![],
            dynamic_routes: vec![],
        }
    }

    pub fn populate_file(mut self, path: &str) -> Result<Self, Box<dyn Error>> {
        let string = fs::read_to_string(path)?;
        let sections = Tomlish::parse_tomlish(&string)?;

        // Hack to make sure content_path is always set first
        if let Some(list) = sections.get("data_dirs")
            && let Some((_, TomlishValue::Path(v, true))) =
                list.iter().find(|(k, _)| *k == "content")
        {
            self.content_path = v.into();
        }

        for (section, entries) in sections {
            for (key, value) in entries {
                match section {
                    "server" => match (key, value) {
                        ("host", TomlishValue::String(v)) => self.host = v,
                        ("port", TomlishValue::Number(v)) => self.port = v.try_into()?,
                        ("domain", TomlishValue::String(v)) => self.domain = v,
                        (key, _) => {
                            return Err(
                                format!("Invalid value or unknown key in [server]: {key}").into()
                            );
                        }
                    },

                    "data_dirs" => match (key, value) {
                        ("content", TomlishValue::Path(v, _)) => self.content_path = v,
                        ("templates", TomlishValue::ContentPath(v, _)) => {
                            self.templates_path = format!("{}/{}", self.content_path, v)
                        }
                        ("assets", TomlishValue::ContentPath(v, _)) => {
                            self.assets_path = format!("{}/{}", self.content_path, v)
                        }
                        ("generated", TomlishValue::ContentPath(v, _)) => {
                            self.generated_path = format!("{}/{}", self.content_path, v)
                        }
                        (key, _) => {
                            return Err(
                                format!("Invalid value or unknown key in [dirs]: {key}").into()
                            );
                        }
                    },

                    "structure" => match (key, value) {
                        ("fallback", TomlishValue::Route(v)) => self.fallback_route = Some(v),
                        // ("layout", TomlishValue::ContentPath(v, _)) => {
                        //     self.layout_template = Some(format!("{}/{}", self.content_path, v))
                        // }
                        ("error", TomlishValue::ContentPath(v, _)) => {
                            self.error_template = Some(format!("{}/{}", self.content_path, v))
                        }
                        ("rss", TomlishValue::ContentPath(v, _)) => {
                            self.rss_template = Some(format!("{}/{}", self.content_path, v))
                        }
                        (key, _) => {
                            return Err(format!(
                                "Invalid value or unknown key in [structure]: {key}"
                            )
                            .into());
                        }
                    },

                    "variables" => self.variables.push((
                        key.to_owned(),
                        match value {
                            TomlishValue::ContentPath(path, is_dir) => TomlishValue::ContentPath(
                                format!("{}/{}", self.content_path, path),
                                is_dir,
                            ),
                            v => v,
                        },
                    )),

                    "static_routes" => match value {
                        TomlishValue::ContentPath(v, _) => self
                            .static_routes
                            .push((key.to_owned(), format!("{}/{}", self.content_path, v))),
                        _ => {
                            return Err(
                                format!("Expected content path for static route: {key}").into()
                            );
                        }
                    },

                    "dynamic_routes" => match value {
                        TomlishValue::Object(mut fields) => {
                            let template = match fields.remove("template") {
                                Some(mut values) => match values.pop() {
                                    Some(TomlishValue::ContentPath(v, _)) => {
                                        format!("{}/{}", self.content_path, v)
                                    }
                                    _ => {
                                        return Err(
                                            format!("Invalid template for route {key}").into()
                                        );
                                    }
                                },
                                None => {
                                    return Err(format!("Missing template for route {key}").into());
                                }
                            };

                            let context_var = match fields.remove("context_var") {
                                Some(mut values) => match values.pop() {
                                    Some(TomlishValue::String(v)) => v,
                                    _ => {
                                        return Err(
                                            format!("Invalid context_var for route {key}").into()
                                        );
                                    }
                                },
                                None => {
                                    return Err(
                                        format!("Missing context_var for route {key}").into()
                                    );
                                }
                            };

                            let bind = match fields.remove("bind") {
                                Some(mut values) => match values.pop() {
                                    Some(TomlishValue::String(v)) => v,
                                    _ => return Err(format!("Invalid bind for route {key}").into()),
                                },
                                None => return Err(format!("Missing bind for route {key}").into()),
                            };

                            self.dynamic_routes.push((
                                key.to_owned(),
                                DynamicRouteConfig {
                                    template,
                                    context_var,
                                    bind,
                                },
                            ));
                        }
                        _ => return Err(format!("Expected object for dynamic route: {key}").into()),
                    },

                    _ => return Err(format!("Unknown section: {section}").into()),
                }
            }
        }

        Ok(self)
    }
}
