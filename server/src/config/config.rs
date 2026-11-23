use std::{env, error::Error, fs};

use crate::runtime::{
    config::parser::{Tomlish, TomlishValue},
    server::ratelimiter::{RateLimit, RateLimiter},
};

#[derive(Debug)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub domain: String,
    pub rate_limit_ip: Option<u64>,
    pub burst_limit_ip: Option<u64>,
    pub rate_limit_path: Option<u64>,
    pub burst_limit_path: Option<u64>,

    pub content_path: String,
    pub templates_path: String,
    pub assets_path: String,
    pub generated_path: String,
    pub api_lib_path: String,
    // pub path_rate_limits: HashMap<String, u16>,
    pub fallback_route: Option<String>,
    // pub layout_template: Option<String>,
    pub error_template: Option<String>,
    pub rss_template: Option<String>,

    pub variables: Vec<(String, TomlishValue)>,
    pub static_routes: Vec<(String, StaticRouteConfig)>,
    pub dynamic_routes: Vec<(String, DynamicRouteConfig)>,
}

#[derive(Debug)]
pub struct StaticRouteConfig {
    pub path: String,
    pub rate_limit: Option<RateLimit>,
}

#[derive(Debug)]
pub struct DynamicRouteConfig {
    pub template: String,
    pub context_var: String,
    pub bind: String,
    pub rate_limit: Option<RateLimit>,
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
            rate_limit_ip: None,
            burst_limit_ip: None,
            rate_limit_path: None,
            burst_limit_path: None,
            content_path: "content".into(),
            templates_path: "content/templates".into(),
            assets_path: "content/assets".into(),
            generated_path: "content/gen".into(),
            api_lib_path: "api".into(),
            fallback_route: None,
            // layout_template: None,
            error_template: None,
            rss_template: None,
            variables: vec![],
            static_routes: vec![],
            dynamic_routes: vec![],
            // path_rate_limits: HashMap::new()
        }
    }

    pub fn from_file(path: &str) -> Result<Self, Box<dyn Error>> {
        let mut base = Config::default();

        let string = fs::read_to_string(path)?;
        let tomlish = Tomlish::parse_tomlish(&string)?;

        // Hack to make sure content_path is always set first
        if let Some(list) = tomlish.get("data_dirs")
            && let Some((_, TomlishValue::Path(v, true))) =
                list.iter().find(|(k, _)| *k == "content")
        {
            base.content_path = v.into();
        }

        for (section, entries) in tomlish {
            for (key, value) in entries {
                match section {
                    "server" => match (key, value) {
                        ("host", TomlishValue::String(v)) => base.host = v,
                        ("port", TomlishValue::Number(v)) => base.port = v.try_into()?,
                        ("domain", TomlishValue::String(v)) => base.domain = v,

                        (key, _) => {
                            return Err(
                                format!("Invalid value or unknown key in [server]: {key}").into()
                            );
                        }
                    },
                    "rate_limits" => match (key, value) {
                        ("ip_rate", TomlishValue::Number(n)) => {
                            if n > 0 {
                                base.rate_limit_ip = Some(n as u64);
                            } else {
                                return Err(format!("Ip rate limit must be positive: {n}").into());
                            }
                        }
                        ("ip_burst", TomlishValue::Number(n)) => {
                            if n > 0 {
                                base.burst_limit_ip = Some(n as u64);
                            } else {
                                return Err(format!("Ip burst limit must be positive: {n}").into());
                            }
                        }
                        ("path_rate", TomlishValue::Number(n)) => {
                            if n > 0 {
                                base.rate_limit_path = Some(n as u64);
                            } else {
                                return Err(format!("Path rate limit must be positive: {n}").into());
                            }
                        }
                        ("path_burst", TomlishValue::Number(n)) => {
                            if n > 0 {
                                base.burst_limit_path = Some(n as u64);
                            } else {
                                return Err(
                                    format!("Path burst limit must be positive: {n}").into()
                                );
                            }
                        }
                        (key, _) => {
                            return Err(
                                format!("Invalid value or unknown key in [server]: {key}").into()
                            );
                        }
                    },
                    "dirs" => match (key, value) {
                        ("content", TomlishValue::Path(v, _)) => base.content_path = v,
                        ("templates", TomlishValue::ContentPath(v, _)) => {
                            base.templates_path = format!("{}/{}", base.content_path, v)
                        }
                        ("assets", TomlishValue::ContentPath(v, _)) => {
                            base.assets_path = format!("{}/{}", base.content_path, v)
                        }
                        ("generated", TomlishValue::ContentPath(v, _)) => {
                            base.generated_path = format!("{}/{}", base.content_path, v)
                        }
                        ("api", TomlishValue::Path(v, _)) => base.api_lib_path = v,
                        (key, _) => {
                            return Err(
                                format!("Invalid value or unknown key in [dirs]: {key}").into()
                            );
                        }
                    },

                    "structure" => match (key, value) {
                        ("fallback", TomlishValue::Route(v)) => base.fallback_route = Some(v),
                        // ("layout", TomlishValue::ContentPath(v, _)) => {
                        //     self.layout_template = Some(format!("{}/{}", self.content_path, v))
                        // }
                        ("error", TomlishValue::ContentPath(v, _)) => {
                            base.error_template = Some(format!("{}/{}", base.content_path, v))
                        }
                        ("rss", TomlishValue::ContentPath(v, _)) => {
                            base.rss_template = Some(format!("{}/{}", base.content_path, v))
                        }
                        (key, _) => {
                            return Err(format!(
                                "Invalid value or unknown key in [structure]: {key}"
                            )
                            .into());
                        }
                    },

                    "variables" => base.variables.push((
                        key.to_owned(),
                        match value {
                            TomlishValue::ContentPath(path, is_dir) => TomlishValue::ContentPath(
                                format!("{}/{}", base.content_path, path),
                                is_dir,
                            ),
                            v => v,
                        },
                    )),

                    "static_routes" => match value {
                        TomlishValue::ContentPath(v, _) => base.static_routes.push((
                            key.to_owned(),
                            StaticRouteConfig {
                                path: format!("{}/{}", base.content_path, v),
                                rate_limit: None,
                            },
                        )),
                        TomlishValue::Object(obj) => {
                            let path = match obj.get("path") {
                                Some(TomlishValue::ContentPath(v, _)) => {
                                    format!("{}/{}", base.content_path, v)
                                }
                                _ => {
                                    return Err(format!(
                                        "Expected content path for static route: {key}"
                                    )
                                    .into());
                                }
                            };

                            let rate_limit = match obj.get("rate_limit") {
                                Some(TomlishValue::Number(n)) if *n >= 0 => Some(*n as u64),
                                None => None,
                                _ => {
                                    return Err(format!(
                                        "Invalid rate limit for static route: {key}"
                                    )
                                    .into());
                                }
                            };

                            let burst_limit = match obj.get("burst_limit") {
                                Some(TomlishValue::Number(n)) if *n >= 0 => Some(*n as u64),
                                None => None,
                                _ => {
                                    return Err(format!(
                                        "Invalid burst limit for static route: {key}"
                                    )
                                    .into());
                                }
                            };

                            base.static_routes.push((
                                key.to_owned(),
                                StaticRouteConfig {
                                    path,
                                    rate_limit: RateLimiter::make_rate_limit(
                                        rate_limit,
                                        burst_limit,
                                    ),
                                },
                            ));
                        }
                        _ => {
                            return Err(
                                format!("Expected content path for static route: {key}").into()
                            );
                        }
                    },

                    "dynamic_routes" => match value {
                        TomlishValue::Object(mut fields) => {
                            let template = match fields.get("template") {
                                Some(TomlishValue::ContentPath(v, _)) => {
                                    format!("{}/{}", base.content_path, v)
                                }
                                Some(tomlish) => {
                                    return Err(format!(
                                        "Invalid value for route config {key}: {tomlish:?}"
                                    )
                                    .into());
                                }
                                None => {
                                    return Err(format!("Missing template for route {key}").into());
                                }
                            };

                            let context_var = match fields.remove("context_var") {
                                Some(TomlishValue::String(v)) => v,

                                Some(tomlish) => {
                                    return Err(format!(
                                        "Invalid context_var for route {key}: {tomlish:?}"
                                    )
                                    .into());
                                }
                                None => {
                                    return Err(
                                        format!("Missing context_var for route {key}").into()
                                    );
                                }
                            };

                            let bind = match fields.remove("bind") {
                                Some(TomlishValue::String(v)) => v,
                                Some(tomlish) => {
                                    return Err(format!(
                                        "Invalid bind for route {key}: {tomlish:?}"
                                    )
                                    .into());
                                }
                                None => return Err(format!("Missing bind for route {key}").into()),
                            };

                            let rate_limit = match fields.get("rate_limit") {
                                Some(TomlishValue::Number(n)) if *n >= 0 => Some(*n as u64),
                                None => None,
                                _ => {
                                    return Err(format!(
                                        "Invalid rate limit for static route: {key}"
                                    )
                                    .into());
                                }
                            };

                            let burst_limit = match fields.get("burst_limit") {
                                Some(TomlishValue::Number(n)) if *n >= 0 => Some(*n as u64),
                                None => None,
                                _ => {
                                    return Err(format!(
                                        "Invalid burst limit for static route: {key}"
                                    )
                                    .into());
                                }
                            };
                            base.dynamic_routes.push((
                                key.to_owned(),
                                DynamicRouteConfig {
                                    template,
                                    context_var,
                                    bind,
                                    rate_limit: RateLimiter::make_rate_limit(
                                        rate_limit,
                                        burst_limit,
                                    ),
                                },
                            ));
                        }
                        _ => return Err(format!("Expected object for dynamic route: {key}").into()),
                    },

                    _ => {
                        println!("Skipped unknown section: {section}");
                    }
                }
            }
        }

        Ok(base)
    }
}
