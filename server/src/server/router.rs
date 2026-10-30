use std::collections::HashMap;
use std::fmt::Debug;
use std::vec;

use crate::runtime::assets::asset::{AssetData, AssetDataRef};
use crate::runtime::assets::content::Content;
use crate::runtime::config::config::{Config, DynamicRouteConfig};
use crate::runtime::db::db::Db;
use crate::runtime::server::api::Api;
use crate::runtime::server::error::{HttpResponseCode, HttpServerError};
use crate::runtime::server::server::HttpRequestHeader;
use crate::runtime::templating::context::{Context, LocalContext, TemplateContext};
use crate::runtime::templating::error::{self, TemplateError};
use crate::runtime::templating::template::Template;
use crate::runtime::templating::values::{TemplateValue, ToTemplateValue};

// === Router ===

#[derive(Debug)]
pub struct DynamicRoute {
    pub base_dir: String,
    pub page_var_name: String,
    pub page_var_key: String,
    pub list_var_name: String,
    pub template_path: String,
    pub slug: String,
}

#[derive(Debug, Clone)]
pub struct StaticRoute {
    pub path: String,
    pub hidden: bool,
}

impl StaticRoute {
    pub fn new(path: &str, hidden: bool) -> Self {
        Self {
            path: path.to_owned(),
            hidden,
        }
    }
}

#[derive(Debug)]
pub struct Router<'a> {
    pub content: Content,
    pub context: Context,
    pub db: &'a mut Db,
    pub static_routes: HashMap<String, StaticRoute>,
    pub dynamic_routes: HashMap<String, DynamicRoute>,

    pub fallback: Option<String>,
    pub error_page: Option<String>,
    pub rss_template: Option<String>,

    pub asset_path: String,
    pub template_path: String,
    pub generated_path: String,

    pub api: Api,
}

impl<'a> Router<'a> {
    // pub fn new(content: Content, context: Context, db: Db) -> Self {
    //     Router {
    //         content,
    //         context,
    //         db,
    //         static_routes: HashMap::new(),
    //         dynamic_routes: HashMap::new(),
    //         fallback: None,
    //         error_page: None,
    //         rss_template: None,
    //     }
    // }

    pub fn from_config(config: Config, content: Content, context: Context, db: &'a mut Db) -> Self {
        let mut router = Router {
            content,
            context,
            db,
            static_routes: HashMap::new(),
            dynamic_routes: HashMap::new(),
            fallback: None,
            error_page: None,
            rss_template: None,
            asset_path: config.assets_path,
            template_path: config.templates_path,
            generated_path: config.generated_path,
            api: Api::new(),
        };

        if let Some(fallback) = config.fallback_route {
            router = router.fallback(&fallback)
        };

        if let Some(error) = config.error_template {
            router = router.error_page(&error)
        };

        for (route, template_path) in config.static_routes {
            router = router.route_static_page(&route, &template_path);
        }

        for (
            route,
            DynamicRouteConfig {
                template,
                context_var,
                bind,
            },
        ) in config.dynamic_routes
        {
            router = router.route_dynamic_pages(&route, &context_var, &bind, &template);
        }
        if let Some(rss) = config.rss_template {
            router = router.rss(&rss)
        };

        router
    }

    pub fn add_to_static_pages(context: &mut Context, obj: TemplateValue) {
        if let Some(pages) = context.lookup_mut("pages-static") {
            match pages {
                TemplateValue::List(list) => list.push(obj),
                _ => panic!("\"pages-static\" overwrote by wrong type"),
            }
        } else {
            context.insert_global("pages-static", vec![obj]);
        }
    }

    pub fn route_static_page(mut self, path: &str, template: &str) -> Self {
        let route = StaticRoute::new(template, false);
        self.static_routes.insert(path.into(), route.clone());
        let name = path.split('/').next_back().expect("valid path");

        let obj = hash_map! {
          "url".to_string() => path.to_string().to_template_value(),
          "hidden".to_string() => route.hidden.to_template_value(),
          "name".to_string() => name.to_string().to_template_value(),
        };

        Self::add_to_static_pages(&mut self.context, obj.to_template_value());

        self
    }

    pub fn route_static_hidden(mut self, path: &str, template: &str) -> Self {
        self.static_routes
            .insert(path.into(), StaticRoute::new(template, true));
        self
    }

    pub fn route_dynamic_pages(
        mut self,
        path: &str,
        list_var_name: &str,
        page_var_name: &str,
        base_template_path: &str,
    ) -> Self {
        let template_value = self
            .context
            .lookup(list_var_name)
            .unwrap_or_else(|| panic!("Failed to find var {} in context", list_var_name))
            .clone();

        let page_object = match template_value {
            TemplateValue::Object(object) => object,
            _ => {
                todo!("dynamic page source must be a object, got {template_value:?}");
            }
        };

        for (key, page) in page_object {
            if let TemplateValue::Object(ref object) = page
                && let Some(TemplateValue::Text(slug)) = object.get("slug")
            {
                let url = format!("{path}/{slug}");

                let dyn_route = DynamicRoute {
                    base_dir: path.to_owned(),
                    page_var_name: page_var_name.to_owned(),
                    page_var_key: key,
                    list_var_name: list_var_name.to_owned(),
                    template_path: base_template_path.to_owned(),
                    slug: slug.to_string(),
                };

                self.dynamic_routes.insert(url, dyn_route);
            }
        }

        self
    }

    pub fn fallback(mut self, page: &str) -> Self {
        self.fallback = Some(page.to_string());
        self
    }

    pub fn error_page(mut self, template: &str) -> Self {
        match self.content.templates.get(template) {
            None => panic!("Error template page: \"{template}\" must be in the templates"),
            Some(Err(err)) => {
                panic!(
                    "Error template page: \"{template}\" has a render or parsing error: {err:#?}"
                )
            }
            Some(Ok(_)) => self.error_page = Some(template.to_owned()),
        }
        self
    }

    pub fn rss(mut self, template: &str) -> Self {
        match self.content.templates.get(template) {
            None => {
                let keys = self.content.templates.keys();
                panic!("RSS template page: \"{template}\" must be in the templates {keys:?}")
            }
            Some(Err(err)) => {
                panic!("RSS template page: \"{template}\" has a render or parsing error: {err:#?}")
            }
            Some(Ok(_)) => self.rss_template = Some(template.to_owned()),
        }
        self.static_routes
            .insert("/rss".into(), StaticRoute::new(template, false));

        let obj = TemplateValue::Object(hash_map! {
          "url".to_string() => TemplateValue::Text("/rss".to_string()),
          "name".to_string() => TemplateValue::Text("rss".to_string()),
        });

        Self::add_to_static_pages(&mut self.context, obj);

        self
    }

    pub fn serve_page(
        &self,
        header: &HttpRequestHeader,
        _body: AssetData,
        render_buffer: &'a mut String,
        template_cache: &'a mut HashMap<String, String>,
    ) -> Result<AssetDataRef<'a>, HttpServerError> {
        match self.static_routes.get(header.path) {
            Some(route) if header.path == "/stats" => {
                let stats = self
                    .db
                    .load_stats()
                    .expect("TOPO improve error handeling to make this work")
                    .to_template_value();
                let local_context = LocalContext::new(&self.context, "stats", &stats);

                let page = Self::render_template(
                    &self.content.templates,
                    &local_context,
                    &route.path,
                    render_buffer,
                )?;

                Ok(AssetDataRef::Html(page))
            }
            Some(route) => {
                let page = Self::render_template_cacheable(
                    &self.content.templates,
                    &self.context,
                    &route.path,
                    &route.path,
                    render_buffer,
                    template_cache,
                )?;
                if header.path == "/rss" {
                    Ok(AssetDataRef::Text(page))
                } else {
                    Ok(AssetDataRef::Html(page))
                }
            }

            _ => match self.dynamic_routes.get(header.path) {
                Some(dyn_route) => {
                    let page_context_var = if let Some(TemplateValue::Object(posts)) =
                        self.context.lookup(&dyn_route.list_var_name)
                        && let Some(template_value) = posts.get(&dyn_route.page_var_key)
                    {
                        template_value
                    } else {
                        todo!("slug not found");
                    };
                    let local_context = LocalContext::new(
                        &self.context,
                        &dyn_route.page_var_name,
                        page_context_var,
                    );

                    let page = Self::render_template_cacheable(
                        &self.content.templates,
                        &local_context,
                        &dyn_route.template_path,
                        &dyn_route.slug,
                        render_buffer,
                        template_cache,
                    )?;

                    Ok(AssetDataRef::Html(page))
                }

                None if let Some(fallback) = &self.fallback => {
                    println!("Path {} not found, redirecting to {fallback}", header.path);

                    Err(HttpServerError::Redirect(fallback.to_string()))
                }
                _ => Ok(AssetDataRef::Text(HttpResponseCode::NotFound.status_line())),
            },
        }
    }

    fn render_template_cacheable(
        templates: &HashMap<String, Result<Template, TemplateError>>,
        context: &dyn TemplateContext,
        path: &str,
        slug: &str,
        render_buffer: &'a mut String,
        path_cache: &'a mut HashMap<String, String>,
    ) -> Result<&'a str, TemplateError> {
        if !path_cache.contains_key(slug) {
            let rendered = Self::render_template(templates, context, path, render_buffer)?;
            path_cache.insert(slug.to_owned(), rendered.to_owned());
        }

        let (_, rendered) = path_cache
            .get_key_value(slug)
            .expect("value was just cached");

        Ok(rendered)
    }

    fn render_template(
        templates: &HashMap<String, Result<Template, TemplateError>>,
        context: &dyn TemplateContext,
        path: &str,
        render_buffer: &'a mut String,
    ) -> Result<&'a str, TemplateError> {
        //TODO unfuck
        let mut slug = path.strip_suffix(".html").unwrap_or(path);
        slug = slug.strip_prefix("pages").unwrap_or(slug);
        let url = &slug.to_string().to_template_value();

        let context = LocalContext::new(context, "current_page_url", url);

        match templates.get(path).expect("invariant because of router") {
            Ok(template) => {
                if let Some(parent_path) = &template.parent {
                    match templates
                        .get(parent_path)
                        .unwrap_or_else(|| panic!(r#"Parent template not found: {parent_path}"#))
                    {
                        Ok(parent_template) => {
                            if parent_template.parent.is_some() {
                                todo!("nested parents")
                            } else {
                                template.render_with_parent(
                                    &context,
                                    parent_template,
                                    render_buffer,
                                )
                            }
                        }
                        Err(err) => Err(err.clone().enhance_error(template)),
                    }
                } else {
                    template.render(&context, render_buffer)
                }
            }
            Err(template_error) => Err(template_error.clone()),
        }
    }

    pub fn serve_api(
        &self,
        header: &HttpRequestHeader,
        body: AssetData,
    ) -> Result<AssetData, HttpServerError> {
        self.api.handle(header, body, self.db)
    }
}
