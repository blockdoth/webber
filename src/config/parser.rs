use std::{collections::HashMap, error::Error, path::Path};

use crate::runtime::{
    assets::{asset::Asset, content::Content},
    templating::values::{TemplateValue, ToTemplateValue},
};

pub struct Tomlish {}

impl Tomlish {
    #[allow(clippy::type_complexity)]
    pub fn parse_tomlish(
        string: &str,
    ) -> Result<HashMap<&str, Vec<(&str, TomlishValue)>>, Box<dyn Error>> {
        let lines = string.lines();

        let mut keys = HashMap::new();

        let mut current_header = None;

        for line in lines {
            let line = line.trim();
            if line.is_empty() || line.starts_with("//") {
                continue;
            }

            if let Some(line) = line.strip_prefix("[")
                && let Some(line) = line.strip_suffix("]")
            {
                current_header = Some(line);
                keys.insert(line, vec![]);
                continue;
            } else if let Some(header) = current_header
                && let Some((key, value)) = line.split_once("=")
            {
                let value = TomlishValue::parse(value.trim())?;
                keys.entry(header).and_modify(|e| {
                    e.push((key.trim(), value));
                });
            } else {
                return Err("No header specified".into());
            }
        }

        Ok(keys)
    }
}

#[derive(Debug, Clone)]
pub enum TomlishValue {
    Number(i64),
    String(String),
    Object(HashMap<String, Vec<TomlishValue>>),
    Boolean(bool),
    Array(Vec<TomlishValue>),

    Path(String, bool),
    ContentPath(String, bool),
    Route(String),
}

impl TomlishValue {
    fn parse(line: &str) -> Result<Self, Box<dyn Error>> {
        use TomlishValue::*;

        if let Ok(number) = line.parse::<i64>() {
            return Ok(Number(number));
        }

        if line.eq("true") {
            return Ok(Boolean(true));
        }

        if line.eq("false") {
            return Ok(Boolean(false));
        }

        if let Some(line) = line.strip_prefix("\"")
            && let Some(line) = line.strip_suffix("\"")
        {
            return Ok(String(line.to_owned()));
        }

        if let Some(line) = line.strip_prefix("@") {
            return Ok(ContentPath(line.to_owned(), line.ends_with("/")));
        }

        if let Some(line) = line.strip_prefix("./") {
            return Ok(Path(line.to_owned(), line.ends_with("/")));
        }

        if line.strip_prefix("/").is_some() {
            return Ok(Route(line.to_owned()));
        }

        if let Some(line) = line.strip_prefix("[")
            && let Some(line) = line.strip_suffix("]")
        {
            let mut array = vec![];
            for item in line.split(",") {
                let item = item.trim();
                let value = TomlishValue::parse(item)?;
                array.push(value);
            }
            return Ok(Array(array));
        }

        if let Some(line) = line.strip_prefix("{")
            && let Some(line) = line.strip_suffix("}")
        {
            let mut object = HashMap::new();

            for key_value in line.split(',') {
                let (key, value) = key_value
                    .split_once('=')
                    .ok_or("Expected key = value in object")?;

                object.insert(
                    key.trim().to_owned(),
                    vec![TomlishValue::parse(value.trim())?],
                );
            }

            return Ok(Object(object));
        }

        Err(format!("Unable to parse line {line}").into())
    }

    pub fn resolve(self, content: &Content, asset_path: &str) -> TemplateValue {
        match self {
            TomlishValue::Number(n) => TemplateValue::Number(n),
            TomlishValue::String(s) => TemplateValue::Text(s),
            TomlishValue::Boolean(b) => TemplateValue::Bool(b),
            TomlishValue::Array(values) => TemplateValue::List(
                values
                    .into_iter()
                    .map(ToTemplateValue::to_template_value)
                    .collect(),
            ),
            TomlishValue::Object(entries) => TemplateValue::Object(
                entries
                    .into_iter()
                    .filter_map(|(key, mut values)| {
                        values
                            .pop()
                            .map(|value| (key, value.resolve(content, asset_path)))
                    })
                    .collect(),
            ),

            TomlishValue::Path(path, _) | TomlishValue::Route(path) => TemplateValue::Text(path),
            TomlishValue::ContentPath(path, true) => {
                // is dir

                let assets = content.assets.get_partial(&path); // seperate because otherwise rust gets mad about temp values

                let mut object = HashMap::new();
                assets.iter().for_each(|(key, asset)| {
                    if let Ok(left_over_path) = Path::new(key).strip_prefix(&path)
                        && let Ok(asset) = asset
                            .data
                            .clone()
                            .to_template_value_with_path(key, asset_path)
                    {
                        let components: Vec<String> = left_over_path
                            .components()
                            .map(|component| component.as_os_str().to_string_lossy().into_owned())
                            .collect();

                        insert_nested(&mut object, &components, asset);
                    }
                });
                TemplateValue::Object(object)
            }
            TomlishValue::ContentPath(path, false) => {
                // is file
                // println!("{path} -> {file:#?}");
                content
                    .assets
                    .get_ref(&path)
                    .expect("todo")
                    .data
                    .clone()
                    .to_template_value()
            }
        }
    }
}

pub fn insert_nested(
    object: &mut HashMap<String, TemplateValue>,
    components: &[String],
    value: TemplateValue,
) {
    let Some((first, rest)) = components.split_first() else {
        return;
    };

    if rest.is_empty() {
        object.insert(first.clone(), value);
        return;
    }

    let entry = object
        .entry(first.clone())
        .or_insert_with(|| TemplateValue::Object(HashMap::new()));

    if let TemplateValue::Object(children) = entry {
        insert_nested(children, rest, value);
    }
}
