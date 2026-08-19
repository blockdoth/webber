use std::collections::HashMap;
use std::fmt::Debug;

use crate::runtime::templating::values::{TemplateValue, ToTemplateValue};

#[derive(Debug)]
pub struct Context {
    pub global_context: HashMap<String, TemplateValue>,
}

impl Context {
    pub fn new() -> Self {
        Context {
            global_context: HashMap::new(),
        }
    }

    pub fn insert_global(&mut self, key: impl Into<String>, value: impl ToTemplateValue) {
        self.global_context
            .insert(key.into(), value.to_template_value());
    }

    pub fn lookup_mut(&mut self, key: &str) -> Option<&mut TemplateValue> {
        self.global_context.get_mut(key)
    }
}

pub struct LocalContext<'a> {
    pub parent: &'a dyn TemplateContext,
    pub key: &'a str,
    pub value: &'a TemplateValue,
}

impl<'a> LocalContext<'a> {
    pub fn new(parent: &'a dyn TemplateContext, key: &'a str, value: &'a TemplateValue) -> Self {
        Self { parent, key, value }
    }
}

pub trait TemplateContext {
    fn lookup(&self, key: &str) -> Option<&TemplateValue>;
}

impl TemplateContext for Context {
    fn lookup(&self, key: &str) -> Option<&TemplateValue> {
        self.global_context.get(key)
    }
}

impl TemplateContext for LocalContext<'_> {
    fn lookup(&self, key: &str) -> Option<&TemplateValue> {
        if self.key == key {
            Some(self.value)
        } else {
            self.parent.lookup(key)
        }
    }
}
