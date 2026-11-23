use core::fmt;
use std::{borrow::Borrow, ops::Deref, rc::Rc};

#[derive(Debug)]
pub struct StringCache {
    strings: Vec<Rc<str>>,
}

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct InternedString(pub Rc<str>);

impl StringCache {
    pub fn new() -> Self {
        StringCache { strings: vec![] }
    }

    pub fn intern(&mut self, value: &str) -> InternedString {
        for string in &self.strings {
            if string.as_ref() == value {
                return InternedString(string.clone());
            }
        }

        let string = Rc::<str>::from(value);
        self.strings.push(string.clone());

        InternedString(string)
    }

    pub fn get(&self, value: &str) -> Option<InternedString> {
        for string in &self.strings {
            if string.as_ref() == value {
                return Some(InternedString(string.clone()));
            }
        }
        None
    }
}

impl Default for StringCache {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for InternedString {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for InternedString {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for InternedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
