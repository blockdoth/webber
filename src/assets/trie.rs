use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::path::PathBuf;
use std::vec;

#[derive(Debug)]
struct TrieNode<T> {
    asset: Option<T>,
    children: HashMap<String, TrieNode<T>>,
}

impl<T> Default for TrieNode<T> {
    fn default() -> Self {
        Self {
            asset: None,
            children: HashMap::new(),
        }
    }
}

#[derive(Default, Debug)]
pub struct Trie<T> {
    root: TrieNode<T>,
    paths: HashSet<String>,
}

impl<T> Trie<T> {
    pub fn new() -> Self {
        Trie {
            root: TrieNode::default(),
            paths: HashSet::new(),
        }
    }

    pub fn insert(&mut self, path: String, asset: T) {
        let mut current_node = &mut self.root;

        for key in path.split('/').filter(|part| !part.is_empty()) {
            current_node = current_node.children.entry(key.to_owned()).or_default();
        }
        current_node.asset = Some(asset);
        self.paths.insert(path);
    }

    pub fn get_ref_mut(&mut self, path: &str) -> Option<&mut T> {
        let mut current_node = &mut self.root;

        for key in path.split('/').filter(|part| !part.is_empty()) {
            match current_node.children.get_mut(key) {
                Some(node) => current_node = node,
                None => return None,
            }
        }

        current_node.asset.as_mut()
    }

    pub fn get_ref(&self, path: &str) -> Option<&T> {
        let mut current_node = &self.root;

        for path_component in path.split('/').filter(|part| !part.is_empty()) {
            match current_node.children.get(path_component) {
                Some(node) => current_node = node,
                None => return None,
            }
        }

        current_node.asset.as_ref()
    }

    // gets everything from path downwards
    pub fn get_partial(&self, path: &str) -> Vec<(String, &T)> {
        let mut current_node = &self.root;

        for key in path.split('/').filter(|part| !part.is_empty()) {
            match current_node.children.get(key) {
                Some(node) => current_node = node,
                None => return vec![],
            }
        }

        let mut result = Vec::new();

        let mut stack = vec![(path.trim_end_matches('/').to_owned(), current_node)];

        while let Some((current_path, node)) = stack.pop() {
            if let Some(asset) = &node.asset {
                result.push((current_path.clone(), asset));
            }

            for (name, child) in &node.children {
                stack.push((format!("{current_path}/{name}"), child));
            }
        }

        result
    }
    // TODO less dirty
    pub fn collect_kv_mut(&mut self) -> Vec<(PathBuf, &mut T)> {
        let mut result = Vec::new();

        Self::dfs(&mut self.root, &mut PathBuf::with_capacity(16), &mut result);

        result
    }

    fn dfs<'a>(
        node: &'a mut TrieNode<T>,
        path: &mut PathBuf,
        result: &mut Vec<(PathBuf, &'a mut T)>,
    ) {
        if let Some(asset) = node.asset.as_mut() {
            result.push((path.to_owned(), asset));
        }

        for (key, child) in &mut node.children {
            path.push(key);
            Self::dfs(child, path, result);
            path.pop();
        }
    }

    pub fn contains(&self, path: &str) -> bool {
        let mut current_node = &self.root;

        for key in path.split('/').filter(|part| !part.is_empty()) {
            match current_node.children.get(key) {
                Some(node) => current_node = node,
                None => return false,
            }
        }

        current_node.asset.is_some()
    }

    pub fn remove(&mut self, path: &String) -> bool {
        let mut current_node = &mut self.root;

        for key in path.split('/').filter(|part| !part.is_empty()) {
            if let Some(node) = current_node.children.get_mut(key) {
                current_node = node;
            } else {
                return false;
            }
        }

        current_node.asset = None;
        self.paths.remove(path);
        // TODO remove the emtpy data nodes left behind
        true
    }
    pub fn remove_other_than_except_generated(&mut self, current_paths: Vec<String>) -> bool {
        let current_paths_set: HashSet<String> = current_paths.into_iter().collect();

        let paths_to_delete: Vec<String> =
            self.paths.difference(&current_paths_set).cloned().collect();

        let mut changed = false;

        for path in &paths_to_delete {
            if path.starts_with("/generated") {
                continue;
            }
            println!("Removed file {path:?}");
            changed |= self.remove(path);
        }
        self.paths = current_paths_set;

        changed
    }

    fn len(&self) -> usize {
        self.paths.len()
    }
}
