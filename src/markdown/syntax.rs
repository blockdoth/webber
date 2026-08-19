#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub enum SyntaxHighlightLang {
    Bash,
    C,
    Clike,
    Css,
    Haskell,
    Nix,
    Rust,
    Markdown,
    Markup,
    Elixir,
    Html,
    Javascript,
    Typescript,
}

impl SyntaxHighlightLang {
    pub fn from_str(input: &str) -> Option<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "bash" => Some(Self::Bash),
            "c" => Some(Self::C),
            "clike" => Some(Self::Clike),
            "css" => Some(Self::Css),
            "haskell" => Some(Self::Haskell),
            "nix" => Some(Self::Nix),
            "rust" => Some(Self::Rust),
            "markdown" => Some(Self::Markdown),
            "markup" => Some(Self::Markup),
            "elixir" => Some(Self::Elixir),
            "html" => Some(Self::Html),
            "javascript" => Some(Self::Javascript),
            "typescript" => Some(Self::Typescript),
            _ => None,
        }
    }
    pub fn to_str(self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::C => "c",
            Self::Clike => "clike",
            Self::Css => "css",
            Self::Haskell => "haskell",
            Self::Nix => "nix",
            Self::Rust => "rust",
            Self::Markdown => "markdown",
            Self::Markup => "markup",
            Self::Elixir => "elixir",
            Self::Html => "html",
            Self::Javascript => "javascript",
            Self::Typescript => "typescript",
        }
    }

    pub fn include_dependencies(langs: &[SyntaxHighlightLang]) -> Vec<SyntaxHighlightLang> {
        use SyntaxHighlightLang::*;
        let mut result = vec![];

        for &lang in langs {
            let dependency = match lang {
                Javascript | Typescript => Clike,
                Html => Markup,
                _ => continue,
            };
            if !result.contains(&dependency) {
                result.push(dependency);
            }
        }

        result.extend_from_slice(langs);
        result
    }
}
