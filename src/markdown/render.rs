use crate::runtime::markdown::{
    parser::{MarkdownNode, MarkdownParser, ParsedMarkdown},
    syntax::SyntaxHighlightLang,
};

pub struct MarkdownRenderer;

impl MarkdownRenderer {
    pub fn to_html(node: &MarkdownNode) -> String {
        let mut html = String::new();
        Self::html_helper(node, &mut html);
        html
    }

    fn html_helper(node: &MarkdownNode, builder: &mut String) {
        match node {
            MarkdownNode::BreakLine => {
                builder.push_str("<br>");
            }
            MarkdownNode::Document(nodes) => {
                nodes.iter().for_each(|n| Self::html_helper(n, builder));
            }
            MarkdownNode::Paragraph(children) => {
                builder.push_str("<p class=\"post_paragraph\">");
                children.iter().for_each(|n| Self::html_helper(n, builder));

                builder.push_str("</p>\n");
            }
            MarkdownNode::Text(text) => {
                builder.push_str(text);
            }
            MarkdownNode::Bold(children) => {
                builder.push_str("<strong>");
                children.iter().for_each(|n| Self::html_helper(n, builder));
                builder.push_str("</strong>");
            }
            MarkdownNode::Italic(children) => {
                builder.push_str("<em>");
                children.iter().for_each(|n| Self::html_helper(n, builder));
                builder.push_str("</em>");
            }
            MarkdownNode::StrikeThrough(children) => {
                builder.push_str("<s>");
                children.iter().for_each(|n| Self::html_helper(n, builder));
                builder.push_str("</s>");
            }
            MarkdownNode::Heading { level, children } => {
                let header_level = match level {
                    0 => panic!("Should not be parsed"),
                    1 => "h1",
                    2 => "h2",
                    3 => "h3",
                    4 => "h4",
                    5 => "h5",
                    _ => "h6",
                };

                builder.push('<');
                builder.push_str(header_level);
                builder.push('>');
                children.iter().for_each(|n| Self::html_helper(n, builder));
                builder.push_str("</");
                builder.push_str(header_level);
                builder.push_str(">\n");
                if *level < 3 {
                    builder.push_str("<hr/>\n");
                }
            }
            MarkdownNode::InlineCode(code) => {
                builder.push_str("<code class=\"inline_code\">");
                builder.push_str(code);
                builder.push_str("</code>");
            }
            MarkdownNode::CodeBlock { language, content } => {
                builder.push_str("<div class=\"codeblock_wrapper\"><pre><code class=\"language-");
                builder.push_str(language.unwrap_or(SyntaxHighlightLang::Bash).to_str());
                builder.push_str(" codeblock\">");
                for (idx, line) in content.iter().enumerate() {
                    if idx != 0 {
                        builder.push('\n');
                    }
                    Self::push_escaped_code(builder, line);
                }
                builder.push_str("</code></pre></div>\n");
            }
            MarkdownNode::OrderedList(nodes) => {
                builder.push_str("<ol>\n");
                nodes.iter().for_each(|n| Self::html_helper(n, builder));
                builder.push_str("</ol>\n");
            }
            MarkdownNode::UnorderedList(nodes) => {
                builder.push_str("<ul>\n");
                nodes.iter().for_each(|n| Self::html_helper(n, builder));
                builder.push_str("</ul>\n");
            }
            MarkdownNode::ListItem(nodes) => {
                builder.push_str("<li>");
                nodes.iter().for_each(|n| Self::html_helper(n, builder));
                builder.push_str("</li>\n");
            }
            MarkdownNode::BlockQuote(nodes) => {
                builder.push_str("<blockquote class=\"blockquote\">\n");
                for child in nodes {
                    Self::html_helper(child, builder);
                    builder.push('\n');
                }
                builder.push_str("</blockquote>\n");
            }
            MarkdownNode::HorizontalLine => {
                builder.push_str("<hr/>\n");
            }
            MarkdownNode::Link { text, url } => {
                builder.push_str("<a class=\"link\" href=\"");
                builder.push_str(url);
                builder.push_str("\">");

                for n in text.iter() {
                    Self::html_helper(n, builder);
                }
                builder.push_str("</a>");
            }
            MarkdownNode::Image { path, .. } => {
                builder.push_str("<img class=\"post_image\" src=\"");
                builder.push_str(path);
                builder.push('"');
                // builder.push_str(" alt=\"");
                // builder.push_str(alt);
                // builder.push_str("\"");
                builder.push('>');
            }
            MarkdownNode::_Table => todo!("tabble"),
        }
    }
    pub fn to_text(node: &MarkdownNode<'_>) -> String {
        match node {
            MarkdownNode::Document(children)
            | MarkdownNode::Paragraph(children)
            | MarkdownNode::Heading { children, .. }
            | MarkdownNode::OrderedList(children)
            | MarkdownNode::UnorderedList(children)
            | MarkdownNode::BlockQuote(children)
            | MarkdownNode::ListItem(children)
            | MarkdownNode::Italic(children)
            | MarkdownNode::Bold(children)
            | MarkdownNode::StrikeThrough(children) => children.iter().map(Self::to_text).collect(),
            MarkdownNode::Text(text) => text.to_string(),
            MarkdownNode::InlineCode(code) => code.to_string(),
            MarkdownNode::Link { text, .. } => text.iter().map(Self::to_text).collect(),
            MarkdownNode::Image { _alt, .. } => _alt.to_string(),
            MarkdownNode::CodeBlock { content, .. } => content.join("\n"),
            MarkdownNode::HorizontalLine | MarkdownNode::_Table | MarkdownNode::BreakLine => {
                String::new()
            }
        }
    }

    fn push_escaped_code(builder: &mut String, input: &str) {
        for character in input.chars() {
            match character {
                '&' => builder.push_str("&amp;"),
                '<' => builder.push_str("&lt;"),
                '>' => builder.push_str("&gt;"),
                _ => builder.push(character),
            }
        }
    }
}
