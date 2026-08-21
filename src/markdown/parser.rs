use std::{iter::Peekable, str::CharIndices, vec::IntoIter};

use crate::runtime::markdown::{
    Span,
    metadata::{self, PostMetadata},
    render::MarkdownRenderer,
    syntax::SyntaxHighlightLang,
};

pub struct MarkdownParser {}

impl MarkdownParser {
    pub fn parse(input: &str) -> ParsedMarkdown {
        let (metadata_partial, markdown_input) = PostMetadata::parse_metadata(input)
            .map_or((None, input), |(metadata, markdown_input)| {
                (Some(metadata), markdown_input)
            });

        let lex = Self::lex(markdown_input);
        let blocks = Self::parse_blocks(&lex, markdown_input);
        let ast = Self::parse_block_content(&blocks, markdown_input);
        let highlighted_langs = Self::get_highlighted_langs(&blocks);
        let images = Self::get_images(&ast);
        let html = MarkdownRenderer::to_html(&ast);

        if let Some(mut metadata_partial) = metadata_partial {
            let metadata = metadata_partial.finalize(ast);
            ParsedMarkdown::Post(MarkdownPost {
                html,
                images,
                metadata,
                highlighted_langs,
            })
        } else {
            ParsedMarkdown::File(MarkdownFile {
                html,
                highlighted_langs,
            })
        }
    }

    pub fn get_highlighted_langs(blocks: &Vec<MarkdownBlock<'_>>) -> Vec<SyntaxHighlightLang> {
        let mut langs = vec![];
        for block in blocks {
            match block {
                MarkdownBlock::CodeBlock {
                    language: Some(language),
                    ..
                } if !langs.contains(language) => langs.push(*language),
                _ => continue,
            }
        }

        langs
    }
    fn get_images(ast: &MarkdownNode<'_>) -> Vec<String> {
        let mut images = vec![];

        for node in ast.into_iter() {
            match node {
                MarkdownNode::Image { path, .. } => images.push(path.to_string()),
                _ => continue,
            }
        }
        images
    }

    fn lex(input: &str) -> Vec<MarkdownToken> {
        use MarkdownToken::*;

        let mut tokens = vec![];
        let mut chars = input.char_indices().peekable();

        let mut start_text_idx = 0;
        let mut text_len = 0;
        while let Some((i, c)) = chars.next() {
            let token = match c {
                '\n' => Some((NewLine(Span::from_single(i)), 1)),
                '[' => Some((BracketOpen(Span::from_single(i)), 1)),
                ']' => Some((BracketClose(Span::from_single(i)), 1)),
                '(' => Some((ParenOpen(Span::from_single(i)), 1)),
                ')' => Some((ParenClose(Span::from_single(i)), 1)),
                '!' => Some((Exclamation(Span::from_single(i)), 1)),

                '#' | '-' | ' ' | '_' | '+' | '>' | '`' | '*' | '~' => {
                    let repeated = Self::count_repeated(&mut chars, c);
                    match c {
                        '#' => Some((HeadingMarker(Span::from_double(i, i + repeated)), repeated)),
                        '-' => Some((Dash(Span::from_double(i, i + repeated)), repeated)),
                        ' ' => Some((Whitespace(Span::from_double(i, i + repeated)), repeated)),
                        '_' => Some((Underscore(Span::from_double(i, i + repeated)), repeated)),
                        '+' => Some((Plus(Span::from_double(i, i + repeated)), repeated)),
                        '>' => Some((
                            BlockQuoteMarker(Span::from_double(i, i + repeated)),
                            repeated,
                        )),
                        '`' => Some((Backtick(Span::from_double(i, i + repeated)), repeated)),
                        '*' => Some((Asterisk(Span::from_double(i, i + repeated)), repeated)),
                        '~' => Some((Tilde(Span::from_double(i, i + repeated)), repeated)),
                        _ => panic!("invariant"),
                    }
                }
                _ => None,
            };

            if let Some((token, repeated_non_text)) = token {
                if text_len > 0 {
                    tokens.push(TextRaw(Span::from_double(
                        start_text_idx,
                        start_text_idx + text_len,
                    )));
                    start_text_idx += text_len;
                    text_len = 0;
                }

                start_text_idx += repeated_non_text;
                tokens.push(token);
            } else {
                text_len += c.len_utf8();
            }
        }

        if text_len != 0 {
            tokens.push(TextRaw(Span::from_double(
                start_text_idx,
                start_text_idx + text_len,
            )));
        }

        tokens
    }

    fn count_repeated(chars: &mut Peekable<CharIndices<'_>>, expected: char) -> usize {
        let mut count = 1;
        while let Some((_, c)) = chars.peek() {
            if *c != expected {
                break;
            }
            chars.next();
            count += 1;
        }
        count
    }

    fn parse_blocks<'tok: 'src, 'src>(
        tokens: &'tok [MarkdownToken],
        input: &'src str,
    ) -> Vec<MarkdownBlock<'src>> {
        use MarkdownBlock::*;
        use MarkdownToken::*;

        let mut blocks = vec![];
        let mut tokens = tokens;

        let mut first_content_found = false;

        while let [first, rest @ ..] = tokens {
            tokens = match first {
                NewLine(_) => {
                    if first_content_found {
                        blocks.push(BreakLine);
                    }
                    let mut rest = rest;
                    while let [NewLine(_), tail @ ..] = rest {
                        rest = tail;
                    }
                    rest
                }
                Dash(span) if span.len() >= 3 => {
                    blocks.push(HorizontalLine);
                    first_content_found = true;
                    rest
                }
                HeadingMarker(span) if span.len() <= 6 => {
                    let (content, rest) = Self::until_tok(rest, MarkdownTokenTyp::NewLine, false);
                    blocks.push(Heading {
                        level: span.len(),
                        content,
                    });
                    first_content_found = true;

                    rest
                }
                BlockQuoteMarker(_) if let Some((content, after)) = Self::parse_quote(tokens) => {
                    blocks.push(content);
                    first_content_found = true;

                    after
                }
                Backtick(span)
                    if span.len() == 3
                        && let Some((content, after)) = Self::parse_codeblock(tokens, input) =>
                {
                    blocks.push(content);
                    first_content_found = true;

                    after
                }
                _ if let Some((content, after)) = Self::parse_list(tokens, input) => {
                    blocks.push(content);
                    first_content_found = true;

                    after
                }
                _ => {
                    let (content, after) =
                        Self::until_tok(tokens, MarkdownTokenTyp::NewLine, false);

                    blocks.push(Paragraph { content });
                    first_content_found = true;

                    after
                }
            }
        }
        blocks
    }

    fn parse_codeblock<'a>(
        tokens: &'a [MarkdownToken],
        input: &'a str,
    ) -> Option<(MarkdownBlock<'a>, &'a [MarkdownToken])> {
        use MarkdownBlock::*;
        use MarkdownToken::*;

        if let [Backtick(span), rest @ ..] = tokens
            && span.len() == 3
        {
            let (rest, language) = if let [TextRaw(lang), NewLine { .. }, inner_rest @ ..] = rest {
                (inner_rest, Some(lang.to_str(input)))
            } else {
                (rest, None)
            };
            let (content, rest) = Self::until_tok(rest, MarkdownTokenTyp::Backtick(3), false);

            if content.is_empty() {
                None
            } else {
                Some((
                    CodeBlock {
                        language: language.and_then(SyntaxHighlightLang::from_str),
                        content,
                    },
                    rest,
                ))
            }
        } else {
            None
        }
    }

    fn parse_list<'a>(
        mut tokens: &'a [MarkdownToken],
        input: &'a str,
    ) -> Option<(MarkdownBlock<'a>, &'a [MarkdownToken])> {
        let mut content = vec![];
        let mut marker = None;

        while !tokens.is_empty() {
            let (line, rest) = Self::until_tok(tokens, MarkdownTokenTyp::NewLine, false);
            let Some(line) = MarkdownListLine::parse_line(line, input) else {
                break;
            };

            if marker.is_none() {
                marker = Some(line.list_marker);
            }

            if let Some(marker) = marker
                && line.list_marker != marker
            {
                break;
            }

            content.push(line.content);
            tokens = rest;
        }

        match marker {
            Some(ListMarker::Numbered) => Some((MarkdownBlock::OrderedList { content }, tokens)),
            Some(ListMarker::Dash | ListMarker::Asterisk | ListMarker::Plus) => {
                Some((MarkdownBlock::UnorderedList { content }, tokens))
            }
            None => None,
        }
    }

    fn parse_quote(
        mut tokens: &'_ [MarkdownToken],
    ) -> Option<(MarkdownBlock<'_>, &[MarkdownToken])> {
        use MarkdownBlock::*;
        use MarkdownToken::*;

        let mut content = vec![];

        while !tokens.is_empty() {
            let (line, rest) = Self::until_tok(tokens, MarkdownTokenTyp::NewLine, false);
            match line {
                [BlockQuoteMarker(span), Whitespace(_), quote_content @ ..]
                | [BlockQuoteMarker(span), quote_content @ ..]
                    if span.len() > 0 =>
                {
                    content.push(quote_content);
                    tokens = rest;
                }
                _ => break,
            }
        }

        if content.is_empty() {
            None
        } else {
            Some((BlockQuote { content }, tokens))
        }
    }

    // With split inc;lludes split in rest
    fn until_tok(
        tokens: &[MarkdownToken],
        until: MarkdownTokenTyp,
        include_split: bool,
    ) -> (&[MarkdownToken], &[MarkdownToken]) {
        let Some(split) = tokens.iter().position(|token| token.typ() == until) else {
            return (tokens, &tokens[0..0]);
        };

        let (content, rest) = tokens.split_at(split);

        let rest = match (rest, &until) {
            (with_split @ [tok, ..], _) if tok.typ() == until && include_split => with_split,
            ([tok, rest_without_split @ ..], _) if tok.typ() == until => rest_without_split,
            _ => rest,
        };

        (content, rest)
    }

    fn tokens_to_string<'a>(tokens: &'a [MarkdownToken], input: &'a str) -> Vec<&'a str> {
        let Some(first) = tokens.first() else {
            return Vec::new();
        };

        let last = tokens.last().expect("invariant");
        let content = &input[first.start()..last.end()];

        content.split('\n').collect()
    }

    fn parse_block_content<'a>(blocks: &'a [MarkdownBlock], input: &'a str) -> MarkdownNode<'a> {
        let mut nodes = vec![];

        for block in blocks {
            match block {
                MarkdownBlock::Heading { level, content } => {
                    nodes.push(MarkdownNode::Heading {
                        level: *level,
                        children: Self::parse_inline_helper(content, input),
                    });
                }
                MarkdownBlock::Paragraph { content } => {
                    nodes.push(MarkdownNode::Paragraph(Self::parse_inline_helper(
                        content, input,
                    )));
                }
                MarkdownBlock::OrderedList { content } => {
                    let lines = content
                        .iter()
                        .map(|line| MarkdownNode::ListItem(Self::parse_inline_helper(line, input)))
                        .collect();
                    nodes.push(MarkdownNode::OrderedList(lines));
                }
                MarkdownBlock::UnorderedList { content } => {
                    let lines = content
                        .iter()
                        .map(|line| MarkdownNode::ListItem(Self::parse_inline_helper(line, input)))
                        .collect();
                    nodes.push(MarkdownNode::UnorderedList(lines));
                }
                MarkdownBlock::BlockQuote { content } => {
                    let lines = content
                        .iter()
                        .map(|line| MarkdownNode::Paragraph(Self::parse_inline_helper(line, input)))
                        .collect();
                    nodes.push(MarkdownNode::BlockQuote(lines));
                }
                MarkdownBlock::_Table { .. } => {
                    todo!()
                }
                MarkdownBlock::CodeBlock { language, content } => {
                    nodes.push(MarkdownNode::CodeBlock {
                        language: *language,
                        content: Self::tokens_to_string(content, input),
                    });
                }
                MarkdownBlock::BreakLine => nodes.push(MarkdownNode::BreakLine),
                MarkdownBlock::HorizontalLine => nodes.push(MarkdownNode::HorizontalLine),
            }
        }

        MarkdownNode::Document(nodes)
    }

    fn find_closing(tokens: &[MarkdownToken], closing: MarkdownTokenTyp) -> Option<(&Span, usize)> {
        tokens.iter().enumerate().find_map(|(i, token)| {
            if token.typ() == closing {
                Some((token.span(), i))
            } else {
                None
            }
        })
    }

    fn parse_inline_helper<'a>(
        mut tokens: &'a [MarkdownToken],
        input: &'a str,
    ) -> Vec<MarkdownNode<'a>> {
        use MarkdownNode::*;
        use MarkdownToken::*;
        let mut nodes = vec![];

        while !tokens.is_empty() {
            match &tokens {
                [Backtick(open), rest @ ..] if open.len() == 1 => {
                    tokens = if let Some((close_span, close_index)) =
                        Self::find_closing(rest, MarkdownTokenTyp::Backtick(1))
                    {
                        nodes.push(InlineCode(&input[open.end..close_span.start]));
                        &rest[close_index + 1..]
                    } else {
                        nodes.push(Text(open.to_str(input)));
                        rest
                    }
                }
                [
                    open @ (Underscore(open_span) | Asterisk(open_span) | Tilde(open_span)),
                    rest @ ..,
                ] if open_span.len() == 1 => {
                    let (closing, make_node): (
                        MarkdownTokenTyp,
                        fn(Vec<MarkdownNode<'a>>) -> MarkdownNode<'a>,
                    ) = match open {
                        Underscore(_) => (MarkdownTokenTyp::Underscore(1), Italic),
                        Asterisk(_) => (MarkdownTokenTyp::Asterisk(1), Bold),
                        Tilde(_) => (MarkdownTokenTyp::Tilde(1), StrikeThrough),
                        _ => unreachable!(),
                    };

                    if let Some((_, close_index)) = Self::find_closing(rest, closing) {
                        nodes.push(make_node(Self::parse_inline_helper(
                            &rest[..close_index],
                            input,
                        )));

                        tokens = &rest[close_index + 1..];
                    } else {
                        nodes.push(Text(open_span.to_str(input)));
                        tokens = rest;
                    }
                }
                [first @ BracketOpen { .. }, after_open @ ..] => {
                    tokens = if let Some((node, rest)) = Self::try_parse_link(after_open, input) {
                        nodes.push(node);
                        rest
                    } else {
                        nodes.push(Text(first.span().to_str(input)));
                        after_open
                    }
                }
                [
                    first @ Exclamation { .. },
                    second @ BracketOpen { .. },
                    after_open @ ..,
                ] => {
                    tokens = if let Some((node, rest)) = Self::try_parse_image(after_open, input) {
                        nodes.push(node);
                        rest
                    } else {
                        nodes.push(Text(&input[first.start()..second.end()]));
                        after_open
                    }
                }
                _ => {
                    let mut text_token_count = 0;

                    while let [first, ..] = &tokens[text_token_count..] {
                        if Self::is_inline_special(first) {
                            break;
                        }

                        text_token_count += 1;
                    }

                    if text_token_count == 0 {
                        let first = &tokens[0];

                        nodes.push(Text(&input[first.start()..first.end()]));
                        tokens = &tokens[1..];
                    } else {
                        let plain = &tokens[..text_token_count];
                        let start = plain.first().unwrap().start();
                        let end = plain.last().unwrap().end();

                        nodes.push(Text(&input[start..end]));
                        tokens = &tokens[text_token_count..];
                    }
                }
            }
        }

        nodes
    }

    fn try_parse_link<'a>(
        tokens: &'a [MarkdownToken],
        input: &'a str,
    ) -> Option<(MarkdownNode<'a>, &'a [MarkdownToken])> {
        use MarkdownNode::*;
        use MarkdownToken::*;

        let close_bracket = tokens
            .iter()
            .position(|token| matches!(token, BracketClose { .. }))?;

        let text_tokens = &tokens[..close_bracket];
        let after_bracket = &tokens[close_bracket + 1..];

        let [ParenOpen { .. }, TextRaw(url), ParenClose { .. }, rest @ ..] = after_bracket else {
            return None;
        };

        Some((
            Link {
                text: Self::parse_inline_helper(text_tokens, input),
                url: url.to_str(input),
            },
            rest,
        ))
    }

    fn try_parse_image<'a>(
        tokens: &'a [MarkdownToken],
        input: &'a str,
    ) -> Option<(MarkdownNode<'a>, &'a [MarkdownToken])> {
        use MarkdownNode::*;
        use MarkdownToken::*;

        let close_bracket = tokens
            .iter()
            .position(|token| matches!(token, BracketClose { .. }))?;

        let text_tokens = &tokens[..close_bracket];
        let after_bracket = &tokens[close_bracket + 1..];

        let [ParenOpen { .. }, TextRaw(url), ParenClose { .. }, rest @ ..] = after_bracket else {
            return None;
        };

        let first = text_tokens.first().unwrap().start();
        let last = text_tokens.last().unwrap().end();
        let title = &input[first..last];

        Some((
            Image {
                _alt: title,
                path: url.to_str(input),
            },
            rest,
        ))
    }
    fn is_inline_special(token: &MarkdownToken) -> bool {
        matches!(
            token,
            MarkdownToken::BracketOpen { .. }
                | MarkdownToken::Backtick(_)
                | MarkdownToken::Underscore(_)
                | MarkdownToken::Asterisk(_)
                | MarkdownToken::Tilde(_)
        )
    }
    fn delimiter_can_open(tokens: &[MarkdownToken]) -> bool {
        tokens.first().is_some_and(|token| {
            !matches!(
                token,
                MarkdownToken::Whitespace(_) | MarkdownToken::NewLine(_)
            )
        })
    }

    fn delimiter_can_close(tokens: &[MarkdownToken], index: usize) -> bool {
        index
            .checked_sub(1)
            .and_then(|index| tokens.get(index))
            .is_some_and(|token| {
                !matches!(
                    token,
                    MarkdownToken::Whitespace(_) | MarkdownToken::NewLine(_)
                )
            })
    }
}

#[derive(Debug)]
pub enum MarkdownNode<'a> {
    Document(Vec<MarkdownNode<'a>>),

    // Block
    Paragraph(Vec<MarkdownNode<'a>>),
    Heading {
        level: usize,
        children: Vec<MarkdownNode<'a>>,
    },
    CodeBlock {
        language: Option<SyntaxHighlightLang>,
        content: Vec<&'a str>,
    },
    OrderedList(Vec<MarkdownNode<'a>>),
    UnorderedList(Vec<MarkdownNode<'a>>),
    BlockQuote(Vec<MarkdownNode<'a>>),
    ListItem(Vec<MarkdownNode<'a>>),
    HorizontalLine,
    _Table,
    BreakLine,

    // Inline
    Text(&'a str),
    Italic(Vec<MarkdownNode<'a>>),
    Bold(Vec<MarkdownNode<'a>>),
    StrikeThrough(Vec<MarkdownNode<'a>>),
    InlineCode(&'a str),
    Link {
        text: Vec<MarkdownNode<'a>>,
        url: &'a str,
    },
    Image {
        _alt: &'a str,
        path: &'a str,
    },
}

impl<'a> MarkdownNode<'a> {
    fn children(&self) -> &[MarkdownNode<'a>] {
        match self {
            MarkdownNode::Document(children)
            | MarkdownNode::Paragraph(children)
            | MarkdownNode::OrderedList(children)
            | MarkdownNode::UnorderedList(children)
            | MarkdownNode::BlockQuote(children)
            | MarkdownNode::ListItem(children)
            | MarkdownNode::Italic(children)
            | MarkdownNode::Bold(children)
            | MarkdownNode::StrikeThrough(children) => children,

            MarkdownNode::Heading { children, .. } => children,
            MarkdownNode::Link { text, .. } => text,

            MarkdownNode::CodeBlock { .. }
            | MarkdownNode::HorizontalLine
            | MarkdownNode::_Table
            | MarkdownNode::BreakLine
            | MarkdownNode::Text(_)
            | MarkdownNode::InlineCode(_)
            | MarkdownNode::Image { .. } => &[],
        }
    }
}

pub struct MarkdownNodeIter<'a> {
    stack: Vec<&'a MarkdownNode<'a>>,
}

impl<'a> Iterator for MarkdownNodeIter<'a> {
    type Item = &'a MarkdownNode<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let node = self.stack.pop()?;

        self.stack.extend(node.children().iter().rev());

        Some(node)
    }
}

impl<'a> IntoIterator for &'a MarkdownNode<'a> {
    type Item = &'a MarkdownNode<'a>;
    type IntoIter = MarkdownNodeIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        MarkdownNodeIter { stack: vec![self] }
    }
}

#[derive(Debug, Clone)]
pub enum MarkdownBlock<'a> {
    Heading {
        level: usize,
        content: &'a [MarkdownToken],
    },
    Paragraph {
        content: &'a [MarkdownToken],
    },
    OrderedList {
        content: Vec<&'a [MarkdownToken]>,
    },
    UnorderedList {
        content: Vec<&'a [MarkdownToken]>,
    },
    BlockQuote {
        content: Vec<&'a [MarkdownToken]>,
    },
    _Table {
        content: Vec<&'a [MarkdownToken]>,
    },
    CodeBlock {
        language: Option<SyntaxHighlightLang>,
        content: &'a [MarkdownToken],
    },
    BreakLine,
    HorizontalLine,
}

#[derive(Debug, Clone)]
pub enum MarkdownToken {
    NewLine(Span),
    BracketOpen(Span),
    BracketClose(Span),
    ParenOpen(Span),
    ParenClose(Span),

    HeadingMarker(Span),
    BlockQuoteMarker(Span),
    Whitespace(Span),
    Asterisk(Span),
    Tilde(Span),
    Underscore(Span),
    Backtick(Span),
    Dash(Span),
    Plus(Span),
    Exclamation(Span),

    TextRaw(Span),
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum MarkdownTokenTyp {
    NewLine,
    BracketOpen,
    BracketClose,
    ParenOpen,
    ParenClose,

    HeadingMarker(usize),
    BlockQuoteMarker(usize),
    Whitespace(usize),
    Asterisk(usize),
    Underscore(usize),
    Backtick(usize),
    Dash(usize),
    Plus(usize),
    Tilde(usize),
    Exclamation(usize),

    TextRaw,
}

impl MarkdownToken {
    fn typ(&self) -> MarkdownTokenTyp {
        use MarkdownToken::*;
        match self {
            NewLine(_) => MarkdownTokenTyp::NewLine,
            BracketOpen(_) => MarkdownTokenTyp::BracketOpen,
            BracketClose(_) => MarkdownTokenTyp::BracketClose,
            ParenOpen(_) => MarkdownTokenTyp::ParenOpen,
            ParenClose(_) => MarkdownTokenTyp::ParenClose,
            HeadingMarker(span) => MarkdownTokenTyp::HeadingMarker(span.len()),
            BlockQuoteMarker(span) => MarkdownTokenTyp::BlockQuoteMarker(span.len()),
            Whitespace(span) => MarkdownTokenTyp::Whitespace(span.len()),
            Asterisk(span) => MarkdownTokenTyp::Asterisk(span.len()),
            Underscore(span) => MarkdownTokenTyp::Underscore(span.len()),
            Backtick(span) => MarkdownTokenTyp::Backtick(span.len()),
            Dash(span) => MarkdownTokenTyp::Dash(span.len()),
            Tilde(span) => MarkdownTokenTyp::Tilde(span.len()),
            Plus(span) => MarkdownTokenTyp::Plus(span.len()),
            Exclamation(span) => MarkdownTokenTyp::Exclamation(span.len()),
            TextRaw(_) => MarkdownTokenTyp::TextRaw,
        }
    }

    fn span(&self) -> &Span {
        use MarkdownToken::*;
        match self {
            NewLine(span)
            | BracketOpen(span)
            | BracketClose(span)
            | ParenOpen(span)
            | ParenClose(span)
            | HeadingMarker(span)
            | BlockQuoteMarker(span)
            | Whitespace(span)
            | Asterisk(span)
            | Underscore(span)
            | Backtick(span)
            | Dash(span)
            | Tilde(span)
            | Plus(span)
            | Exclamation(span)
            | TextRaw(span) => span,
        }
    }

    fn start(&self) -> usize {
        self.span().start
    }

    fn end(&self) -> usize {
        self.span().end
    }
}

struct MarkdownListLine<'a> {
    _indent: usize,
    content: &'a [MarkdownToken],
    list_marker: ListMarker,
}

#[derive(PartialEq, Eq, Debug, Copy, Clone)]
enum ListMarker {
    Numbered,
    Dash,
    Asterisk,
    Plus,
}

impl<'a> MarkdownListLine<'a> {
    fn parse_line(tokens: &'a [MarkdownToken], input: &str) -> Option<MarkdownListLine<'a>> {
        use MarkdownToken::*;

        let (indent, rest) = match tokens {
            [Whitespace(span), rest @ ..] => (span.len(), rest),
            rest => (0, rest),
        };
        let (list_marker, content) = match rest {
            [Dash(span), Whitespace(_), content @ ..] if span.len() == 1 => {
                (ListMarker::Dash, content)
            }
            [Asterisk(span), Whitespace(_), content @ ..] if span.len() == 1 => {
                (ListMarker::Asterisk, content)
            }
            [Plus(span), Whitespace(_), content @ ..] if span.len() == 1 => {
                (ListMarker::Plus, content)
            }
            [TextRaw(text), Whitespace(_), content @ ..]
                if text
                    .to_str(input)
                    .strip_suffix('.')
                    .is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit())) =>
            {
                (ListMarker::Numbered, content)
            }
            _ => return None,
        };

        Some(MarkdownListLine {
            _indent: indent,
            content,
            list_marker,
        })
    }
}

#[derive(Clone, Debug)]
pub enum ParsedMarkdown {
    Post(MarkdownPost),
    File(MarkdownFile),
}

impl ParsedMarkdown {
    pub fn as_str(&self) -> &str {
        match self {
            ParsedMarkdown::Post(markdown_post) => &markdown_post.html,
            ParsedMarkdown::File(markdown_file) => &markdown_file.html,
        }
    }
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            ParsedMarkdown::Post(markdown_post) => markdown_post.html.as_bytes(),
            ParsedMarkdown::File(markdown_file) => markdown_file.html.as_bytes(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct MarkdownPost {
    pub html: String,
    pub images: Vec<String>,
    pub metadata: PostMetadata,
    pub highlighted_langs: Vec<SyntaxHighlightLang>,
}

#[derive(Clone, Debug)]
pub struct MarkdownFile {
    pub html: String,
    pub highlighted_langs: Vec<SyntaxHighlightLang>,
}
