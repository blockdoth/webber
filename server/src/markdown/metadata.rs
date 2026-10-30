use crate::runtime::{
    markdown::{
        parser::{MarkdownNode, MarkdownParser, ParsedMarkdown},
        render::MarkdownRenderer,
    },
    misc::date::Date,
};

#[derive(Clone, Debug)]
pub struct PostMetadataPartial {
    title: Option<String>,
    slug: Option<String>,
    published: Result<Date, &'static str>,
    tags: Vec<String>,
    summary: Option<String>,
    draft: bool,
}

impl PostMetadataPartial {
    pub fn finalize(mut self, ast: MarkdownNode<'_>) -> PostMetadata {
        if self.title.is_none()
            && let Some(title) = ast.into_iter().find_map(|node| match node {
                MarkdownNode::Heading { level: 1, .. } => Some(MarkdownRenderer::to_text(node)),
                _ => None,
            })
        {
            self.title = Some(title);
        }

        if self.slug.is_none()
            && let Some(title) = &self.title
        {
            self.slug = Some(
                title
                    .trim()
                    .replace(' ', "-")
                    .replace(',', "")
                    .to_lowercase(),
            );
        }

        PostMetadata {
            title: self.title.unwrap_or("Untitled".to_owned()),
            slug: self.slug.unwrap_or("untitled".to_owned()),
            published: self.published,
            tags: self.tags,
            summary: self.summary,
            draft: self.draft,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PostMetadata {
    pub title: String,
    pub slug: String,
    pub published: Result<Date, &'static str>,
    pub tags: Vec<String>,
    pub summary: Option<String>,
    pub draft: bool,
}

impl PostMetadata {
    pub fn parse_metadata(input: &str) -> Option<(PostMetadataPartial, &str)> {
        let mut cursor = 0;

        let first_line_end = input.find('\n').unwrap_or(input.len());
        let first_line = &input[..first_line_end];

        if !first_line.starts_with("::::") {
            return None;
        }

        cursor = if first_line_end < input.len() {
            first_line_end + 1
        } else {
            first_line_end
        };

        let mut metadata_lines = Vec::new();

        loop {
            let line_end = input[cursor..]
                .find('\n')
                .map_or(input.len(), |offset| cursor + offset);

            let line = &input[cursor..line_end];

            if line.starts_with("::::") {
                cursor = if line_end < input.len() {
                    line_end + 1
                } else {
                    line_end
                };

                break;
            }

            metadata_lines.push(line);

            if line_end == input.len() {
                return None;
            }

            cursor = line_end + 1;
        }

        let metadata = Self::parse_metadata_content(metadata_lines)?;

        Some((metadata, &input[cursor..]))
    }

    fn parse_metadata_content(lines: Vec<&str>) -> Option<PostMetadataPartial> {
        let mut title: Option<String> = None;
        let mut slug: Option<String> = None;
        let mut published: Option<Result<Date, &'static str>> = None;
        let mut tags: Vec<String> = Vec::new();
        let mut draft: bool = true;
        let mut summary: Option<String> = None;

        for line in lines {
            let line = line.trim();

            if line.is_empty() {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let key = key.trim();
            let value = value.trim();

            match key {
                "title" => title = Self::parse_string(value),
                "slug" => slug = Self::parse_string(value),
                "summary" => summary = Self::parse_string(value),
                "published" => published = Some(Self::parse_date(value)),
                "tags" => tags = Self::parse_tags(value),
                "draft" => match value {
                    "true" => draft = true,
                    "false" => draft = false,
                    _ => continue,
                },
                _ => continue,
            }
        }

        Some(PostMetadataPartial {
            title,
            slug,
            published: published?,
            tags,
            draft,
            summary,
        })
    }

    fn parse_string(value: &str) -> Option<String> {
        let value = value.trim();
        if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
            Some(value[1..value.len() - 1].to_string())
        } else {
            None
        }
    }

    fn parse_date(date: &str) -> Result<Date, &'static str> {
        let mut parts = date.split('-');

        let year: i32 = parts
            .next()
            .ok_or("missing year")?
            .parse()
            .map_err(|_| "invalid year")?;
        let month: u32 = parts
            .next()
            .ok_or("missing month")?
            .parse()
            .map_err(|_| "invalid month")?;
        let day: u32 = parts
            .next()
            .ok_or("missing day")?
            .parse()
            .map_err(|_| "invalid day")?;

        if parts.next().is_some() {
            return Err("too many components");
        }

        let days = Date::days_from_civil(year, month, day);

        Ok(Date {
            day: days,
            hour: 0,
            minute: 0,
            second: 0,
        })
    }

    fn parse_tags(value: &str) -> Vec<String> {
        if !value.starts_with('[') || !value.ends_with(']') {
            return vec![];
        }

        let inner = &value[1..value.len() - 1];

        if inner.trim().is_empty() {
            return vec![];
        }

        let mut tags = vec![];
        for tag in inner.split(',') {
            if let Some(tag) = Self::parse_string(tag.trim()) {
                tags.push(tag);
            } else {
                return vec![];
            }
        }
        tags
    }
}
