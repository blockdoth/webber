pub mod metadata;
pub mod parser;
pub mod render;
pub mod syntax;

#[derive(Debug, PartialEq, Clone)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    pub fn len(&self) -> usize {
        self.end - self.start
    }
    pub fn from_single(idx: usize) -> Self {
        Self {
            start: idx,
            end: idx + 1,
        }
    }
    pub fn from_double(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    pub fn to_str<'a>(&self, input: &'a str) -> &'a str {
        &input[self.start..self.end]
    }

    pub fn to_line<'a>(&self, input: &'a str, newlines: &[usize]) -> &'a str {
        let line_start = match newlines.partition_point(|&newline| newline < self.start) {
            0 => 0,
            index => newlines[index - 1],
        };

        let line_end = match newlines.partition_point(|&newline| newline < self.end) {
            index if index < newlines.len() => newlines[index] - 1,
            _ => input.len(),
        };

        &input[line_start..line_end]
    }
}
