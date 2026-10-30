use std::collections::HashMap;

use crate::runtime::templating::values::{self, TemplateValue};

#[derive(Debug, Clone)]
enum Grammar {
    Sequence(Vec<Grammar>),
    Repetitions(Box<Grammar>),
    Literal(String),
    Capture(String),
    Optional(Box<Grammar>),
    Any,
}

// Grammar::Sequence(vec![
//     Grammar::Literal("\"".into()),
//     Grammar::Capture("quote".into()),
//     Grammar::Literal("\"".into()),
//     Grammar::Literal("\n~".into()),
//     Grammar::Capture("author".into()),
//     Grammar::Optional(Box::new(Grammar::Sequence(vec![
//         Grammar::Literal(", ".into()),
//         Grammar::Capture("source".into()),
//     ]))),
// ])

struct GrammarParser<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> GrammarParser<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    fn peek(&self) -> Option<char> {
        self.input[self.pos..].chars().next()
    }

    fn bump(&mut self) -> Option<char> {
        let ch = self.peek()?;
        self.pos += ch.len_utf8();
        Some(ch)
    }

    fn consume(&mut self, expected: char) -> bool {
        if self.peek() == Some(expected) {
            self.bump();
            true
        } else {
            false
        }
    }

    fn expect(&mut self, expected: char) -> Result<(), String> {
        if self.consume(expected) {
            Ok(())
        } else {
            Err(format!("expected {expected:?} at byte {}", self.pos))
        }
    }

    fn skip_whitespace(&mut self) {
        while self.peek().is_some_and(char::is_whitespace) {
            self.bump();
        }
    }

    fn parse(&mut self) -> Result<Grammar, String> {
        self.skip_whitespace();

        let grammar = self.parse_expression()?;

        self.skip_whitespace();
        if self.pos != self.input.len() {
            return Err(format!("unexpected input at byte {}", self.pos));
        }

        Ok(grammar)
    }

    fn parse_sequence(&mut self, end: char) -> Result<Grammar, String> {
        let mut expressions = Vec::new();

        while let Some(ch) = self.peek()
            && ch != end
        {
            if ch.is_whitespace() {
                self.skip_whitespace();
                continue;
            }

            expressions.push(self.parse_expression()?);
        }
        Ok(Grammar::Sequence(expressions))
    }

    fn parse_expression(&mut self) -> Result<Grammar, String> {
        match self.peek() {
            Some('[') => {
                self.bump();
                self.skip_whitespace();
                let sequence = self.parse_sequence(']')?;
                if let Grammar::Sequence(mut seq) = sequence {
                    seq.push(Grammar::Literal("\n".to_string()));
                    self.expect(']')?;
                    Ok(Grammar::Repetitions(Box::new(Grammar::Sequence(seq))))
                } else {
                    unreachable!()
                }
            }

            Some('(') => {
                self.bump();
                let inner = self.parse_sequence(')')?;
                self.expect(')')?;
                if self.consume('?') {
                    Ok(Grammar::Optional(Box::new(inner)))
                } else {
                    Ok(inner)
                }
            }

            Some('{') => {
                self.bump();
                let mut name = String::new();

                while let Some(ch) = self.peek()
                    && ch != '}'
                {
                    name.push(self.bump().unwrap());
                }

                self.expect('}')?;

                if name.is_empty() {
                    return Err("empty capture name".into());
                }

                Ok(Grammar::Capture(name))
            }

            Some('*') => {
                self.bump();
                Ok(Grammar::Any)
            }

            Some(_) => Ok(self.parse_literal()?),

            None => Err("unexpected end of grammar".into()),
        }
    }

    fn parse_literal(&mut self) -> Result<Grammar, String> {
        let mut literal = String::new();

        loop {
            match self.peek() {
                Some('[') | Some(']') | Some('{') | Some('}') | Some(')') | Some('(')
                | Some('*') => break,
                Some('\n') => {
                    literal.push('\n');
                    self.bump();
                    while let Some(' ') = self.peek() {
                        self.bump();
                    }
                }
                Some(ch) => {
                    self.bump();
                    literal.push(ch)
                }
                None => return Err("unterminated string literal".into()),
            }
        }

        Ok(Grammar::Literal(literal))
    }
}

impl TemplateValue {
    pub fn parse_from_grammar(base: &str, grammar: &str, content: &str) -> TemplateValue {
        // println!("{t:#?}");
        match GrammarParser::new(grammar).parse() {
            Ok(grammar) => {
                // println!("Grammar {grammar:#?}");
                match parse_with_grammar(&grammar, content) {
                    Ok((Some(template_value), "")) => template_value,
                    Ok((gram, remaining)) => TemplateValue::Text(base.to_string()),
                    Err(err) => {
                        println!("Err {err}");
                        TemplateValue::Text(base.to_string())
                    }
                }
            }
            Err(err) => {
                println!("Err {err}");

                TemplateValue::Text(base.to_string())
            }
        }
    }
}

fn parse_with_grammar<'a>(
    grammar: &Grammar,
    content: &'a str,
) -> Result<(Option<TemplateValue>, &'a str), String> {
    match grammar {
        Grammar::Sequence(expressions) => {
            let (values, remaining) = parse_sequence(expressions, content)?;
            Ok((Some(TemplateValue::List(values)), remaining))
        }

        Grammar::Repetitions(expression) => {
            let mut remaining_content = content;
            let mut values = Vec::new();

            while !remaining_content.is_empty() {
                remaining_content = remaining_content.trim_ascii_start();
                let previous_len = remaining_content.len();

                let (value, remaining) = parse_with_grammar(expression, remaining_content)?;

                // Prevent infinite loops if the expression matches empty input.
                if remaining.len() >= previous_len {
                    break;
                }

                if let Some(value) = value {
                    match value {
                        TemplateValue::List(items) => values.extend(items),
                        value => values.push(value),
                    }
                }

                remaining_content = remaining;
            }

            Ok((Some(TemplateValue::List(values)), remaining_content))
        }

        Grammar::Literal(literal) => {
            // let content = content.trim_ascii_start();
            match content.strip_prefix(literal.as_str()) {
                Some(remaining) => Ok((Some(TemplateValue::Text(literal.clone())), remaining)),
                None => Err(format!(
                    "Expected {literal:?} at the start of {:?}",
                    &content.get(..literal.len()).unwrap_or(content)
                )),
            }
        }

        Grammar::Capture(name) => Err(format!("Capture {name:?} requires a following expression")),

        Grammar::Optional(inner) => match parse_with_grammar(inner, content) {
            Ok(result) => Ok(result),
            Err(_) => Ok((None, content)),
        },

        Grammar::Any => Ok((Some(TemplateValue::Text(content.to_string())), "")),
    }
}

fn parse_expression_with_following<'a>(
    expression: &Grammar,
    following: &[Grammar],
    content: &'a str,
) -> Result<(Option<TemplateValue>, &'a str), String> {
    match expression {
        Grammar::Capture(name) => {
            let (captured, remaining) = capture_until(following, content)?;

            Ok((
                Some(TemplateValue::Object(hash_map! {
                    name.to_string() => TemplateValue::Text(captured.trim().to_string())
                })),
                remaining,
            ))
        }

        Grammar::Repetitions(expression) => match expression.as_ref() {
            Grammar::Sequence(expressions) => {
                let (items, remaining) = parse_repeated_sequence(expressions, content)?;
                Ok((Some(TemplateValue::List(items)), remaining))
            }
            _ => {
                let (value, remaining) = parse_with_grammar(expression, content)?;
                Ok((value, remaining))
            }
        },

        Grammar::Sequence(expressions) => {
            let (values, remaining) = parse_sequence(expressions, content)?;

            Ok((Some(TemplateValue::List(values)), remaining))
        }

        Grammar::Literal(_) => {
            let (_, remaining) = parse_with_grammar(expression, content)?;
            Ok((None, remaining))
        }
        Grammar::Any => {
            if let Some(mid) = content.trim_ascii_start().find('\n') {
                let (line, rest) = content.trim_ascii_start().split_at(mid);
                // println!("{line:?} {rest:?}");
                Ok((Some(TemplateValue::Text(line.to_string())), rest))
            } else {
                Ok((Some(TemplateValue::Text(content.to_string())), ""))
            }
        }
        Grammar::Optional(_) => {
            let (value, remaining) = parse_with_grammar(expression, content)?;
            match value {
                Some(TemplateValue::List(list))
                    if list
                        .iter()
                        .all(|item| matches!(item, TemplateValue::Object(_))) =>
                {
                    let merged = list
                        .into_iter()
                        .filter_map(|item| match item {
                            TemplateValue::Object(fields) => Some(fields),
                            _ => None,
                        })
                        .reduce(|mut acc, fields| {
                            acc.extend(fields);
                            acc
                        })
                        .unwrap_or_default();

                    Ok((Some(TemplateValue::Object(merged)), remaining))
                }
                _ => Ok((value, remaining)),
            }
        }
    }
}

fn parse_repeated_sequence<'a>(
    expressions: &[Grammar],
    content: &'a str,
) -> Result<(Vec<TemplateValue>, &'a str), String> {
    let mut items = Vec::new();
    let mut remaining = content;

    loop {
        remaining = remaining.trim_ascii_start();

        if remaining.is_empty() {
            break;
        }

        let previous_len = remaining.len();

        match parse_sequence(expressions, remaining) {
            Ok((values, rest)) if rest.len() < previous_len => {
                items.push(TemplateValue::List(values));
                remaining = rest;
            }
            Ok(_) => {
                return Err(format!(
                    "Repeated sequence made no progress at {remaining:?}"
                ));
            }
            Err(_) if !items.is_empty() => break,
            Err(err) => return Err(err),
        }
    }

    Ok((items, remaining))
}

fn parse_sequence<'a>(
    expressions: &[Grammar],
    content: &'a str,
) -> Result<(Vec<TemplateValue>, &'a str), String> {
    let mut values = Vec::new();
    let mut object = HashMap::new();
    let mut remaining = content;

    // println!("{expressions:?} {content:?}");

    for (index, expression) in expressions.iter().enumerate() {
        let following = &expressions[index + 1..];

        let (value, rest) = parse_expression_with_following(expression, following, remaining)?;
        // println!("{expression:?} {following:?} {remaining:?} {value:?}");

        if let Some(TemplateValue::Object(fields)) = value {
            object.extend(fields);
        } else if let Some(value) = value {
            values.push(value);
        }

        remaining = rest;
    }

    if !object.is_empty() {
        values.push(TemplateValue::Object(object));
    }
    // println!("-> {values:?}");

    Ok((values, remaining))
}

fn capture_until<'a>(
    following: &[Grammar],
    content: &'a str,
) -> Result<(&'a str, &'a str), String> {
    for index in content
        .char_indices()
        .map(|(index, _)| index)
        .chain(std::iter::once(content.len()))
    {
        let (captured, remaining) = content.split_at(index);

        if parse_sequence(following, remaining).is_ok_and(|(_, rest)| rest.len() < remaining.len())
        {
            return Ok((captured, remaining));
        }
    }

    if parse_sequence(following, "").is_ok_and(|(_, rest)| rest.is_empty()) {
        return Ok((content, ""));
    }

    Err("No capture boundary allows the remaining grammar to match".into())
}
