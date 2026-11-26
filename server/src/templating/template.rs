use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt::Debug;
use std::fmt::Write as FmtWrite;

use std::fs;
use std::hash_map;
use std::path::Path;
use std::rc::Rc;
use std::time::SystemTime;

use crate::runtime::misc::date::DateFormat;
use crate::runtime::templating::context::{LocalContext, TemplateContext};
use crate::runtime::templating::error::TemplateErrorMsg;
use crate::runtime::templating::parser::BinaryOperator;
use crate::runtime::templating::parser::ForIterBind;
use crate::runtime::templating::parser::UnaryOperator;
use crate::runtime::templating::parser::{TemplateNode, TemplateParser, TemplateStatement};
use crate::runtime::templating::values::TemplateValueKind;
use crate::runtime::templating::values::ToTemplateValue;
use crate::runtime::templating::{error::TemplateError, values::TemplateValue};

#[derive(Debug)]
pub struct Template {
    pub template: Vec<TemplateNode>,
    pub parent: Option<String>,
    pub blocks: HashMap<String, Vec<TemplateNode>>,
    pub origin_file: Rc<str>,
    pub last_modified: SystemTime,
    pub input: String,
    pub newlines: Vec<usize>,
}

impl Template {
    pub fn from_path<P: AsRef<Path> + Debug + Copy>(path: P) -> Result<Self, TemplateError> {
        let path_string = path.as_ref().to_string_lossy();

        let template_str = fs::read_to_string(path).expect("invariant");

        TemplateParser::parse(&template_str, &path_string)
    }

    pub fn update_from_path<P: AsRef<Path> + Debug + Copy>(
        template: &mut Result<Template, TemplateError>,
        path: P,
    ) {
        let path_string = path.as_ref().to_string_lossy();

        *template = match fs::read_to_string(path) {
            Ok(template_str) => TemplateParser::parse(&template_str, path_string.as_ref()),
            Err(e) => Err(TemplateError::only_file(
                TemplateErrorMsg::GenericError(e.to_string()),
                path_string.as_ref().into(),
            )),
        };
    }

    pub fn render<'a>(
        &self,
        context: &dyn TemplateContext,
        render_buffer: &'a mut String,
    ) -> Result<&'a str, TemplateError> {
        render_buffer.clear();
        Self::render_helper(&self.template, context, &HashMap::new(), render_buffer)
            .map_err(|e| e.enhance_error(self))?;
        Ok(render_buffer)
    }

    pub fn render_with_parent<'a>(
        &self,
        context: &dyn TemplateContext,
        parent: &Template,
        render_buffer: &'a mut String,
    ) -> Result<&'a str, TemplateError> {
        render_buffer.clear();

        Self::render_helper(&parent.template, context, &self.blocks, render_buffer)
            .map_err(|e| e.enhance_error(self))?;

        Ok(render_buffer)
    }

    fn eval<'a>(
        expr: &'a TemplateNode,
        context: &'a dyn TemplateContext,
        blocks: &HashMap<String, Vec<TemplateNode>>,
    ) -> Result<Cow<'a, TemplateValue>, TemplateError> {
        use TemplateValue::*;

        match &expr.expr {
            TemplateStatement::BinaryOp { op, left, right } => {
                Self::eval_binary(op, left, right, context, blocks)
            }
            TemplateStatement::UnaryOp { op, operand } => {
                Self::eval_unary(op, operand, context, blocks)
            }
            TemplateStatement::Variable(var) => {
                match context.lookup(var) {
                    Some(var) => Ok(Cow::Borrowed(var)), // TODO remove clone
                    None => {
                        let mut pos = expr.pos.clone();

                        if let Some(span) = &mut pos.span {
                            span.end = span.start + var.len();
                        }

                        Err(TemplateError::new(
                            TemplateErrorMsg::VariableNotFound(var.clone()),
                            pos,
                        ))
                    }
                }
            }

            TemplateStatement::Field {
                parent,
                name,
                optional,
            } => match Self::eval(parent, context, blocks)? {
                Cow::Borrowed(TemplateValue::Object(obj)) => {
                    if let Some(value) = obj.get(name) {
                        Ok(Cow::Borrowed(value))
                    } else if *optional {
                        Ok(Cow::Owned(TemplateValue::Null))
                    } else {
                        todo!()
                    }
                }
                Cow::Owned(TemplateValue::Object(mut obj)) => {
                    if let Some(value) = obj.remove(name) {
                        Ok(Cow::Owned(value))
                    } else if *optional {
                        Ok(Cow::Owned(TemplateValue::Null))
                    } else {
                        todo!()
                    }
                }
                _ => todo!(),
            },
            TemplateStatement::Index { parent, name: idx } => {
                match (
                    Self::eval(parent, context, blocks)?,
                    Self::eval(idx, context, blocks)?.as_ref(),
                ) {
                    (Cow::Borrowed(TemplateValue::List(list)), TemplateValue::Number(idx))
                        if *idx >= 0 && *idx < list.len() as i64 =>
                    {
                        Ok(Cow::Borrowed(
                            list.get(*idx as usize).expect("bounds invariant"),
                        ))
                    }
                    (Cow::Owned(TemplateValue::List(list)), TemplateValue::Number(idx))
                        if *idx >= 0 && *idx < list.len() as i64 =>
                    {
                        Ok(Cow::Owned(
                            list.get(*idx as usize).expect("bounds invariant").clone(),
                        ))
                    }
                    _ => todo!(),
                }
            }
            TemplateStatement::Range { parent, start, end } => {
                match (
                    Self::eval(parent, context, blocks)?.as_ref(),
                    Self::eval(start, context, blocks)?.as_ref(),
                    Self::eval(end, context, blocks)?.as_ref(),
                ) {
                    (
                        TemplateValue::List(list),
                        TemplateValue::Number(start),
                        TemplateValue::Number(end),
                    ) if *start >= 0 && *end < list.len() as i64 && end <= start => {
                        Ok(Cow::Owned(TemplateValue::List(
                            list[*start as usize..*end as usize].to_vec(),
                        ))) //TODO change
                    }
                    _ => todo!(),
                }
            }

            TemplateStatement::Number(number) => Ok(Cow::Owned(TemplateValue::Number(*number))),
            TemplateStatement::Bool(bool) => Ok(Cow::Owned(TemplateValue::Bool(*bool))),
            TemplateStatement::Date { date_var, format } => {
                match Self::eval(date_var, context, blocks)?.as_ref() {
                    Date(date) => {
                        if let Some(dateformat) = DateFormat::parse(&format.to_string()) {
                            Ok(Cow::Owned(TemplateValue::Text(date.format(&dateformat))))
                        } else {
                            Err(TemplateError::new(
                                TemplateErrorMsg::UnknownDateFormat(format.to_string()),
                                expr.pos.clone(),
                            ))
                        }
                    }
                    _ => todo!(),
                }
            }
            TemplateStatement::Expression(_template_nodes) => todo!(),
            _ => unreachable!(),
        }
    }

    fn render_helper(
        nodes: &Vec<TemplateNode>,
        context: &dyn TemplateContext,
        blocks: &HashMap<String, Vec<TemplateNode>>,
        out: &mut String,
    ) -> Result<(), TemplateError> {
        use TemplateValue::*;
        for node in nodes {
            match &node.expr {
                TemplateStatement::Text(text) => write!(out, "{text}")?,
                TemplateStatement::Block { ident, body } => {
                    if let Some(override_body) = blocks.get(ident) {
                        Self::render_helper(override_body, context, blocks, out)?
                    } else {
                        Self::render_helper(body, context, blocks, out)?
                    }
                }
                TemplateStatement::If {
                    condition,
                    then_branch,
                    else_branch,
                } => {
                    if Self::eval_bool(condition, context, blocks)? {
                        Self::render_helper(then_branch, context, blocks, out)?
                    } else if let Some(else_branch) = else_branch {
                        Self::render_helper(else_branch, context, blocks, out)?
                    }
                }
                TemplateStatement::For {
                    iter_bind,
                    iter_src,
                    body,
                } => {
                    // Todo remove clone
                    match (Self::eval(iter_src, context, blocks)?.as_ref(), iter_bind) {
                        (List(iter), ForIterBind::Simple(iter_bind)) => {
                            for it in iter.iter() {
                                let child_context = LocalContext::new(context, iter_bind, it);

                                Self::render_helper(body, &child_context, blocks, out)?;
                            }
                        }
                        (List(_), ForIterBind::Object(_)) => {
                            return Err(TemplateError::new(
                                TemplateErrorMsg::WrongIterBindForList,
                                node.pos.clone(),
                            ));
                        }

                        (Object(iter), ForIterBind::Object((key_bind, iter_bind))) => {
                            let mut sorted: Vec<(&String, &TemplateValue)> = iter.iter().collect();
                            sorted.sort_unstable_by_key(|(key, _)| *key);
                            for (key, bind) in sorted.into_iter() {
                                let key = key.clone().to_template_value(); //todo remove clone
                                let child_context = LocalContext::new(context, key_bind, &key);
                                let child_context =
                                    LocalContext::new(&child_context, iter_bind, bind);

                                Self::render_helper(body, &child_context, blocks, out)?;
                            }
                        }

                        (Object(iter), ForIterBind::Simple(iter_bind)) => {
                            let mut sorted: Vec<(&String, &TemplateValue)> = iter.iter().collect();
                            sorted.sort_unstable_by_key(|(key, _)| *key);
                            for (key, bind) in sorted.into_iter() {
                                let key = key.clone().to_template_value(); //todo remove clone
                                let object = TemplateValue::Object(hash_map! {
                                    "key".to_string() => key,
                                    "value".to_string() => bind.clone(), // Todo remove clone
                                });

                                let child_context = LocalContext::new(context, iter_bind, &object);

                                Self::render_helper(body, &child_context, blocks, out)?;
                            }
                        }

                        (other, _) => {
                            return Err(TemplateError::new(
                                TemplateErrorMsg::TemplateValueNotOfExptectedType(
                                    other.kind(),
                                    TemplateValueKind::List,
                                ),
                                node.pos.clone(),
                            ));
                        }
                    }
                }

                _ => {
                    let str = Self::eval(node, context, blocks)?;
                    write!(out, "{str}")?;
                }
            };
        }

        Ok(())
    }

    fn eval_unary<'a>(
        op: &UnaryOperator,
        expr: &TemplateNode,
        context: &'a dyn TemplateContext,
        blocks: &HashMap<String, Vec<TemplateNode>>,
    ) -> Result<Cow<'a, TemplateValue>, TemplateError> {
        match (op, Self::eval(expr, context, blocks)?.as_ref()) {
            (UnaryOperator::Not, TemplateValue::Bool(bool)) => {
                Ok(Cow::Owned(TemplateValue::Bool(!bool)))
            }
            _ => todo!(),
        }
    }

    fn eval_binary<'a>(
        op: &BinaryOperator,
        left: &TemplateNode,
        right: &TemplateNode,
        context: &'a dyn TemplateContext,
        blocks: &HashMap<String, Vec<TemplateNode>>,
    ) -> Result<Cow<'a, TemplateValue>, TemplateError> {
        use BinaryOperator::*;

        match (
            Self::eval(left, context, blocks)?.as_ref(),
            op,
            Self::eval(right, context, blocks)?.as_ref(),
        ) {
            (TemplateValue::Bool(left), Equals, TemplateValue::Bool(right)) => {
                Ok(Cow::Owned(TemplateValue::Bool(left == right)))
            }
            _ => todo!(),
        }
    }

    fn eval_bool(
        expr: &TemplateNode,
        context: &dyn TemplateContext,
        blocks: &HashMap<String, Vec<TemplateNode>>,
    ) -> Result<bool, TemplateError> {
        use TemplateValue::*;
        match Self::eval(expr, context, blocks)?.as_ref() {
            Bool(cond) => Ok(*cond),
            List(template_values) => Ok(!template_values.is_empty()),
            Text(text) => Ok(!text.is_empty()),
            Object(obj) => Ok(!obj.is_empty()),
            _ => todo!(),
        }
    }
}
