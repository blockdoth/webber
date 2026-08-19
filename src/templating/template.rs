use std::collections::HashMap;
use std::fmt::Debug;
use std::fmt::Write as FmtWrite;

use std::fs;
use std::path::Path;
use std::time::SystemTime;

use crate::runtime::misc::date::DateFormat;
use crate::runtime::templating::context::{LocalContext, TemplateContext};
use crate::runtime::templating::error::TemplateErrorMsg;
use crate::runtime::templating::lexer::{TemplateInfo, TemplatePositionData};
use crate::runtime::templating::parser::{
    ConditionExpr, TemplateNode, TemplateNodeData, TemplateParser, Var, VarIndex,
};
use crate::runtime::templating::values::TemplateValueKind;
use crate::runtime::templating::{error::TemplateError, values::TemplateValue};

#[derive(Debug)]
pub struct Template {
    pub template: Vec<TemplateNode>,
    pub parent: Option<String>,
    pub blocks: HashMap<String, Vec<TemplateNode>>,
    pub origin_file: String,
    pub last_modified: SystemTime,
    pub input: String,
    pub newlines: Vec<usize>,
}

impl Template {
    pub fn from_path<P: AsRef<Path> + Debug + Copy>(path: P) -> Result<Self, TemplateError> {
        let path_string = path.as_ref().to_string_lossy().to_string();

        let template_str = fs::read_to_string(path).expect("invariant");

        TemplateParser::parse(&template_str, &path_string)
    }

    pub fn update_from_path<P: AsRef<Path> + Debug + Copy>(
        template: &mut Result<Template, TemplateError>,
        path: P,
    ) {
        let path_string = path.as_ref().to_string_lossy().to_string();

        *template = match fs::read_to_string(path) {
            Ok(template_str) => TemplateParser::parse(&template_str, &path_string),
            Err(e) => Err(TemplateError::only_file(
                TemplateErrorMsg::GenericError(e.to_string()),
                &path_string,
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

        Self::render_helper(&parent.template, context, &self.blocks, render_buffer).map_err(
            |e| match &e.pos {
                Some(pos) => {
                    if pos.file == self.origin_file {
                        e.enhance_error(self)
                    } else if pos.file == parent.origin_file {
                        e.enhance_error(self)
                    } else {
                        panic!("cosmic ray type event")
                    }
                }
                None => e.enhance_error(self),
            },
        )?;
        Ok(render_buffer)
    }

    fn render_helper(
        template: &[TemplateNode],
        context: &dyn TemplateContext,
        blocks: &HashMap<String, Vec<TemplateNode>>,
        out: &mut String,
    ) -> Result<(), TemplateError> {
        use TemplateValue::*;
        for node in template {
            match &node.data {
                TemplateNodeData::Text(text) => out.push_str(text),
                TemplateNodeData::Variable(var) => {
                    match Self::resolve_var(var, context, &node.pos)? {
                        Text(text) => out.push_str(text),
                        Number(number) => out.push_str(&number.to_string()),
                        Bool(bool_val) => write!(out, "{bool_val}")?,
                        List(list) => write!(out, "{list:?}")?,
                        Object(object) => write!(out, "{object:?}")?,
                        Date(date) => write!(out, "{date}")?,
                    }
                }
                TemplateNodeData::If {
                    condition,
                    then_branch,
                    else_branch,
                } => {
                    let cond = match condition {
                        ConditionExpr::Literal(bool_lit) => *bool_lit,
                        ConditionExpr::Var(var) => Self::resolve_bool(var, context, node)?,
                        ConditionExpr::VarComp(var_1, var_2) => {
                            let var_1 = Self::resolve_var(var_1, context, &node.pos)?;
                            let var_2 = Self::resolve_var(var_2, context, &node.pos)?;

                            match (var_1, var_2) {
                                (Text(text_1), Text(text_2)) => text_1 == text_2,
                                _ => {
                                    return Err(TemplateError::new(
                                        TemplateErrorMsg::CantCompareTemplateValues(
                                            var_1.kind(),
                                            var_2.kind(),
                                        ),
                                        node.pos.clone(),
                                    ));
                                }
                            }
                        }
                        ConditionExpr::LiteralComp(var, literal) => {
                            let var = Self::resolve_var(var, context, &node.pos)?;
                            match var {
                                Text(var_text) => var_text == literal,
                                _ => {
                                    return Err(TemplateError::new(
                                        TemplateErrorMsg::CantCompareWithLiteral(var.kind()),
                                        node.pos.clone(),
                                    ));
                                }
                            }
                        }
                    };

                    if cond {
                        Self::render_helper(then_branch, context, blocks, out)?
                    } else {
                        Self::render_helper(else_branch, context, blocks, out)?
                    };
                }
                TemplateNodeData::For {
                    iter_bind,
                    iter_src,
                    body,
                    skip,
                } => {
                    // Todo remove clone
                    match Self::resolve_var(iter_src, context, &node.pos)? {
                        List(iter) => {
                            for it in iter.iter().skip(*skip) {
                                let child_context = LocalContext::new(context, iter_bind, it);

                                Self::render_helper(body, &child_context, blocks, out)?;
                            }
                        }

                        other => {
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
                TemplateNodeData::Block { ident, body } => {
                    if let Some(override_body) = blocks.get(ident) {
                        Self::render_helper(override_body, context, blocks, out)?;
                    } else {
                        Self::render_helper(body, context, blocks, out)?;
                    }
                }
                TemplateNodeData::Date { date_var, format } => {
                    match Self::resolve_var(date_var, context, &node.pos)? {
                        Date(date) => {
                            if let Some(dateformat) = DateFormat::parse(format) {
                                let date = date.format(&dateformat);
                                out.push_str(&date)
                            } else {
                                return Err(TemplateError::new(
                                    TemplateErrorMsg::UnknownDateFormat(format.to_string()),
                                    node.pos.clone(),
                                ));
                            }
                        }
                        other => {
                            return Err(TemplateError::new(
                                TemplateErrorMsg::TemplateValueNotOfExptectedType(
                                    other.kind(),
                                    TemplateValueKind::Date,
                                ),
                                node.pos.clone(),
                            ));
                        }
                    }
                }
            };
        }
        Ok(())
    }

    fn resolve_var<'a>(
        var: &Var,
        context: &'a dyn TemplateContext,
        pos: &TemplatePositionData,
    ) -> Result<&'a TemplateValue, TemplateError> {
        let Some(mut current) = context.lookup(&var.base) else {
            let mut pos = pos.clone();

            if let Some(span) = &mut pos.span {
                span.end = span.start + var.base.len();
            }

            return Err(TemplateError::new(
                TemplateErrorMsg::VariableNotFound(var.base.clone()),
                pos,
            ));
        };

        let node_span = pos.span.as_ref().expect("variable must have span");
        let mut _access_start = node_span.start + var.base.len();

        for access in &var.indices {
            _access_start += 1;

            current = match access {
                VarIndex::Field { field, span } => {
                    let TemplateValue::Object(map) = current else {
                        return Err(TemplateError::new(
                            TemplateErrorMsg::TemplateValueNotOfExptectedType(
                                current.kind(),
                                TemplateValueKind::Object,
                            ),
                            TemplatePositionData {
                                file: pos.file.clone(),
                                span: Some(span.clone()),
                            },
                        ));
                    };

                    map.get(field).ok_or_else(|| {
                        TemplateError::new(
                            TemplateErrorMsg::FieldNotFoundOnVariable(
                                Box::new(var.clone()),
                                field.to_string(),
                            ),
                            TemplatePositionData {
                                file: pos.file.clone(),
                                span: Some(span.clone()),
                            },
                        )
                    })?
                }

                VarIndex::Index { idx, span } => {
                    let TemplateValue::List(list) = current else {
                        return Err(TemplateError::new(
                            TemplateErrorMsg::TemplateValueNotOfExptectedType(
                                current.kind(),
                                TemplateValueKind::List,
                            ),
                            TemplatePositionData {
                                file: pos.file.clone(),
                                span: Some(span.clone()),
                            },
                        ));
                    };

                    list.get(*idx).ok_or_else(|| {
                        TemplateError::new(
                            TemplateErrorMsg::IndexNotInRange(*idx as i64, list.len()),
                            TemplatePositionData {
                                file: pos.file.clone(),
                                span: Some(span.clone()),
                            },
                        )
                    })?
                }

                VarIndex::Var { var, span } => {
                    let TemplateValue::List(list) = current else {
                        return Err(TemplateError::new(
                            TemplateErrorMsg::TemplateValueNotOfExptectedType(
                                current.kind(),
                                TemplateValueKind::List,
                            ),
                            TemplatePositionData {
                                file: pos.file.clone(),
                                span: Some(span.clone()),
                            },
                        ));
                    };

                    let index_value = Self::resolve_var(var, context, pos)?;

                    let TemplateValue::Number(index) = index_value else {
                        return Err(TemplateError::new(
                            TemplateErrorMsg::TemplateValueNotOfExptectedType(
                                index_value.kind(),
                                TemplateValueKind::Number,
                            ),
                            TemplatePositionData {
                                file: pos.file.clone(),
                                span: Some(span.clone()),
                            },
                        ));
                    };

                    if *index < 0 || *index as usize >= list.len() {
                        return Err(TemplateError::new(
                            TemplateErrorMsg::IndexNotInRange(*index, list.len()),
                            TemplatePositionData {
                                file: pos.file.clone(),
                                span: Some(span.clone()),
                            },
                        ));
                    }

                    &list[*index as usize]
                }
            };

            _access_start += access.len();
        }

        Ok(current)
    }

    fn resolve_bool(
        var: &Var,
        context: &dyn TemplateContext,
        node: &TemplateNode,
    ) -> Result<bool, TemplateError> {
        use TemplateValue::*;
        match Self::resolve_var(var, context, &node.pos) {
            Ok(Bool(cond)) => Ok(*cond),
            Ok(List(template_values)) => Ok(!template_values.is_empty()),
            Ok(Text(text)) => Ok(!text.is_empty()),
            Ok(Object(obj)) => Ok(!obj.is_empty()),

            Err(TemplateError {
                typ: TemplateErrorMsg::IndexNotInRange(_, _),
                ..
            }) => Ok(false),

            Err(TemplateError {
                typ: TemplateErrorMsg::FieldNotFoundOnVariable(_, _),
                ..
            }) => Ok(false),

            Ok(other) => Err(TemplateError::new(
                TemplateErrorMsg::TemplateValueNotOfExptectedType(
                    other.kind(),
                    TemplateValueKind::Bool,
                ),
                node.pos.clone(),
            ))?,
            Err(err) => Err(err),
        }
    }
}
