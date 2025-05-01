use github_actions_models::common::{If, expr::ExplicitExpr};

use super::{Audit, AuditLoadError, AuditState, audit_meta};
use crate::{
    expr::{Context, Expr},
    finding::{Confidence, Severity},
    models::JobExt,
};

const USER_CONTROLLABLE_CONTEXTS: &[&str] = &[
    "env.GITHUB_ACTOR",
    "env.GITHUB_BASE_REF",
    "env.GITHUB_HEAD_REF",
    "env.GITHUB_REF",
    "env.GITHUB_REF_NAME",
    "env.GITHUB_SHA",
    "env.GITHUB_TRIGGERING_ACTOR",
    "github.actor",
    "github.base_ref",
    "github.head_ref",
    "github.ref",
    "github.ref_name",
    "github.sha",
    "github.triggering_actor",
    "inputs.",
];

pub(crate) struct BypassableContainsConditions;

audit_meta!(
    BypassableContainsConditions,
    "bypassable-contains-conditions",
    "bypassable contains conditions checks"
);

impl Audit for BypassableContainsConditions {
    fn new(_state: &AuditState<'_>) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn audit_normal_job<'w>(
        &self,
        job: &super::NormalJob<'w>,
    ) -> anyhow::Result<Vec<super::Finding<'w>>> {
        let conditions = job
            .r#if
            .iter()
            .map(|cond| (cond, job.location()))
            .chain(
                job.steps()
                    .filter_map(|step| step.r#if.as_ref().map(|cond| (cond, step.location()))),
            )
            .filter_map(|(cond, loc)| {
                if let If::Expr(expr) = cond {
                    Some((expr.as_str(), loc))
                } else {
                    None
                }
            });

        conditions
            .flat_map(|(expr, loc)| {
                Self::insecure_contains(expr).into_iter().map(move |(severity, context)| {
                    Self::finding()
                        .severity(severity)
                        .confidence(Confidence::High)
                        .add_location(
                            loc.with_keys(&["if".into()])
                                .primary()
                                .annotated(format!("contains(..) condition can be bypassed if attacker can control '{context}'")),
                        )
                        .build(job.parent())
                })
            })
            .collect()
    }
}

impl BypassableContainsConditions {
    fn walk_tree_for_insecure_contains<'a>(
        expr: &'a Expr,
    ) -> Box<dyn Iterator<Item = (&'a str, &'a Context<'a>)> + 'a> {
        match expr {
            Expr::Call { func, args: exprs } if func == "contains" => {
                match exprs.as_slice() {
                    [Expr::String(s), Expr::Context(c)] => {
                        Box::new(std::iter::once((s.as_str(), c)))
                    }
                    args => Box::new(args.iter().flat_map(Self::walk_tree_for_insecure_contains)),
                }
            }
            Expr::Call {
                func: _,
                args: exprs,
            }
            | Expr::Context(Context {
                raw: _,
                components: exprs,
            }) => Box::new(exprs.iter().flat_map(Self::walk_tree_for_insecure_contains)),
            Expr::Index(expr) => Self::walk_tree_for_insecure_contains(expr),
            Expr::BinOp { lhs, rhs, .. } => {
                let bc_lhs = Self::walk_tree_for_insecure_contains(lhs);
                let bc_rhs = Self::walk_tree_for_insecure_contains(rhs);

                Box::new(bc_lhs.chain(bc_rhs))
            }
            Expr::UnOp { expr, .. } => Self::walk_tree_for_insecure_contains(expr),
            _ => Box::new(std::iter::empty()),
        }
    }

    fn insecure_contains(expr: &str) -> Vec<(Severity, String)> {
        let bare = match ExplicitExpr::from_curly(expr) {
            Some(raw_expr) => raw_expr.as_bare().to_string(),
            None => expr.to_string(),
        };

        Expr::parse(&bare)
            .inspect_err(|_err| tracing::warn!("couldn't parse expression: {expr}"))
            .iter()
            .flat_map(|expression| Self::walk_tree_for_insecure_contains(expression))
            .map(|(_s, ctx)| {
                let severity = if USER_CONTROLLABLE_CONTEXTS.iter().any(|item| {
                    let context = &ctx.as_str();
                    item == context || (item.ends_with(".") && context.starts_with(item))
                }) {
                    Severity::High
                } else {
                    Severity::Informational
                };
                (severity, ctx.as_str().to_string())
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bot_condition() {
        for (cond, severity) in &[
            // Vulnerable conditions
            (
                "contains('refs/heads/main refs/heads/develop', github.ref)",
                vec![(Severity::High, String::from("github.ref"))],
            ),
            (
                "false || contains('main,develop', github.head_ref)",
                vec![(Severity::High, String::from("github.head_ref"))],
            ),
            (
                "!contains('main|develop', github.base_ref)",
                vec![(Severity::High, String::from("github.base_ref"))],
            ),
            (
                "contains(fromJSON('[true]'), contains('refs/heads/main refs/heads/develop', env.GITHUB_REF))",
                vec![(Severity::High, String::from("env.GITHUB_REF"))],
            ),
            (
                "contains('push pull_request', github.event_name)",
                vec![(Severity::Informational, String::from("github.event_name"))],
            ),
            // These are okay.
            (
                "github.ref == 'refs/heads/main' || github.ref == 'refs/heads/develop'",
                vec![],
            ),
            (
                "contains(fromJSON('[\"refs/heads/main\", \"refs/heads/develop\"]'), github.ref)",
                vec![],
            ),
        ] {
            assert_eq!(
                BypassableContainsConditions::insecure_contains(cond).as_slice(),
                severity.as_slice()
            );
        }
    }
}
