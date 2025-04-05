use github_actions_models::common::{If, expr::ExplicitExpr};

use super::{Audit, AuditState, audit_meta};
use crate::{
    expr::{self, Context, Expr},
    finding::{Confidence, Severity},
    models::JobExt,
};

pub(crate) struct BotConditions;

audit_meta!(BotConditions, "bot-conditions", "spoofable bot actor check");

const SPOOFABLE_ACTOR_CONTEXTS: &[&str] = &["github.actor", "github.triggering_actor"];

impl Audit for BotConditions {
    fn new(_state: &AuditState<'_>) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn audit_normal_job<'w>(
        &self,
        job: &super::NormalJob<'w>,
    ) -> anyhow::Result<Vec<super::Finding<'w>>> {
        let mut findings = vec![];

        // TODO: Consider other triggers as well?
        // In practice we expect to mostly see this problem with `pull_request_target`
        // triggers inside of "automerge this Dependabot PR"-style workflows.
        if !job.parent().has_pull_request_target() {
            return Ok(vec![]);
        }

        let mut conds = vec![];
        if let Some(If::Expr(expr)) = &job.r#if {
            conds.push((expr, job.location()));
        }

        for step in job.steps() {
            if let Some(If::Expr(expr)) = &step.r#if {
                conds.push((expr, step.location()));
            }
        }

        for (expr, loc) in conds {
            if let Some(confidence) = Self::bot_condition(expr) {
                findings.push(
                    Self::finding()
                        .severity(Severity::High)
                        .confidence(confidence)
                        .add_location(
                            loc.with_keys(&["if".into()])
                                .primary()
                                .annotated("actor context may be spoofable"),
                        )
                        .build(job.parent())?,
                );
            }
        }

        Ok(findings)
    }
}

impl BotConditions {
    fn walk_tree_for_bot_condition(expr: &Expr, dominating: bool) -> (bool, bool) {
        match expr {
            // We can't easily analyze the call's semantics, but we can
            // check to see if any of the call's arguments are
            // bot conditions. We treat a call as non-dominating always.
            Expr::Call {
                func: _,
                args: exprs,
            }
            | Expr::Context(Context {
                raw: _,
                components: exprs,
            }) => exprs
                .iter()
                .map(|arg| Self::walk_tree_for_bot_condition(arg, false))
                .reduce(|(bc, _), (bc_next, _)| (bc || bc_next, false))
                .unwrap_or((false, dominating)),
            Expr::Index(expr) => Self::walk_tree_for_bot_condition(expr, dominating),
            Expr::BinOp { lhs, op, rhs } => match op {
                // || is dominating.
                expr::BinOp::Or => {
                    let (bc_lhs, _) = Self::walk_tree_for_bot_condition(lhs, true);
                    let (bc_rhs, _) = Self::walk_tree_for_bot_condition(rhs, true);

                    (bc_lhs || bc_rhs, true)
                }
                // == is trivially dominating.
                expr::BinOp::Eq => match (lhs.as_ref(), rhs.as_ref()) {
                    (Expr::Context(ctx), Expr::String(s))
                    | (Expr::String(s), Expr::Context(ctx)) => {
                        // NOTE: Can't use `contains` here because we need
                        // Context's `PartialEq` for case insensitive matching.
                        if SPOOFABLE_ACTOR_CONTEXTS.iter().any(|x| ctx == *x)
                            && s.ends_with("[bot]")
                        {
                            (true, true)
                        } else {
                            (false, true)
                        }
                    }
                    (lhs, rhs) => {
                        let (bc_lhs, _) = Self::walk_tree_for_bot_condition(lhs, true);
                        let (bc_rhs, _) = Self::walk_tree_for_bot_condition(rhs, true);

                        (bc_lhs || bc_rhs, true)
                    }
                },
                // Every other binop is non-dominating.
                _ => {
                    let (bc_lhs, _) = Self::walk_tree_for_bot_condition(lhs, false);
                    let (bc_rhs, _) = Self::walk_tree_for_bot_condition(rhs, false);

                    (bc_lhs || bc_rhs, false)
                }
            },
            Expr::UnOp { op, expr } => match op {
                // We don't really know what we're negating, so naively
                // assume we're non-dominating.
                //
                // TODO: This is slightly incorrect, since we should
                // treat `!(github.actor == 'dependabot[bot]')` as a
                // negative case even though it has an interior bot condition.
                // However, to model this correctly we need to go from a
                // boolean condition to a three-state: `Some(bool)` for
                // an explicitly toggled condition, and `None` for no condition.
                expr::UnOp::Not => Self::walk_tree_for_bot_condition(expr, false),
            },
            _ => (false, dominating),
        }
    }

    fn bot_condition(expr: &str) -> Option<Confidence> {
        // TODO: Remove clones here.
        let bare = match ExplicitExpr::from_curly(expr) {
            Some(raw_expr) => raw_expr.as_bare().to_string(),
            None => expr.to_string(),
        };

        let Ok(expr) = Expr::parse(&bare) else {
            tracing::warn!("couldn't parse expression: {expr}");
            return None;
        };

        // We're looking for `github.actor == *[bot]` anywhere in the expression tree.
        // The bot condition is said to "dominate" if controls the entire
        // expression truth value. For example, `github.actor == 'dependabot[bot]' || foo`
        // has the bot condition as dominating, since regardless of `foo` the check
        // always passes if the actor is dependabot[bot].
        match Self::walk_tree_for_bot_condition(&expr, true) {
            // We have a bot condition and it dominates the expression.
            (true, true) => Some(Confidence::High),
            // We have a bot condition but it doesn't dominate the expression.
            (true, false) => Some(Confidence::Medium),
            // No bot condition.
            (..) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{audit::bot_conditions::BotConditions, finding::Confidence};

    #[test]
    fn test_bot_condition() {
        for (cond, confidence) in &[
            // Trivial dominating cases.
            ("github.actor == 'dependabot[bot]'", Confidence::High),
            ("'dependabot[bot]' == github.actor", Confidence::High),
            ("'dependabot[bot]' == GitHub.actor", Confidence::High),
            ("'dependabot[bot]' == GitHub.ACTOR", Confidence::High),
            (
                "'dependabot[bot]' == GitHub.triggering_actor",
                Confidence::High,
            ),
            // Dominating cases with OR.
            (
                "'dependabot[bot]' == github.actor || true",
                Confidence::High,
            ),
            (
                "'dependabot[bot]' == github.actor || false",
                Confidence::High,
            ),
            (
                "'dependabot[bot]' == github.actor || github.actor == 'foobar'",
                Confidence::High,
            ),
            (
                "github.actor == 'foobar' || 'dependabot[bot]' == github.actor",
                Confidence::High,
            ),
            // Non-dominating cases with AND.
            (
                "'dependabot[bot]' == github.actor && something.else",
                Confidence::Medium,
            ),
            (
                "something.else && 'dependabot[bot]' == github.actor",
                Confidence::Medium,
            ),
        ] {
            assert_eq!(BotConditions::bot_condition(cond).unwrap(), *confidence);
        }
    }
}
