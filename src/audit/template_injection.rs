//! (Very) primitive template injection detection.
//!
//! This looks for job steps where the step contains indicators of template
//! expansion, i.e. anything matching `${{ }}`.
//!
//! The following steps are currently supported:
//! * `run:`, indicating template expansion into a shell script or similar
//! * `actions/github-script`, indicating template expansion into a JavaScript function
//!
//! A small amount of additional processing is done to remove template
//! expressions that an attacker can't control.

use std::ops::Deref;

use github_actions_models::{
    common::expr::LoE,
    workflow::job::{NormalJob, StepBody, Strategy},
};

use super::{audit_meta, WorkflowAudit};
use crate::{
    expr::{BinOp, Expr, UnOp},
    finding::{Confidence, Persona, Severity},
    models,
    state::AuditState,
    utils::extract_expressions,
};

pub(crate) struct TemplateInjection;

audit_meta!(
    TemplateInjection,
    "template-injection",
    "code injection via template expansion"
);

/// Context members that are believed to be always safe.
const SAFE_CONTEXTS: &[&str] = &[
    // The GitHub event name (i.e. trigger) is itself safe.
    "github.event_name",
    // Safe keys within the otherwise generally unsafe github.event context.
    "github.event.issue.number",
    "github.event.merge_group.base_sha",
    "github.event.number",
    "github.event.pull_request.commits", // number of commits in PR
    "github.event.pull_request.number",  // the PR's own number
    "github.event.workflow_run.id",
    // Information about the GitHub repository
    "github.repository",
    "github.repository_id",
    "github.repositoryUrl",
    // Information about the GitHub repository owner (account/org or ID)
    "github.repository_owner",
    "github.repository_owner_id",
    // Unique numbers assigned by GitHub for workflow runs
    "github.run_attempt",
    "github.run_id",
    "github.run_number",
    // Always a 40-char SHA-1 reference.
    "github.sha",
    // Like `secrets.*`: not safe to expose, but safe to interpolate.
    "github.token",
    // GitHub Actions-controlled local directory.
    "github.workspace",
    // GitHub Actions-controller runner architecture.
    "runner.arch",
    // Debug logging is (1) or is not (0) enabled on GitHub Actions runner.
    "runner.debug",
    // GitHub Actions runner operating system.
    "runner.os",
];

impl TemplateInjection {
    /// Checks whether an expression is "safe" for the purposes of template
    /// injection.
    ///
    /// In the context of template injection, a "safe" expression is one that
    /// can only ever return a literal node (i.e. bool, number, string, etc.).
    /// All branches/flows of the expression must uphold that invariant;
    /// no taint tracking is currently done.
    fn expr_is_safe(expr: &Expr) -> bool {
        match expr {
            Expr::Number(_) => true,
            Expr::String(_) => true,
            Expr::Boolean(_) => true,
            Expr::Null => true,
            // NOTE: Currently unreachable, since we churlishly consider
            // indexing expressions unsafe and `Expr::Star` only occurs
            // within indices at the moment.
            Expr::Star => unreachable!(),
            // NOTE: Some index operations may be safe, but for now
            // we consider them all unsafe.
            Expr::Index { .. } => false,
            // NOTE: Some function calls may be safe, but for now
            // we consider them all unsafe.
            Expr::Call { .. } => false,
            // We consider all context accesses unsafe. This isn't true,
            // but our audit filters the safe ones later on.
            Expr::Context(_) => false,
            Expr::BinOp { lhs, op, rhs } => {
                match op {
                    // `==` and `!=` are always safe, since they evaluate to
                    // boolean rather than to the truthy value.
                    BinOp::Eq | BinOp::Neq => true,
                    // `&&` is safe if its RHS is safe, since && cannot
                    // short-circuit.
                    BinOp::And => Self::expr_is_safe(rhs),
                    // We consider all other binops safe if both sides are safe,
                    // regardless of the actual operation type. This could be
                    // refined to check only one side with taint information.
                    // TODO: Relax this for >/>=/</<=?
                    _ => Self::expr_is_safe(lhs) && Self::expr_is_safe(rhs),
                }
            }
            Expr::UnOp { op, .. } => match op {
                // !expr always produces a boolean.
                UnOp::Not => true,
            },
        }
    }

    fn injectable_template_expressions(
        &self,
        run: &str,
        job: &NormalJob,
    ) -> Vec<(String, Severity, Confidence, Persona)> {
        let mut bad_expressions = vec![];
        for expr in extract_expressions(run) {
            let Ok(parsed) = Expr::parse(expr.as_bare()) else {
                tracing::warn!("couldn't parse expression: {expr}", expr = expr.as_bare());
                continue;
            };

            if Self::expr_is_safe(&parsed) {
                // Emit a pedantic finding for all expressions, since
                // all template injections are code smells, even if unexploitable.
                bad_expressions.push((
                    expr.as_raw().into(),
                    Severity::Unknown,
                    Confidence::Unknown,
                    Persona::Pedantic,
                ));
                continue;
            }

            for context in parsed.contexts() {
                if context.starts_with("secrets.") {
                    // While not ideal, secret expansion is typically not exploitable.
                    continue;
                } else if SAFE_CONTEXTS.contains(&context) {
                    continue;
                } else if context.starts_with("inputs.") {
                    // TODO: Currently low confidence because we don't check the
                    // input's type. In the future, we should index back into
                    // the workflow's triggers and exclude input expansions
                    // from innocuous types, e.g. booleans.
                    bad_expressions.push((
                        context.into(),
                        Severity::High,
                        Confidence::Low,
                        Persona::default(),
                    ));
                } else if context.starts_with("env.") {
                    // Almost never exploitable.
                    bad_expressions.push((
                        context.into(),
                        Severity::Low,
                        Confidence::High,
                        Persona::default(),
                    ));
                } else if context.starts_with("github.event.") || context == "github.ref_name" {
                    // TODO: Filter these more finely; not everything in the event
                    // context is actually attacker-controllable.
                    bad_expressions.push((
                        context.into(),
                        Severity::High,
                        Confidence::High,
                        Persona::default(),
                    ));
                } else if context.starts_with("matrix.") || context == "matrix" {
                    if let Some(Strategy { matrix, .. }) = &job.strategy {
                        let matrix_is_static = match matrix {
                            // The matrix is generated by an expression, meaning
                            // that it's trivially not static.
                            Some(LoE::Expr(_)) => false,

                            Some(inner) => models::Matrix::new(inner).is_static(),
                            // Context specifies a matrix, but there is no matrix defined.
                            // This is an invalid workflow so there's no point in flagging it.
                            None => continue,
                        };

                        if !matrix_is_static {
                            bad_expressions.push((
                                context.into(),
                                Severity::Medium,
                                Confidence::Medium,
                                Persona::default(),
                            ));
                        }
                    }
                    continue;
                } else {
                    // All other contexts are typically not attacker controllable,
                    // but may be in obscure cases.
                    bad_expressions.push((
                        context.into(),
                        Severity::Informational,
                        Confidence::Low,
                        Persona::default(),
                    ));
                }
            }
        }

        bad_expressions
    }
}

impl WorkflowAudit for TemplateInjection {
    fn new(_state: AuditState) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn audit_step<'w>(&self, step: &super::Step<'w>) -> anyhow::Result<Vec<super::Finding<'w>>> {
        let mut findings = vec![];

        let (script, script_loc) = match &step.deref().body {
            StepBody::Uses { uses, with } => {
                if uses.starts_with("actions/github-script") {
                    match with.get("script") {
                        Some(script) => (
                            &script.to_string(),
                            step.location().with_keys(&["with".into(), "script".into()]),
                        ),
                        None => return Ok(findings),
                    }
                } else {
                    return Ok(findings);
                }
            }
            StepBody::Run { run, .. } => (run, step.location().with_keys(&["run".into()])),
        };

        for (expr, severity, confidence, persona) in
            self.injectable_template_expressions(script, step.job())
        {
            findings.push(
                Self::finding()
                    .severity(severity)
                    .confidence(confidence)
                    .persona(persona)
                    .add_location(step.location_with_name())
                    .add_location(
                        script_loc.clone().annotated(format!(
                            "{expr} may expand into attacker-controllable code"
                        )),
                    )
                    .build(step.workflow())?,
            )
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use crate::audit::template_injection::TemplateInjection;

    use super::Expr;

    #[test]
    fn test_expr_is_safe() {
        let cases = &[
            // Literals are always safe.
            ("true", true),
            ("false", true),
            ("1.0", true),
            ("null", true),
            ("'some string'", true),
            // negation is always safe.
            ("!true", true),
            ("!some.context", true),
            // == / != are always safe, even if their hands are not.
            ("true == true", true),
            ("'true' == true", true),
            ("some.context == true", true),
            ("contains(some.context, 'foo') != true", true),
            // || is safe if both hands are safe.
            ("true || true", true),
            ("some.context || true", false),
            ("true || some.context", false),
            // && is true if the RHS is safe.
            ("true && true", true),
            ("some.context && true", true),
            ("true && other.context", false),
            ("some.context && other.context", false),
            // Index ops and function calls are unsafe.
            ("some.context[0]", false),
            ("some.context[*]", false),
            ("someFunction()", false),
            ("fromJSON(some.context)", false),
            ("toJSON(fromJSON(some.context))", false),
            // Context accesses are unsafe.
            ("some.context", false),
            ("some.context.*.something", false),
            // More complicated cases:
            ("some.condition && '--some-arg' || ''", true),
            ("some.condition && some.context || ''", false),
            ("some.condition && '--some-arg' || some.context", false),
            (
                "(github.actor != 'github-actions[bot]' && github.actor) || 'BrewTestBot'",
                false,
            ),
        ];

        for (case, safe) in cases {
            let expr = Expr::parse(case).unwrap();
            assert_eq!(TemplateInjection::expr_is_safe(&expr), *safe, "{expr:#?}");
        }
    }
}
