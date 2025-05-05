//! (Very) primitive template injection detection.
//!
//! This looks for job steps where the step contains indicators of template
//! expansion, i.e. anything matching `${{ }}`.
//!
//! The list of injection sinks is based on [CodeQL's models](https://github.com/github/codeql/blob/main/actions/ql/lib/ext).
//! The models are processed and filtered by a workflow on the zizmor repository.
//!
//! A small amount of additional processing is done to remove template
//! expressions that an attacker can't control.

use std::{collections::HashMap, sync::LazyLock};

use github_actions_models::{
    common::{Uses, expr::LoE},
    workflow::job::Strategy,
};
use itertools::Itertools;

use super::{Audit, AuditLoadError, audit_meta};
use crate::{
    expr::{BinOp, Expr, UnOp},
    finding::{Confidence, Finding, Persona, Severity, SymbolicLocation},
    models::{self, CompositeStep, Step, StepCommon, uses::RepositoryUsesExt as _},
    state::AuditState,
    utils::extract_expressions,
};

pub(crate) struct TemplateInjection;

audit_meta!(
    TemplateInjection,
    "template-injection",
    "code injection via template expansion"
);

/// Contexts that are believed to be always safe.
const SAFE_CONTEXTS: &[&str] = &[
    // The action path is always safe.
    "github.action_path",
    // The GitHub event name (i.e. trigger) is itself safe.
    "github.event_name",
    // Safe keys within the otherwise generally unsafe github.event context.
    "github.event.after",                // hexadecimal SHA ref
    "github.event.before",               // hexadecimal SHA ref
    "github.event.issue.number",         // the issue's own number
    "github.event.merge_group.base_sha", // hexadecimal SHA ref
    "github.event.number",
    "github.event.pull_request.base.sha", // hexadecimal SHA ref
    "github.event.pull_request.head.sha", // hexadecimal SHA ref
    "github.event.pull_request.head.repo.fork", // boolean
    "github.event.pull_request.commits",  // number of commits in PR
    "github.event.pull_request.number",   // the PR's own number
    "github.event.workflow_run.id",
    // Corresponds to the job ID, which is workflow-controlled
    // but can only be [A-Za-z0-9-_].
    // See: https://docs.github.com/en/actions/writing-workflows/workflow-syntax-for-github-actions#jobsjob_id
    "github.job",
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
    // Typically something like `https://github.com`; you have bigger problems if
    // this is attacker-controlled.
    "github.server_url",
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
    // GitHub Actions temporary directory, value controlled by the runner itself.
    "runner.temp",
    // GitHub Actions cached tool directory, value controlled by the runner itself.
    "runner.tool_cache",
];

impl TemplateInjection {
    /// For the name of an action (e.g. `actions/github-script`) gets the `inputs`
    /// which may allow code injection.
    fn action_injection_inputs(action_name: &str) -> &[&'static str] {
        static MODEL_INJECTION_SINKS: LazyLock<HashMap<&str, Vec<&str>>> = LazyLock::new(|| {
            let mut m = HashMap::new();
            let model_data = include_str!("../../code-injection-models.txt");

            for line in model_data.split_terminator("\n") {
                let (action, inputs) = line.split("|").collect_tuple().unwrap();
                let inputs = inputs.split(",").collect();
                m.insert(action, inputs);
            }

            m
        });

        match action_name {
            // Hardcoded sinks which are not part of CodeQL models yet
            "amadevus/pwsh-script" => &["script"],
            "jannekem/run-python-script-action" => &["script"],
            "cardinalby/js-eval-action" => &["expression"],
            _ => match MODEL_INJECTION_SINKS.get(action_name) {
                Some(inputs) => inputs,
                None => &[],
            },
        }
    }

    fn scripts_with_location<'s>(
        step: &impl StepCommon<'s>,
    ) -> Vec<(String, SymbolicLocation<'s>)> {
        match step.body() {
            models::StepBodyCommon::Uses {
                uses: Uses::Repository(uses),
                with,
            } => TemplateInjection::action_injection_inputs(&uses.path_without_ref())
                .iter()
                .filter_map(|input| {
                    let input = *input;
                    with.get(input).map(|script| {
                        (
                            script.to_string(),
                            step.location().with_keys(&["with".into(), input.into()]),
                        )
                    })
                })
                .collect(),
            models::StepBodyCommon::Run { run, .. } => {
                vec![(run.to_string(), step.location().with_keys(&["run".into()]))]
            }
            _ => vec![],
        }
    }

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
            // NOTE: Currently unreachable, since these only occur
            // within Expr::Context and we handle that at the top-level.
            Expr::Star | Expr::Identifier(_) | Expr::Index(_) => unreachable!(),
            // NOTE: Some function calls may be safe, but for now
            // we consider them all unsafe.
            Expr::Call { .. } => false,
            // We consider all context accesses unsafe. This isn't true,
            // but our audit filters the safe ones later on.
            Expr::Context { .. } => false,
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

    fn injectable_template_expressions<'s>(
        &self,
        run: &str,
        step: &impl StepCommon<'s>,
    ) -> Vec<(String, Severity, Confidence, Persona)> {
        let mut bad_expressions = vec![];
        for (expr, _) in extract_expressions(run) {
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

            for context in parsed.dataflow_contexts() {
                if context.child_of("secrets") {
                    // While not ideal, secret expansion is typically not exploitable.
                    continue;
                } else if SAFE_CONTEXTS.iter().any(|safe| *context == **safe) {
                    continue;
                } else if context.child_of("inputs") {
                    // TODO: Currently low confidence because we don't check the
                    // input's type. In the future, we should index back into
                    // the workflow's triggers and exclude input expansions
                    // from innocuous types, e.g. booleans.
                    bad_expressions.push((
                        context.as_str().into(),
                        Severity::High,
                        Confidence::Low,
                        Persona::default(),
                    ));
                } else if let Some(env) = context.pop_if("env") {
                    let env_is_static = step.env_is_static(env);

                    if !env_is_static {
                        bad_expressions.push((
                            context.as_str().into(),
                            Severity::Low,
                            Confidence::High,
                            Persona::default(),
                        ));
                    }
                } else if context.child_of("github") {
                    // TODO: Filter these more finely; not everything in the event
                    // context is actually attacker-controllable.
                    bad_expressions.push((
                        context.as_str().into(),
                        Severity::High,
                        Confidence::High,
                        Persona::default(),
                    ));
                } else if context.child_of("matrix") || context == "matrix" {
                    if let Some(Strategy { matrix, .. }) = step.strategy() {
                        let matrix_is_static = match matrix {
                            // The matrix is generated by an expression, meaning
                            // that it's trivially not static.
                            Some(LoE::Expr(_)) => false,
                            // The matrix may expand to static values according to the context
                            Some(inner) => models::Matrix::new(inner)
                                .expands_to_static_values(context.as_str()),
                            // Context specifies a matrix, but there is no matrix defined.
                            // This is an invalid workflow so there's no point in flagging it.
                            None => continue,
                        };

                        if !matrix_is_static {
                            bad_expressions.push((
                                context.as_str().into(),
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
                        context.as_str().into(),
                        Severity::Informational,
                        Confidence::Low,
                        Persona::default(),
                    ));
                }
            }
        }

        bad_expressions
    }

    fn process_step<'doc>(
        &self,
        step: &impl StepCommon<'doc>,
    ) -> anyhow::Result<Vec<Finding<'doc>>> {
        let mut findings = vec![];

        for (script, script_loc) in Self::scripts_with_location(step) {
            for (expr, severity, confidence, persona) in
                self.injectable_template_expressions(&script, step)
            {
                findings.push(
                    Self::finding()
                        .severity(severity)
                        .confidence(confidence)
                        .persona(persona)
                        .add_location(step.location().hidden())
                        .add_location(step.location_with_name())
                        .add_location(script_loc.clone().primary().annotated(format!(
                            "{expr} may expand into attacker-controllable code"
                        )))
                        .build(step)?,
                )
            }
        }

        Ok(findings)
    }
}

impl Audit for TemplateInjection {
    fn new(_state: &AuditState<'_>) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn audit_step<'doc>(&self, step: &Step<'doc>) -> anyhow::Result<Vec<Finding<'doc>>> {
        self.process_step(step)
    }

    fn audit_composite_step<'a>(
        &self,
        step: &CompositeStep<'a>,
    ) -> anyhow::Result<Vec<Finding<'a>>> {
        self.process_step(step)
    }
}

#[cfg(test)]
mod tests {
    use super::{Expr, TemplateInjection};

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
