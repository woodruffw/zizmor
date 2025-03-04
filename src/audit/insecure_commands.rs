use std::ops::Deref;

use anyhow::Result;
use github_actions_models::action;
use github_actions_models::common::expr::LoE;
use github_actions_models::common::{Env, EnvValue};
use github_actions_models::workflow::job::StepBody;

use super::{audit_meta, Job};
use crate::audit::Audit;
use crate::finding::{Confidence, Finding, Persona, Severity, SymbolicLocation};
use crate::models::{JobExt as _, Steps, Workflow};
use crate::state::AuditState;

pub(crate) struct InsecureCommands;

audit_meta!(
    InsecureCommands,
    "insecure-commands",
    "execution of insecure workflow commands is enabled"
);

impl InsecureCommands {
    fn insecure_commands_maybe_present<'w>(
        &self,
        doc: &'w impl AsRef<yamlpath::Document>,
        location: SymbolicLocation<'w>,
    ) -> Result<Finding<'w>> {
        Self::finding()
            .confidence(Confidence::Low)
            .severity(Severity::High)
            .persona(Persona::Auditor)
            .add_location(
                location.primary().with_keys(&["env".into()]).annotated(
                    "non-static environment may contain ACTIONS_ALLOW_UNSECURE_COMMANDS",
                ),
            )
            .build(doc)
    }

    fn insecure_commands_allowed<'w>(
        &self,
        doc: &'w impl AsRef<yamlpath::Document>,
        location: SymbolicLocation<'w>,
    ) -> Result<Finding<'w>> {
        Self::finding()
            .confidence(Confidence::High)
            .severity(Severity::High)
            .add_location(
                location
                    .primary()
                    .with_keys(&["env".into()])
                    .annotated("insecure commands enabled here"),
            )
            .build(doc)
    }

    fn has_insecure_commands_enabled(&self, env: &Env) -> bool {
        if let Some(EnvValue::String(value)) = env.get("ACTIONS_ALLOW_UNSECURE_COMMANDS") {
            !value.is_empty()
        } else {
            false
        }
    }

    fn audit_steps<'w>(
        &self,
        workflow: &'w Workflow,
        steps: Steps<'w>,
    ) -> Result<Vec<Finding<'w>>> {
        steps
            .into_iter()
            .filter_map(|step| {
                let StepBody::Run {
                    run: _,
                    working_directory: _,
                    shell: _,
                    env,
                } = &step.deref().body
                else {
                    return None;
                };

                match env {
                    // The entire environment block is an expression, which we
                    // can't follow (for now). Emit an auditor-only finding.
                    LoE::Expr(_) => {
                        Some(self.insecure_commands_maybe_present(workflow, step.location()))
                    }
                    LoE::Literal(env) => self
                        .has_insecure_commands_enabled(env)
                        .then(|| self.insecure_commands_allowed(workflow, step.location())),
                }
            })
            .collect()
    }
}

impl Audit for InsecureCommands {
    fn new(_state: &AuditState<'_>) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn audit_workflow<'w>(&self, workflow: &'w Workflow) -> anyhow::Result<Vec<Finding<'w>>> {
        let mut results = vec![];

        match &workflow.env {
            LoE::Expr(_) => {
                results.push(self.insecure_commands_maybe_present(workflow, workflow.location())?)
            }
            LoE::Literal(env) => {
                if self.has_insecure_commands_enabled(env) {
                    results.push(self.insecure_commands_allowed(workflow, workflow.location())?)
                }
            }
        }

        for job in workflow.jobs() {
            if let Job::NormalJob(normal) = job {
                match &normal.env {
                    LoE::Expr(_) => results
                        .push(self.insecure_commands_maybe_present(workflow, normal.location())?),
                    LoE::Literal(env) => {
                        if self.has_insecure_commands_enabled(env) {
                            results
                                .push(self.insecure_commands_allowed(workflow, normal.location())?);
                        }
                    }
                }

                results.extend(self.audit_steps(workflow, normal.steps())?)
            }
        }

        Ok(results)
    }

    fn audit_composite_step<'a>(
        &self,
        step: &super::CompositeStep<'a>,
    ) -> Result<Vec<Finding<'a>>> {
        let mut findings = vec![];

        let action::StepBody::Run { env, .. } = &step.body else {
            return Ok(findings);
        };

        match env {
            LoE::Expr(_) => {
                findings.push(self.insecure_commands_maybe_present(step.action(), step.location())?)
            }
            LoE::Literal(env) => {
                if self.has_insecure_commands_enabled(env) {
                    findings.push(self.insecure_commands_allowed(step.action(), step.location())?);
                }
            }
        }

        Ok(findings)
    }
}
