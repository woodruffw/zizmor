//! Audits workflows for usage of self-hosted runners,
//! which are frequently unsafe to use in public repositories
//! due to the potential for persistence between workflow runs.
//!
//! This audit is "auditor" only, since zizmor can't detect
//! whether self-hosted runners are ephemeral or not.

use crate::{
    finding::{Confidence, Persona, Severity},
    AuditState,
};

use super::{audit_meta, Audit};
use crate::models::Matrix;
use anyhow::Result;
use github_actions_models::{
    common::expr::{ExplicitExpr, LoE},
    workflow::{job::RunsOn, Job},
};

pub(crate) struct SelfHostedRunner;

audit_meta!(
    SelfHostedRunner,
    "self-hosted-runner",
    "runs on a self-hosted runner"
);

impl Audit for SelfHostedRunner {
    fn new(_state: AuditState) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn audit_workflow<'w>(
        &self,
        workflow: &'w crate::models::Workflow,
    ) -> Result<Vec<crate::finding::Finding<'w>>> {
        let mut results = vec![];

        for job in workflow.jobs() {
            let Job::NormalJob(normal) = *job else {
                continue;
            };

            match &normal.runs_on {
                LoE::Literal(RunsOn::Target(labels)) => {
                    {
                        let Some(label) = labels.first() else {
                            continue;
                        };

                        if label == "self-hosted" {
                            // All self-hosted runners start with the 'self-hosted'
                            // label followed by any specifiers.
                            results.push(
                                Self::finding()
                                    .confidence(Confidence::High)
                                    .severity(Severity::Unknown)
                                    .persona(Persona::Auditor)
                                    .add_location(
                                        job.location()
                                            .primary()
                                            .with_keys(&["runs-on".into()])
                                            .annotated("self-hosted runner used here"),
                                    )
                                    .build(workflow)?,
                            );
                        } else if ExplicitExpr::from_curly(label).is_some() {
                            // The job might also have its runner expanded via an
                            // expression. Long-term we should perform this evaluation
                            // to increase our confidence, but for now we flag it as
                            // potentially expanding to self-hosted.
                            results.push(
                                Self::finding()
                                    .confidence(Confidence::Low)
                                    .severity(Severity::Unknown)
                                    .persona(Persona::Auditor)
                                    .add_location(
                                        job.location()
                                            .primary()
                                            .with_keys(&["runs-on".into()])
                                            .annotated(
                                                "expression may expand into a self-hosted runner",
                                            ),
                                    )
                                    .build(workflow)?,
                            );
                        }
                    }
                }
                // NOTE: GHA docs are unclear on whether runner groups always
                // imply self-hosted runners or not. All examples suggest that they
                // do, but I'm not sure.
                // See: https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/managing-access-to-self-hosted-runners-using-groups
                // See: https://docs.github.com/en/actions/writing-workflows/choosing-where-your-workflow-runs/choosing-the-runner-for-a-job
                LoE::Literal(RunsOn::Group { .. }) => results.push(
                    Self::finding()
                        .confidence(Confidence::Low)
                        .severity(Severity::Unknown)
                        .persona(Persona::Auditor)
                        .add_location(
                            job.location()
                                .primary()
                                .with_keys(&["runs-on".into()])
                                .annotated("runner group implies self-hosted runner"),
                        )
                        .build(workflow)?,
                ),
                // The entire `runs-on:` is an expression, which may or may
                // not be a self-hosted runner when expanded, like above.
                LoE::Expr(exp) => {
                    let Ok(matrix) = Matrix::try_from(&job) else {
                        continue;
                    };

                    let expansions = matrix.expanded_values;

                    let self_hosted = expansions.iter().any(|(path, expansion)| {
                        exp.as_bare() == path && expansion.contains("self-hosted")
                    });

                    if self_hosted {
                        results.push(
                            Self::finding()
                                .confidence(Confidence::High)
                                .severity(Severity::Unknown)
                                .persona(Persona::Auditor)
                                .add_location(
                                    job.location()
                                        .with_keys(&["strategy".into()])
                                        .annotated("matrix declares self-hosted runner"),
                                )
                                .add_location(
                                    job.location()
                                        .primary()
                                        .with_keys(&["runs-on".into()])
                                        .annotated(
                                            "expression may expand into a self-hosted runner",
                                        ),
                                )
                                .build(workflow)?,
                        )
                    }
                }
            }
        }

        Ok(results)
    }
}
