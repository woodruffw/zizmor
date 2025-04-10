//! Audits reusable workflows and action usage for confusable refs.
//!
//! This is similar to "impostor" commit detection, but with only named
//! refs instead of fully pinned commits: a user may pin a ref such as
//! `@foo` thinking that `foo` will always refer to either a branch or a tag,
//! but the upstream repository may host *both* a branch and a tag named
//! `foo`, making it unclear to the end user which is selected.

use anyhow::{Result, anyhow};
use github_actions_models::common::{RepositoryUses, Uses};

use super::{Audit, Job, audit_meta};
use crate::finding::Finding;
use crate::models::{CompositeStep, JobExt as _};
use crate::{
    finding::{Confidence, Severity},
    github_api,
    models::uses::RepositoryUsesExt as _,
    state::AuditState,
};

const REF_CONFUSION_ANNOTATION: &str =
    "uses a ref that's provided by both the branch and tag namespaces";

pub(crate) struct RefConfusion {
    client: github_api::Client,
}

audit_meta!(
    RefConfusion,
    "ref-confusion",
    "git ref for action with ambiguous ref type"
);

impl RefConfusion {
    fn confusable(&self, uses: &RepositoryUses) -> Result<bool> {
        let Some(sym_ref) = uses.symbolic_ref() else {
            return Ok(false);
        };

        let branches_match = self.client.has_branch(&uses.owner, &uses.repo, sym_ref)?;
        let tags_match = self.client.has_tag(&uses.owner, &uses.repo, sym_ref)?;

        // If both the branch and tag namespaces have a match, we have a
        // confusable ref.
        Ok(branches_match && tags_match)
    }
}

impl Audit for RefConfusion {
    fn new(state: &AuditState<'_>) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        if state.no_online_audits {
            return Err(anyhow!("offline audits only requested"));
        }

        let Some(client) = state.github_client() else {
            return Err(anyhow!("can't run without a GitHub API token"));
        };

        Ok(Self { client })
    }

    fn audit_workflow<'w>(
        &self,
        workflow: &'w crate::models::Workflow,
    ) -> anyhow::Result<Vec<crate::finding::Finding<'w>>> {
        let mut findings = vec![];

        for job in workflow.jobs() {
            match job {
                Job::NormalJob(normal) => {
                    for step in normal.steps() {
                        let Some(Uses::Repository(uses)) = step.uses() else {
                            continue;
                        };

                        if self.confusable(uses)? {
                            findings.push(
                                Self::finding()
                                    .severity(Severity::Medium)
                                    .confidence(Confidence::High)
                                    .add_location(
                                        step.location()
                                            .primary()
                                            .with_keys(&["uses".into()])
                                            .annotated(REF_CONFUSION_ANNOTATION),
                                    )
                                    .build(workflow)?,
                            );
                        }
                    }
                }
                Job::ReusableWorkflowCallJob(reusable) => {
                    let Uses::Repository(uses) = &reusable.uses else {
                        continue;
                    };

                    if self.confusable(uses)? {
                        findings.push(
                            Self::finding()
                                .severity(Severity::Medium)
                                .confidence(Confidence::High)
                                .add_location(
                                    reusable
                                        .location()
                                        .primary()
                                        .annotated(REF_CONFUSION_ANNOTATION),
                                )
                                .build(workflow)?,
                        )
                    }
                }
            }
        }

        Ok(findings)
    }

    fn audit_composite_step<'a>(&self, step: &CompositeStep<'a>) -> Result<Vec<Finding<'a>>> {
        let mut findings = vec![];

        let Some(Uses::Repository(uses)) = step.uses() else {
            return Ok(findings);
        };

        if self.confusable(uses)? {
            findings.push(
                Self::finding()
                    .severity(Severity::Medium)
                    .confidence(Confidence::High)
                    .add_location(
                        step.location()
                            .primary()
                            .with_keys(&["uses".into()])
                            .annotated(REF_CONFUSION_ANNOTATION),
                    )
                    .build(step.action())?,
            );
        }

        Ok(findings)
    }
}
