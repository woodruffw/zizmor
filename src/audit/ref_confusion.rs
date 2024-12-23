//! Audits reusable workflows and action usage for confusable refs.
//!
//! This is similar to "impostor" commit detection, but with only named
//! refs instead of fully pinned commits: a user may pin a ref such as
//! `@foo` thinking that `foo` will always refer to either a branch or a tag,
//! but the upstream repository may host *both* a branch and a tag named
//! `foo`, making it unclear to the end user which is selected.

use std::ops::Deref;

use anyhow::{anyhow, Result};
use github_actions_models::workflow::Job;

use super::{audit_meta, Audit};
use crate::{
    finding::{Confidence, Severity},
    github_api,
    models::{RepositoryUses, Uses},
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

        let branches_match = self.client.has_branch(uses.owner, uses.repo, sym_ref)?;
        let tags_match = self.client.has_tag(uses.owner, uses.repo, sym_ref)?;

        // If both the branch and tag namespaces have a match, we have a
        // confusable ref.
        Ok(branches_match && tags_match)
    }
}

impl Audit for RefConfusion {
    fn new(state: AuditState) -> anyhow::Result<Self>
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
            match job.deref() {
                Job::NormalJob(_) => {
                    for step in job.steps() {
                        let Some(Uses::Repository(uses)) = step.uses() else {
                            continue;
                        };

                        if self.confusable(&uses)? {
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
                    let Some(uses) = Uses::from_reusable(&reusable.uses) else {
                        continue;
                    };

                    if self.confusable(&uses)? {
                        findings.push(
                            Self::finding()
                                .severity(Severity::Medium)
                                .confidence(Confidence::High)
                                .add_location(
                                    job.location().primary().annotated(REF_CONFUSION_ANNOTATION),
                                )
                                .build(workflow)?,
                        )
                    }
                }
            }
        }

        Ok(findings)
    }
}
