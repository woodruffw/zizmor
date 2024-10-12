//! Audits reusable workflows and pinned actions for "impostor" commits,
//! using the ref lookup technique from [`clank`].
//!
//! `clank` is licensed by Chainguard under the Apache-2.0 License.
//!
//! [`clank`]: https://github.com/chainguard-dev/clank

use std::ops::Deref;

use anyhow::{anyhow, Result};
use github_actions_models::workflow::{job::StepBody, Job};

use super::WorkflowAudit;
use crate::{
    finding::{Confidence, Finding, Severity},
    github_api::{self, Branch, ComparisonStatus, Tag},
    models::{Uses, Workflow},
    state::State,
};

pub const IMPOSTOR_ANNOTATION: &str = "uses a commit that doesn't belong to the specified org/repo";

pub(crate) struct ImpostorCommit {
    pub(crate) client: github_api::Client,
}

impl ImpostorCommit {
    fn named_refs(&self, uses: Uses<'_>) -> Result<(Vec<Branch>, Vec<Tag>)> {
        let branches = self.client.list_branches(uses.owner, uses.repo)?;
        let tags = self.client.list_tags(uses.owner, uses.repo)?;
        Ok((branches, tags))
    }

    fn named_ref_contains_commit(
        &self,
        uses: &Uses<'_>,
        base_ref: &str,
        head_ref: &str,
    ) -> Result<bool> {
        Ok(
            match self
                .client
                .compare_commits(uses.owner, uses.repo, base_ref, head_ref)?
            {
                // A base ref "contains" a commit if the base is either identical
                // to the head ("identical") or the target is behind the base ("behind").
                Some(comp) => {
                    matches!(comp, ComparisonStatus::Behind | ComparisonStatus::Identical)
                }
                // GitHub's API returns 404 when the refs under comparison
                // are completely divergent, i.e. no contains relationship is possible.
                None => false,
            },
        )
    }

    /// Returns a boolean indicating whether or not this commit is an "impostor",
    /// i.e. resolves due to presence in GitHub's fork network but is not actually
    /// present in any of the specified `owner/repo`'s tags or branches.
    fn impostor(&self, uses: Uses<'_>) -> Result<bool> {
        let (branches, tags) = self.named_refs(uses)?;

        // If there's no ref or the ref is not a commit, there's nothing to impersonate.
        let Some(head_ref) = uses.commit_ref() else {
            return Ok(false);
        };

        for branch in branches {
            if self.named_ref_contains_commit(
                &uses,
                &format!("refs/heads/{}", &branch.name),
                head_ref,
            )? {
                return Ok(false);
            }
        }

        for tag in tags {
            if self.named_ref_contains_commit(
                &uses,
                &format!("refs/tags/{}", &tag.name),
                head_ref,
            )? {
                return Ok(false);
            }
        }

        // If we've made it here, the commit isn't present in any commit or tag's history,
        // strongly suggesting that it's an impostor.
        log::warn!(
            "strong impostor candidate: {head_ref} for {org}/{repo}",
            org = uses.owner,
            repo = uses.repo
        );
        Ok(true)
    }
}

impl WorkflowAudit for ImpostorCommit {
    fn ident() -> &'static str {
        "impostor-commit"
    }

    fn desc() -> &'static str
    where
        Self: Sized,
    {
        "commit with no history in referenced repository"
    }

    fn new(state: State) -> Result<Self> {
        if state.config.offline {
            return Err(anyhow!("offline audits only requested"));
        }

        let Some(gh_token) = &state.config.gh_token else {
            return Err(anyhow!("can't audit without a GitHub API token"));
        };

        let client = github_api::Client::new(gh_token, state.caches.clone());

        Ok(ImpostorCommit { client })
    }

    fn audit<'w>(&self, workflow: &'w Workflow) -> Result<Vec<Finding<'w>>> {
        let mut findings = vec![];

        for job in workflow.jobs() {
            match *job {
                Job::NormalJob(_) => {
                    for step in job.steps() {
                        let StepBody::Uses { uses, .. } = &step.deref().body else {
                            continue;
                        };

                        let Some(uses) = Uses::from_step(uses) else {
                            continue;
                        };

                        if self.impostor(uses)? {
                            findings.push(
                                Self::finding()
                                    .severity(Severity::High)
                                    .confidence(Confidence::High)
                                    .add_location(step.location().annotated(IMPOSTOR_ANNOTATION))
                                    .build(workflow)?,
                            );
                        }
                    }
                }
                Job::ReusableWorkflowCallJob(reusable) => {
                    // Reusable workflows can also be commit pinned, meaning
                    // they can also be impersonated.
                    let Some(uses) = Uses::from_reusable(&reusable.uses) else {
                        continue;
                    };

                    if self.impostor(uses)? {
                        findings.push(
                            Self::finding()
                                .severity(Severity::High)
                                .confidence(Confidence::High)
                                .add_location(job.location().annotated(IMPOSTOR_ANNOTATION))
                                .build(workflow)?,
                        );
                    }
                }
            }
        }

        Ok(findings)
    }
}
