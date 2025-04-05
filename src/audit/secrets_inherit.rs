use github_actions_models::workflow::job::Secrets;

use super::{Audit, AuditState, audit_meta};
use crate::{finding::Confidence, models::JobExt as _};

pub(crate) struct SecretsInherit;

audit_meta!(
    SecretsInherit,
    "secrets-inherit",
    "secrets unconditionally inherited by called workflow"
);

impl Audit for SecretsInherit {
    fn new(_state: &AuditState<'_>) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn audit_reusable_job<'w>(
        &self,
        job: &super::ReusableWorkflowCallJob<'w>,
    ) -> anyhow::Result<Vec<super::Finding<'w>>> {
        let mut findings = vec![];

        if matches!(job.secrets, Some(Secrets::Inherit)) {
            findings.push(
                Self::finding()
                    .add_location(
                        job.location()
                            .primary()
                            .with_keys(&["uses".into()])
                            .annotated("this reusable workflow"),
                    )
                    .add_location(
                        job.location()
                            .with_keys(&["secrets".into()])
                            .annotated("inherits all parent secrets"),
                    )
                    .confidence(Confidence::High)
                    .severity(crate::finding::Severity::Medium)
                    .build(job.parent())?,
            );
        }

        Ok(findings)
    }
}
