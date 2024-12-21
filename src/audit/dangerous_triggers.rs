use anyhow::Result;

use super::{audit_meta, Audit};
use crate::finding::{Confidence, Finding, Severity};
use crate::models::Workflow;
use crate::state::AuditState;

pub(crate) struct DangerousTriggers;

audit_meta!(
    DangerousTriggers,
    "dangerous-triggers",
    "use of fundamentally insecure workflow trigger"
);

impl Audit for DangerousTriggers {
    fn new(_: AuditState) -> Result<Self> {
        Ok(Self)
    }

    fn audit_workflow<'w>(&self, workflow: &'w Workflow) -> Result<Vec<Finding<'w>>> {
        let mut findings = vec![];
        if workflow.has_pull_request_target() {
            findings.push(
                Self::finding()
                    .confidence(Confidence::Medium)
                    .severity(Severity::High)
                    .add_location(
                        workflow
                            .location()
                            .primary()
                            .with_keys(&["on".into()])
                            .annotated("pull_request_target is almost always used insecurely"),
                    )
                    .build(workflow)?,
            );
        }
        if workflow.has_workflow_run() {
            findings.push(
                Self::finding()
                    .confidence(Confidence::Medium)
                    .severity(Severity::High)
                    .add_location(
                        workflow
                            .location()
                            .primary()
                            .with_keys(&["on".into()])
                            .annotated("workflow_run is almost always used insecurely"),
                    )
                    .build(workflow)?,
            );
        }

        Ok(findings)
    }
}
