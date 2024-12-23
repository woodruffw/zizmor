use crate::finding::{Confidence, Persona, Severity};

use super::{audit_meta, Audit, AuditState, Finding, Step};

pub(crate) struct UnpinnedUses;

audit_meta!(UnpinnedUses, "unpinned-uses", "unpinned action reference");

impl Audit for UnpinnedUses {
    fn new(_state: AuditState) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn audit_step<'w>(&self, step: &Step<'w>) -> anyhow::Result<Vec<Finding<'w>>> {
        let mut findings = vec![];

        let Some(uses) = step.uses() else {
            return Ok(vec![]);
        };

        let (annotation, severity, persona) = if uses.unpinned() {
            (
                "action is not pinned to a tag, branch, or hash ref",
                Severity::Medium,
                Persona::default(),
            )
        } else if uses.unhashed() {
            (
                "action is not pinned to a hash ref",
                Severity::Low,
                Persona::Pedantic,
            )
        } else {
            return Ok(vec![]);
        };

        findings.push(
            Self::finding()
                .confidence(Confidence::High)
                .severity(severity)
                .persona(persona)
                .add_location(
                    step.location()
                        .primary()
                        .with_keys(&["uses".into()])
                        .annotated(annotation),
                )
                .build(step.workflow())?,
        );

        Ok(findings)
    }
}
