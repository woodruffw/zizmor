use github_actions_models::common::Uses;

use super::{Audit, AuditState, Finding, Step, audit_meta};
use crate::finding::{Confidence, Persona, Severity};
use crate::models::{CompositeStep, uses::UsesExt as _};

pub(crate) struct UnpinnedUses;

audit_meta!(UnpinnedUses, "unpinned-uses", "unpinned action reference");

impl UnpinnedUses {
    pub fn evaluate_pinning<'u>(&self, uses: &Uses) -> Option<(&'u str, Severity, Persona)> {
        // Don't evaluate pinning for local `uses:`, since unpinned references
        // are fully controlled by the repository anyways.
        // TODO: auditor-level findings instead, perhaps?
        if matches!(uses, Uses::Local(_)) {
            return None;
        }

        if uses.unpinned() {
            Some((
                "action is not pinned to a tag, branch, or hash ref",
                Severity::Medium,
                Persona::default(),
            ))
        } else if uses.unhashed() {
            Some((
                "action is not pinned to a hash ref",
                Severity::Low,
                Persona::Pedantic,
            ))
        } else {
            None
        }
    }
}

impl Audit for UnpinnedUses {
    fn new(_state: &AuditState<'_>) -> anyhow::Result<Self>
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

        if let Some((annotation, severity, persona)) = self.evaluate_pinning(uses) {
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
        };

        Ok(findings)
    }

    fn audit_composite_step<'a>(
        &self,
        step: &CompositeStep<'a>,
    ) -> anyhow::Result<Vec<Finding<'a>>> {
        let mut findings = vec![];

        let Some(uses) = step.uses() else {
            return Ok(vec![]);
        };

        if let Some((annotation, severity, persona)) = self.evaluate_pinning(uses) {
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
                    .build(step.action())?,
            );
        };

        Ok(findings)
    }
}
