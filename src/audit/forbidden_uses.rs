use github_actions_models::common::{RepositoryUses, Uses};

use super::{audit_meta, Audit, AuditState, Finding, Step};
use crate::finding::{Confidence, Persona, Severity};
use crate::models::{uses::RepositoryUsesExt, CompositeStep};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ForbiddenUsesConfig {
    #[serde(skip)]
    is_default: bool,
    allow: Vec<String>,
}

const DEFAULT_ALLOWLIST: [&str; 3] = [
    "actions/checkout",
    "actions/cache",
    "actions/upload-artifact",
];

impl Default for ForbiddenUsesConfig {
    fn default() -> Self {
        Self {
            is_default: true,
            allow: DEFAULT_ALLOWLIST
                .iter()
                .map(|item| item.to_string())
                .collect(),
        }
    }
}

impl ForbiddenUsesConfig {
    fn is_uses_allowed(&self, uses: &RepositoryUses) -> bool {
        self.allow
            .iter()
            .any(|allowlist_entry| uses.matches(allowlist_entry))
    }

    #[inline]
    fn is_uses_denied(&self, uses: &RepositoryUses) -> bool {
        !self.is_uses_allowed(uses)
    }
}

pub(crate) struct ForbiddenUses {
    config: ForbiddenUsesConfig,
}

audit_meta!(ForbiddenUses, "forbidden-uses", "fobidden action used");

impl ForbiddenUses {
    pub fn evaluate_allowlist<'u>(&self, uses: &Uses) -> Option<(&'u str, Severity, Persona)> {
        let Uses::Repository(repo_uses) = uses else {
            return None;
        };

        let auditor = if self.config.is_default {
            Persona::Auditor
        } else {
            Persona::default()
        };

        self.config.is_uses_denied(repo_uses).then_some((
            "action is not on the allowlist",
            Severity::Medium,
            auditor,
        ))
    }
}

impl Audit for ForbiddenUses {
    fn new(state: &AuditState<'_>) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            config: state.config.rule_config(Self::ident())?,
        })
    }

    fn audit_step<'w>(&self, step: &Step<'w>) -> anyhow::Result<Vec<Finding<'w>>> {
        let mut findings = vec![];

        let Some(uses) = step.uses() else {
            return Ok(vec![]);
        };

        if let Some((annotation, severity, persona)) = self.evaluate_allowlist(uses) {
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

        if let Some((annotation, severity, persona)) = self.evaluate_allowlist(uses) {
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
