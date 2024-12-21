use std::ops::Deref;

use anyhow::Ok;
use github_actions_models::{common::EnvValue, workflow::job::StepBody};
use indexmap::IndexMap;

use super::{audit_meta, Audit};
use crate::{
    finding::{Confidence, Severity},
    models::Uses,
    state::AuditState,
};

const USES_MANUAL_CREDENTIAL: &str =
    "uses a manually-configured credential instead of Trusted Publishing";

const KNOWN_PYTHON_TP_INDICES: &[&str] = &[
    "https://upload.pypi.org/legacy/",
    "https://test.pypi.org/legacy/",
];

pub(crate) struct UseTrustedPublishing {
    pub(crate) _state: AuditState,
}

audit_meta!(
    UseTrustedPublishing,
    "use-trusted-publishing",
    "prefer trusted publishing for authentication"
);

impl UseTrustedPublishing {
    fn pypi_publish_uses_manual_credentials(&self, with: &IndexMap<String, EnvValue>) -> bool {
        // `password` implies the step isn't using Trusted Publishing,
        // but we also need to check `repository-url` to prevent false-positives
        // on third-party indices.
        let has_manual_credential = with.contains_key("password");

        match with
            .get("repository-url")
            .or_else(|| with.get("repository_url"))
        {
            Some(repo_url) => {
                has_manual_credential
                    && KNOWN_PYTHON_TP_INDICES.contains(&repo_url.to_string().as_str())
            }
            None => has_manual_credential,
        }
    }

    fn release_gem_uses_manual_credentials(&self, with: &IndexMap<String, EnvValue>) -> bool {
        match with.get("setup-trusted-publisher") {
            Some(v) if v.to_string() == "true" => false,
            // Anything besides `true` means to *not* use trusted publishing.
            Some(_) => true,
            // Not set means the default, which is trusted publishing.
            None => false,
        }
    }

    fn rubygems_credential_uses_manual_credentials(
        &self,
        with: &IndexMap<String, EnvValue>,
    ) -> bool {
        with.contains_key("api-token")
    }
}

impl Audit for UseTrustedPublishing {
    fn new(state: AuditState) -> anyhow::Result<Self> {
        Ok(Self { _state: state })
    }

    fn audit_step<'w>(&self, step: &super::Step<'w>) -> anyhow::Result<Vec<super::Finding<'w>>> {
        let mut findings = vec![];

        let StepBody::Uses { uses, with } = &step.deref().body else {
            return Ok(findings);
        };

        let Some(Uses::Repository(uses)) = Uses::from_step(uses) else {
            return Ok(findings);
        };

        let candidate = Self::finding()
            .severity(Severity::Informational)
            .confidence(Confidence::High)
            .add_location(
                step.location()
                    .primary()
                    .with_keys(&["uses".into()])
                    .annotated("this step"),
            );

        if uses.matches("pypa/gh-action-pypi-publish")
            && self.pypi_publish_uses_manual_credentials(with)
        {
            findings.push(
                candidate
                    .add_location(
                        step.location()
                            .primary()
                            .with_keys(&["with".into(), "password".into()])
                            .annotated(USES_MANUAL_CREDENTIAL),
                    )
                    .build(step.workflow())?,
            );
        } else if ((uses.matches("rubygems/release-gem"))
            && self.release_gem_uses_manual_credentials(with))
            || (uses.matches("rubygems/configure-rubygems-credential")
                && self.rubygems_credential_uses_manual_credentials(with))
        {
            findings.push(
                candidate
                    .add_location(step.location().primary().annotated(USES_MANUAL_CREDENTIAL))
                    .build(step.workflow())?,
            );
        }

        Ok(findings)
    }
}
