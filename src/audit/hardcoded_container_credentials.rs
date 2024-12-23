use std::ops::Deref;

use github_actions_models::{
    common::expr::ExplicitExpr,
    workflow::{
        job::{Container, DockerCredentials},
        Job,
    },
};

use super::{audit_meta, Audit};
use crate::{
    finding::{Confidence, Severity},
    state::AuditState,
};

pub(crate) struct HardcodedContainerCredentials {}

audit_meta!(
    HardcodedContainerCredentials,
    "hardcoded-container-credentials",
    "hardcoded credential in GitHub Actions container configurations"
);

impl Audit for HardcodedContainerCredentials {
    fn new(_state: AuditState) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self {})
    }

    fn audit_workflow<'w>(
        &self,
        workflow: &'w crate::models::Workflow,
    ) -> anyhow::Result<Vec<crate::finding::Finding<'w>>> {
        let mut findings = vec![];

        for job in workflow.jobs() {
            let Job::NormalJob(normal) = job.deref() else {
                continue;
            };

            if let Some(Container::Container {
                image: _,
                credentials:
                    Some(DockerCredentials {
                        username: _,
                        password: Some(password),
                    }),
                ..
            }) = &normal.container
            {
                // If the password doesn't parse as an expression, it's hardcoded.
                if ExplicitExpr::from_curly(password).is_none() {
                    findings.push(
                        Self::finding()
                            .severity(Severity::High)
                            .confidence(Confidence::High)
                            .add_location(
                                job.location()
                                    .primary()
                                    .with_keys(&["container".into(), "credentials".into()])
                                    .annotated("container registry password is hard-coded"),
                            )
                            .build(workflow)?,
                    )
                }
            }

            for (service, config) in normal.services.iter() {
                if let Container::Container {
                    image: _,
                    credentials:
                        Some(DockerCredentials {
                            username: _,
                            password: Some(password),
                        }),
                    ..
                } = &config
                {
                    if ExplicitExpr::from_curly(password).is_none() {
                        findings.push(
                            Self::finding()
                                .severity(Severity::High)
                                .confidence(Confidence::High)
                                .add_location(
                                    job.location()
                                        .primary()
                                        .with_keys(&[
                                            "services".into(),
                                            service.as_str().into(),
                                            "credentials".into(),
                                        ])
                                        .annotated(format!(
                                            "service {service}: container registry password is \
                                         hard-coded"
                                        )),
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
