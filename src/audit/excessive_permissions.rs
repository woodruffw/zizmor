use std::{collections::HashMap, ops::Deref, sync::LazyLock};

use github_actions_models::{
    common::{BasePermission, Permission, Permissions},
    workflow::Job,
};

use super::{audit_meta, Audit};
use crate::{
    finding::{Confidence, Persona, Severity},
    AuditState,
};

// Subjective mapping of permissions to severities, when given `write` access.
static KNOWN_PERMISSIONS: LazyLock<HashMap<&str, Severity>> = LazyLock::new(|| {
    [
        ("actions", Severity::High),
        ("attestations", Severity::High),
        ("checks", Severity::Medium),
        ("contents", Severity::High),
        ("deployments", Severity::High),
        ("discussions", Severity::Medium),
        ("id-token", Severity::High),
        ("issues", Severity::High),
        ("packages", Severity::High),
        ("pages", Severity::High),
        ("pull-requests", Severity::High),
        ("repository-projects", Severity::Medium),
        ("security-events", Severity::Medium),
        // What does the write permission even do here?
        ("statuses", Severity::Low),
    ]
    .into()
});

audit_meta!(
    ExcessivePermissions,
    "excessive-permissions",
    "overly broad workflow or job-level permissions"
);

pub(crate) struct ExcessivePermissions {
    pub(crate) _config: AuditState,
}

impl Audit for ExcessivePermissions {
    fn new(config: AuditState) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self { _config: config })
    }

    fn audit_workflow<'w>(
        &self,
        workflow: &'w crate::models::Workflow,
    ) -> anyhow::Result<Vec<crate::finding::Finding<'w>>> {
        let mut findings = vec![];

        // Top-level permissions are a minor issue if there's only one
        // job in the workflow, since they're equivalent to job-level
        // permissions in that case. Emit only pedantic findings in
        // that case.
        let persona = if workflow.jobs.len() == 1 {
            Persona::Pedantic
        } else {
            Persona::Regular
        };

        // Top-level permissions.
        for (severity, confidence, note) in self.check_permissions(&workflow.permissions, None) {
            findings.push(
                Self::finding()
                    .severity(severity)
                    .confidence(confidence)
                    .persona(persona)
                    .add_location(
                        workflow
                            .location()
                            .primary()
                            .with_keys(&["permissions".into()])
                            .annotated(note),
                    )
                    .build(workflow)?,
            )
        }

        for job in workflow.jobs() {
            let Job::NormalJob(normal) = job.deref() else {
                continue;
            };

            for (severity, confidence, note) in
                self.check_permissions(&normal.permissions, Some(&workflow.permissions))
            {
                findings.push(
                    Self::finding()
                        .severity(severity)
                        .confidence(confidence)
                        .add_location(
                            job.location()
                                .primary()
                                .with_keys(&["permissions".into()])
                                .annotated(note),
                        )
                        .build(workflow)?,
                )
            }
        }

        Ok(findings)
    }
}

impl ExcessivePermissions {
    fn check_permissions(
        &self,
        permissions: &Permissions,
        parent: Option<&Permissions>,
    ) -> Vec<(Severity, Confidence, String)> {
        match permissions {
            Permissions::Base(base) => match base {
                // TODO: Think more about what to do here. Flagging default
                // permissions is likely to be noisy and is annoying to do,
                // since it involves the *absence* of a key in the YAML
                // rather than its presence.
                BasePermission::Default => vec![],
                BasePermission::ReadAll => vec![(
                    Severity::Medium,
                    Confidence::High,
                    "uses read-all permissions".into(),
                )],
                BasePermission::WriteAll => vec![(
                    Severity::High,
                    Confidence::High,
                    "uses write-all permissions".into(),
                )],
            },
            Permissions::Explicit(perms) => match parent {
                // In the general case, it's impossible to tell whether a
                // job-level permission block is over-scoped.
                Some(_) => vec![],
                // Top-level permission-blocks should almost never contain
                // write permissions.
                None => {
                    let mut results = vec![];

                    for (name, perm) in perms {
                        if *perm != Permission::Write {
                            continue;
                        }

                        match KNOWN_PERMISSIONS.get(name.as_str()) {
                            Some(sev) => results.push((
                                *sev,
                                Confidence::High,
                                format!("{name}: write is overly broad at the workflow level"),
                            )),
                            None => {
                                tracing::debug!("unknown permission: {name}");

                                results.push((
                                    Severity::Unknown,
                                    Confidence::High,
                                    format!("{name}: write is overly broad at the workflow level"),
                                ))
                            }
                        }
                    }

                    results
                }
            },
        }
    }
}
