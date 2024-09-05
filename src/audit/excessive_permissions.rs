use std::ops::Deref;

use github_actions_models::{
    common::{BasePermission, Permissions},
    workflow::Job,
};

use crate::{
    finding::{Confidence, Severity},
    models::AuditConfig,
};

use super::WorkflowAudit;

pub(crate) struct ExcessivePermissions<'a> {
    pub(crate) _config: AuditConfig<'a>,
}

impl<'a> WorkflowAudit<'a> for ExcessivePermissions<'a> {
    fn ident() -> &'static str
    where
        Self: Sized,
    {
        "excessive-permissions"
    }

    fn new(config: crate::models::AuditConfig<'a>) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self { _config: config })
    }

    fn audit<'w>(
        &mut self,
        workflow: &'w crate::models::Workflow,
    ) -> anyhow::Result<Vec<crate::finding::Finding<'w>>> {
        let mut findings = vec![];
        // Top-level permissions.
        if let Some((severity, confidence, note)) =
            self.check_permissions(&workflow.permissions, None)
        {
            findings.push(
                Self::finding()
                    .severity(severity)
                    .confidence(confidence)
                    .add_location(workflow.key_location("permissions").annotated(note))
                    .build(workflow)?,
            )
        }

        for job in workflow.jobs() {
            let Job::NormalJob(normal) = job.deref() else {
                continue;
            };

            if let Some((severity, confidence, note)) =
                self.check_permissions(&normal.permissions, Some(&workflow.permissions))
            {
                findings.push(
                    Self::finding()
                        .severity(severity)
                        .confidence(confidence)
                        .add_location(job.key_location("permissions").annotated(note))
                        .build(workflow)?,
                )
            }
        }

        Ok(findings)
    }
}

impl<'a> ExcessivePermissions<'a> {
    fn check_permissions(
        &self,
        permissions: &Permissions,
        parent: Option<&Permissions>,
    ) -> Option<(Severity, Confidence, &'static str)> {
        match permissions {
            Permissions::Base(base) => match base {
                // If no explicit permissions are specified, our behavior
                // depends on the presence of a parent (workflow) permission
                // specifier.
                BasePermission::Default => match parent {
                    // If there's a parent permissions block, this job inherits
                    // from it and has nothing new to report.
                    Some(_) => None,
                    // If there's no parent permissions block, we're at the workflow
                    // level and should report the default permissions as potentially
                    // being too broad.
                    None => Some((
                        Severity::Medium,
                        Confidence::Low,
                        "workflow uses default permissions, which may be excessive",
                    )),
                },
                BasePermission::ReadAll => Some((
                    Severity::Medium,
                    Confidence::High,
                    "uses read-all permissions, which may grant read access to more resources \
                     than necessary",
                )),
                BasePermission::WriteAll => Some((
                    Severity::High,
                    Confidence::High,
                    "uses write-all permissions, which grants destructive access to repository \
                     resources",
                )),
            },
            Permissions::Explicit(perms) => match parent {
                // In the general case, it's impossible to tell whether a
                // job-level permission block is over-scoped.
                Some(_) => None,
                // Top-level permission-blocks should almost never contain
                // write permissions.
                None => todo!(),
            },
        }
    }
}
