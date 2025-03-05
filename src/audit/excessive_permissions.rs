use std::{collections::HashMap, sync::LazyLock};

use github_actions_models::common::{BasePermission, Permission, Permissions};

use super::{audit_meta, Audit, Job};
use crate::models::JobExt as _;
use crate::{
    finding::{Confidence, Persona, Severity, SymbolicLocation},
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
    "overly broad permissions"
);

pub(crate) struct ExcessivePermissions;

impl Audit for ExcessivePermissions {
    fn new(_state: &AuditState<'_>) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn audit_workflow<'w>(
        &self,
        workflow: &'w crate::models::Workflow,
    ) -> anyhow::Result<Vec<crate::finding::Finding<'w>>> {
        let mut findings = vec![];

        let all_jobs_have_permissions = workflow
            .jobs()
            .map(|job| match job {
                Job::NormalJob(job) => &job.permissions,
                Job::ReusableWorkflowCallJob(job) => &job.permissions,
            })
            .all(|perm| !matches!(perm, Permissions::Base(BasePermission::Default)));

        let explicit_parent_permissions = !matches!(
            &workflow.permissions,
            Permissions::Base(BasePermission::Default)
        );

        let workflow_is_reusable_only =
            workflow.has_workflow_call() && workflow.has_single_trigger();

        // Top-level permissions are a pedantic finding under the following
        // conditions:
        //
        // 1. The workflow has only one job.
        // 2. All jobs in the workflow have their own explicit permissions.
        // 3. The workflow is reusable and has only one trigger.
        let workflow_finding_persona =
            if workflow.jobs.len() == 1 || all_jobs_have_permissions || workflow_is_reusable_only {
                Persona::Pedantic
            } else {
                Persona::Regular
            };

        // Handle top-level permissions.
        let location = workflow.location().primary();

        for (severity, confidence, perm_location) in
            self.check_workflow_permissions(&workflow.permissions, location)
        {
            findings.push(
                Self::finding()
                    .severity(severity)
                    .confidence(confidence)
                    .persona(workflow_finding_persona)
                    .add_location(perm_location)
                    .build(workflow)?,
            );
        }

        for job in workflow.jobs() {
            let (permissions, job_location, job_finding_persona) = match job {
                Job::NormalJob(job) => {
                    // For normal jobs: if the workflow is reusable-only, we
                    // emit pedantic findings.
                    let persona = if workflow_is_reusable_only {
                        Persona::Pedantic
                    } else {
                        Persona::Regular
                    };

                    (&job.permissions, job.location(), persona)
                }
                Job::ReusableWorkflowCallJob(job) => {
                    // For reusable jobs: the caller is always responsible for
                    // permissions, so we emit regular findings even if
                    // the workflow is reusable-only.
                    (&job.permissions, job.location(), Persona::Regular)
                }
            };

            if let Some((severity, confidence, perm_location)) = self.check_job_permissions(
                permissions,
                explicit_parent_permissions,
                job_location.clone(),
            ) {
                findings.push(
                    Self::finding()
                        .severity(severity)
                        .confidence(confidence)
                        .persona(job_finding_persona)
                        .add_location(job_location)
                        .add_location(perm_location.primary())
                        .build(workflow)?,
                )
            }
        }

        Ok(findings)
    }
}

impl ExcessivePermissions {
    fn check_workflow_permissions<'a>(
        &self,
        permissions: &'a Permissions,
        location: SymbolicLocation<'a>,
    ) -> Vec<(Severity, Confidence, SymbolicLocation<'a>)> {
        let mut results = vec![];

        match &permissions {
            Permissions::Base(base) => match base {
                BasePermission::Default => results.push((
                    Severity::Medium,
                    Confidence::Medium,
                    location.annotated("default permissions used due to no permissions: block"),
                )),
                BasePermission::ReadAll => results.push((
                    Severity::Medium,
                    Confidence::High,
                    location
                        .with_keys(&["permissions".into()])
                        .annotated("uses read-all permissions"),
                )),
                BasePermission::WriteAll => results.push((
                    Severity::High,
                    Confidence::High,
                    location
                        .with_keys(&["permissions".into()])
                        .annotated("uses write-all permissions"),
                )),
            },
            Permissions::Explicit(perms) => {
                for (name, perm) in perms {
                    if *perm != Permission::Write {
                        continue;
                    }

                    let severity = KNOWN_PERMISSIONS.get(name.as_str()).unwrap_or_else(|| {
                        tracing::warn!("unknown permission: {name}");

                        &Severity::Unknown
                    });

                    results.push((
                        *severity,
                        Confidence::High,
                        location
                            .with_keys(&["permissions".into(), name.as_str().into()])
                            .annotated(format!(
                                "{name}: write is overly broad at the workflow level"
                            )),
                    ));
                }
            }
        }

        results
    }

    fn check_job_permissions<'a>(
        &self,
        permissions: &Permissions,
        explicit_parent_permissions: bool,
        location: SymbolicLocation<'a>,
    ) -> Option<(Severity, Confidence, SymbolicLocation<'a>)> {
        match permissions {
            Permissions::Base(base) => match base {
                // The job has no explicit permissions, meaning it gets
                // the default $GITHUB_TOKEN *if* the workflow doesn't
                // set any permissions.
                BasePermission::Default if !explicit_parent_permissions => Some((
                    Severity::Medium,
                    Confidence::Medium,
                    location.annotated("default permissions used due to no permissions: block"),
                )),
                BasePermission::Default => None,
                BasePermission::ReadAll => Some((
                    Severity::Medium,
                    Confidence::High,
                    location
                        .with_keys(&["permissions".into()])
                        .annotated("uses read-all permissions"),
                )),
                BasePermission::WriteAll => Some((
                    Severity::High,
                    Confidence::High,
                    location
                        .with_keys(&["permissions".into()])
                        .annotated("uses write-all permissions"),
                )),
            },
            // In the general case, it's impossible to tell whether a job-level
            // permission block is over-scoped.
            // TODO: We could in theory refine this by collecting minimum permission
            // sets for common actions, but that might be overkill.
            Permissions::Explicit(_) => None,
        }
    }
}
