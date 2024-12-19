//! Core namespace for zizmor's audits.

use anyhow::Result;
use tracing::instrument;

use crate::{
    finding::{Finding, FindingBuilder},
    models::{Job, Step, Workflow},
    state::AuditState,
};

pub(crate) mod artipacked;
pub(crate) mod cache_poisoning;
pub(crate) mod dangerous_triggers;
pub(crate) mod excessive_permissions;
pub(crate) mod github_env;
pub(crate) mod hardcoded_container_credentials;
pub(crate) mod impostor_commit;
pub(crate) mod insecure_commands;
pub(crate) mod known_vulnerable_actions;
pub(crate) mod ref_confusion;
pub(crate) mod self_hosted_runner;
pub(crate) mod template_injection;
pub(crate) mod unpinned_uses;
pub(crate) mod use_trusted_publishing;

/// A supertrait for all audits.
///
/// Workflow audits, action audits, and all future audit types
/// must derive this trait, either manually or via the [`audit_meta`]
/// macro.
pub(crate) trait Audit {
    fn ident() -> &'static str
    where
        Self: Sized;

    fn desc() -> &'static str
    where
        Self: Sized;

    fn url() -> &'static str
    where
        Self: Sized;

    fn finding<'w>() -> FindingBuilder<'w>
    where
        Self: Sized,
    {
        FindingBuilder::new(Self::ident(), Self::desc(), Self::url())
    }
}

/// A convenience macro for implementing [`Audit`] on a type.
///
/// Example use:
///
/// ```no_run
/// struct SomeAudit;
///
/// audit_meta!(SomeAudit, "some-audit", "brief description");
/// ```
macro_rules! audit_meta {
    ($t:ty, $id:literal, $desc:expr) => {
        use crate::audit::Audit;

        impl Audit for $t {
            fn ident() -> &'static str {
                $id
            }

            fn desc() -> &'static str
            where
                Self: Sized,
            {
                $desc
            }

            fn url() -> &'static str {
                concat!("https://woodruffw.github.io/zizmor/audits#", $id)
            }
        }
    };
}

pub(crate) use audit_meta;

/// Workflow auditing trait.
///
/// Implementors of this trait can choose the level of specificity/context
/// they need:
///
/// 1. [`WorkflowAudit::audit_workflow`]: runs at the top of the workflow (most general)
/// 1. [`WorkflowAudit::audit_normal_job`] and/or [`WorkflowAudit::audit_reusable_job`]:
///    runs on each normal/reusable job definition
/// 1. [`WorkflowAudit::audit_step`]: runs on each step within each normal job (most specific)
///
/// Picking a higher specificity means that the lower methods are shadowed.
/// In other words, if an audit chooses to implement [`WorkflowAudit::audit`], it should implement
/// **only** [`WorkflowAudit::audit`] and not [`WorkflowAudit::audit_normal_job`] or
/// [`WorkflowAudit::audit_step`].
pub(crate) trait WorkflowAudit: Audit {
    fn new(state: AuditState) -> Result<Self>
    where
        Self: Sized;

    fn audit_step<'w>(&self, _step: &Step<'w>) -> Result<Vec<Finding<'w>>> {
        Ok(vec![])
    }

    fn audit_normal_job<'w>(&self, job: &Job<'w>) -> Result<Vec<Finding<'w>>> {
        let mut results = vec![];
        for step in job.steps() {
            results.extend(self.audit_step(&step)?);
        }
        Ok(results)
    }

    fn audit_reusable_job<'w>(&self, _job: &Job<'w>) -> Result<Vec<Finding<'w>>> {
        Ok(vec![])
    }

    fn audit_workflow<'w>(&self, workflow: &'w Workflow) -> Result<Vec<Finding<'w>>> {
        let mut results = vec![];

        for job in workflow.jobs() {
            match *job {
                github_actions_models::workflow::Job::NormalJob(_) => {
                    results.extend(self.audit_normal_job(&job)?);
                }
                github_actions_models::workflow::Job::ReusableWorkflowCallJob(_) => {
                    results.extend(self.audit_reusable_job(&job)?);
                }
            }
        }

        Ok(results)
    }

    /// The top-level workflow auditing function.
    ///
    /// Implementors **should not** override this blanket implementation,
    /// since it's marked with tracing instrumentation.
    #[instrument(skip(self))]
    fn audit<'w>(&self, workflow: &'w Workflow) -> Result<Vec<Finding<'w>>> {
        self.audit_workflow(workflow)
    }
}

/// (Composite) action auditing trait.
///
///
pub(crate) trait ActionAudit: Audit {
    fn new(state: AuditState) -> Result<Self>
    where
        Self: Sized;

    // /// The top-level action auditing function.
    // ///
    // /// Implementors **should not** override this blanket implementation,
    // /// since it's marked with tracing instrumentation.
    // #[instrument(skip(self))]
    // fn audit<'w>(&self, workflow: &'w Workflow) -> Result<Vec<Finding<'w>>> {
    //     self.audit_action(workflow)
    // }
}
