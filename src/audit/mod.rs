//! Core namespace for zizmor's audits.

use anyhow::Result;
use github_actions_models::action;
use tracing::instrument;

use crate::{
    finding::{Finding, FindingBuilder},
    models::{Action, CompositeStep, Job, Step, Workflow},
    registry::InputKey,
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

#[derive(Debug)]
pub(crate) enum AuditInput {
    Workflow(Workflow),
    Action(Action),
}

impl AuditInput {
    pub(crate) fn key(&self) -> &InputKey {
        match self {
            AuditInput::Workflow(workflow) => &workflow.key,
            AuditInput::Action(action) => &action.key,
        }
    }

    pub(crate) fn document(&self) -> &yamlpath::Document {
        match self {
            AuditInput::Workflow(workflow) => &workflow.document,
            AuditInput::Action(action) => &action.document,
        }
    }

    pub(crate) fn link(&self) -> Option<&str> {
        match self {
            AuditInput::Workflow(workflow) => workflow.link.as_deref(),
            AuditInput::Action(action) => action.link.as_deref(),
        }
    }
}

impl From<Workflow> for AuditInput {
    fn from(value: Workflow) -> Self {
        Self::Workflow(value)
    }
}

impl From<Action> for AuditInput {
    fn from(value: Action) -> Self {
        Self::Action(value)
    }
}

/// A supertrait for all audits.
///
/// Workflow audits, action audits, and all future audit types
/// must derive this trait, either manually or via the [`audit_meta`]
/// macro.
pub(crate) trait AuditCore {
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
        use crate::audit::AuditCore;

        impl AuditCore for $t {
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

/// Auditing trait.
///
/// Implementors of this trait can choose the level of specificity/context
/// they need for workflows and/or action definitions:
///
/// For workflows:
///
/// 1. [`Audit::audit_workflow`]: runs at the top of the workflow (most general)
/// 1. [`Audit::audit_normal_job`] and/or [`Audit::audit_reusable_job`]:
///    runs on each normal/reusable job definition
/// 1. [`Audit::audit_step`]: runs on each step within each normal job (most specific)
///
/// For actions:
///
/// 1. [`Audit::audit_action`]: runs at the top of the action (most general)
/// 2. [`Audit::audit_composite_step`]: runs on each composite step within the
///    action (most specific)
///
/// Picking a higher specificity means that the lower methods are shadowed.
/// In other words, if an audit chooses to implement [`Audit::audit`], it should implement
/// **only** [`Audit::audit`] and not [`Audit::audit_normal_job`] or
/// [`Audit::audit_step`].
pub(crate) trait Audit: AuditCore {
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

    fn audit_composite_step<'a>(&self, _step: &CompositeStep<'a>) -> Result<Vec<Finding<'a>>> {
        Ok(vec![])
    }

    fn audit_action<'a>(&self, action: &'a Action) -> Result<Vec<Finding<'a>>> {
        let mut results = vec![];

        if matches!(action.runs, action::Runs::Composite(_)) {
            for step in action.steps() {
                results.extend(self.audit_composite_step(&step)?);
            }
        }

        Ok(results)
    }

    /// The top-level auditing function for both workflows and actions.
    ///
    /// Implementors **should not** override this blanket implementation,
    /// since it's marked with tracing instrumentation.
    #[instrument(skip(self))]
    fn audit<'w>(&self, input: &'w AuditInput) -> Result<Vec<Finding<'w>>> {
        match input {
            AuditInput::Workflow(workflow) => self.audit_workflow(workflow),
            AuditInput::Action(action) => self.audit_action(action),
        }
    }
}
