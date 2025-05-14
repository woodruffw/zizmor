//! Core namespace for zizmor's audits.

use github_actions_models::action;
use line_index::LineIndex;
use thiserror::Error;
use tracing::instrument;
use yamlpath::Document;

use crate::{
    finding::{Finding, FindingBuilder, SymbolicLocation},
    models::{
        Action, AsDocument, CompositeStep, Job, NormalJob, ReusableWorkflowCallJob, Step, Workflow,
    },
    registry::InputKey,
    state::AuditState,
};

pub(crate) mod artipacked;
pub(crate) mod bot_conditions;
pub(crate) mod cache_poisoning;
pub(crate) mod dangerous_triggers;
pub(crate) mod excessive_permissions;
pub(crate) mod forbidden_uses;
pub(crate) mod github_env;
pub(crate) mod hardcoded_container_credentials;
pub(crate) mod impostor_commit;
pub(crate) mod insecure_commands;
pub(crate) mod known_vulnerable_actions;
pub(crate) mod obfuscation;
pub(crate) mod overprovisioned_secrets;
pub(crate) mod ref_confusion;
pub(crate) mod secrets_inherit;
pub(crate) mod secret_without_env;
pub(crate) mod self_hosted_runner;
pub(crate) mod stale_action_refs;
pub(crate) mod template_injection;
pub(crate) mod unpinned_images;
pub(crate) mod unpinned_uses;
pub(crate) mod unredacted_secrets;
pub(crate) mod unsound_contains;
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

    pub(crate) fn line_index(&self) -> &LineIndex {
        match self {
            AuditInput::Workflow(workflow) => &workflow.line_index,
            AuditInput::Action(action) => &action.line_index,
        }
    }

    pub(crate) fn link(&self) -> Option<&str> {
        match self {
            AuditInput::Workflow(workflow) => workflow.link.as_deref(),
            AuditInput::Action(action) => action.link.as_deref(),
        }
    }

    pub(crate) fn location(&self) -> SymbolicLocation {
        match self {
            AuditInput::Workflow(workflow) => workflow.location(),
            AuditInput::Action(action) => action.location(),
        }
    }
}

impl<'a> AsDocument<'a, 'a> for AuditInput {
    fn as_document(&'a self) -> &'a Document {
        match self {
            AuditInput::Workflow(workflow) => workflow.as_document(),
            AuditInput::Action(action) => action.as_document(),
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

    fn finding<'doc>() -> FindingBuilder<'doc>
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
    ($t:ty, $id:literal, $desc:expr_2021) => {
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
                concat!("https://docs.zizmor.sh/audits/#", $id)
            }
        }
    };
}

pub(crate) use audit_meta;

#[derive(Error, Debug)]
pub(crate) enum AuditLoadError {
    /// The audit's initialization failed in a way that suggests it should
    /// be skipped, rather than failing the entire run.
    #[error("{0}")]
    Skip(anyhow::Error),
    /// The audit's initialization failed in a way that suggests that the
    /// entire run should be aborted.
    #[error("{0}")]
    Fail(anyhow::Error),
}

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
/// For both:
///
/// 1. [`Audit::audit_raw`]: runs on the raw, unparsed YAML document source
///
/// Picking a higher specificity means that the lower methods are shadowed.
/// In other words, if an audit chooses to implement [`Audit::audit`], it should implement
/// **only** [`Audit::audit`] and not [`Audit::audit_normal_job`] or
/// [`Audit::audit_step`].
pub(crate) trait Audit: AuditCore {
    fn new(state: &AuditState<'_>) -> Result<Self, AuditLoadError>
    where
        Self: Sized;

    fn audit_step<'doc>(&self, _step: &Step<'doc>) -> anyhow::Result<Vec<Finding<'doc>>> {
        Ok(vec![])
    }

    fn audit_normal_job<'doc>(&self, job: &NormalJob<'doc>) -> anyhow::Result<Vec<Finding<'doc>>> {
        let mut results = vec![];
        for step in job.steps() {
            results.extend(self.audit_step(&step)?);
        }
        Ok(results)
    }

    fn audit_reusable_job<'doc>(
        &self,
        _job: &ReusableWorkflowCallJob<'doc>,
    ) -> anyhow::Result<Vec<Finding<'doc>>> {
        Ok(vec![])
    }

    fn audit_workflow<'doc>(&self, workflow: &'doc Workflow) -> anyhow::Result<Vec<Finding<'doc>>> {
        let mut results = vec![];

        for job in workflow.jobs() {
            match job {
                Job::NormalJob(normal) => {
                    results.extend(self.audit_normal_job(&normal)?);
                }
                Job::ReusableWorkflowCallJob(reusable) => {
                    results.extend(self.audit_reusable_job(&reusable)?);
                }
            }
        }

        Ok(results)
    }

    fn audit_composite_step<'doc>(
        &self,
        _step: &CompositeStep<'doc>,
    ) -> anyhow::Result<Vec<Finding<'doc>>> {
        Ok(vec![])
    }

    fn audit_action<'doc>(&self, action: &'doc Action) -> anyhow::Result<Vec<Finding<'doc>>> {
        let mut results = vec![];

        if matches!(action.runs, action::Runs::Composite(_)) {
            for step in action.steps() {
                results.extend(self.audit_composite_step(&step)?);
            }
        }

        Ok(results)
    }

    fn audit_raw<'doc>(&self, _input: &'doc AuditInput) -> anyhow::Result<Vec<Finding<'doc>>> {
        Ok(vec![])
    }

    /// The top-level auditing function for both workflows and actions.
    ///
    /// Implementors **should not** override this blanket implementation,
    /// since it's marked with tracing instrumentation.
    #[instrument(skip(self))]
    fn audit<'doc>(&self, input: &'doc AuditInput) -> anyhow::Result<Vec<Finding<'doc>>> {
        let mut results = match input {
            AuditInput::Workflow(workflow) => self.audit_workflow(workflow),
            AuditInput::Action(action) => self.audit_action(action),
        }?;

        results.extend(self.audit_raw(input)?);

        Ok(results)
    }
}
