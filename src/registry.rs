//! Functionality for registering and managing the lifecycles of
//! audits.

use std::{fmt::Display, process::ExitCode};

use crate::{
    audit::WorkflowAudit,
    config::Config,
    finding::{Confidence, Finding, Persona, Severity},
    models::{RepositoryUses, Workflow},
    App,
};
use anyhow::{anyhow, Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use indexmap::IndexMap;
use serde::Serialize;
use tracing::instrument;

#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize)]
pub(crate) struct LocalWorkflowKey {
    path: Utf8PathBuf,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize)]
pub(crate) struct RemoteWorkflowKey {
    owner: String,
    repo: String,
    git_ref: Option<String>,
    path: Utf8PathBuf,
}

/// A unique identifying "key" for a workflow file in a given run of zizmor.
///
/// zizmor currently knows two different kinds of keys: local keys
/// are just canonical paths to files on disk, while remote keys are
/// relative paths within a referenced GitHub repository.
#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize)]
pub(crate) enum WorkflowKey {
    Local(LocalWorkflowKey),
    Remote(RemoteWorkflowKey),
}

impl Display for WorkflowKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkflowKey::Local(local) => write!(f, "file://{path}", path = local.path),
            WorkflowKey::Remote(remote) => {
                // No ref means assume HEAD, i.e. whatever's on the default branch.
                let git_ref = remote.git_ref.as_deref().unwrap_or("HEAD");
                write!(
                    f,
                    "https://github.com/{owner}/{repo}/blob/{git_ref}/{path}",
                    owner = remote.owner,
                    repo = remote.repo,
                    path = remote.path
                )
            }
        }
    }
}

impl WorkflowKey {
    pub(crate) fn local(path: Utf8PathBuf) -> Result<Self> {
        // All workflow keys must have a filename component.
        if path.file_name().is_none() {
            return Err(anyhow!("invalid local workflow: no filename component"));
        }

        Ok(Self::Local(LocalWorkflowKey { path }))
    }

    pub(crate) fn remote(slug: &RepositoryUses, path: String) -> Result<Self> {
        if Utf8Path::new(&path).file_name().is_none() {
            return Err(anyhow!("invalid remote workflow: no filename component"));
        }

        Ok(Self::Remote(RemoteWorkflowKey {
            owner: slug.owner.into(),
            repo: slug.repo.into(),
            git_ref: slug.git_ref.map(Into::into),
            path: path.into(),
        }))
    }

    /// Returns this [`WorkflowKey`]'s filepath component.
    ///
    /// This will be an absolute path for local keys, and a relative
    /// path for remote keys.
    pub(crate) fn path(&self) -> &str {
        match self {
            WorkflowKey::Local(local) => local.path.as_str(),
            WorkflowKey::Remote(remote) => remote.path.as_str(),
        }
    }

    /// Returns the filename component of this [`WorkflowKey`].
    pub(crate) fn filename(&self) -> &str {
        // NOTE: Safe unwraps, since the presence of a filename component
        // is a construction invariant of all `WorkflowKey` variants.
        match self {
            WorkflowKey::Local(local) => local.path.file_name().unwrap(),
            WorkflowKey::Remote(remote) => remote.path.file_name().unwrap(),
        }
    }
}

pub(crate) struct WorkflowRegistry {
    pub(crate) workflows: IndexMap<WorkflowKey, Workflow>,
}

impl WorkflowRegistry {
    pub(crate) fn new() -> Self {
        Self {
            workflows: Default::default(),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.workflows.len()
    }

    #[instrument(skip(self))]
    pub(crate) fn register(&mut self, workflow: Workflow) -> Result<()> {
        if self.workflows.contains_key(&workflow.key) {
            return Err(anyhow!(
                "can't register {key} more than once",
                key = workflow.key
            ));
        }

        self.workflows.insert(workflow.key.clone(), workflow);

        Ok(())
    }

    #[instrument(skip(self))]
    pub(crate) fn register_by_path(&mut self, path: &Utf8Path) -> Result<()> {
        let workflow =
            Workflow::from_file(path).with_context(|| "couldn't load workflow from file")?;

        self.register(workflow)
    }

    pub(crate) fn iter_workflows(&self) -> indexmap::map::Iter<'_, WorkflowKey, Workflow> {
        self.workflows.iter()
    }

    pub(crate) fn get_workflow(&self, key: &WorkflowKey) -> &Workflow {
        self.workflows
            .get(key)
            .expect("API misuse: requested an un-registered workflow")
    }

    /// Returns a subjective relative path for the given workflow.
    ///
    /// In general, this will be a relative path within the repository root,
    /// e.g. if zizmor was told to scan `/tmp/src` then one of the discovered
    /// workflows might be `.github/workflows/ci.yml` relative to `/tmp/src`.
    ///
    /// The exceptional case here is when zizmor is asked to scan a single
    /// workflow at some arbitrary location on disk. In that case, just
    /// the base workflow filename itself is returned.
    pub(crate) fn get_workflow_relative_path<'a>(&self, key: &'a WorkflowKey) -> &'a str {
        let path = key.path();

        match path.rfind(".github/workflows") {
            Some(start) => &path[start..],
            // NOTE: Unwraps are safe since file component is always present and
            // all paths are UTF-8 by construction.
            None => key.filename(),
        }
    }
}

pub(crate) struct AuditRegistry {
    pub(crate) workflow_audits: IndexMap<&'static str, Box<dyn WorkflowAudit>>,
}

impl AuditRegistry {
    pub(crate) fn new() -> Self {
        Self {
            workflow_audits: Default::default(),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.workflow_audits.len()
    }

    pub(crate) fn register_workflow_audit(
        &mut self,
        ident: &'static str,
        audit: Box<dyn WorkflowAudit>,
    ) {
        self.workflow_audits.insert(ident, audit);
    }

    pub(crate) fn iter_workflow_audits(&self) -> indexmap::map::Iter<&str, Box<dyn WorkflowAudit>> {
        self.workflow_audits.iter()
    }
}

/// A registry of all findings discovered during a `zizmor` run.
pub(crate) struct FindingRegistry<'a> {
    config: &'a Config,
    minimum_severity: Option<Severity>,
    minimum_confidence: Option<Confidence>,
    persona: Persona,
    suppressed: Vec<Finding<'a>>,
    ignored: Vec<Finding<'a>>,
    findings: Vec<Finding<'a>>,
    highest_seen_severity: Option<Severity>,
}

impl<'a> FindingRegistry<'a> {
    pub(crate) fn new(app: &App, config: &'a Config) -> Self {
        Self {
            config,
            minimum_severity: app.min_severity,
            minimum_confidence: app.min_confidence,
            persona: app.persona,
            suppressed: Default::default(),
            ignored: Default::default(),
            findings: Default::default(),
            highest_seen_severity: None,
        }
    }

    /// Adds one or more findings to the current findings set,
    /// filtering with the configuration in the process.
    pub(crate) fn extend(&mut self, results: Vec<Finding<'a>>) {
        // TODO: is it faster to iterate like this, or do `find_by_max`
        // and then `extend`?
        for finding in results {
            if self.persona > finding.determinations.persona {
                self.suppressed.push(finding);
            } else if finding.ignored
                || self
                    .minimum_severity
                    .map_or(false, |min| min > finding.determinations.severity)
                || self
                    .minimum_confidence
                    .map_or(false, |min| min > finding.determinations.confidence)
                || self.config.ignores(&finding)
            {
                self.ignored.push(finding);
            } else {
                if self
                    .highest_seen_severity
                    .map_or(true, |s| finding.determinations.severity > s)
                {
                    self.highest_seen_severity = Some(finding.determinations.severity);
                }

                self.findings.push(finding);
            }
        }
    }

    /// The total count of all findings, regardless of status.
    pub(crate) fn count(&self) -> usize {
        self.findings.len() + self.ignored.len() + self.suppressed.len()
    }

    /// All non-ignored and non-suppressed findings.
    pub(crate) fn findings(&self) -> &[Finding<'a>] {
        &self.findings
    }

    /// All ignored findings.
    pub(crate) fn ignored(&self) -> &[Finding<'a>] {
        &self.ignored
    }

    /// All persona-suppressed findings.
    pub(crate) fn suppressed(&self) -> &[Finding<'a>] {
        &self.suppressed
    }
}

impl From<FindingRegistry<'_>> for ExitCode {
    fn from(value: FindingRegistry<'_>) -> Self {
        match value.highest_seen_severity {
            Some(sev) => match sev {
                Severity::Unknown => ExitCode::from(10),
                Severity::Informational => ExitCode::from(11),
                Severity::Low => ExitCode::from(12),
                Severity::Medium => ExitCode::from(13),
                Severity::High => ExitCode::from(14),
            },
            None => ExitCode::SUCCESS,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::models::Uses;

    use super::WorkflowKey;

    #[test]
    fn test_workflow_key_display() {
        let local = WorkflowKey::local("/foo/bar/baz.yml".into()).unwrap();
        assert_eq!(local.to_string(), "file:///foo/bar/baz.yml");

        // No ref
        let Uses::Repository(slug) = Uses::from_step("foo/bar").unwrap() else {
            panic!()
        };
        let remote = WorkflowKey::remote(&slug, ".github/workflows/baz.yml".into()).unwrap();
        assert_eq!(
            remote.to_string(),
            "https://github.com/foo/bar/blob/HEAD/.github/workflows/baz.yml"
        );

        // With a git ref
        let Uses::Repository(slug) = Uses::from_step("foo/bar@v1").unwrap() else {
            panic!()
        };
        let remote = WorkflowKey::remote(&slug, ".github/workflows/baz.yml".into()).unwrap();
        assert_eq!(
            remote.to_string(),
            "https://github.com/foo/bar/blob/v1/.github/workflows/baz.yml"
        );
    }
}
