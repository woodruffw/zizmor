//! Functionality for registering and managing the lifecycles of
//! audits.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use anyhow::Result;

use crate::{audit::WorkflowAudit, models::Workflow};

pub(crate) struct WorkflowRegistry {
    pub(crate) workflows: HashMap<PathBuf, Workflow>,
}

impl WorkflowRegistry {
    pub(crate) fn new() -> Self {
        Self {
            workflows: Default::default(),
        }
    }

    pub(crate) fn register_workflow(&mut self, path: &Path) -> Result<()> {
        self.workflows
            .insert(path.canonicalize()?, Workflow::from_file(&path)?);

        Ok(())
    }

    pub(crate) fn iter_workflows(&self) -> std::collections::hash_map::Iter<'_, PathBuf, Workflow> {
        self.workflows.iter()
    }
}

pub(crate) struct AuditRegistry<'config> {
    pub(crate) workflow_audits: HashMap<&'static str, Box<dyn WorkflowAudit<'config> + 'config>>,
}

impl<'config> AuditRegistry<'config> {
    pub(crate) fn new() -> Self {
        Self {
            workflow_audits: Default::default(),
        }
    }

    pub(crate) fn register_workflow_audit(
        &mut self,
        ident: &'static str,
        audit: Box<dyn WorkflowAudit<'config> + 'config>,
    ) {
        self.workflow_audits.insert(ident, audit);
    }

    pub(crate) fn iter_workflow_audits(
        &mut self,
    ) -> std::collections::hash_map::IterMut<'_, &str, Box<dyn WorkflowAudit<'config> + 'config>>
    {
        self.workflow_audits.iter_mut()
    }
}
