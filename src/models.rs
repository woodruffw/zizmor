use std::{collections::hash_map, iter::Enumerate, ops::Deref, path::Path};

use anyhow::{Context, Result};
use github_actions_models::workflow;

use crate::finding::{JobOrKey, WorkflowLocation};

pub(crate) struct Workflow {
    pub(crate) filename: String,
    pub(crate) document: yamlpath::Document,
    inner: workflow::Workflow,
}

impl Deref for Workflow {
    type Target = workflow::Workflow;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Workflow {
    pub(crate) fn from_file<P: AsRef<Path>>(p: P) -> Result<Self> {
        let raw = std::fs::read_to_string(p.as_ref())?;

        let inner = serde_yaml::from_str(&raw)
            .with_context(|| format!("invalid GitHub Actions workflow: {:?}", p.as_ref()))?;

        let document = yamlpath::Document::new(raw)?;

        // NOTE: file_name().unwrap() is safe since the read above only succeeds
        // on a well-formed filepath.
        Ok(Self {
            filename: p
                .as_ref()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            document,
            inner,
        })
    }

    pub(crate) fn location(&self) -> WorkflowLocation {
        WorkflowLocation {
            name: &self.filename,
            job_or_key: None,
            annotation: None,
        }
    }

    pub(crate) fn key_location(&self, key: &'static str) -> WorkflowLocation {
        self.location().with_key(key)
    }

    pub(crate) fn jobs(&self) -> Jobs<'_> {
        Jobs::new(self)
    }
}

pub(crate) struct Job<'w> {
    pub(crate) id: &'w str,
    pub(crate) inner: &'w workflow::Job,
    parent: WorkflowLocation<'w>,
}

impl<'w> Deref for Job<'w> {
    type Target = workflow::Job;

    fn deref(&self) -> &Self::Target {
        self.inner
    }
}

impl<'w> Job<'w> {
    pub(crate) fn new(id: &'w str, inner: &'w workflow::Job, parent: WorkflowLocation<'w>) -> Self {
        Self { id, inner, parent }
    }

    pub(crate) fn location(&self) -> WorkflowLocation<'w> {
        self.parent.with_job(self)
    }

    pub(crate) fn key_location(&self, key: &'w str) -> WorkflowLocation<'w> {
        let mut location = self.parent.with_job(self);
        let Some(JobOrKey::Job(job)) = location.job_or_key else {
            panic!("unreachable")
        };
        let job = job.with_key(key);

        location.job_or_key = Some(JobOrKey::Job(job));

        location
    }

    pub(crate) fn steps(&self) -> Steps<'w> {
        Steps::new(self)
    }
}

pub(crate) struct Jobs<'w> {
    inner: hash_map::Iter<'w, String, workflow::Job>,
    location: WorkflowLocation<'w>,
}

impl<'w> Jobs<'w> {
    pub(crate) fn new(workflow: &'w Workflow) -> Self {
        Self {
            inner: workflow.jobs.iter(),
            location: workflow.location(),
        }
    }
}

impl<'w> Iterator for Jobs<'w> {
    type Item = Job<'w>;

    fn next(&mut self) -> Option<Self::Item> {
        let item = self.inner.next();

        match item {
            Some((id, job)) => Some(Job::new(id, job, self.location.clone())),
            None => None,
        }
    }
}

#[derive(Clone)]
pub(crate) struct Step<'w> {
    pub(crate) index: usize,
    pub(crate) inner: &'w workflow::job::Step,
    parent: WorkflowLocation<'w>,
}

impl<'w> Deref for Step<'w> {
    type Target = workflow::job::Step;

    fn deref(&self) -> &'w Self::Target {
        self.inner
    }
}

impl<'w> Step<'w> {
    pub(crate) fn new(
        index: usize,
        inner: &'w workflow::job::Step,
        parent: WorkflowLocation<'w>,
    ) -> Self {
        Self {
            index,
            inner,
            parent,
        }
    }

    pub(crate) fn location(&self) -> WorkflowLocation<'w> {
        self.parent.with_step(self)
    }
}

pub(crate) struct Steps<'w> {
    inner: Enumerate<std::slice::Iter<'w, github_actions_models::workflow::job::Step>>,
    location: WorkflowLocation<'w>,
}

impl<'w> Steps<'w> {
    pub(crate) fn new(job: &Job<'w>) -> Self {
        // TODO: do something less silly here.
        match &job.inner {
            workflow::Job::ReusableWorkflowCallJob(_) => {
                panic!("API misuse: can't call steps() on a reusable job")
            }
            workflow::Job::NormalJob(ref n) => Self {
                inner: n.steps.iter().enumerate(),
                location: job.location(),
            },
        }
    }
}

impl<'w> Iterator for Steps<'w> {
    type Item = Step<'w>;

    fn next(&mut self) -> Option<Self::Item> {
        let item = self.inner.next();

        match item {
            Some((idx, step)) => Some(Step::new(idx, step, self.location.clone())),
            None => None,
        }
    }
}

#[derive(Copy, Clone)]
pub(crate) struct AuditConfig<'a> {
    pub(crate) pedantic: bool,
    pub(crate) gh_token: &'a str,
}

/// Represents the components of an "action ref", i.e. the value
/// of a `uses:` clause in a normal job step or a reusable workflow job.
/// Does not support `docker://` refs, or "local" (i.e. `./`) refs.
#[derive(Copy, Clone, Debug, PartialEq)]
pub(crate) struct Uses<'a> {
    pub(crate) owner: &'a str,
    pub(crate) repo: &'a str,
    pub(crate) subpath: Option<&'a str>,
    pub(crate) git_ref: Option<&'a str>,
}

impl<'a> Uses<'a> {
    /// Create a new `Uses` manually. No validation of the constituent
    /// parts is performed.
    fn new(
        owner: &'a str,
        repo: &'a str,
        subpath: Option<&'a str>,
        git_ref: Option<&'a str>,
    ) -> Self {
        Self {
            owner,
            repo,
            subpath,
            git_ref,
        }
    }

    fn from_common(uses: &'a str) -> Option<Self> {
        // We don't currently have enough context to resolve local actions.
        if uses.starts_with("./") {
            return None;
        }

        // NOTE: Technically both git refs and action paths can contain `@`,
        // so this isn't guaranteed to be correct. In practice, however,
        // splitting on the last `@` is mostly reliable.
        let (path, git_ref) = match uses.rsplit_once('@') {
            Some((path, git_ref)) => (path, Some(git_ref)),
            None => (uses, None),
        };

        let components = path.splitn(3, '/').collect::<Vec<_>>();
        if components.len() < 2 {
            log::debug!("malformed `uses:` ref: {uses}");
            return None;
        }

        Some(Self::new(
            components[0],
            components[1],
            components.get(2).copied(),
            git_ref,
        ))
    }

    pub(crate) fn from_step(uses: &'a str) -> Option<Self> {
        if uses.starts_with("docker://") {
            return None;
        }

        Self::from_common(uses)
    }

    pub(crate) fn from_reusable(uses: &'a str) -> Option<Self> {
        match Self::from_common(uses) {
            // Reusable workflows require a git ref.
            Some(uses) if uses.git_ref.is_none() => None,
            Some(uses) => Some(uses),
            None => None,
        }
    }

    pub(crate) fn ref_is_commit(&self) -> bool {
        match self.git_ref {
            Some(git_ref) => git_ref.len() == 40 && git_ref.chars().all(|c| c.is_ascii_hexdigit()),
            None => false,
        }
    }

    pub(crate) fn commit_ref(&self) -> Option<&str> {
        match self.git_ref {
            Some(git_ref) if self.ref_is_commit() => Some(git_ref),
            _ => None,
        }
    }

    pub(crate) fn symbolic_ref(&self) -> Option<&str> {
        match self.git_ref {
            Some(git_ref) if !self.ref_is_commit() => Some(git_ref),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Uses;

    #[test]
    fn uses_from_step() {
        let vectors = [
            (
                // Valid: fully pinned.
                "actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3",
                Some(Uses::new(
                    "actions",
                    "checkout",
                    None,
                    Some("8f4b7f84864484a7bf31766abe9204da3cbe65b3"),
                )),
            ),
            (
                // Valid: fully pinned, subpath
                "actions/aws/ec2@8f4b7f84864484a7bf31766abe9204da3cbe65b3",
                Some(Uses::new(
                    "actions",
                    "aws",
                    Some("ec2"),
                    Some("8f4b7f84864484a7bf31766abe9204da3cbe65b3"),
                )),
            ),
            (
                // Valid: fully pinned, complex subpath
                "example/foo/bar/baz/quux@8f4b7f84864484a7bf31766abe9204da3cbe65b3",
                Some(Uses::new(
                    "example",
                    "foo",
                    Some("bar/baz/quux"),
                    Some("8f4b7f84864484a7bf31766abe9204da3cbe65b3"),
                )),
            ),
            (
                // Valid: pinned with branch/tag
                "actions/checkout@v4",
                Some(Uses::new("actions", "checkout", None, Some("v4"))),
            ),
            (
                "actions/checkout@abcd",
                Some(Uses::new("actions", "checkout", None, Some("abcd"))),
            ),
            (
                // Valid: unpinned
                "actions/checkout",
                Some(Uses::new("actions", "checkout", None, None)),
            ),
            // Invalid: missing user/repo
            ("checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3", None),
            // Invalid: local action refs not supported
            (
                "./.github/actions/hello-world-action@172239021f7ba04fe7327647b213799853a9eb89",
                None,
            ),
            // Invalid: Docker refs not supported
            ("docker://alpine:3.8", None),
        ];

        for (input, expected) in vectors {
            assert_eq!(Uses::from_step(input), expected);
        }
    }

    #[test]
    fn uses_from_reusable() {
        let vectors = [
            // Valid, as expected.
            (
                "octo-org/this-repo/.github/workflows/workflow-1.yml@\
                 172239021f7ba04fe7327647b213799853a9eb89",
                Some(Uses::new(
                    "octo-org",
                    "this-repo",
                    Some(".github/workflows/workflow-1.yml"),
                    Some("172239021f7ba04fe7327647b213799853a9eb89"),
                )),
            ),
            (
                "octo-org/this-repo/.github/workflows/workflow-1.yml@notahash",
                Some(Uses::new(
                    "octo-org",
                    "this-repo",
                    Some(".github/workflows/workflow-1.yml"),
                    Some("notahash"),
                )),
            ),
            (
                "octo-org/this-repo/.github/workflows/workflow-1.yml@abcd",
                Some(Uses::new(
                    "octo-org",
                    "this-repo",
                    Some(".github/workflows/workflow-1.yml"),
                    Some("abcd"),
                )),
            ),
            // Invalid: no ref at all
            ("octo-org/this-repo/.github/workflows/workflow-1.yml", None),
            // Invalid: missing user/repo
            (
                "workflow-1.yml@172239021f7ba04fe7327647b213799853a9eb89",
                None,
            ),
            // Invalid: local reusable workflow refs not supported
            (
                "./.github/workflows/workflow-1.yml@172239021f7ba04fe7327647b213799853a9eb89",
                None,
            ),
        ];

        for (input, expected) in vectors {
            assert_eq!(Uses::from_reusable(input), expected);
        }
    }

    #[test]
    fn uses_ref_is_commit() {
        assert!(
            Uses::from_step("actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3")
                .unwrap()
                .ref_is_commit()
        );

        assert!(!Uses::from_step("actions/checkout@v4")
            .unwrap()
            .ref_is_commit());

        assert!(!Uses::from_step("actions/checkout@abcd")
            .unwrap()
            .ref_is_commit());
    }
}
