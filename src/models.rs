//! Enriching/context-bearing wrappers over GitHub Actions models
//! from the `github-actions-models` crate.

use crate::finding::{Route, SymbolicLocation};
use crate::registry::InputKey;
use crate::utils::{self, extract_expressions};
use anyhow::{anyhow, bail, Context, Result};
use camino::Utf8Path;
use github_actions_models::action;
use github_actions_models::common::expr::LoE;
use github_actions_models::workflow::event::{BareEvent, OptionalBody};
use github_actions_models::workflow::job::{RunsOn, Strategy};
use github_actions_models::workflow::{
    self, job,
    job::{NormalJob, StepBody},
    Trigger,
};
use indexmap::IndexMap;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fmt::Debug;
use std::{iter::Enumerate, ops::Deref};
use terminal_link::Link;

/// Common interfaces between workflow and action steps.
pub(crate) trait StepCommon {
    /// Returns whether the given `env.name` environment access is "static,"
    /// i.e. is not influenced by another expression.
    fn env_is_static(&self, name: &str) -> bool;

    /// Returns this step's job's strategy, if present.
    ///
    /// Composite action steps have no strategy.
    fn strategy(&self) -> Option<&Strategy>;
}

/// Represents an entire GitHub Actions workflow.
///
/// This type implements [`Deref`] for [`workflow::Workflow`],
/// providing access to the underlying data model.
pub(crate) struct Workflow {
    /// This workflow's unique key into zizmor's runtime registry.
    pub(crate) key: InputKey,
    /// A clickable (OSC 8) link to this workflow, if remote.
    pub(crate) link: Option<String>,
    pub(crate) document: yamlpath::Document,
    inner: workflow::Workflow,
}

impl AsRef<yamlpath::Document> for Workflow {
    fn as_ref(&self) -> &yamlpath::Document {
        &self.document
    }
}

impl Debug for Workflow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{key}", key = self.key)
    }
}

impl Deref for Workflow {
    type Target = workflow::Workflow;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Workflow {
    /// Load a workflow from a buffer, with an assigned name.
    pub(crate) fn from_string(contents: String, key: InputKey) -> Result<Self> {
        let inner = serde_yaml::from_str(&contents)
            .with_context(|| format!("invalid GitHub Actions workflow: {key}"))?;

        let document = yamlpath::Document::new(&contents)?;

        let link = match key {
            InputKey::Local(_) => None,
            InputKey::Remote(_) => {
                // NOTE: WorkflowKey's Display produces a URL, hence `key.to_string()`.
                Some(Link::new(key.path(), &key.to_string()).to_string())
            }
        };

        Ok(Self {
            link,
            key,
            document,
            inner,
        })
    }

    /// Load a workflow from the given file on disk.
    pub(crate) fn from_file<P: AsRef<Utf8Path>>(p: P) -> Result<Self> {
        let contents = std::fs::read_to_string(p.as_ref())?;
        let path = p.as_ref().canonicalize_utf8()?;

        Self::from_string(contents, InputKey::local(path)?)
    }

    /// Returns the filename (i.e. base component) of the loaded workflow.
    ///
    /// For example, if the workflow was loaded from `/foo/bar/baz.yml`,
    /// [`Self::filename()`] returns `baz.yml`.
    pub(crate) fn filename(&self) -> &str {
        self.key.filename()
    }

    /// This workflow's [`SymbolicLocation`].
    pub(crate) fn location(&self) -> SymbolicLocation {
        SymbolicLocation {
            key: &self.key,
            annotation: "this workflow".to_string(),
            link: None,
            route: Route::new(),
            primary: false,
        }
    }

    /// A [`Jobs`] iterator over this workflow's constituent [`Job`]s.
    pub(crate) fn jobs(&self) -> Jobs<'_> {
        Jobs::new(self)
    }

    /// Whether this workflow's is triggered by pull_request_target.
    pub(crate) fn has_pull_request_target(&self) -> bool {
        match &self.on {
            Trigger::BareEvent(event) => *event == BareEvent::PullRequestTarget,
            Trigger::BareEvents(events) => events.contains(&BareEvent::PullRequestTarget),
            Trigger::Events(events) => !matches!(events.pull_request_target, OptionalBody::Missing),
        }
    }

    /// Whether this workflow's is triggered by workflow_run.
    pub(crate) fn has_workflow_run(&self) -> bool {
        match &self.on {
            Trigger::BareEvent(event) => *event == BareEvent::WorkflowRun,
            Trigger::BareEvents(events) => events.contains(&BareEvent::WorkflowRun),
            Trigger::Events(events) => !matches!(events.workflow_run, OptionalBody::Missing),
        }
    }
}

/// Represents a single GitHub Actions job.
///
/// This type implements [`Deref`] for [`workflow::Job`], providing
/// access to the underlying data model.
#[derive(Clone)]
pub(crate) struct Job<'w> {
    /// The job's unique ID (i.e., its key in the workflow's `jobs:` block).
    pub(crate) id: &'w str,
    /// The underlying job.
    inner: &'w workflow::Job,
    /// The job's parent [`Workflow`].
    parent: &'w Workflow,
}

impl<'w> Deref for Job<'w> {
    type Target = &'w workflow::Job;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'w> Job<'w> {
    fn new(id: &'w str, inner: &'w workflow::Job, parent: &'w Workflow) -> Self {
        Self { id, inner, parent }
    }

    /// This job's parent [`Workflow`]
    pub(crate) fn parent(&self) -> &'w Workflow {
        self.parent
    }

    /// This job's [`SymbolicLocation`].
    pub(crate) fn location(&self) -> SymbolicLocation<'w> {
        self.parent().location().with_job(self)
    }

    /// An iterator of this job's constituent [`Step`]s.
    pub(crate) fn steps(&self) -> Steps<'w> {
        Steps::new(self)
    }

    /// Perform feats of heroism to figure of what this job's runner's
    /// default shell is.
    ///
    /// Returns `None` if the job is not a normal job, or if the runner
    /// environment is indeterminate (e.g. controlled by an expression).
    pub(crate) fn runner_default_shell(&self) -> Option<&'static str> {
        let workflow::Job::NormalJob(normal) = self.inner else {
            return None;
        };

        match &normal.runs_on {
            // The entire runs-on is an expression, so there's nothing we can do.
            LoE::Expr(_) => None,
            LoE::Literal(RunsOn::Group { group: _, labels })
            | LoE::Literal(RunsOn::Target(labels)) => {
                for label in labels {
                    match label.as_str() {
                        // Default self-hosted routing labels.
                        "linux" | "macOS" => return Some("bash"),
                        "windows" => return Some("pwsh"),
                        // Standard GitHub-hosted runners, e.g. `ubuntu-latest`.
                        // We check only the prefix here so that we don't have to keep track
                        // of every possible variation of these runners.
                        l if l.contains("ubuntu-") || l.contains("macos") => return Some("bash"),
                        l if l.contains("windows-") => return Some("pwsh"),
                        _ => continue,
                    }
                }

                None
            }
        }
    }
}

/// An iterable container for jobs within a [`Workflow`].
pub(crate) struct Jobs<'w> {
    parent: &'w Workflow,
    inner: indexmap::map::Iter<'w, String, workflow::Job>,
}

impl<'w> Jobs<'w> {
    fn new(workflow: &'w Workflow) -> Self {
        Self {
            parent: workflow,
            inner: workflow.jobs.iter(),
        }
    }
}

impl<'w> Iterator for Jobs<'w> {
    type Item = Job<'w>;

    fn next(&mut self) -> Option<Self::Item> {
        let item = self.inner.next();

        match item {
            Some((id, job)) => Some(Job::new(id, job, self.parent)),
            None => None,
        }
    }
}

/// Represents an execution Matrix within a Job.
///
/// This type implements [`Deref`] for [`job::NormalJob::strategy`], providing
/// access to the underlying data model.
#[derive(Clone)]
pub(crate) struct Matrix<'w> {
    inner: &'w LoE<job::Matrix>,
    pub(crate) expanded_values: Vec<(String, String)>,
}

impl<'w> Deref for Matrix<'w> {
    type Target = &'w LoE<job::Matrix>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'w> TryFrom<&'w Job<'w>> for Matrix<'w> {
    type Error = anyhow::Error;

    fn try_from(value: &'w Job<'w>) -> std::result::Result<Self, Self::Error> {
        let workflow::Job::NormalJob(job) = value.deref() else {
            bail!("job is not a normal job")
        };

        let Some(Strategy {
            matrix: Some(inner),
            ..
        }) = &job.strategy
        else {
            bail!("job does not define a strategy or interior matrix")
        };

        Ok(Matrix::new(inner))
    }
}

impl<'w> Matrix<'w> {
    pub(crate) fn new(inner: &'w LoE<job::Matrix>) -> Self {
        Self {
            inner,
            expanded_values: Matrix::expand_values(inner),
        }
    }

    /// Checks whether some expanded path leads to an expression
    pub(crate) fn expands_to_static_values(&self, context: &str) -> bool {
        let expands_to_expression = self.expanded_values.iter().any(|(path, expansion)| {
            // Each expanded value in the matrix might be an expression, or contain
            // one or more expressions (e.g. `foo-${{ bar }}-${{ baz }}`). So we
            // need to check for *any* expression in the expanded value,
            // not just that it starts and ends with the expression delimiters.
            let expansion_contains_expression = !extract_expressions(expansion).is_empty();
            context == path && expansion_contains_expression
        });

        !expands_to_expression
    }

    /// Expands the current Matrix into all possible values
    /// By default, the return is a pair (String, String), in which
    /// the first component is the expanded path (e.g. 'matrix.os') and
    /// the second component is the string representation for the expanded value
    /// (e.g. ubuntu-latest)
    ///
    fn expand_values(inner: &LoE<job::Matrix>) -> Vec<(String, String)> {
        match inner {
            LoE::Expr(_) => vec![],
            LoE::Literal(matrix) => {
                let LoE::Literal(dimensions) = &matrix.dimensions else {
                    return vec![];
                };

                let mut expansions = Matrix::expand_dimensions(dimensions);

                if let LoE::Literal(includes) = &matrix.include {
                    let additional_expansions = includes
                        .iter()
                        .flat_map(Matrix::expand_explicit_rows)
                        .collect::<Vec<_>>();

                    expansions.extend(additional_expansions);
                };

                let LoE::Literal(excludes) = &matrix.exclude else {
                    return expansions;
                };

                let to_exclude = excludes
                    .iter()
                    .flat_map(Matrix::expand_explicit_rows)
                    .collect::<Vec<_>>();

                expansions
                    .into_iter()
                    .filter(|expanded| !to_exclude.contains(expanded))
                    .collect()
            }
        }
    }

    fn expand_explicit_rows(
        include: &IndexMap<String, serde_yaml::Value>,
    ) -> Vec<(String, String)> {
        let normalized = include
            .iter()
            .map(|(k, v)| (k.to_owned(), json!(v)))
            .collect::<HashMap<_, _>>();

        Matrix::expand(normalized)
    }

    fn expand_dimensions(
        dimensions: &IndexMap<String, LoE<Vec<serde_yaml::Value>>>,
    ) -> Vec<(String, String)> {
        let normalized = dimensions
            .iter()
            .map(|(k, v)| (k.to_owned(), json!(v)))
            .collect::<HashMap<_, _>>();

        Matrix::expand(normalized)
    }

    fn expand(values: HashMap<String, serde_json::Value>) -> Vec<(String, String)> {
        values
            .iter()
            .flat_map(|(key, value)| Matrix::walk_path(value, format!("matrix.{}", key)))
            .collect()
    }

    // Walks recursively a serde_json::Value tree, expanding it into a Vec<(String, String)>
    // according to the inner value of each node
    fn walk_path(tree: &serde_json::Value, current_path: String) -> Vec<(String, String)> {
        match tree {
            Value::Null => vec![],

            // In the case of scalars, we just convert the value to a string
            Value::Bool(inner) => vec![(current_path, inner.to_string())],
            Value::Number(inner) => vec![(current_path, inner.to_string())],
            Value::String(inner) => vec![(current_path, inner.to_string())],

            // In the case of an array, we recursively create on expansion pair for each item
            Value::Array(inner) => inner
                .iter()
                .flat_map(|value| Matrix::walk_path(value, current_path.clone()))
                .collect(),

            // In the case of an object, we recursively create on expansion pair for each
            // value in the key/value set, using the key to form the expanded path using
            // the dot notation
            Value::Object(inner) => inner
                .iter()
                .flat_map(|(key, value)| {
                    let mut new_path = current_path.clone();
                    new_path.push('.');
                    new_path.push_str(key);
                    Matrix::walk_path(value, new_path)
                })
                .collect(),
        }
    }
}

/// Represents a single step in a normal workflow job.
///
/// This type implements [`Deref`] for [`workflow::job::Step`], which
/// provides access to the step's actual fields.
#[derive(Clone)]
pub(crate) struct Step<'w> {
    /// The step's index within its parent job.
    pub(crate) index: usize,
    /// The inner step model.
    inner: &'w workflow::job::Step,
    /// The parent [`Job`].
    pub(crate) parent: Job<'w>,
}

impl<'w> Deref for Step<'w> {
    type Target = &'w workflow::job::Step;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl StepCommon for Step<'_> {
    fn env_is_static(&self, name: &str) -> bool {
        // Collect each of the step, job, and workflow-level `env` blocks
        // and check each.
        let mut envs = vec![];

        match &self.body {
            workflow::job::StepBody::Uses { .. } => {
                panic!("API misuse: can't call env_is_static on a uses: step")
            }
            workflow::job::StepBody::Run {
                run: _,
                working_directory: _,
                shell: _,
                env,
            } => envs.push(env),
        };

        envs.push(&self.job().env);
        envs.push(&self.workflow().env);

        utils::env_is_static(name, &envs)
    }

    fn strategy(&self) -> Option<&Strategy> {
        self.job().strategy.as_ref()
    }
}

impl<'w> Step<'w> {
    fn new(index: usize, inner: &'w workflow::job::Step, parent: Job<'w>) -> Self {
        Self {
            index,
            inner,
            parent,
        }
    }

    /// Returns this step's parent [`NormalJob`].
    ///
    /// Note that this returns the [`NormalJob`], not the wrapper [`Job`].
    pub(crate) fn job(&self) -> &'w NormalJob {
        match *self.parent {
            workflow::Job::NormalJob(job) => job,
            // NOTE(ww): Unreachable because steps are always parented by normal jobs.
            workflow::Job::ReusableWorkflowCallJob(_) => unreachable!(),
        }
    }

    /// Returns this step's (grand)parent [`Workflow`].
    pub(crate) fn workflow(&self) -> &'w Workflow {
        self.parent.parent()
    }

    /// Returns a [`Uses`] for this [`Step`], if it has one.
    pub(crate) fn uses(&self) -> Option<Uses<'w>> {
        let StepBody::Uses { uses, .. } = &self.inner.body else {
            return None;
        };

        Uses::from_step(uses)
    }

    /// Returns the name of the shell used by this step, or `None`
    /// if the shell can't be statically inferred.
    ///
    /// Invariant: panics if the step is not a `run:` step.
    pub(crate) fn shell(&self) -> Option<&str> {
        let StepBody::Run {
            run: _,
            working_directory: _,
            shell,
            env: _,
        } = &self.inner.body
        else {
            panic!("API misuse: can't call shell() on a uses: step")
        };

        // The steps's own `shell:` takes precedence, followed by the
        // job's default, followed by the entire workflow's default,
        // followed by the runner's default.
        let shell = shell
            .as_deref()
            .or_else(|| {
                self.job()
                    .defaults
                    .as_ref()
                    .and_then(|d| d.run.as_ref().and_then(|r| r.shell.as_deref()))
            })
            .or_else(|| {
                self.workflow()
                    .defaults
                    .as_ref()
                    .and_then(|d| d.run.as_ref().and_then(|r| r.shell.as_deref()))
            })
            .or_else(|| self.parent.runner_default_shell());

        shell
    }

    /// Returns a symbolic location for this [`Step`].
    pub(crate) fn location(&self) -> SymbolicLocation<'w> {
        self.parent.location().with_step(self)
    }

    /// Like [`Step::location`], except with the step's `name`
    /// key as the final path component if present.
    pub(crate) fn location_with_name(&self) -> SymbolicLocation<'w> {
        match self.inner.name {
            Some(_) => self.location().with_keys(&["name".into()]),
            None => self.location(),
        }
        .annotated("this step")
    }
}

/// An iterable container for steps within a [`Job`].
pub(crate) struct Steps<'w> {
    inner: Enumerate<std::slice::Iter<'w, github_actions_models::workflow::job::Step>>,
    parent: Job<'w>,
}

impl<'w> Steps<'w> {
    /// Create a new [`Steps`].
    ///
    /// Invariant: panics if the given [`Job`] is a reusable job, rather than a "normal" job.
    fn new(job: &Job<'w>) -> Self {
        // TODO: do something less silly here.
        match &job.inner {
            workflow::Job::ReusableWorkflowCallJob(_) => {
                panic!("API misuse: can't call steps() on a reusable job")
            }
            workflow::Job::NormalJob(ref n) => Self {
                inner: n.steps.iter().enumerate(),
                parent: job.clone(),
            },
        }
    }
}

impl<'w> Iterator for Steps<'w> {
    type Item = Step<'w>;

    fn next(&mut self) -> Option<Self::Item> {
        let item = self.inner.next();

        match item {
            Some((idx, step)) => Some(Step::new(idx, step, self.parent.clone())),
            None => None,
        }
    }
}

/// The contents of a `uses: docker://` step stanza.
#[derive(Copy, Clone, Debug, PartialEq)]
pub(crate) struct DockerUses<'a> {
    pub(crate) registry: Option<&'a str>,
    pub(crate) image: &'a str,
    pub(crate) tag: Option<&'a str>,
    pub(crate) hash: Option<&'a str>,
}

/// The contents of a `uses: some/repo` step stanza.
#[derive(Copy, Clone, Debug, PartialEq)]
pub(crate) struct RepositoryUses<'a> {
    pub(crate) owner: &'a str,
    pub(crate) repo: &'a str,
    pub(crate) subpath: Option<&'a str>,
    pub(crate) git_ref: Option<&'a str>,
}

impl<'a> TryFrom<&'a str> for RepositoryUses<'a> {
    type Error = anyhow::Error;

    fn try_from(value: &'a str) -> std::result::Result<Self, Self::Error> {
        let Some(Uses::Repository(uses)) = Uses::from_common(value) else {
            return Err(anyhow!("invalid repository uses: {value}"));
        };

        Ok(uses)
    }
}

impl RepositoryUses<'_> {
    /// Returns whether this `uses:` clause "matches" the given template.
    /// The template is itself formatted like a normal `uses:` clause.
    ///
    /// This is an asymmetrical match: `actions/checkout@v3` "matches"
    /// the `actions/checkout` template but not vice versa.
    pub(crate) fn matches<'a>(&self, template: impl TryInto<RepositoryUses<'a>>) -> bool {
        let Ok(other) = template.try_into() else {
            return false;
        };

        self.owner == other.owner
            && self.repo == other.repo
            && self.subpath == other.subpath
            && other
                .git_ref
                .map_or(true, |git_ref| Some(git_ref) == self.git_ref)
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

/// Represents the components of an "action ref", i.e. the value
/// of a `uses:` clause in a normal job step or a reusable workflow job.
/// Supports Docker (`docker://`) and repository (`actions/checkout`)
/// style references, but not local (`./foo`) references.
#[derive(Copy, Clone, Debug, PartialEq)]
pub(crate) enum Uses<'a> {
    Docker(DockerUses<'a>),
    Repository(RepositoryUses<'a>),
}

impl<'a> Uses<'a> {
    fn is_registry(registry: &str) -> bool {
        // https://stackoverflow.com/a/42116190
        registry == "localhost" || registry.contains('.') || registry.contains(':')
    }

    /// Parses a Docker image reference.
    /// See: <https://docs.docker.com/reference/cli/docker/image/tag/>
    fn from_image_ref(image: &'a str) -> Option<Self> {
        let (registry, image) = match image.split_once('/') {
            Some((registry, image)) if Self::is_registry(registry) => (Some(registry), image),
            _ => (None, image),
        };

        // NOTE(ww): hashes aren't mentioned anywhere in Docker's own docs,
        // but appear to be an OCI thing. GitHub doesn't support them
        // yet either, but we expect them to soon (with "immutable actions").
        if let Some(at_pos) = image.find('@') {
            let (image, hash) = image.split_at(at_pos);

            let hash = if hash.is_empty() {
                None
            } else {
                Some(&hash[1..])
            };

            Some(Self::Docker(DockerUses {
                registry,
                image,
                tag: None,
                hash,
            }))
        } else {
            let (image, tag) = match image.split_once(':') {
                Some((image, "")) => (image, None),
                Some((image, tag)) => (image, Some(tag)),
                _ => (image, None),
            };

            Some(Self::Docker(DockerUses {
                registry,
                image,
                tag,
                hash: None,
            }))
        }
    }

    fn from_common(uses: &'a str) -> Option<Self> {
        if uses.starts_with("./") {
            None
        } else if let Some(image) = uses.strip_prefix("docker://") {
            Self::from_image_ref(image)
        } else {
            // NOTE: Technically both git refs and action paths can contain `@`,
            // so this isn't guaranteed to be correct. In practice, however,
            // splitting on the last `@` is mostly reliable.
            let (path, git_ref) = match uses.rsplit_once('@') {
                Some((path, git_ref)) => (path, Some(git_ref)),
                None => (uses, None),
            };

            let components = path.splitn(3, '/').collect::<Vec<_>>();
            if components.len() < 2 {
                tracing::debug!("malformed `uses:` ref: {uses}");
                return None;
            }

            Some(Self::Repository(RepositoryUses {
                owner: components[0],
                repo: components[1],
                subpath: components.get(2).copied(),
                git_ref,
            }))
        }
    }

    pub(crate) fn from_step(uses: &'a str) -> Option<Self> {
        Self::from_common(uses)
    }

    /// Parse a [`Uses`] from a reusable workflow `uses:` clause.
    ///
    /// Returns only the [`RepositoryUses`] variant since Docker actions
    /// can't be used in reusable workflows.
    pub(crate) fn from_reusable(uses: &'a str) -> Option<RepositoryUses<'a>> {
        match Self::from_common(uses) {
            // Reusable workflows don't support Docker actions.
            Some(Uses::Docker(DockerUses { .. })) => None,
            // Reusable workflows require a git ref.
            Some(Uses::Repository(RepositoryUses {
                owner: _,
                repo: _,
                subpath: _,
                git_ref,
            })) if git_ref.is_none() => None,
            Some(Uses::Repository(repo)) => Some(repo),
            None => None,
        }
    }

    pub(crate) fn unpinned(&self) -> bool {
        match self {
            Uses::Docker(docker) => docker.hash.is_none() && docker.tag.is_none(),
            Uses::Repository(repo) => repo.git_ref.is_none(),
        }
    }

    pub(crate) fn unhashed(&self) -> bool {
        match self {
            Uses::Docker(docker) => docker.hash.is_some(),
            Uses::Repository(repo) => !repo.ref_is_commit(),
        }
    }
}

/// Represents an entire (composite) action.
///
/// This type implements [`Deref`] for [`action::Composite`], providing
/// access to the underlying data model.
pub(crate) struct Action {
    /// This action's unique key into zizmor's runtime registry.
    pub(crate) key: InputKey,
    pub(crate) document: yamlpath::Document,
    inner: action::Action,
}

impl AsRef<yamlpath::Document> for Action {
    fn as_ref(&self) -> &yamlpath::Document {
        &self.document
    }
}

impl Deref for Action {
    type Target = action::Action;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Debug for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{key}", key = self.key)
    }
}

impl Action {
    /// Load an action from the given file on disk.
    pub(crate) fn from_file<P: AsRef<Utf8Path>>(p: P) -> Result<Self> {
        let contents =
            std::fs::read_to_string(p.as_ref()).with_context(|| "couldn't read action file")?;
        let path = p.as_ref().canonicalize_utf8()?;

        Self::from_string(contents, InputKey::local(path)?)
    }

    /// Load a workflow from a buffer, with an assigned name.
    pub(crate) fn from_string(contents: String, key: InputKey) -> Result<Self> {
        let inner = serde_yaml::from_str(&contents)
            .with_context(|| format!("invalid GitHub Actions definition: {key}"))?;

        let document = yamlpath::Document::new(&contents)?;

        Ok(Self {
            key,
            document,
            inner,
        })
    }

    /// This actions's [`SymbolicLocation`].
    pub(crate) fn location(&self) -> SymbolicLocation {
        SymbolicLocation {
            key: &self.key,
            annotation: "this action".to_string(),
            link: None,
            route: Route::new(),
            primary: false,
        }
    }

    /// A [`CompositeSteps`] iterator over this workflow's constituent [`CompositeStep`]s.
    pub(crate) fn steps(&self) -> CompositeSteps<'_> {
        CompositeSteps::new(self)
    }
}

/// An iterable container for steps within a [`Job`].
pub(crate) struct CompositeSteps<'a> {
    inner: Enumerate<std::slice::Iter<'a, github_actions_models::action::Step>>,
    parent: &'a Action,
}

impl<'a> CompositeSteps<'a> {
    /// Create a new [`CompositeSteps`].
    ///
    /// Invariant: panics if the given [`Action`] is not a composite action.
    fn new(action: &'a Action) -> Self {
        match &action.inner.runs {
            action::Runs::Composite(composite) => Self {
                inner: composite.steps.iter().enumerate(),
                parent: action,
            },
            _ => panic!("API misuse: can't call steps() on a non-composite action"),
        }
    }
}

impl<'a> Iterator for CompositeSteps<'a> {
    type Item = CompositeStep<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let item = self.inner.next();

        match item {
            Some((idx, step)) => Some(CompositeStep::new(idx, step, self.parent)),
            None => None,
        }
    }
}

pub(crate) struct CompositeStep<'a> {
    /// The step's index within its parent job.
    pub(crate) index: usize,
    /// The inner step model.
    pub(crate) inner: &'a action::Step,
    /// The parent [`Action`].
    pub(crate) parent: &'a Action,
}

impl<'a> Deref for CompositeStep<'a> {
    type Target = &'a action::Step;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl StepCommon for CompositeStep<'_> {
    fn env_is_static(&self, name: &str) -> bool {
        let env = match &self.body {
            action::StepBody::Uses { .. } => {
                panic!("API misuse: can't call env_is_static on a uses: step")
            }
            action::StepBody::Run {
                run: _,
                working_directory: _,
                shell: _,
                env,
            } => env,
        };

        utils::env_is_static(name, &[env])
    }

    fn strategy(&self) -> Option<&Strategy> {
        None
    }
}

impl<'a> CompositeStep<'a> {
    pub(crate) fn new(index: usize, inner: &'a action::Step, parent: &'a Action) -> Self {
        Self {
            index,
            inner,
            parent,
        }
    }

    /// Returns a symbolic location for this [`Step`].
    pub(crate) fn location(&self) -> SymbolicLocation<'a> {
        self.parent.location().with_composite_step(self)
    }

    /// Like [`CompositeStep::location`], except with the step's `name`
    /// key as the final path component if present.
    pub(crate) fn location_with_name(&self) -> SymbolicLocation<'a> {
        match self.inner.body {
            action::StepBody::Run { .. } => self.location().with_keys(&["name".into()]),
            _ => self.location(),
        }
        .annotated("this step")
    }

    /// Returns this composite step's parent [`Action`].
    pub(crate) fn action(&self) -> &'a Action {
        self.parent
    }
}

#[cfg(test)]
mod tests {
    use super::{DockerUses, RepositoryUses, Uses};

    #[test]
    fn uses_from_step() {
        let vectors = [
            (
                // Valid: fully pinned.
                "actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3",
                Some(Uses::Repository(RepositoryUses {
                    owner: "actions",
                    repo: "checkout",
                    subpath: None,
                    git_ref: Some("8f4b7f84864484a7bf31766abe9204da3cbe65b3"),
                })),
            ),
            (
                // Valid: fully pinned, subpath
                "actions/aws/ec2@8f4b7f84864484a7bf31766abe9204da3cbe65b3",
                Some(Uses::Repository(RepositoryUses {
                    owner: "actions",
                    repo: "aws",
                    subpath: Some("ec2"),
                    git_ref: Some("8f4b7f84864484a7bf31766abe9204da3cbe65b3"),
                })),
            ),
            (
                // Valid: fully pinned, complex subpath
                "example/foo/bar/baz/quux@8f4b7f84864484a7bf31766abe9204da3cbe65b3",
                Some(Uses::Repository(RepositoryUses {
                    owner: "example",
                    repo: "foo",
                    subpath: Some("bar/baz/quux"),
                    git_ref: Some("8f4b7f84864484a7bf31766abe9204da3cbe65b3"),
                })),
            ),
            (
                // Valid: pinned with branch/tag
                "actions/checkout@v4",
                Some(Uses::Repository(RepositoryUses {
                    owner: "actions",
                    repo: "checkout",
                    subpath: None,
                    git_ref: Some("v4"),
                })),
            ),
            (
                "actions/checkout@abcd",
                Some(Uses::Repository(RepositoryUses {
                    owner: "actions",
                    repo: "checkout",
                    subpath: None,
                    git_ref: Some("abcd"),
                })),
            ),
            (
                // Valid: unpinned
                "actions/checkout",
                Some(Uses::Repository(RepositoryUses {
                    owner: "actions",
                    repo: "checkout",
                    subpath: None,
                    git_ref: None,
                })),
            ),
            (
                // Valid: Docker ref, implicit registry
                "docker://alpine:3.8",
                Some(Uses::Docker(DockerUses {
                    registry: None,
                    image: "alpine",
                    tag: Some("3.8"),
                    hash: None,
                })),
            ),
            (
                // Valid: Docker ref, localhost
                "docker://localhost/alpine:3.8",
                Some(Uses::Docker(DockerUses {
                    registry: Some("localhost"),
                    image: "alpine",
                    tag: Some("3.8"),
                    hash: None,
                })),
            ),
            (
                // Valid: Docker ref, localhost w/ port
                "docker://localhost:1337/alpine:3.8",
                Some(Uses::Docker(DockerUses {
                    registry: Some("localhost:1337"),
                    image: "alpine",
                    tag: Some("3.8"),
                    hash: None,
                })),
            ),
            (
                // Valid: Docker ref, custom registry
                "docker://ghcr.io/foo/alpine:3.8",
                Some(Uses::Docker(DockerUses {
                    registry: Some("ghcr.io"),
                    image: "foo/alpine",
                    tag: Some("3.8"),
                    hash: None,
                })),
            ),
            (
                // Valid: Docker ref, missing tag
                "docker://ghcr.io/foo/alpine",
                Some(Uses::Docker(DockerUses {
                    registry: Some("ghcr.io"),
                    image: "foo/alpine",
                    tag: None,
                    hash: None,
                })),
            ),
            (
                // Invalid, but allowed: Docker ref, empty tag
                "docker://ghcr.io/foo/alpine:",
                Some(Uses::Docker(DockerUses {
                    registry: Some("ghcr.io"),
                    image: "foo/alpine",
                    tag: None,
                    hash: None,
                })),
            ),
            (
                // Valid: Docker ref, bare
                "docker://alpine",
                Some(Uses::Docker(DockerUses {
                    registry: None,
                    image: "alpine",
                    tag: None,
                    hash: None,
                })),
            ),
            (
                // Valid: Docker ref, hash
                "docker://alpine@hash",
                Some(Uses::Docker(DockerUses {
                    registry: None,
                    image: "alpine",
                    tag: None,
                    hash: Some("hash"),
                })),
            ),
            // Invalid: missing user/repo
            ("checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3", None),
            // Invalid: local action refs not supported
            (
                "./.github/actions/hello-world-action@172239021f7ba04fe7327647b213799853a9eb89",
                None,
            ),
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
                Some(RepositoryUses {
                    owner: "octo-org",
                    repo: "this-repo",
                    subpath: Some(".github/workflows/workflow-1.yml"),
                    git_ref: Some("172239021f7ba04fe7327647b213799853a9eb89"),
                }),
            ),
            (
                "octo-org/this-repo/.github/workflows/workflow-1.yml@notahash",
                Some(RepositoryUses {
                    owner: "octo-org",
                    repo: "this-repo",
                    subpath: Some(".github/workflows/workflow-1.yml"),
                    git_ref: Some("notahash"),
                }),
            ),
            (
                "octo-org/this-repo/.github/workflows/workflow-1.yml@abcd",
                Some(RepositoryUses {
                    owner: "octo-org",
                    repo: "this-repo",
                    subpath: Some(".github/workflows/workflow-1.yml"),
                    git_ref: Some("abcd"),
                }),
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
            Uses::from_reusable("actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3")
                .unwrap()
                .ref_is_commit()
        );

        assert!(!Uses::from_reusable("actions/checkout@v4")
            .unwrap()
            .ref_is_commit());

        assert!(!Uses::from_reusable("actions/checkout@abcd")
            .unwrap()
            .ref_is_commit());
    }

    #[test]
    fn test_repositoryuses_matches() {
        for (uses, template, matches) in [
            // OK: `uses:` is more specific than template
            ("actions/checkout@v3", "actions/checkout", true),
            ("actions/checkout/foo@v3", "actions/checkout/foo", true),
            // OK: equally specific
            ("actions/checkout@v3", "actions/checkout@v3", true),
            ("actions/checkout", "actions/checkout", true),
            ("actions/checkout/foo", "actions/checkout/foo", true),
            ("actions/checkout/foo@v3", "actions/checkout/foo@v3", true),
            // NOT OK: owner/repo do not match
            ("actions/checkout@v3", "foo/checkout", false),
            ("actions/checkout@v3", "actions/bar", false),
            // NOT OK: subpath does not match
            ("actions/checkout/foo", "actions/checkout", false),
            ("actions/checkout/foo@v3", "actions/checkout@v3", false),
            // NOT OK: template is more specific than `uses:`
            ("actions/checkout", "actions/checkout@v3", false),
            ("actions/checkout/foo", "actions/checkout/foo@v3", false),
        ] {
            let Some(Uses::Repository(uses)) = Uses::from_common(uses) else {
                panic!();
            };

            assert_eq!(uses.matches(template), matches)
        }
    }
}
