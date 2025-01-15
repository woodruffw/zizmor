//! Enriching/context-bearing wrappers over GitHub Actions models
//! from the `github-actions-models` crate.

use crate::finding::{Route, SymbolicLocation};
use crate::registry::InputKey;
use crate::utils::{self, extract_expressions};
use anyhow::{bail, Context, Result};
use camino::Utf8Path;
use github_actions_models::common::expr::LoE;
use github_actions_models::common::Env;
use github_actions_models::workflow::event::{BareEvent, OptionalBody};
use github_actions_models::workflow::job::{RunsOn, Strategy};
use github_actions_models::workflow::{self, job, job::StepBody, Trigger};
use github_actions_models::{action, common};
use indexmap::IndexMap;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fmt::Debug;
use std::{iter::Enumerate, ops::Deref};
use terminal_link::Link;

pub(crate) mod coordinate;
pub(crate) mod uses;

/// Common fields between workflow and action step bodies.
pub(crate) enum StepBodyCommon<'s> {
    Uses {
        uses: &'s common::Uses,
        with: &'s Env,
    },
    Run {
        run: &'s str,
        _working_directory: Option<&'s str>,
        _shell: Option<&'s str>,
        _env: &'s LoE<Env>,
    },
}

/// Common interfaces between workflow and action steps.
pub(crate) trait StepCommon<'s> {
    /// Returns whether the given `env.name` environment access is "static,"
    /// i.e. is not influenced by another expression.
    fn env_is_static(&self, name: &str) -> bool;

    /// Returns this step's job's strategy, if present.
    ///
    /// Composite action steps have no strategy.
    fn strategy(&self) -> Option<&Strategy>;

    /// Returns a [`StepBodyCommon`] for this step.
    fn body(&self) -> StepBodyCommon;

    /// Returns a [`SymbolicLocation`] for this step.
    fn location(&self) -> SymbolicLocation<'s>;
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
                // NOTE: InputKey's Display produces a URL, hence `key.to_string()`.
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

/// Common behavior across both normal and reusable jobs.
pub(crate) trait JobExt<'w> {
    /// The job's unique ID (i.e., its key in the workflow's `jobs:` block).
    fn id(&self) -> &'w str;

    /// The job's symbolic location.
    fn location(&self) -> SymbolicLocation<'w>;

    /// The job's parent [`Workflow`].
    fn parent(&self) -> &'w Workflow;
}

/// Represents a single "normal" GitHub Actions job.
#[derive(Clone)]
pub(crate) struct NormalJob<'w> {
    /// The job's unique ID (i.e., its key in the workflow's `jobs:` block).
    pub(crate) id: &'w str,
    /// The underlying job.
    inner: &'w job::NormalJob,
    /// The job's parent [`Workflow`].
    parent: &'w Workflow,
}

impl<'w> NormalJob<'w> {
    pub(crate) fn new(id: &'w str, inner: &'w job::NormalJob, parent: &'w Workflow) -> Self {
        Self { id, inner, parent }
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
        match &self.runs_on {
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

impl<'w> JobExt<'w> for NormalJob<'w> {
    fn id(&self) -> &'w str {
        self.id
    }

    fn location(&self) -> SymbolicLocation<'w> {
        self.parent()
            .location()
            .annotated("this job")
            .with_job(self)
    }

    fn parent(&self) -> &'w Workflow {
        self.parent
    }
}

impl<'w> Deref for NormalJob<'w> {
    type Target = &'w job::NormalJob;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// Represents a reusable workflow call job.
#[derive(Clone)]
pub(crate) struct ReusableWorkflowCallJob<'w> {
    /// The job's unique ID (i.e., its key in the workflow's `jobs:` block).
    pub(crate) id: &'w str,
    /// The underlying job.
    inner: &'w job::ReusableWorkflowCallJob,
    /// The job's parent [`Workflow`].
    parent: &'w Workflow,
}

impl<'w> ReusableWorkflowCallJob<'w> {
    pub(crate) fn new(
        id: &'w str,
        inner: &'w job::ReusableWorkflowCallJob,
        parent: &'w Workflow,
    ) -> Self {
        Self { id, inner, parent }
    }
}

impl<'w> JobExt<'w> for ReusableWorkflowCallJob<'w> {
    fn id(&self) -> &'w str {
        self.id
    }

    fn location(&self) -> SymbolicLocation<'w> {
        self.parent()
            .location()
            .annotated("this job")
            .with_job(self)
    }

    fn parent(&self) -> &'w Workflow {
        self.parent
    }
}

impl<'w> Deref for ReusableWorkflowCallJob<'w> {
    type Target = &'w job::ReusableWorkflowCallJob;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// Represents a single GitHub Actions job.
#[derive(Clone)]
pub(crate) enum Job<'w> {
    NormalJob(NormalJob<'w>),
    ReusableWorkflowCallJob(ReusableWorkflowCallJob<'w>),
}

impl<'w> Job<'w> {
    fn new(id: &'w str, inner: &'w workflow::Job, parent: &'w Workflow) -> Self {
        match inner {
            workflow::Job::NormalJob(normal) => Job::NormalJob(NormalJob::new(id, normal, parent)),
            workflow::Job::ReusableWorkflowCallJob(reusable) => {
                Job::ReusableWorkflowCallJob(ReusableWorkflowCallJob::new(id, reusable, parent))
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

impl<'w> TryFrom<&'w NormalJob<'w>> for Matrix<'w> {
    type Error = anyhow::Error;

    fn try_from(job: &'w NormalJob<'w>) -> std::result::Result<Self, Self::Error> {
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
    pub(crate) parent: NormalJob<'w>,
}

impl<'w> Deref for Step<'w> {
    type Target = &'w workflow::job::Step;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'s> StepCommon<'s> for Step<'s> {
    fn env_is_static(&self, name: &str) -> bool {
        // Collect each of the step, job, and workflow-level `env` blocks
        // and check each.
        let mut envs = vec![];

        match &self.body {
            // `uses:` does not have an `env:` but its parent
            // job and workflow might, so we skip instead of failing.
            workflow::job::StepBody::Uses { .. } => (),
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

    fn body(&self) -> StepBodyCommon {
        match &self.body {
            StepBody::Uses { uses, with } => StepBodyCommon::Uses { uses, with },
            StepBody::Run {
                run,
                working_directory,
                shell,
                env,
            } => StepBodyCommon::Run {
                run,
                _working_directory: working_directory.as_deref(),
                _shell: shell.as_deref(),
                _env: env,
            },
        }
    }

    fn location(&self) -> SymbolicLocation<'s> {
        self.location()
    }
}

impl<'w> Step<'w> {
    fn new(index: usize, inner: &'w workflow::job::Step, parent: NormalJob<'w>) -> Self {
        Self {
            index,
            inner,
            parent,
        }
    }

    /// Returns this step's parent [`NormalJob`].
    pub(crate) fn job(&self) -> &'w NormalJob {
        &self.parent
    }

    /// Returns this step's (grand)parent [`Workflow`].
    pub(crate) fn workflow(&self) -> &'w Workflow {
        self.parent.parent()
    }

    /// Returns a [`common::Uses`] for this [`Step`], if it has one.
    pub(crate) fn uses(&self) -> Option<&common::Uses> {
        let StepBody::Uses { uses, .. } = &self.inner.body else {
            return None;
        };

        Some(uses)
    }

    /// Returns the the shell used by this step, or `None`
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
    parent: NormalJob<'w>,
}

impl<'w> Steps<'w> {
    /// Create a new [`Steps`].
    ///
    /// Invariant: panics if the given [`Job`] is a reusable job, rather than a "normal" job.
    fn new(job: &NormalJob<'w>) -> Self {
        Self {
            inner: job.steps.iter().enumerate(),
            parent: job.clone(),
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

/// Represents an entire (composite) action.
///
/// This type implements [`Deref`] for [`action::Action`], providing
/// access to the underlying data model.
pub(crate) struct Action {
    /// This action's unique key into zizmor's runtime registry.
    pub(crate) key: InputKey,
    pub(crate) link: Option<String>,
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
        let inner: action::Action = serde_yaml::from_str(&contents)
            .with_context(|| format!("invalid GitHub Actions definition: {key}"))?;

        let document = yamlpath::Document::new(&contents)?;

        let link = match key {
            InputKey::Local(_) => None,
            InputKey::Remote(_) => {
                // NOTE: InputKey's Display produces a URL, hence `key.to_string()`.
                Some(Link::new(key.path(), &key.to_string()).to_string())
            }
        };

        Ok(Self {
            key,
            link,
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

impl<'s> StepCommon<'s> for CompositeStep<'s> {
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

    fn body(&self) -> StepBodyCommon {
        match &self.body {
            action::StepBody::Uses { uses, with } => StepBodyCommon::Uses { uses, with },
            action::StepBody::Run {
                run,
                working_directory,
                shell,
                env,
            } => StepBodyCommon::Run {
                run,
                _working_directory: working_directory.as_deref(),
                _shell: Some(shell),
                _env: env,
            },
        }
    }

    fn location(&self) -> SymbolicLocation<'s> {
        self.location()
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
        match self.inner.name {
            Some(_) => self.location().with_keys(&["name".into()]),
            None => self.location(),
        }
        .annotated("this step")
    }

    /// Returns this composite step's parent [`Action`].
    pub(crate) fn action(&self) -> &'a Action {
        self.parent
    }

    /// Returns a [`common::Uses`] for this [`Step`], if it has one.
    pub(crate) fn uses(&self) -> Option<&common::Uses> {
        let action::StepBody::Uses { uses, .. } = &self.inner.body else {
            return None;
        };

        Some(uses)
    }
}
