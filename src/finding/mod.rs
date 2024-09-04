use anyhow::Result;
use locate::Locator;
use serde::Serialize;

use crate::models::{Job, Step, Workflow};

pub(crate) mod locate;

// TODO: Traits + more flexible models here.

#[derive(Default, Serialize)]
pub(crate) enum Confidence {
    #[default]
    Unknown,
    Low,
    Medium,
    High,
}

#[derive(Default, Serialize)]
pub(crate) enum Severity {
    #[default]
    Unknown,
    Informational,
    Low,
    Medium,
    High,
}

#[derive(Serialize, Clone)]
pub(crate) struct StepLocation<'w> {
    pub(crate) index: usize,
    pub(crate) id: Option<&'w str>,
    pub(crate) name: Option<&'w str>,
}

impl<'w> From<&Step<'w>> for StepLocation<'w> {
    fn from(step: &Step<'w>) -> Self {
        Self {
            index: step.index,
            id: step.inner.id.as_deref(),
            name: step.inner.name.as_deref(),
        }
    }
}

#[derive(Serialize, Clone)]
pub(crate) struct JobLocation<'w> {
    /// The job's unique ID within its parent workflow.
    pub(crate) id: &'w str,

    /// A non-step job-level key, like [`WorkflowLocation::key`].
    pub(crate) key: Option<&'w str>,

    /// The job's name, if present.
    pub(crate) name: Option<&'w str>,

    /// The location of a step within the job, if present.
    pub(crate) step: Option<StepLocation<'w>>,
}

impl<'w> JobLocation<'w> {
    /// Creates a new `JobLocation` with the given non-step `key`.
    ///
    /// Clears any `step` in the process.
    pub(crate) fn with_key(&self, key: &'w str) -> JobLocation<'w> {
        JobLocation {
            id: &self.id,
            key: Some(key),
            name: self.name,
            step: None,
        }
    }

    /// Creates a new `JobLocation` with the given interior step location.
    ///
    /// Clears any non-step `key` in the process.
    fn with_step(&self, step: &Step<'w>) -> JobLocation<'w> {
        JobLocation {
            id: self.id,
            key: None,
            name: self.name,
            step: Some(step.into()),
        }
    }
}

/// Represents a symbolic workflow location.
#[derive(Serialize, Clone)]
pub(crate) struct WorkflowLocation<'w> {
    pub(crate) name: &'w str,

    /// A top-level workflow key to isolate, if present.
    pub(crate) key: Option<&'w str>,

    /// The job location within this workflow, if present.
    pub(crate) job: Option<JobLocation<'w>>,

    /// An optional annotation for this location.
    pub(crate) annotation: Option<String>,
}

impl<'w> WorkflowLocation<'w> {
    /// Creates a new `WorkflowLocation` with the given `key`. Any inner
    /// job location is cleared.
    pub(crate) fn with_key(&self, key: &'w str) -> WorkflowLocation<'w> {
        WorkflowLocation {
            name: self.name,
            key: Some(key),
            job: None,
            annotation: self.annotation.clone(),
        }
    }

    /// Creates a new `WorkflowLocation` with the given `Job` added to it.
    pub(crate) fn with_job(&self, job: &Job<'w>) -> WorkflowLocation<'w> {
        WorkflowLocation {
            name: self.name,
            key: None,
            job: Some(JobLocation {
                id: job.id,
                key: None,
                name: job.inner.name(),
                step: None,
            }),
            annotation: self.annotation.clone(),
        }
    }

    /// Creates a new `WorkflowLocation` with the given `Step` added to it.
    ///
    /// This can only be called after the `WorkflowLocation` already has a job,
    /// since steps belong to jobs.
    pub(crate) fn with_step(&self, step: &Step<'w>) -> WorkflowLocation<'w> {
        match &self.job {
            None => panic!("API misuse: can't set step without parent job"),
            Some(job) => WorkflowLocation {
                name: self.name,
                key: None,
                job: Some(job.with_step(step)),
                annotation: self.annotation.clone(),
            },
        }
    }

    /// Concretize this `WorkflowLocation`, consuming it in the process.
    pub(crate) fn concretize(self, workflow: &'w Workflow) -> Result<Location<'w>> {
        let feature = Locator::new().concretize(workflow, &self)?;

        Ok(Location {
            symbolic: self,
            concrete: feature,
        })
    }

    /// Adds a human-readable annotation to the current `WorkflowLocation`.
    pub(crate) fn annotated(mut self, annotation: impl Into<String>) -> WorkflowLocation<'w> {
        self.annotation = Some(annotation.into());
        self
    }
}

/// Represents a `(row, column)` point within a file.
#[derive(Serialize)]
pub(crate) struct Point {
    pub(crate) row: usize,
    pub(crate) column: usize,
}

impl From<tree_sitter::Point> for Point {
    fn from(value: tree_sitter::Point) -> Self {
        Self {
            row: value.row,
            column: value.column,
        }
    }
}

/// A "concrete" location for some feature.
/// Every concrete location contains two spans: a line-and-column span,
/// and an offset range.
#[derive(Serialize)]
pub(crate) struct ConcreteLocation {
    pub(crate) start_point: Point,
    pub(crate) end_point: Point,
    pub(crate) start_offset: usize,
    pub(crate) end_offset: usize,
}

impl From<tree_sitter::Node<'_>> for ConcreteLocation {
    fn from(value: tree_sitter::Node) -> Self {
        Self {
            start_point: value.start_position().into(),
            end_point: value.end_position().into(),
            start_offset: value.start_byte(),
            end_offset: value.end_byte(),
        }
    }
}

/// An extracted feature, along with its concrete location.
#[derive(Serialize)]
pub(crate) struct Feature<'w> {
    /// The feature's concrete location, as both an offset range and point span.
    pub(crate) location: ConcreteLocation,
    /// The feature's textual content.
    pub(crate) feature: &'w str,
}

/// A location within a GitHub Actions workflow, with both symbolic and concrete components.
#[derive(Serialize)]
pub(crate) struct Location<'w> {
    /// The symbolic workflow location.
    pub(crate) symbolic: WorkflowLocation<'w>,
    /// The concrete location, including extracted feature.
    pub(crate) concrete: Feature<'w>,
}

/// A finding's "determination," i.e. its confidence and severity classifications.
#[derive(Serialize)]
pub(crate) struct Determinations {
    pub(crate) confidence: Confidence,
    pub(crate) severity: Severity,
}

#[derive(Serialize)]
pub(crate) struct Finding<'w> {
    pub(crate) ident: &'static str,
    pub(crate) determinations: Determinations,
    pub(crate) locations: Vec<Location<'w>>,
}

pub(crate) struct FindingBuilder<'w> {
    ident: &'static str,
    severity: Severity,
    confidence: Confidence,
    locations: Vec<WorkflowLocation<'w>>,
}

impl<'w> FindingBuilder<'w> {
    pub(crate) fn new(ident: &'static str) -> Self {
        Self {
            ident,
            severity: Default::default(),
            confidence: Default::default(),
            locations: vec![],
        }
    }

    pub(crate) fn severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    pub(crate) fn confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    pub(crate) fn add_location(mut self, location: WorkflowLocation<'w>) -> Self {
        self.locations.push(location);
        self
    }

    pub(crate) fn build(self, workflow: &'w Workflow) -> Result<Finding<'w>> {
        Ok(Finding {
            ident: self.ident,
            determinations: Determinations {
                confidence: self.confidence,
                severity: self.severity,
            },
            locations: self
                .locations
                .into_iter()
                .map(|l| l.concretize(workflow))
                .collect::<Result<Vec<_>>>()?,
        })
    }
}
