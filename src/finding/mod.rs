//! Models and APIs for handling findings and their locations.

use std::{borrow::Cow, sync::LazyLock};

use anyhow::{anyhow, Result};
use clap::ValueEnum;
use locate::Locator;
use regex::Regex;
use serde::Serialize;
use terminal_link::Link;

use crate::{
    models::{CompositeStep, Job, Step},
    registry::InputKey,
};

pub(crate) mod locate;

/// Represents the expected "persona" that would be interested in a given
/// finding. This is used to model the sensitivity of different use-cases
/// to false positives.
#[derive(
    Copy, Clone, Debug, Default, Eq, Hash, Ord, PartialOrd, PartialEq, Serialize, ValueEnum,
)]
pub(crate) enum Persona {
    /// The "auditor" persona (false positives OK).
    ///
    /// This persona wants all results, including results that are likely
    /// to be false positives.
    Auditor,

    /// The "pedantic" persona (code smells OK).
    ///
    /// This persona wants findings that may or may not be problems,
    /// but are potential "code smells".
    Pedantic,

    /// The "regular" persona (minimal false positives).
    ///
    /// This persona wants actionable findings, and is sensitive to
    /// false positives.
    #[default]
    Regular,
}

#[derive(
    Copy, Clone, Debug, Default, Eq, Hash, Ord, PartialOrd, PartialEq, Serialize, ValueEnum,
)]
pub(crate) enum Confidence {
    #[default]
    Unknown,
    Low,
    Medium,
    High,
}

#[derive(
    Copy, Clone, Debug, Default, Eq, Hash, Ord, PartialOrd, PartialEq, Serialize, ValueEnum,
)]
pub(crate) enum Severity {
    #[default]
    Unknown,
    Informational,
    Low,
    Medium,
    High,
}

#[derive(Serialize, Clone, Debug)]
pub(crate) struct StepLocation<'w> {
    pub(crate) index: usize,
    pub(crate) id: Option<&'w str>,
    pub(crate) name: Option<&'w str>,
}

impl<'w> From<&Step<'w>> for StepLocation<'w> {
    fn from(step: &Step<'w>) -> Self {
        Self {
            index: step.index,
            id: step.id.as_deref(),
            name: step.name.as_deref(),
        }
    }
}

#[derive(Serialize, Clone, Debug)]
pub(crate) enum RouteComponent<'w> {
    Key(Cow<'w, str>),
    Index(usize),
}

impl From<usize> for RouteComponent<'_> {
    fn from(value: usize) -> Self {
        Self::Index(value)
    }
}

impl<'w> From<&'w str> for RouteComponent<'w> {
    fn from(value: &'w str) -> Self {
        Self::Key(Cow::Borrowed(value))
    }
}

#[derive(Serialize, Clone, Debug)]
pub(crate) struct Route<'w> {
    components: Vec<RouteComponent<'w>>,
}

impl<'w> Route<'w> {
    pub(crate) fn new() -> Route<'w> {
        Self {
            components: Default::default(),
        }
    }

    fn with_keys(&self, keys: &[RouteComponent<'w>]) -> Route<'w> {
        let mut components = self.components.clone();
        components.extend(keys.iter().cloned());
        Route { components }
    }
}

/// Represents a symbolic workflow location.
#[derive(Serialize, Clone, Debug)]
pub(crate) struct SymbolicLocation<'w> {
    /// The unique ID of the workflow, as it appears in the workflow registry.
    pub(crate) key: &'w InputKey,

    /// An annotation for this location.
    pub(crate) annotation: String,

    /// An OSC 8 rendered link for the location's annotation, if applicable.
    ///
    /// Not serialized, since it contains ANSI escape codes.
    #[serde(skip_serializing)]
    pub(crate) link: Option<String>,

    /// A symbolic route (of keys and indices) to the final location.
    pub(crate) route: Route<'w>,

    /// Whether this location is subjectively "primary" to a finding,
    /// or merely a "supporting" location.
    ///
    /// This distinction only matters in output formats like SARIF,
    /// where locations are split between locations and "related" locations.
    pub(crate) primary: bool,
}

impl<'w> SymbolicLocation<'w> {
    pub(crate) fn with_keys(&self, keys: &[RouteComponent<'w>]) -> SymbolicLocation<'w> {
        SymbolicLocation {
            key: self.key,
            annotation: self.annotation.clone(),
            link: None,
            route: self.route.with_keys(keys),
            primary: self.primary,
        }
    }

    pub(crate) fn with_job(&self, job: &Job<'w>) -> SymbolicLocation<'w> {
        self.with_keys(&["jobs".into(), job.id.into()])
    }

    pub(crate) fn with_step(&self, step: &Step<'w>) -> SymbolicLocation<'w> {
        self.with_keys(&["steps".into(), step.index.into()])
    }

    pub(crate) fn with_composite_step(&self, step: &CompositeStep<'w>) -> SymbolicLocation<'w> {
        self.with_keys(&["runs".into(), "steps".into(), step.index.into()])
    }

    /// Adds a human-readable annotation to the current `SymbolicLocation`.
    pub(crate) fn annotated(mut self, annotation: impl Into<String>) -> SymbolicLocation<'w> {
        self.annotation = annotation.into();
        self
    }

    /// Adds a URL to the current `SymbolicLocation`.
    pub(crate) fn with_url(mut self, url: impl Into<String>) -> SymbolicLocation<'w> {
        self.link = Some(Link::new(&self.annotation, &url.into()).to_string());
        self
    }

    /// Mark the current `SymbolicLocation` as a "primary" location.
    pub(crate) fn primary(mut self) -> SymbolicLocation<'w> {
        self.primary = true;
        self
    }

    /// Concretize this `SymbolicLocation`, consuming it in the process.
    pub(crate) fn concretize(
        self,
        document: &'w impl AsRef<yamlpath::Document>,
    ) -> Result<Location<'w>> {
        let feature = Locator::new().concretize(document, &self)?;

        Ok(Location {
            symbolic: self,
            concrete: feature,
        })
    }
}

/// Represents a `(row, column)` point within a file.
#[derive(Serialize)]
pub(crate) struct Point {
    pub(crate) row: usize,
    pub(crate) column: usize,
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

impl From<&yamlpath::Location> for ConcreteLocation {
    fn from(value: &yamlpath::Location) -> Self {
        Self {
            start_point: Point {
                row: value.point_span.0 .0,
                column: value.point_span.0 .1,
            },
            end_point: Point {
                row: value.point_span.1 .0,
                column: value.point_span.1 .1,
            },
            start_offset: value.byte_span.0,
            end_offset: value.byte_span.1,
        }
    }
}

static IGNORE_EXPR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^# zizmor: ignore\[(.+)\]\s*$").unwrap());

/// Represents a single source comment.
#[derive(Serialize)]
#[serde(transparent)]
pub(crate) struct Comment<'w>(&'w str);

impl Comment<'_> {
    fn ignores(&self, rule_id: &str) -> bool {
        // Extracts foo,bar from `# zizmor: ignore[foo,bar]`
        let Some(caps) = IGNORE_EXPR.captures(self.0) else {
            return false;
        };

        caps.get(1)
            .unwrap()
            .as_str()
            .split(",")
            .any(|r| r.trim() == rule_id)
    }
}

/// An extracted feature, along with its concrete location.
#[derive(Serialize)]
pub(crate) struct Feature<'w> {
    /// The feature's concrete location, as both an offset range and point span.
    pub(crate) location: ConcreteLocation,

    /// The feature's concrete parent location.
    /// This can be the same as the feature's own location, if the feature
    /// is the document root.
    pub(crate) parent_location: ConcreteLocation,

    /// The feature's textual content.
    pub(crate) feature: &'w str,

    /// Any comments within the feature's span.
    pub(crate) comments: Vec<Comment<'w>>,

    /// The feature's parent's textual content.
    pub(crate) parent_feature: &'w str,
}

/// A location within a GitHub Actions workflow, with both symbolic and concrete components.
#[derive(Serialize)]
pub(crate) struct Location<'w> {
    /// The symbolic workflow location.
    pub(crate) symbolic: SymbolicLocation<'w>,
    /// The concrete location, including extracted feature.
    pub(crate) concrete: Feature<'w>,
}

/// A finding's "determination," i.e. its various classifications.
#[derive(Serialize)]
pub(crate) struct Determinations {
    pub(crate) confidence: Confidence,
    pub(crate) severity: Severity,
    pub(super) persona: Persona,
}

#[derive(Serialize)]
pub(crate) struct Finding<'w> {
    pub(crate) ident: &'static str,
    pub(crate) desc: &'static str,
    pub(crate) url: &'static str,
    pub(crate) determinations: Determinations,
    pub(crate) locations: Vec<Location<'w>>,
    pub(crate) ignored: bool,
}

pub(crate) struct FindingBuilder<'w> {
    ident: &'static str,
    desc: &'static str,
    url: &'static str,
    severity: Severity,
    confidence: Confidence,
    persona: Persona,
    locations: Vec<SymbolicLocation<'w>>,
}

impl<'w> FindingBuilder<'w> {
    pub(crate) fn new(ident: &'static str, desc: &'static str, url: &'static str) -> Self {
        Self {
            ident,
            desc,
            url,
            severity: Default::default(),
            confidence: Default::default(),
            persona: Default::default(),
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

    pub(crate) fn persona(mut self, persona: Persona) -> Self {
        self.persona = persona;
        self
    }

    pub(crate) fn add_location(mut self, location: SymbolicLocation<'w>) -> Self {
        self.locations.push(location);
        self
    }

    pub(crate) fn build(self, document: &'w impl AsRef<yamlpath::Document>) -> Result<Finding<'w>> {
        let locations = self
            .locations
            .iter()
            .map(|l| l.clone().concretize(document))
            .collect::<Result<Vec<_>>>()?;

        if !locations.iter().any(|l| l.symbolic.primary) {
            return Err(anyhow!(
                "API misuse: at least one location must be marked with primary()"
            ));
        }

        let should_ignore = self.ignored_from_inlined_comment(&locations, self.ident);

        Ok(Finding {
            ident: self.ident,
            desc: self.desc,
            url: self.url,
            determinations: Determinations {
                confidence: self.confidence,
                severity: self.severity,
                persona: self.persona,
            },
            locations,
            ignored: should_ignore,
        })
    }

    fn ignored_from_inlined_comment(&self, locations: &[Location], id: &str) -> bool {
        locations
            .iter()
            .flat_map(|l| &l.concrete.comments)
            .any(|c| c.ignores(id))
    }
}

#[cfg(test)]
mod tests {
    use crate::finding::Comment;

    #[test]
    fn test_comment_ignores() {
        let cases = &[
            // Trivial cases.
            ("# zizmor: ignore[foo]", "foo", true),
            ("# zizmor: ignore[foo,bar]", "foo", true),
            // Dashes are OK.
            ("# zizmor: ignore[foo,bar,foo-bar]", "foo-bar", true),
            // Spaces are OK.
            ("# zizmor: ignore[foo, bar,   foo-bar]", "foo-bar", true),
            // Extra commas and duplicates are nonsense but OK.
            ("# zizmor: ignore[foo,foo,,foo,,,,foo,]", "foo", true),
            // Valid ignore, but not a match.
            ("# zizmor: ignore[foo,bar]", "baz", false),
            // Invalid ignore: empty rule list.
            ("# zizmor: ignore[]", "", false),
            ("# zizmor: ignore[]", "foo", false),
            // Invalid ignore: no commas.
            ("# zizmor: ignore[foo bar]", "foo", false),
            // Invalid ignore: missing opening and/or closing [].
            ("# zizmor: ignore[foo", "foo", false),
            ("# zizmor: ignore foo", "foo", false),
            ("# zizmor: ignore foo]", "foo", false),
            // Invalid ignore: space after # and : is mandatory and fixed.
            ("# zizmor:ignore[foo]", "foo", false),
            ("#zizmor: ignore[foo]", "foo", false),
            ("#  zizmor: ignore[foo]", "foo", false),
            ("#  zizmor:  ignore[foo]", "foo", false),
        ];

        for (comment, rule, ignores) in cases {
            assert_eq!(
                Comment(comment).ignores(rule),
                *ignores,
                "{comment} does not ignore {rule}"
            )
        }
    }
}
