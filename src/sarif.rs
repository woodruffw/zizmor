//! APIs for rendering SARIF outputs.

use std::collections::HashSet;

use serde_sarif::sarif::{
    ArtifactContent, ArtifactLocation, Location as SarifLocation, LogicalLocation, Message,
    PhysicalLocation, PropertyBag, Region, ReportingDescriptor, Result as SarifResult, ResultKind,
    ResultLevel, Run, Sarif, Tool, ToolComponent,
};

use crate::{
    finding::{Finding, Location, Severity},
    registry::InputRegistry,
};

impl From<Severity> for ResultKind {
    fn from(value: Severity) -> Self {
        // TODO: Does this mapping make sense?
        match value {
            Severity::Unknown => ResultKind::Review,
            Severity::Informational => ResultKind::Review,
            Severity::Low => ResultKind::Fail,
            Severity::Medium => ResultKind::Fail,
            Severity::High => ResultKind::Fail,
        }
    }
}

impl From<Severity> for ResultLevel {
    fn from(value: Severity) -> Self {
        // TODO: Does this mapping make sense?
        match value {
            Severity::Unknown => ResultLevel::None,
            Severity::Informational => ResultLevel::Note,
            Severity::Low => ResultLevel::Warning,
            Severity::Medium => ResultLevel::Warning,
            Severity::High => ResultLevel::Error,
        }
    }
}

pub(crate) fn build(registry: &InputRegistry, findings: &[Finding]) -> Sarif {
    Sarif::builder()
        .version("2.1.0")
        .schema("https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json")
        .runs([build_run(registry, findings)])
        .build()
}

fn build_run(registry: &InputRegistry, findings: &[Finding]) -> Run {
    Run::builder()
        .tool(
            Tool::builder()
                .driver(
                    ToolComponent::builder()
                        .name(env!("CARGO_CRATE_NAME"))
                        .version(env!("CARGO_PKG_VERSION"))
                        .semantic_version(env!("CARGO_PKG_VERSION"))
                        .download_uri(env!("CARGO_PKG_REPOSITORY"))
                        .information_uri(env!("CARGO_PKG_HOMEPAGE"))
                        .rules(build_rules(findings))
                        .build(),
                )
                .build(),
        )
        .results(build_results(registry, findings))
        .build()
}

fn build_rules(findings: &[Finding]) -> Vec<ReportingDescriptor> {
    // use the set to filter out duplicate rules
    let mut unique_rules = HashSet::new();
    findings
        .iter()
        .filter(|finding| unique_rules.insert(finding.ident))
        .map(|finding| build_rule(finding))
        .collect()
}

fn build_rule(finding: &Finding) -> ReportingDescriptor {
    ReportingDescriptor::builder()
        .id(finding.ident)
        .help_uri(finding.url)
        .build()
}

fn build_results(registry: &InputRegistry, findings: &[Finding]) -> Vec<SarifResult> {
    findings.iter().map(|f| build_result(registry, f)).collect()
}

fn build_result(registry: &InputRegistry, finding: &Finding<'_>) -> SarifResult {
    SarifResult::builder()
        .message(finding.desc)
        .rule_id(finding.ident)
        .locations(build_locations(
            registry,
            finding.locations.iter().filter(|l| l.symbolic.primary),
        ))
        .related_locations(build_locations(
            registry,
            finding.locations.iter().filter(|l| !l.symbolic.primary),
        ))
        // TODO: https://github.com/psastras/sarif-rs/pull/770
        .level(
            serde_json::to_value(ResultLevel::from(finding.determinations.severity))
                .expect("failed to serialize SARIF result level"),
        )
        .kind(
            serde_json::to_value(ResultKind::from(finding.determinations.severity))
                .expect("failed to serialize SARIF result kind"),
        )
        .build()
}

fn build_locations<'a>(
    registry: &InputRegistry,
    locations: impl Iterator<Item = &'a Location<'a>>,
) -> Vec<SarifLocation> {
    locations
        .map(|location| {
            SarifLocation::builder()
                .logical_locations([LogicalLocation::builder()
                    .properties(
                        PropertyBag::builder()
                            .additional_properties([(
                                "symbolic".into(),
                                serde_json::value::to_value(location.symbolic.clone()).unwrap(),
                            )])
                            .build(),
                    )
                    .build()])
                .physical_location(
                    PhysicalLocation::builder()
                        .artifact_location(
                            ArtifactLocation::builder()
                                .uri_base_id("%SRCROOT%")
                                .uri(registry.get_workflow_relative_path(location.symbolic.key))
                                .build(),
                        )
                        .region(
                            Region::builder()
                                // NOTE: SARIF lines/columns are 1-based.
                                .start_line((location.concrete.location.start_point.row as i64) + 1)
                                .end_line((location.concrete.location.end_point.row as i64) + 1)
                                .start_column(
                                    (location.concrete.location.start_point.column as i64) + 1,
                                )
                                .end_column(
                                    (location.concrete.location.end_point.column as i64) + 1,
                                )
                                .source_language("yaml")
                                .snippet(
                                    ArtifactContent::builder()
                                        .text(location.concrete.feature)
                                        .build(),
                                )
                                .build(),
                        )
                        .build(),
                )
                .message(
                    Message::builder()
                        .text(&location.symbolic.annotation)
                        .build(),
                )
                .build()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_sarif::sarif::ResultKind;

    use crate::finding::Severity;

    #[test]
    fn test_resultkind_from_severity() {
        assert_eq!(
            serde_json::to_string(&ResultKind::from(Severity::High)).unwrap(),
            "\"fail\""
        );
    }
}
