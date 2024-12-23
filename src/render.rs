//! APIs for rendering zizmor's "plain" (i.e. terminal) output format.

use std::collections::{hash_map::Entry, HashMap};

use crate::{
    finding::{Finding, Location, Severity},
    registry::{FindingRegistry, InputKey, InputRegistry},
};
use annotate_snippets::{Level, Renderer, Snippet};
use anstream::{print, println};
use owo_colors::OwoColorize;
use terminal_link::Link;

impl From<&Severity> for Level {
    fn from(sev: &Severity) -> Self {
        match sev {
            Severity::Unknown => Level::Note,
            Severity::Informational => Level::Info,
            Severity::Low => Level::Help,
            Severity::Medium => Level::Warning,
            Severity::High => Level::Error,
        }
    }
}

pub(crate) fn finding_snippet<'w>(
    registry: &'w InputRegistry,
    finding: &'w Finding<'w>,
) -> Vec<Snippet<'w>> {
    // Our finding might span multiple workflows, so we need to group locations
    // by their enclosing workflow to generate each snippet correctly.
    let mut locations_by_workflow: HashMap<&InputKey, Vec<&Location<'w>>> = HashMap::new();
    for location in &finding.locations {
        match locations_by_workflow.entry(location.symbolic.key) {
            Entry::Occupied(mut e) => {
                e.get_mut().push(location);
            }
            Entry::Vacant(e) => {
                e.insert(vec![location]);
            }
        }
    }

    let mut snippets = vec![];
    for (input_key, locations) in locations_by_workflow {
        let input = registry.get_input(input_key);

        snippets.push(
            Snippet::source(input.document().source())
                .fold(true)
                .line_start(1)
                .origin(input.link().unwrap_or(input_key.path()))
                .annotations(locations.iter().map(|loc| {
                    let annotation = match loc.symbolic.link {
                        Some(ref link) => link,
                        None => &loc.symbolic.annotation,
                    };

                    Level::from(&finding.determinations.severity)
                        .span(loc.concrete.location.start_offset..loc.concrete.location.end_offset)
                        .label(annotation)
                })),
        );
    }

    snippets
}

pub(crate) fn render_findings(registry: &InputRegistry, findings: &FindingRegistry) {
    for finding in findings.findings() {
        render_finding(registry, finding);
        println!();
    }

    let mut qualifiers = vec![];
    if !findings.ignored().is_empty() {
        qualifiers.push(format!(
            "{nignored} ignored",
            nignored = findings.ignored().len().bright_yellow()
        ));
    }
    if !findings.suppressed().is_empty() {
        qualifiers.push(format!(
            "{nsuppressed} suppressed",
            nsuppressed = findings.suppressed().len().bright_yellow()
        ));
    }

    if findings.findings().is_empty() {
        if qualifiers.is_empty() {
            println!("{}", "No findings to report. Good job!".green());
        } else {
            println!(
                "{no_findings} ({qualifiers})",
                no_findings = "No findings to report. Good job!".green(),
                qualifiers = qualifiers.join(", ").bold(),
            );
        }
    } else {
        let mut findings_by_severity = HashMap::new();

        for finding in findings.findings() {
            match findings_by_severity.entry(&finding.determinations.severity) {
                Entry::Occupied(mut e) => {
                    *e.get_mut() += 1;
                }
                Entry::Vacant(e) => {
                    e.insert(1);
                }
            }
        }

        if qualifiers.is_empty() {
            let nfindings = findings.count();
            print!(
                "{nfindings} finding{s}: ",
                nfindings = nfindings.green(),
                s = if nfindings == 1 { "" } else { "s" },
            );
        } else {
            print!(
                "{nfindings} findings ({qualifiers}): ",
                nfindings = findings.count().green(),
                qualifiers = qualifiers.join(", ").bold(),
            );
        }

        println!(
            "{nunknown} unknown, {ninformational} informational, {nlow} low, {nmedium} medium, {nhigh} high",
            nunknown = findings_by_severity.get(&Severity::Unknown).unwrap_or(&0),
            ninformational = findings_by_severity.get(&Severity::Informational).unwrap_or(&0).purple(),
            nlow = findings_by_severity.get(&Severity::Low).unwrap_or(&0).cyan(),
            nmedium = findings_by_severity.get(&Severity::Medium).unwrap_or(&0).yellow(),
            nhigh = findings_by_severity.get(&Severity::High).unwrap_or(&0).red(),
        );
    }
}

fn render_finding(registry: &InputRegistry, finding: &Finding) {
    let link = Link::new(finding.ident, finding.url).to_string();
    let confidence = format!(
        "audit confidence → {:?}",
        &finding.determinations.confidence
    );
    let confidence_footer = Level::Note.title(&confidence);

    let message = Level::from(&finding.determinations.severity)
        .title(finding.desc)
        .id(&link)
        .snippets(finding_snippet(registry, finding))
        .footer(confidence_footer);

    let renderer = Renderer::styled();
    println!("{}", renderer.render(message));
}
