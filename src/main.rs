use std::{io::stdout, path::PathBuf};

use anyhow::{anyhow, Result};
use audit::WorkflowAudit;
use clap::{Parser, ValueEnum};
use models::AuditConfig;

mod audit;
mod finding;
mod github_api;
mod models;
mod sarif;
mod utils;

/// A tool to detect "ArtiPACKED"-type credential disclosures in GitHub Actions.
#[derive(Parser)]
struct Args {
    /// Emit findings even when the context suggests an explicit security decision made by the user.
    #[arg(short, long)]
    pedantic: bool,

    /// Only perform audits that don't require network access.
    #[arg(short, long)]
    offline: bool,

    /// The GitHub API token to use.
    #[arg(long, env)]
    gh_token: String,

    /// The output format to emit. By default, plain text will be emitted
    /// on an interactive terminal and JSON otherwise.
    #[arg(long, value_enum)]
    format: Option<OutputFormat>,

    /// The workflow filename or directory to audit.
    input: PathBuf,
}

#[derive(Debug, Copy, Clone, ValueEnum)]
pub(crate) enum OutputFormat {
    Plain,
    Json,
    Sarif,
}

impl<'a> From<&'a Args> for AuditConfig<'a> {
    fn from(value: &'a Args) -> Self {
        Self {
            pedantic: value.pedantic,
            gh_token: &value.gh_token,
        }
    }
}

fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    let config = AuditConfig::from(&args);

    let mut workflow_paths = vec![];
    if args.input.is_file() {
        workflow_paths.push(args.input.clone());
    } else if args.input.is_dir() {
        let mut absolute = std::fs::canonicalize(&args.input)?;
        if !absolute.ends_with(".github/workflows") {
            absolute.push(".github/workflows")
        }

        log::debug!("collecting workflows from {absolute:?}");

        for entry in std::fs::read_dir(absolute)? {
            let workflow_path = entry?.path();
            match workflow_path.extension() {
                Some(ext) if ext == "yml" || ext == "yaml" => workflow_paths.push(workflow_path),
                _ => continue,
            }
        }

        if workflow_paths.is_empty() {
            return Err(anyhow!(
                "no workflow files collected; empty or wrong directory?"
            ));
        }
    } else {
        return Err(anyhow!("input must be a single workflow file or directory"));
    }

    let mut workflows = vec![];
    for workflow_path in workflow_paths.iter() {
        workflows.push(models::Workflow::from_file(workflow_path)?);
    }

    let mut results = vec![];
    let audits: &mut [&mut dyn WorkflowAudit] = &mut [
        &mut audit::artipacked::Artipacked::new(config)?,
        &mut audit::pull_request_target::PullRequestTarget::new(config)?,
        &mut audit::impostor_commit::ImpostorCommit::new(config)?,
        &mut audit::ref_confusion::RefConfusion::new(config)?,
        &mut audit::use_trusted_publishing::UseTrustedPublishing::new(config)?,
        &mut audit::template_injection::TemplateInjection::new(config)?,
        &mut audit::hardcoded_container_credentials::HardcodedContainerCredentials::new(config)?,
    ];
    for workflow in workflows.iter() {
        // TODO: Proper abstraction for multiple audits here.
        for audit in audits.iter_mut() {
            results.extend(audit.audit(workflow)?);
        }
    }

    match args.format {
        None | Some(OutputFormat::Json) | Some(OutputFormat::Plain) => {
            serde_json::to_writer_pretty(stdout(), &results)?;
        }
        Some(OutputFormat::Sarif) => {
            serde_json::to_writer_pretty(stdout(), &sarif::build(results))?;
        }
    }

    Ok(())
}
