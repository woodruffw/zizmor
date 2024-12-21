use std::{io::stdout, process::ExitCode};

use annotate_snippets::{Level, Renderer};
use anstream::{eprintln, stream::IsTerminal};
use anyhow::{anyhow, Context, Result};
use audit::{Audit, AuditInput};
use camino::{Utf8Path, Utf8PathBuf};
use clap::{Parser, ValueEnum};
use clap_verbosity_flag::InfoLevel;
use config::Config;
use finding::{Confidence, Persona, Severity};
use indicatif::ProgressStyle;
use models::Uses;
use owo_colors::OwoColorize;
use registry::{AuditRegistry, FindingRegistry, InputRegistry};
use state::AuditState;
use tracing::{info_span, instrument, Span};
use tracing_indicatif::{span_ext::IndicatifSpanExt, IndicatifLayer};
use tracing_subscriber::{layer::SubscriberExt as _, util::SubscriberInitExt as _, EnvFilter};

mod audit;
mod config;
mod expr;
mod finding;
mod github_api;
mod models;
mod registry;
mod render;
mod sarif;
mod state;
mod utils;

/// Finds security issues in GitHub Actions setups.
#[derive(Parser)]
#[command(about, version)]
struct App {
    /// Emit 'pedantic' findings.
    ///
    /// This is an alias for --persona=pedantic.
    #[arg(short, long, group = "_persona")]
    pedantic: bool,

    /// The persona to use while auditing.
    #[arg(long, group = "_persona", value_enum, default_value_t)]
    persona: Persona,

    /// Perform only offline operations.
    ///
    /// This disables all online audit rules, and prevents zizmor from
    /// auditing remote repositories.
    #[arg(short, long, env = "ZIZMOR_OFFLINE", group = "_offline")]
    offline: bool,

    /// The GitHub API token to use.
    #[arg(long, env, group = "_offline")]
    gh_token: Option<String>,

    /// Perform only offline audits.
    ///
    /// This is a weaker version of `--offline`: instead of completely
    /// forbidding all online operations, it only disables audits that
    /// require connectivity.
    #[arg(long, env = "ZIZMOR_NO_ONLINE_AUDITS")]
    no_online_audits: bool,

    #[command(flatten)]
    verbose: clap_verbosity_flag::Verbosity<InfoLevel>,

    /// The output format to emit. By default, plain text will be emitted
    #[arg(long, value_enum, default_value_t)]
    format: OutputFormat,

    /// The configuration file to load. By default, any config will be
    /// discovered relative to $CWD.
    #[arg(short, long, group = "conf")]
    config: Option<Utf8PathBuf>,

    /// Disable all configuration loading.
    #[arg(long, group = "conf")]
    no_config: bool,

    /// Disable all error codes besides success and tool failure.
    #[arg(long)]
    no_exit_codes: bool,

    /// Filter all results below this severity.
    #[arg(long)]
    min_severity: Option<Severity>,

    /// Filter all results below this confidence.
    #[arg(long)]
    min_confidence: Option<Confidence>,

    /// The directory to use for HTTP caching. By default, a
    /// host-appropriate user-caching directory will be used.
    #[arg(long)]
    cache_dir: Option<Utf8PathBuf>,

    /// The inputs to audit.
    ///
    /// These can be individual workflow filenames, entire directories,
    /// or a `user/repo` slug for a GitHub repository. In the latter case,
    /// a `@ref` can be appended to audit the repository at a particular
    /// git reference state.
    #[arg(required = true)]
    inputs: Vec<String>,
}

#[derive(Debug, Default, Copy, Clone, ValueEnum)]
pub(crate) enum OutputFormat {
    #[default]
    Plain,
    Json,
    Sarif,
}

fn tip(err: impl AsRef<str>, tip: impl AsRef<str>) -> String {
    let message = Level::Error
        .title(err.as_ref())
        .footer(Level::Note.title(tip.as_ref()));

    let renderer = Renderer::styled();
    format!("{}", renderer.render(message))
}

#[instrument(skip_all)]
fn collect_inputs(inputs: &[String], state: &AuditState) -> Result<InputRegistry> {
    let mut workflow_registry = InputRegistry::new();

    for input in inputs {
        let input_path = Utf8Path::new(input);
        if input_path.is_file() {
            workflow_registry
                .register_by_path(input_path)
                .with_context(|| format!("failed to register workflow: {input_path}"))?;
        } else if input_path.is_dir() {
            let mut absolute = input_path.canonicalize_utf8()?;
            if !absolute.ends_with(".github/workflows") {
                absolute.push(".github/workflows")
            }

            for entry in absolute.read_dir_utf8()? {
                let entry = entry?;
                let workflow_path = entry.path();
                match workflow_path.extension() {
                    Some(ext) if ext == "yml" || ext == "yaml" => {
                        workflow_registry
                            .register_by_path(workflow_path)
                            .with_context(|| {
                                format!("failed to register workflow: {workflow_path}")
                            })?;
                    }
                    _ => continue,
                }
            }
        } else {
            // If this input isn't a file or directory, it's probably an
            // `owner/repo(@ref)?` slug.

            // Our pre-existing `uses: <slug>` parser does 90% of the work for us.
            let Some(Uses::Repository(slug)) = Uses::from_step(input) else {
                return Err(anyhow!(tip(
                    format!("invalid input: {input}"),
                    format!(
                        "pass a single {file}, {directory}, or entire repo by {slug} slug",
                        file = "file".green(),
                        directory = "directory".green(),
                        slug = "owner/repo".green()
                    )
                )));
            };

            // We don't expect subpaths here.
            if slug.subpath.is_some() {
                return Err(anyhow!(tip(
                    "invalid GitHub repository reference",
                    "pass owner/repo or owner/repo@ref"
                )));
            }

            let client = state.github_client().ok_or_else(|| {
                anyhow!(tip(
                    format!("can't retrieve repository: {input}", input = input.green()),
                    format!(
                        "try removing {offline} or passing {gh_token}",
                        offline = "--offline".yellow(),
                        gh_token = "--gh-token <TOKEN>".yellow(),
                    )
                ))
            })?;

            for workflow in client.fetch_workflows(&slug)? {
                workflow_registry.register_workflow(workflow)?;
            }
        }
    }

    if workflow_registry.len() == 0 {
        return Err(anyhow!("no workflow files collected"));
    }

    Ok(workflow_registry)
}

fn run() -> Result<ExitCode> {
    human_panic::setup_panic!();

    let mut app = App::parse();

    // `--pedantic` is a shortcut for `--persona=pedantic`.
    if app.pedantic {
        app.persona = Persona::Pedantic;
    }

    let indicatif_layer = IndicatifLayer::new();

    let filter = EnvFilter::builder()
        .with_default_directive(app.verbose.tracing_level_filter().into())
        .from_env()?;

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(std::io::stderr().is_terminal())
                .with_writer(indicatif_layer.get_stderr_writer()),
        )
        .with(filter)
        .with(indicatif_layer)
        .init();

    let audit_state = AuditState::new(&app);
    let workflow_registry = collect_inputs(&app.inputs, &audit_state)?;

    let config = Config::new(&app)?;

    let mut audit_registry = AuditRegistry::new();
    macro_rules! register_audit {
        ($rule:path) => {{
            use crate::audit::AuditCore as _;
            // HACK: https://github.com/rust-lang/rust/issues/48067
            use $rule as base;
            match base::new(audit_state.clone()) {
                Ok(audit) => audit_registry.register_workflow_audit(base::ident(), Box::new(audit)),
                Err(e) => tracing::warn!("skipping {audit}: {e}", audit = base::ident()),
            }
        }};
    }

    register_audit!(audit::artipacked::Artipacked);
    register_audit!(audit::excessive_permissions::ExcessivePermissions);
    register_audit!(audit::dangerous_triggers::DangerousTriggers);
    register_audit!(audit::impostor_commit::ImpostorCommit);
    register_audit!(audit::ref_confusion::RefConfusion);
    register_audit!(audit::use_trusted_publishing::UseTrustedPublishing);
    register_audit!(audit::template_injection::TemplateInjection);
    register_audit!(audit::hardcoded_container_credentials::HardcodedContainerCredentials);
    register_audit!(audit::self_hosted_runner::SelfHostedRunner);
    register_audit!(audit::known_vulnerable_actions::KnownVulnerableActions);
    register_audit!(audit::unpinned_uses::UnpinnedUses);
    register_audit!(audit::insecure_commands::InsecureCommands);
    register_audit!(audit::github_env::GitHubEnv);
    register_audit!(audit::cache_poisoning::CachePoisoning);

    let mut results = FindingRegistry::new(&app, &config);
    {
        // Note: block here so that we drop the span here at the right time.
        let span = info_span!("audit");
        span.pb_set_length((workflow_registry.len() * audit_registry.len()) as u64);
        span.pb_set_style(
            &ProgressStyle::with_template("[{elapsed_precise}] {bar:!30.cyan/blue} {msg}").unwrap(),
        );

        let _guard = span.enter();

        for (_, workflow) in workflow_registry.iter_workflows() {
            Span::current().pb_set_message(workflow.key.filename());
            for (name, audit) in audit_registry.iter_workflow_audits() {
                results.extend(
                    audit
                        .audit(AuditInput::Workflow(workflow))
                        .with_context(|| {
                            format!(
                                "{name} failed on {workflow}",
                                workflow = workflow.filename()
                            )
                        })?,
                );
                Span::current().pb_inc(1);
            }

            tracing::info!("🌈 completed {workflow}", workflow = workflow.key.path());
        }
    }

    match app.format {
        OutputFormat::Plain => render::render_findings(&workflow_registry, &results),
        OutputFormat::Json => serde_json::to_writer_pretty(stdout(), &results.findings())?,
        OutputFormat::Sarif => serde_json::to_writer_pretty(
            stdout(),
            &sarif::build(&workflow_registry, results.findings()),
        )?,
    };

    if app.no_exit_codes || matches!(app.format, OutputFormat::Sarif) {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(results.into())
    }
}

fn main() -> ExitCode {
    // This is a little silly, but returning an ExitCode like this ensures
    // we always exit cleanly, rather than performing a hard process exit.
    match run() {
        Ok(exit) => exit,
        Err(err) => {
            eprintln!("{err:?}");
            ExitCode::FAILURE
        }
    }
}
