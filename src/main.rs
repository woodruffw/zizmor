use std::{io::stdout, process::ExitCode, str::FromStr};

use annotate_snippets::{Level, Renderer};
use anstream::{eprintln, stream::IsTerminal};
use anyhow::{anyhow, Context, Result};
use audit::Audit;
use camino::{Utf8Path, Utf8PathBuf};
use clap::{Parser, ValueEnum};
use clap_verbosity_flag::InfoLevel;
use config::Config;
use finding::{Confidence, Persona, Severity};
use github_actions_models::common::Uses;
use github_api::GitHubHost;
use indicatif::ProgressStyle;
use models::Action;
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
    #[arg(short, long, env = "ZIZMOR_OFFLINE",
        conflicts_with_all = ["gh_token", "gh_hostname"])]
    offline: bool,

    /// The GitHub API token to use.
    #[arg(long, env)]
    gh_token: Option<String>,

    /// The GitHub Server Hostname. Defaults to github.com
    #[arg(long, env = "GH_HOST", default_value = "github.com", value_parser = GitHubHost::from_clap)]
    gh_hostname: GitHubHost,

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

    /// Control which kinds of inputs are collected for auditing.
    ///
    /// By default, all workflows and composite actions are collected.
    #[arg(long, value_enum, default_value_t)]
    collect: CollectionMode,

    /// The inputs to audit.
    ///
    /// These can be individual workflow filenames, action definitions
    /// (typically `action.yml`), entire directories, or a `user/repo` slug
    /// for a GitHub repository. In the latter case, a `@ref` can be appended
    /// to audit the repository at a particular git reference state.
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

/// How `zizmor` collects inputs from local and remote repository sources.
#[derive(Copy, Clone, Debug, Default, ValueEnum)]
pub(crate) enum CollectionMode {
    /// Collect all supported inputs.
    #[default]
    All,
    /// Collect only workflow definitions.
    WorkflowsOnly,
    /// Collect only action definitions (i.e. `action.yml`).
    ActionsOnly,
}

impl CollectionMode {
    pub(crate) fn workflows(&self) -> bool {
        matches!(self, CollectionMode::All | CollectionMode::WorkflowsOnly)
    }

    pub(crate) fn actions(&self) -> bool {
        matches!(self, CollectionMode::All | CollectionMode::ActionsOnly)
    }
}

fn tip(err: impl AsRef<str>, tip: impl AsRef<str>) -> String {
    let message = Level::Error
        .title(err.as_ref())
        .footer(Level::Note.title(tip.as_ref()));

    let renderer = Renderer::styled();
    format!("{}", renderer.render(message))
}

#[instrument(skip(mode, registry))]
fn collect_from_repo_dir(
    top_dir: &Utf8Path,
    current_dir: &Utf8Path,
    mode: &CollectionMode,
    registry: &mut InputRegistry,
) -> Result<()> {
    // The workflow directory might not exist if we're collecting from
    // a repository that only contains actions.
    if mode.workflows() {
        let workflow_dir = if current_dir.ends_with(".github/workflows") {
            current_dir.into()
        } else {
            current_dir.join(".github/workflows")
        };

        if workflow_dir.is_dir() {
            for entry in workflow_dir.read_dir_utf8()? {
                let entry = entry?;
                let input_path = entry.path();
                match input_path.extension() {
                    Some(ext) if ext == "yml" || ext == "yaml" => {
                        registry
                            .register_by_path(input_path, Some(top_dir))
                            .with_context(|| format!("failed to register input: {input_path}"))?;
                    }
                    _ => continue,
                }
            }
        } else {
            tracing::warn!("{workflow_dir} not found while collecting workflows")
        }
    }

    if mode.actions() {
        for entry in current_dir.read_dir_utf8()? {
            let entry = entry?;
            let entry_path = entry.path();

            if entry_path.is_file()
                && matches!(entry_path.file_name(), Some("action.yml" | "action.yaml"))
            {
                let action = Action::from_file(entry_path, Some(top_dir))?;
                registry.register_input(action.into())?;
            } else if entry_path.is_dir() && !entry_path.ends_with(".github/workflows") {
                // Recurse and limit the collection mode to only actions.
                collect_from_repo_dir(top_dir, entry_path, &CollectionMode::ActionsOnly, registry)?;
            }
        }
    }

    Ok(())
}

fn collect_from_repo_slug(
    input: &str,
    mode: &CollectionMode,
    state: &AuditState,
    registry: &mut InputRegistry,
) -> Result<()> {
    // Our pre-existing `uses: <slug>` parser does 90% of the work for us.
    let Ok(Uses::Repository(slug)) = Uses::from_str(input) else {
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

    if matches!(mode, CollectionMode::WorkflowsOnly) {
        // Performance: if we're *only* collecting workflows, then we
        // can save ourselves a full repo download and only fetch the
        // repo's workflow files.
        for workflow in client.fetch_workflows(&slug)? {
            registry.register_input(workflow.into())?;
        }
    } else {
        let inputs = client.fetch_audit_inputs(&slug).with_context(|| {
            tip(
                format!(
                    "couldn't collect inputs from https://github.com/{owner}/{repo}",
                    owner = slug.owner,
                    repo = slug.repo
                ),
                "confirm the repository exists and that you have access to it",
            )
        })?;

        tracing::info!(
            "collected {len} inputs from {owner}/{repo}",
            len = inputs.len(),
            owner = slug.owner,
            repo = slug.repo
        );

        for input in inputs {
            registry.register_input(input)?;
        }
    }

    Ok(())
}

#[instrument(skip_all)]
fn collect_inputs(
    inputs: &[String],
    mode: &CollectionMode,
    state: &AuditState,
) -> Result<InputRegistry> {
    let mut registry = InputRegistry::new();

    for input in inputs {
        let input_path = Utf8Path::new(input);
        if input_path.is_file() {
            // When collecting individual files, we don't know which part
            // of the input path is the prefix.
            registry
                .register_by_path(input_path, None)
                .with_context(|| format!("failed to register input: {input_path}"))?;
        } else if input_path.is_dir() {
            collect_from_repo_dir(input_path, input_path, mode, &mut registry)?;
        } else {
            // If this input isn't a file or directory, it's probably an
            // `owner/repo(@ref)?` slug.
            collect_from_repo_slug(input, mode, state, &mut registry)?;
        }
    }

    if registry.len() == 0 {
        return Err(anyhow!("no inputs collected"));
    }

    Ok(registry)
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
    let registry = collect_inputs(&app.inputs, &app.collect, &audit_state)?;

    let config = Config::new(&app)?;

    let mut audit_registry = AuditRegistry::new();
    macro_rules! register_audit {
        ($rule:path) => {{
            // HACK: https://github.com/rust-lang/rust/issues/48067
            use $rule as base;

            use crate::audit::AuditCore as _;
            match base::new(audit_state.clone()) {
                Ok(audit) => audit_registry.register_audit(base::ident(), Box::new(audit)),
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
    register_audit!(audit::secrets_inherit::SecretsInherit);
    register_audit!(audit::bot_conditions::BotConditions);

    let mut results = FindingRegistry::new(&app, &config);
    {
        // Note: block here so that we drop the span here at the right time.
        let span = info_span!("audit");
        span.pb_set_length((registry.len() * audit_registry.len()) as u64);
        span.pb_set_style(
            &ProgressStyle::with_template("[{elapsed_precise}] {bar:!30.cyan/blue} {msg}").unwrap(),
        );

        let _guard = span.enter();

        for (_, input) in registry.iter_inputs() {
            Span::current().pb_set_message(input.key().filename());
            for (name, audit) in audit_registry.iter_audits() {
                results.extend(audit.audit(input).with_context(|| {
                    format!("{name} failed on {input}", input = input.key().filename())
                })?);
                Span::current().pb_inc(1);
            }
            tracing::info!(
                "🌈 completed {input}",
                input = input.key().best_effort_relative_path()
            );
        }
    }

    match app.format {
        OutputFormat::Plain => render::render_findings(&registry, &results),
        OutputFormat::Json => serde_json::to_writer_pretty(stdout(), &results.findings())?,
        OutputFormat::Sarif => {
            serde_json::to_writer_pretty(stdout(), &sarif::build(results.findings()))?
        }
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
