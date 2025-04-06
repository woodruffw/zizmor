use std::{
    io::{Write, stdout},
    process::ExitCode,
    str::FromStr,
};

use annotate_snippets::{Level, Renderer};
use anstream::{eprintln, stream::IsTerminal};
use anyhow::{Context, Result, anyhow};
use camino::{Utf8Path, Utf8PathBuf};
use clap::{Parser, ValueEnum};
use clap_verbosity_flag::InfoLevel;
use config::Config;
use finding::{Confidence, Persona, Severity};
use github_actions_models::common::Uses;
use github_api::GitHubHost;
use ignore::WalkBuilder;
use indicatif::ProgressStyle;
use models::Action;
use owo_colors::OwoColorize;
use registry::{AuditRegistry, FindingRegistry, InputRegistry};
use state::AuditState;
use tracing::{Span, info_span, instrument};
use tracing_indicatif::{IndicatifLayer, span_ext::IndicatifSpanExt};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt as _, util::SubscriberInitExt as _};

mod audit;
mod config;
mod expr;
mod finding;
mod github_api;
#[cfg(feature = "lsp")]
mod lsp;
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
    /// Run in language server mode.
    ///
    /// This flag cannot be used with any other flags.
    #[cfg(feature = "lsp")]
    #[arg(long, exclusive = true)]
    lsp: bool,

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
    #[arg(short, long, env = "ZIZMOR_OFFLINE")]
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

    /// Don't show progress bars, even if the terminal supports them.
    #[arg(long)]
    no_progress: bool,

    /// The output format to emit. By default, plain text will be emitted
    #[arg(long, value_enum, default_value_t)]
    format: OutputFormat,

    /// Control the use of color in output.
    #[arg(long, value_enum, value_name = "MODE")]
    color: Option<ColorMode>,

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

    /// Enable naches mode.
    #[arg(long, hide = true, env = "ZIZMOR_NACHES")]
    naches: bool,

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

#[derive(Debug, Copy, Clone, ValueEnum)]
pub(crate) enum ColorMode {
    /// Use color output if the output supports it.
    Auto,
    /// Force color output, even if the output isn't a terminal.
    Always,
    /// Disable color output, even if the output is a compatible terminal.
    Never,
}

impl ColorMode {
    /// Returns a concrete (i.e. non-auto) `anstream::ColorChoice` for the given terminal.
    ///
    /// This is useful for passing to `anstream::AutoStream` when the underlying
    /// stream is something that is a terminal or should be treated as such,
    /// but can't be inferred due to type erasure (e.g. `Box<dyn Write>`).
    fn color_choice_for_terminal(&self, io: impl IsTerminal) -> anstream::ColorChoice {
        match self {
            ColorMode::Auto => {
                if io.is_terminal() {
                    anstream::ColorChoice::Always
                } else {
                    anstream::ColorChoice::Never
                }
            }
            ColorMode::Always => anstream::ColorChoice::Always,
            ColorMode::Never => anstream::ColorChoice::Never,
        }
    }
}

impl From<ColorMode> for anstream::ColorChoice {
    /// Maps `ColorMode` to `anstream::ColorChoice`.
    fn from(value: ColorMode) -> Self {
        match value {
            ColorMode::Auto => Self::Auto,
            ColorMode::Always => Self::Always,
            ColorMode::Never => Self::Never,
        }
    }
}

/// How `zizmor` collects inputs from local and remote repository sources.
#[derive(Copy, Clone, Debug, Default, ValueEnum)]
pub(crate) enum CollectionMode {
    /// Collect all possible inputs, ignoring `.gitignore` files.
    All,
    /// Collect all possible inputs, respecting `.gitignore` files.
    #[default]
    Default,
    /// Collect only workflow definitions.
    WorkflowsOnly,
    /// Collect only action definitions (i.e. `action.yml`).
    ActionsOnly,
}

impl CollectionMode {
    pub(crate) fn respects_gitignore(&self) -> bool {
        matches!(
            self,
            CollectionMode::Default | CollectionMode::WorkflowsOnly | CollectionMode::ActionsOnly
        )
    }

    pub(crate) fn workflows(&self) -> bool {
        matches!(
            self,
            CollectionMode::All | CollectionMode::Default | CollectionMode::WorkflowsOnly
        )
    }

    pub(crate) fn actions(&self) -> bool {
        matches!(
            self,
            CollectionMode::All | CollectionMode::Default | CollectionMode::ActionsOnly
        )
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
fn collect_from_dir(
    input_path: &Utf8Path,
    mode: &CollectionMode,
    registry: &mut InputRegistry,
) -> Result<()> {
    // Start with all filters disabled, i.e. walk everything.
    let mut walker = WalkBuilder::new(input_path);
    let walker = walker.standard_filters(false);

    // If the user wants to respect `.gitignore` files, then we need to
    // explicitly enable it. This also enables filtering by a global
    // `.gitignore` file and the `.git/info/exclude` file, since these
    // typically align with the user's expectations.
    //
    // We honor `.gitignore` and similar files even if `.git/` is not
    // present, since users may retrieve or reconstruct a source archive
    // without a `.git/` directory. In particular, this snares some
    // zizmor integrators.
    //
    // See: https://github.com/woodruffw/zizmor/issues/596
    if mode.respects_gitignore() {
        walker
            .require_git(false)
            .git_ignore(true)
            .git_global(true)
            .git_exclude(true);
    }

    for entry in walker.build() {
        let entry = entry?;
        let entry = <&Utf8Path>::try_from(entry.path())?;

        if mode.workflows()
            && entry.is_file()
            && matches!(entry.extension(), Some("yml" | "yaml"))
            && entry
                .parent()
                .is_some_and(|dir| dir.ends_with(".github/workflows"))
        {
            registry
                .register_by_path(entry, Some(input_path))
                .with_context(|| format!("failed to register input: {entry}"))?;
        }

        if mode.actions()
            && entry.is_file()
            && matches!(entry.file_name(), Some("action.yml" | "action.yaml"))
        {
            let action = Action::from_file(entry, Some(input_path))?;
            registry.register_input(action.into())?;
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
            collect_from_dir(input_path, mode, &mut registry)?;
            // collect_from_repo_dir(input_path, input_path, mode, &mut registry)?;
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

    #[cfg(feature = "lsp")]
    if app.lsp {
        lsp::run();
        return Ok(ExitCode::SUCCESS);
    }

    let color_mode = match app.color {
        Some(color_mode) => color_mode,
        None => {
            // If `--color` wasn't specified, we first check a handful
            // of common environment variables, and then fall
            // back to `anstream`'s auto detection.
            if std::env::var("NO_COLOR").is_ok() {
                ColorMode::Never
            } else if std::env::var("FORCE_COLOR").is_ok()
                || std::env::var("CLICOLOR_FORCE").is_ok()
            {
                ColorMode::Always
            } else {
                ColorMode::Auto
            }
        }
    };

    anstream::ColorChoice::write_global(color_mode.into());

    // Disable progress bars if colorized output is disabled.
    // We do this because `anstream` and `tracing_indicatif` don't
    // compose perfectly: `anstream` wants to strip all ANSI escapes,
    // while `tracing_indicatif` needs line control to render progress bars.
    // TODO: In the future, perhaps we could make these work together.
    if matches!(color_mode, ColorMode::Never) {
        app.no_progress = true;
    }

    // `--pedantic` is a shortcut for `--persona=pedantic`.
    if app.pedantic {
        app.persona = Persona::Pedantic;
    }

    // Unset the GitHub token if we're in offline mode.
    // We do this manually instead of with clap's `conflicts_with` because
    // we want to support explicitly enabling offline mode while still
    // having `GH_TOKEN` present in the environment.
    if app.offline {
        app.gh_token = None;
    }

    let indicatif_layer = IndicatifLayer::new();

    let writer = std::sync::Mutex::new(anstream::AutoStream::new(
        Box::new(indicatif_layer.get_stderr_writer()) as Box<dyn Write + Send>,
        color_mode.color_choice_for_terminal(std::io::stderr()),
    ));

    let filter = EnvFilter::builder()
        .with_default_directive(app.verbose.tracing_level_filter().into())
        .from_env()?;

    let reg = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .without_time()
                // NOTE: We don't need `with_ansi` here since our writer is
                // an `anstream::AutoStream` that handles color output for us.
                .with_writer(writer),
        )
        .with(filter);

    if app.no_progress {
        reg.init();
    } else {
        reg.with(indicatif_layer).init();
    }

    let audit_state = AuditState::new(&app);
    let registry = collect_inputs(&app.inputs, &app.collect, &audit_state)?;

    let config = Config::new(&app)?;

    let audit_registry = AuditRegistry::default_audits(&audit_state);

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
                "🌈 {completed} {input}",
                completed = "completed".green(),
                input = input.key().presentation_path()
            );
        }
    }

    match app.format {
        OutputFormat::Plain => render::render_findings(&app, &registry, &results),
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
