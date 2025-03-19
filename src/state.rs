//! zizmor's runtime state, including application-level caching.

use std::path::PathBuf;

use etcetera::{AppStrategy, AppStrategyArgs, choose_app_strategy};

use crate::{
    App,
    config::Config,
    github_api::{Client, GitHubHost},
};

#[derive(Clone)]
pub(crate) struct AuditState<'a> {
    pub(crate) config: &'a Config,
    pub(crate) no_online_audits: bool,
    pub(crate) cache_dir: PathBuf,
    pub(crate) gh_token: Option<String>,
    pub(crate) gh_hostname: GitHubHost,
}

impl<'a> AuditState<'a> {
    pub(crate) fn new(app: &App, config: &'a Config) -> Self {
        let cache_dir = match &app.cache_dir {
            Some(cache_dir) => cache_dir.as_std_path().to_path_buf(),
            None => choose_app_strategy(AppStrategyArgs {
                top_level_domain: "io.github".into(),
                author: "woodruffw".into(),
                app_name: "zizmor".into(),
            })
            // NOTE: no point in failing gracefully here.
            .expect("failed to determine default cache directory")
            .cache_dir(),
        };

        tracing::debug!("using cache directory: {cache_dir:?}");

        Self {
            config,
            no_online_audits: app.no_online_audits,
            cache_dir,
            gh_token: app.gh_token.clone(),
            gh_hostname: app.gh_hostname.clone(),
        }
    }

    /// Return a cache-configured GitHub API client, if
    /// a GitHub API token is present.
    /// If gh_hostname is also present, set it as api_base for client.
    pub(crate) fn github_client(&self) -> Option<Client> {
        self.gh_token
            .as_ref()
            .map(|token| Client::new(&self.gh_hostname, token, &self.cache_dir))
    }
}
