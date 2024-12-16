//! zizmor's runtime state, including application-level caching.

use std::path::PathBuf;

use etcetera::{choose_app_strategy, AppStrategy, AppStrategyArgs};

use crate::{github_api::Client, App};

#[derive(Clone)]
pub(crate) struct AuditState {
    pub(crate) no_online_audits: bool,
    pub(crate) cache_dir: PathBuf,
    pub(crate) gh_token: Option<String>,
}

impl AuditState {
    pub(crate) fn new(app: &App) -> Self {
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
            no_online_audits: app.no_online_audits,
            cache_dir,
            gh_token: app.gh_token.clone(),
        }
    }

    /// Return a cache-configured GitHub API client, if
    /// a GitHub API token is present.
    pub(crate) fn github_client(&self) -> Option<Client> {
        self.gh_token
            .as_ref()
            .map(|token| Client::new(token, &self.cache_dir))
    }
}
