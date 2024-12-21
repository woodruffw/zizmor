//! A very minimal GitHub API client.
//!
//! Build on synchronous reqwest to avoid octocrab's need to taint
//! the whole codebase with async.

use std::path::Path;

use anyhow::{anyhow, Result};
use http_cache_reqwest::{
    CACacheManager, Cache, CacheMode, CacheOptions, HttpCache, HttpCacheOptions,
};
use reqwest::{
    header::{HeaderMap, ACCEPT, AUTHORIZATION, USER_AGENT},
    StatusCode,
};
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use serde::{de::DeserializeOwned, Deserialize};
use tracing::instrument;

use crate::{
    models::{RepositoryUses, Workflow},
    registry::InputKey,
    utils::PipeSelf,
};

pub(crate) struct Client {
    api_base: &'static str,
    http: ClientWithMiddleware,
}

impl Client {
    pub(crate) fn new(token: &str, cache_dir: &Path) -> Self {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, "zizmor".parse().unwrap());
        headers.insert(
            AUTHORIZATION,
            format!("Bearer {token}")
                .parse()
                .expect("couldn't build authorization header for GitHub client?"),
        );
        headers.insert("X-GitHub-Api-Version", "2022-11-28".parse().unwrap());
        headers.insert(ACCEPT, "application/vnd.github+json".parse().unwrap());

        let http = ClientBuilder::new(
            reqwest::Client::builder()
                .default_headers(headers)
                .build()
                .expect("couldn't build GitHub client?"),
        )
        .with(Cache(HttpCache {
            mode: CacheMode::Default,
            manager: CACacheManager {
                path: cache_dir.into(),
            },
            options: HttpCacheOptions {
                cache_options: Some(CacheOptions {
                    // GitHub API requests made with an API token seem to
                    // always have `Cache-Control: private`, so we need to
                    // explicitly tell http-cache that our cache is not shared
                    // in order for things to cache correctly.
                    shared: false,
                    ..Default::default()
                }),
                ..Default::default()
            },
        }))
        .build();

        Self {
            api_base: "https://api.github.com",
            http,
        }
    }

    async fn paginate<T: DeserializeOwned>(
        &self,
        endpoint: &str,
    ) -> reqwest_middleware::Result<Vec<T>> {
        let mut dest = vec![];
        let url = format!("{api_base}/{endpoint}", api_base = self.api_base);

        // If we were nice, we would parse GitHub's `links` header and extract
        // the remaining number of pages. But this is annoying, and we are
        // not nice, so we simply request pages until GitHub bails on us
        // and returns empty results.
        let mut pageno = 0;
        loop {
            let resp = self
                .http
                .get(&url)
                .query(&[("page", pageno), ("per_page", 100)])
                .send()
                .await?
                .error_for_status()?;

            let page = resp.json::<Vec<T>>().await?;
            if page.is_empty() {
                break;
            }

            dest.extend(page);
            pageno += 1;
        }

        Ok(dest)
    }

    #[instrument(skip(self))]
    #[tokio::main]
    pub(crate) async fn list_branches(&self, owner: &str, repo: &str) -> Result<Vec<Branch>> {
        self.paginate(&format!("repos/{owner}/{repo}/branches"))
            .await
            .map_err(Into::into)
    }

    #[instrument(skip(self))]
    #[tokio::main]
    pub(crate) async fn list_tags(&self, owner: &str, repo: &str) -> Result<Vec<Tag>> {
        self.paginate(&format!("repos/{owner}/{repo}/tags"))
            .await
            .map_err(Into::into)
    }

    #[instrument(skip(self))]
    #[tokio::main]
    pub(crate) async fn has_branch(&self, owner: &str, repo: &str, branch: &str) -> Result<bool> {
        let url = format!(
            "{api_base}/repos/{owner}/{repo}/git/ref/heads/{branch}",
            api_base = self.api_base
        );

        let resp = self.http.get(&url).send().await?;
        match resp.status() {
            StatusCode::OK => Ok(true),
            StatusCode::NOT_FOUND => Ok(false),
            s => Err(anyhow!(
                "{owner}/{repo}: error from GitHub API while checking branch {branch}: {s}"
            )),
        }
    }

    #[instrument(skip(self))]
    #[tokio::main]
    pub(crate) async fn has_tag(&self, owner: &str, repo: &str, tag: &str) -> Result<bool> {
        let url = format!(
            "{api_base}/repos/{owner}/{repo}/git/refs/tags/{tag}",
            api_base = self.api_base
        );

        let resp = self.http.get(&url).send().await?;
        match resp.status() {
            StatusCode::OK => Ok(true),
            StatusCode::NOT_FOUND => Ok(false),
            s => Err(anyhow!(
                "{owner}/{repo}: error from GitHub API while checking tag {tag}: {s}"
            )),
        }
    }

    #[instrument(skip(self))]
    #[tokio::main]
    pub(crate) async fn commit_for_ref(
        &self,
        owner: &str,
        repo: &str,
        git_ref: &str,
    ) -> Result<Option<String>> {
        // GitHub Actions generally resolves branches before tags, so try
        // the repo's branches first.
        let url = format!(
            "{api_base}/repos/{owner}/{repo}/git/ref/heads/{git_ref}",
            api_base = self.api_base
        );

        let resp = self.http.get(url).send().await?;
        match resp.status() {
            StatusCode::OK => Ok(Some(resp.json::<GitRef>().await?.object.sha)),
            StatusCode::NOT_FOUND => {
                let url = format!(
                    "{api_base}/repos/{owner}/{repo}/git/ref/tags/{git_ref}",
                    api_base = self.api_base
                );

                let resp = self.http.get(url).send().await?;
                match resp.status() {
                    StatusCode::OK => Ok(Some(resp.json::<GitRef>().await?.object.sha)),
                    StatusCode::NOT_FOUND => Ok(None),
                    s => Err(anyhow!(
                        "{owner}/{repo}: error from GitHub API while accessing ref {git_ref}: {s}"
                    )),
                }
            }
            s => Err(anyhow!(
                "{owner}/{repo}: error from GitHub API while accessing ref {git_ref}: {s}"
            )),
        }
    }

    #[instrument(skip(self))]
    pub(crate) fn longest_tag_for_commit(
        &self,
        owner: &str,
        repo: &str,
        commit: &str,
    ) -> Result<Option<Tag>> {
        // Annoying: GitHub doesn't provide a rev-parse or similar API to
        // perform the commit -> tag lookup, so we download every tag and
        // do it for them.
        // This could be optimized in various ways, not least of which
        // is not pulling every tag eagerly before scanning them.
        let tags = self.list_tags(owner, repo)?;

        // Heuristic: there can be multiple tags for a commit, so we pick
        // the longest one. This isn't super sound, but it gets us from
        // `sha -> v1.2.3` instead of `sha -> v1`.
        Ok(tags
            .into_iter()
            .filter(|t| t.commit.sha == commit)
            .max_by_key(|t| t.name.len()))
    }

    #[instrument(skip(self))]
    #[tokio::main]
    pub(crate) async fn compare_commits(
        &self,
        owner: &str,
        repo: &str,
        base: &str,
        head: &str,
    ) -> Result<Option<ComparisonStatus>> {
        let url = format!(
            "{api_base}/repos/{owner}/{repo}/compare/{base}...{head}",
            api_base = self.api_base
        );

        let resp = self.http.get(url).send().await?;

        match resp.status() {
            StatusCode::OK => {
                Ok::<_, reqwest::Error>(Some(resp.json::<Comparison>().await?.status))
            }
            StatusCode::NOT_FOUND => Ok(None),
            _ => Err(resp.error_for_status().unwrap_err()),
        }
        .map_err(Into::into)
    }

    #[instrument(skip(self))]
    #[tokio::main]
    pub(crate) async fn gha_advisories(
        &self,
        owner: &str,
        repo: &str,
        version: &str,
    ) -> Result<Vec<Advisory>> {
        // TODO: Paginate this as well.
        let url = format!("{api_base}/advisories", api_base = self.api_base);

        self.http
            .get(url)
            .query(&[
                ("ecosystem", "actions"),
                ("affects", &format!("{owner}/{repo}@{version}")),
            ])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .map_err(Into::into)
    }

    /// Return temporary files for all workflows listed in the repo.
    #[instrument(skip(self))]
    #[tokio::main]
    pub(crate) async fn fetch_workflows(&self, slug: &RepositoryUses) -> Result<Vec<Workflow>> {
        let owner = slug.owner;
        let repo = slug.repo;
        let git_ref = slug.git_ref;

        tracing::debug!("fetching workflows for {owner}/{repo}");

        // It'd be nice if the GitHub contents API allowed us to retrieve
        // all file contents with a directory listing, but it doesn't.
        // Instead, we make `N+1` API calls: one to list the workflows
        // directory, and `N` for the constituent workflow files.
        let url = format!(
            "{api_base}/repos/{owner}/{repo}/contents/.github/workflows",
            api_base = self.api_base
        );
        let resp: Vec<File> = self
            .http
            .get(&url)
            .pipe(|req| match git_ref {
                Some(g) => req.query(&[("ref", g)]),
                None => req,
            })
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let mut workflows = vec![];
        for file in resp
            .into_iter()
            .filter(|file| file.name.ends_with(".yml") || file.name.ends_with(".yaml"))
        {
            let file_url = format!("{url}/{file}", file = file.name);
            tracing::debug!("fetching {file_url}");

            let contents = self
                .http
                .get(file_url)
                .header(ACCEPT, "application/vnd.github.raw+json")
                .pipe(|req| match git_ref {
                    Some(g) => req.query(&[("ref", g)]),
                    None => req,
                })
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;

            workflows.push(Workflow::from_string(
                contents,
                InputKey::remote(slug, file.path)?,
            )?);
        }

        Ok(workflows)
    }
}

/// A single branch, as returned by GitHub's branches endpoints.
///
/// This model is intentionally incomplete.
///
/// See <https://docs.github.com/en/rest/branches/branches?apiVersion=2022-11-28>.
#[derive(Deserialize, Clone)]
pub(crate) struct Branch {
    pub(crate) name: String,
    pub(crate) commit: Object,
}

/// A single tag, as returned by GitHub's tags endpoints.
///
/// This model is intentionally incomplete.
#[derive(Deserialize, Clone)]
pub(crate) struct Tag {
    pub(crate) name: String,
    pub(crate) commit: Object,
}

/// Represents a git object.
#[derive(Deserialize, Clone)]
pub(crate) struct Object {
    pub(crate) sha: String,
}

#[derive(Deserialize)]
pub(crate) struct GitRef {
    pub(crate) object: Object,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ComparisonStatus {
    Ahead,
    Behind,
    Diverged,
    Identical,
}

/// The result of comparing two commits via GitHub's API.
///
/// See <https://docs.github.com/en/rest/commits/commits?apiVersion=2022-11-28>
#[derive(Deserialize)]
pub(crate) struct Comparison {
    pub(crate) status: ComparisonStatus,
}

/// Represents a GHSA advisory.
#[derive(Deserialize)]
pub(crate) struct Advisory {
    pub(crate) ghsa_id: String,
    pub(crate) severity: String,
}

/// Represents a file listing from GitHub's contents API.
#[derive(Deserialize)]
pub(crate) struct File {
    name: String,
    path: String,
}
