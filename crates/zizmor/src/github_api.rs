//! A very minimal GitHub API client.
//!
//! Build on synchronous reqwest to avoid octocrab's need to taint
//! the whole codebase with async.

use std::{
    collections::HashMap,
    io::Read,
    path::{Path, PathBuf},
    sync::RwLock,
};

use anyhow::{Context, Result};
use git2::{ObjectType, Oid, Repository, TreeWalkMode, TreeWalkResult, build::RepoBuilder};
use github_actions_models::common::RepositoryUses;
use http_cache_reqwest::{
    CACacheManager, Cache, CacheMode, CacheOptions, HttpCache, HttpCacheOptions,
};
use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderMap, USER_AGENT};
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use serde::Deserialize;
use tracing::instrument;

use crate::{
    InputRegistry,
    registry::{InputKey, InputKind},
};

/// Represents different types of GitHub hosts.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum GitHubHost {
    Enterprise(String),
    Standard(String),
}

impl GitHubHost {
    pub(crate) fn from_clap(hostname: &str) -> Result<Self, String> {
        let normalized = hostname.to_lowercase();

        // NOTE: ideally we'd do a full domain validity check here.
        // For now, this just checks the most likely kind of user
        // confusion (supplying a URL instead of a bare domain name).
        if normalized.starts_with("https://") || normalized.starts_with("http://") {
            return Err("must be a domain name, not a URL".into());
        }

        if normalized.eq_ignore_ascii_case("github.com") || normalized.ends_with(".ghe.com") {
            Ok(Self::Standard(hostname.into()))
        } else {
            Ok(Self::Enterprise(hostname.into()))
        }
    }

    fn to_api_url(&self) -> String {
        match self {
            Self::Enterprise(host) => format!("https://{host}/api/v3"),
            Self::Standard(host) => format!("https://api.{host}"),
        }
    }

    fn to_repo_url(&self, owner: &str, repo: &str, token: Option<String>) -> String {
        let host = match self {
            Self::Enterprise(host) => host,
            Self::Standard(host) => host,
        };

        let mut url = format!("https://{host}/{owner}/{repo}.git");
        if let Some(token) = token {
            url = format!("https://oauth2:{token}@{host}/{owner}/{repo}.git");
        }
        url
    }
}

pub(crate) struct Client {
    api_base: String,
    http: ClientWithMiddleware,
    host: GitHubHost,
    token: Option<String>,
    cache_dir: PathBuf,
    fetched_repos: RwLock<HashMap<String, PathBuf>>,
}

impl Client {
    pub(crate) fn new(hostname: &GitHubHost, token: &str, cache_dir: &Path) -> Self {
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
            api_base: hostname.to_api_url(),
            http,
            host: hostname.clone(),
            token: match token.len() {
                0 => None,
                _ => Some(token.to_string()),
            },
            cache_dir: cache_dir.to_path_buf(),
            fetched_repos: RwLock::new(HashMap::new()),
        }
    }

    #[instrument(skip(self))]
    pub(crate) async fn list_refs(&self, owner: &str, repo: &str) -> Result<Vec<Ref>> {
        let repository = self.get_repo(owner, repo).await?;
        let refs = repository.references()?;

        Ok(refs
            .enumerate()
            .filter_map(|(_, r)| match r {
                Ok(r) => Some(r),
                Err(_) => None,
            })
            .map(|r| {
                let name = r.name().unwrap_or("");
                let oid = r.peel_to_commit().unwrap().id().to_string();
                if name.starts_with("refs/heads/") {
                    Ref::Branch(Branch {
                        name: name.replace("refs/heads/", ""),
                        commit: Object { sha: oid },
                    })
                } else if name.starts_with("refs/remotes/origin/") {
                    Ref::Branch(Branch {
                        name: name.replace("refs/remotes/origin/", ""),
                        commit: Object { sha: oid },
                    })
                } else {
                    Ref::Tag(Tag {
                        name: name.replace("refs/tags/", ""),
                        commit: Object { sha: oid },
                    })
                }
            })
            .collect())
    }

    #[instrument(skip(self))]
    pub(crate) async fn get_repo(&self, owner: &str, repo: &str) -> Result<Repository> {
        let path = self.cache_dir.join(format!("repositories/{owner}/{repo}"));

        let repository = match self
            .fetched_repos
            .read()
            .unwrap()
            .get(&format!("{owner}/{repo}"))
        {
            Some(path) => {
                let repository = Repository::open(path)?;
                repository
            }
            None => match path.exists() {
                true => {
                    self.run_fetch(&path).await?;
                    let repository = Repository::open(&path)?;
                    repository
                }
                false => {
                    let repository = RepoBuilder::new()
                        .bare(true)
                        .clone(
                            &self.host.to_repo_url(owner, repo, self.token.clone()),
                            &path,
                        )
                        .with_context(|| format!("couldn't clone repo {owner}/{repo}"))?;
                    repository
                }
            },
        };

        self.fetched_repos
            .write()
            .unwrap()
            .insert(format!("{owner}/{repo}"), path.clone());

        Ok(repository)
    }

    #[instrument(skip(self))]
    pub(crate) async fn run_fetch(&self, path: &PathBuf) -> Result<()> {
        let repository = Repository::open(path)?;
        let mut remote = match repository.find_remote("origin") {
            Ok(r) => r,
            Err(_) => return Err(anyhow::anyhow!("couldn't find remote for {path:?}")),
        };

        let refspecs = remote.fetch_refspecs()?;
        let mut normalized_refspecs = vec![];
        for spec in refspecs.iter().filter_map(|r| r).map(|s| s.to_string()) {
            normalized_refspecs.push(spec);
        }
        remote.fetch(&normalized_refspecs, None, None)?;
        Ok(())
    }

    #[instrument(skip(self, repo))]
    pub(crate) async fn revwalk_count(
        &self,
        repo: &Repository,
        base: Oid,
        head: Oid,
    ) -> Result<usize> {
        // Walk the graph from the interesting commit ignoring the other revision.
        // This enables us to count the number of commits between the two as all
        // ancestors of the "hidden" revision are ignored.
        let mut revwalk = repo.revwalk()?;
        revwalk.push(base)?;
        revwalk.hide(head)?;
        Ok(revwalk.count())
    }

    #[instrument(skip(self))]
    #[tokio::main]
    pub(crate) async fn list_branches(&self, owner: &str, repo: &str) -> Result<Vec<Branch>> {
        let refs = self.list_refs(owner, repo).await?;
        let mut branches = vec![];

        for reference in refs.iter() {
            match reference {
                Ref::Branch(branch) => branches.push(branch.clone()),
                _ => {}
            }
        }

        Ok(branches)
    }

    #[instrument(skip(self))]
    #[tokio::main]
    pub(crate) async fn list_tags(&self, owner: &str, repo: &str) -> Result<Vec<Tag>> {
        let mut tags = vec![];

        let refs = self.list_refs(owner, repo).await?;

        for reference in refs.iter() {
            match reference {
                Ref::Tag(tag) => tags.push(tag.clone()),
                _ => {}
            }
        }

        Ok(tags)
    }

    #[instrument(skip(self))]
    #[tokio::main]
    pub(crate) async fn has_branch(&self, owner: &str, repo: &str, branch: &str) -> Result<bool> {
        let refs = self.list_refs(owner, repo).await?;
        Ok(refs
            .iter()
            .filter_map(|reference| match reference {
                Ref::Branch(branch) => Some(branch),
                _ => None,
            })
            .any(|b| b.name == branch))
    }

    #[instrument(skip(self))]
    #[tokio::main]
    pub(crate) async fn has_tag(&self, owner: &str, repo: &str, tag: &str) -> Result<bool> {
        let refs = self.list_refs(owner, repo).await?;
        Ok(refs
            .iter()
            .filter_map(|reference| match reference {
                Ref::Tag(tag) => Some(tag),
                _ => None,
            })
            .any(|t| t.name == tag))
    }

    #[instrument(skip(self))]
    #[tokio::main]
    pub(crate) async fn commit_for_ref(
        &self,
        owner: &str,
        repo: &str,
        git_ref: &str,
    ) -> Result<Option<String>> {
        let refs = self.list_refs(owner, repo).await?;
        let reference = refs.iter().find(|reference| match reference {
            Ref::Branch(branch) => branch.name == git_ref,
            Ref::Tag(tag) => tag.name == git_ref,
        });

        match reference {
            Some(Ref::Branch(branch)) => Ok(Some(branch.commit.sha.clone())),
            Some(Ref::Tag(tag)) => Ok(Some(tag.commit.sha.clone())),
            _ => Ok(None),
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
        let tags = self
            .list_tags(owner, repo)
            .with_context(|| format!("couldn't retrieve tags for {owner}/{repo}@{commit}"))?;

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
        let repository = self.get_repo(owner, repo).await?;
        // Use git2's revwalk to determine the relationship between base and head
        let base_commit = match repository.revparse_single(base) {
            Ok(commit) => commit,
            Err(e) => {
                if e.code() == git2::ErrorCode::NotFound {
                    return Ok(None);
                }
                return Err(e.into());
            }
        };
        let head_commit = match repository.revparse_single(head) {
            Ok(commit) => commit,
            Err(e) => {
                if e.code() == git2::ErrorCode::NotFound {
                    return Ok(None);
                }
                return Err(e.into());
            }
        };

        let base_oid = base_commit.id();
        let head_oid = head_commit.id();

        if base_oid == head_oid {
            return Ok(Some(ComparisonStatus::Identical));
        }

        let ahead = self.revwalk_count(&repository, base_oid, head_oid).await?;
        let behind = self.revwalk_count(&repository, head_oid, base_oid).await?;

        let status = match (ahead, behind) {
            (0, 0) => ComparisonStatus::Identical,
            (_, 0) => ComparisonStatus::Ahead,
            (0, _) => ComparisonStatus::Behind,
            (_, _) => ComparisonStatus::Diverged,
        };

        return Ok(Some(status));
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

    /// Collect all workflows (and only workflows) defined in the given remote
    /// repository slug into the given input registry.
    ///
    /// This is an optimized variant of `fetch_audit_inputs` for the workflow-only
    /// collection case.
    #[instrument(skip(self, registry))]
    #[tokio::main]
    pub(crate) async fn fetch_workflows(
        &self,
        slug: &RepositoryUses,
        registry: &mut InputRegistry,
    ) -> Result<()> {
        let owner = &slug.owner;
        let repo = &slug.repo;
        let git_ref = &slug.git_ref;

        tracing::debug!("fetching workflows for {owner}/{repo}");

        let repository = self.get_repo(owner, repo).await?;
        let concrete_ref = match git_ref {
            Some(reference) => match Oid::from_str(reference.as_str()) {
                Ok(_) => reference,
                Err(_) => &format!("refs/remotes/origin/{reference}").to_string(),
            },
            None => &"HEAD".to_string(),
        };

        let commit = repository.revparse_single(concrete_ref)?;
        let tree = commit.peel_to_tree()?;

        let mut entries = vec![];

        let _ = tree.walk(git2::TreeWalkMode::PreOrder, |name, entry| {
            let full_path = format!("{name}{}", entry.name().unwrap());
            if full_path.contains(".github/workflows")
                && (full_path.ends_with(".yml") || full_path.ends_with(".yaml"))
                && matches!(entry.kind(), Some(ObjectType::Blob))
            {
                entries.push((entry.id(), full_path));
            }
            TreeWalkResult::Ok
        });

        for (blob, path) in entries
            .iter()
            .map(|(id, path)| (repository.find_blob(*id).unwrap(), path))
        {
            let mut str_content = String::new();
            let mut contents = blob.content();
            contents.read_to_string(&mut str_content)?;
            let key = InputKey::remote(slug, path.clone())?;
            registry.register(InputKind::Workflow, str_content, key)?;
        }

        Ok(())
    }

    /// Fetch all auditable inputs (both workflows and actions)
    /// from the given remote repository slug.
    ///
    /// This is much slower than `fetch_workflows`, since it involves
    /// retrieving the entire repository archive and decompressing it.
    #[instrument(skip(self, registry))]
    #[tokio::main]
    pub(crate) async fn fetch_audit_inputs(
        &self,
        slug: &RepositoryUses,
        registry: &mut InputRegistry,
    ) -> Result<()> {
        tracing::debug!("fetching repo: {}/{}", slug.owner, slug.repo);

        let repository = self
            .get_repo(slug.owner.as_str(), slug.repo.as_str())
            .await?;
        let concrete_ref = match slug.git_ref.as_deref() {
            Some(reference) => match Oid::from_str(reference) {
                Ok(_) => &reference.to_string(),
                Err(_) => &format!("refs/remotes/origin/{reference}").to_string(),
            },
            None => &"HEAD".to_string(),
        };

        let commit = repository.revparse_single(concrete_ref)?;
        let tree = commit.peel_to_tree()?;

        let mut workflow_entries = Vec::new();
        let mut action_entries = Vec::new();
        let _ = tree.walk(TreeWalkMode::PreOrder, |name, entry| {
            let full_path = format!("{name}{}", entry.name().unwrap());
            if full_path.contains(".github/workflows")
                && (full_path.ends_with(".yml") || full_path.ends_with(".yaml"))
                && matches!(entry.kind(), Some(ObjectType::Blob))
            {
                workflow_entries.push((entry.id(), full_path.clone()));
            }
            if matches!(entry.name(), Some("action.yml") | Some("action.yaml"))
                && matches!(entry.kind(), Some(ObjectType::Blob))
            {
                action_entries.push((entry.id(), full_path.clone()));
            }
            TreeWalkResult::Ok
        });

        for (blob, path) in workflow_entries
            .iter()
            .map(|(blob, path)| (repository.find_blob(*blob).unwrap(), path))
        {
            let key = InputKey::remote(slug, path.clone())?;
            let mut str_content = String::new();
            let mut contents = blob.content();
            contents.read_to_string(&mut str_content)?;
            registry.register(InputKind::Workflow, str_content, key)?;
        }

        for (blob, path) in action_entries
            .iter()
            .map(|(blob, path)| (repository.find_blob(*blob).unwrap(), path))
        {
            let key = InputKey::remote(slug, path.clone())?;
            let mut str_content = String::new();
            let mut contents = blob.content();
            contents.read_to_string(&mut str_content)?;
            registry.register(InputKind::Action, str_content, key)?;
        }

        Ok(())
    }
}

pub(crate) enum Ref {
    Branch(Branch),
    Tag(Tag),
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

#[derive(Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ComparisonStatus {
    Ahead,
    Behind,
    Diverged,
    Identical,
}

/// Represents a GHSA advisory.
#[derive(Deserialize)]
pub(crate) struct Advisory {
    pub(crate) ghsa_id: String,
    pub(crate) severity: String,
}

#[cfg(test)]
mod tests {
    use crate::github_api::GitHubHost;

    #[test]
    fn test_github_host() {
        for (host, expected) in [
            ("github.com", "https://api.github.com"),
            ("something.ghe.com", "https://api.something.ghe.com"),
            (
                "selfhosted.example.com",
                "https://selfhosted.example.com/api/v3",
            ),
        ] {
            assert_eq!(GitHubHost::from_clap(host).unwrap().to_api_url(), expected);
        }
    }
}
