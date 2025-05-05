//! Extension traits for the `Uses` APIs.

use std::{str::FromStr, sync::LazyLock};

use github_actions_models::common::{RepositoryUses, Uses};
use regex::Regex;
use serde::Deserialize;

/// Matches all variants of [`RepositoryUsesPattern`] except `*`.
static REPOSITORY_USES_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?mi)^([\w-]+)/([\w\.-]+|\*)(?:/(.+))?$"#).unwrap());

/// Represents a pattern for matching repository `uses` references.
/// These patterns are ordered by specificity; more specific patterns
/// should be listed first.
#[derive(Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub(crate) enum RepositoryUsesPattern {
    /// Matches exactly `owner/repo/subpath`.
    ExactPath {
        owner: String,
        repo: String,
        subpath: String,
    },
    /// Matches exactly `owner/repo`.
    ExactRepo { owner: String, repo: String },
    /// Matches `owner/repo/*` (i.e. any subpath under the given repo, including
    /// the empty subpath).
    InRepo { owner: String, repo: String },
    /// Matches `owner/*` (i.e. any repo under the given owner).
    InOwner(String),
    /// Matches any `owner/repo`.
    Any,
}

impl RepositoryUsesPattern {
    pub(crate) fn matches(&self, uses: &RepositoryUses) -> bool {
        match self {
            RepositoryUsesPattern::ExactPath {
                owner,
                repo,
                subpath,
            } => {
                // TODO: Normalize the subpath here.
                // This is nontrivial, since we need to normalize
                // both leading slashes *and* arbitrary ./.. components.
                // Utf8Path gets us part of the way there, but is
                // platform dependent (i.e. will do the wrong thing
                // if the platform separator is not /).
                uses.owner.eq_ignore_ascii_case(owner)
                    && uses.repo.eq_ignore_ascii_case(repo)
                    && uses.subpath.as_deref().is_some_and(|s| s == subpath)
            }
            RepositoryUsesPattern::ExactRepo { owner, repo } => {
                uses.owner.eq_ignore_ascii_case(owner)
                    && uses.repo.eq_ignore_ascii_case(repo)
                    && uses.subpath.is_none()
            }
            RepositoryUsesPattern::InRepo { owner, repo } => {
                uses.owner.eq_ignore_ascii_case(owner) && uses.repo.eq_ignore_ascii_case(repo)
            }
            RepositoryUsesPattern::InOwner(owner) => uses.owner.eq_ignore_ascii_case(owner),
            RepositoryUsesPattern::Any => true,
        }
    }
}

impl FromStr for RepositoryUsesPattern {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "*" {
            return Ok(RepositoryUsesPattern::Any);
        }

        let caps = REPOSITORY_USES_PATTERN
            .captures(s)
            .ok_or_else(|| anyhow::anyhow!("invalid pattern: {s}"))?;

        let owner = &caps[1];
        let repo = &caps[2];
        let subpath = caps.get(3).map(|m| m.as_str());

        match (owner, repo, subpath) {
            (owner, "*", None) => Ok(RepositoryUsesPattern::InOwner(owner.into())),
            (owner, repo, None) => Ok(RepositoryUsesPattern::ExactRepo {
                owner: owner.into(),
                repo: repo.into(),
            }),
            (_, "*", Some(_)) => Err(anyhow::anyhow!("invalid pattern: {s}")),
            (owner, repo, Some("*")) => Ok(RepositoryUsesPattern::InRepo {
                owner: owner.into(),
                repo: repo.into(),
            }),
            (owner, repo, Some(subpath)) => Ok(RepositoryUsesPattern::ExactPath {
                owner: owner.into(),
                repo: repo.into(),
                subpath: subpath.into(),
            }),
        }
    }
}

impl<'de> Deserialize<'de> for RepositoryUsesPattern {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        RepositoryUsesPattern::from_str(&s).map_err(serde::de::Error::custom)
    }
}

/// Useful APIs for interacting with `uses: owner/repo` clauses.
pub(crate) trait RepositoryUsesExt {
    /// Returns the path consisting of `owner/repo[/subpath]`, but without ref.
    /// The path is converted to lowercase.
    fn path_without_ref(&self) -> String;

    /// Returns whether this `uses:` clause "matches" the given template.
    /// The template is itself formatted like a normal `uses:` clause.
    ///
    /// This is an asymmetrical match: `actions/checkout@v3` "matches"
    /// the `actions/checkout` template but not vice versa.
    ///
    /// Comparisons are case-insensitive, since GitHub's own APIs are insensitive.
    ///
    /// TODO: Remove this API and replace it with [`RepositoryUsesPattern`].
    fn matches(&self, template: &str) -> bool;

    /// Like [`RepositoryUsesExt::matches`].
    fn matches_uses(&self, template: &RepositoryUses) -> bool;

    /// Returns whether this `uses:` clause has a `git` ref and, if so,
    /// whether that ref is a commit ref.
    ///
    /// For example, `foo/bar@baz` returns false while `foo/bar@1234...`
    /// returns true.
    fn ref_is_commit(&self) -> bool;

    /// Returns the `git` ref for this `uses:`, if present.
    fn commit_ref(&self) -> Option<&str>;

    /// Returns the *symbolic* `git` ref for this `uses`, if present.
    ///
    /// Commit refs (i.e. SHA refs) are not returned.
    fn symbolic_ref(&self) -> Option<&str>;
}

impl RepositoryUsesExt for RepositoryUses {
    fn path_without_ref(&self) -> String {
        format!(
            "{}/{}{}",
            self.owner,
            self.repo,
            self.subpath
                .as_ref()
                .map_or("".to_owned(), |subpath| format!("/{subpath}"))
        )
        .to_lowercase()
    }

    fn matches(&self, template: &str) -> bool {
        let Ok(other) = template.parse::<RepositoryUses>() else {
            return false;
        };

        self.matches_uses(&other)
    }

    fn matches_uses(&self, template: &RepositoryUses) -> bool {
        self.owner.eq_ignore_ascii_case(&template.owner)
            && (template.repo == "*" || self.repo.eq_ignore_ascii_case(&template.repo))
            && self.subpath.as_ref().map(|s| s.to_lowercase())
                == template.subpath.as_ref().map(|s| s.to_lowercase())
            && template.git_ref.as_ref().is_none_or(|git_ref| {
                Some(git_ref.to_lowercase()) == self.git_ref.as_ref().map(|r| r.to_lowercase())
            })
    }

    fn ref_is_commit(&self) -> bool {
        match &self.git_ref {
            Some(git_ref) => git_ref.len() == 40 && git_ref.chars().all(|c| c.is_ascii_hexdigit()),
            None => false,
        }
    }

    fn commit_ref(&self) -> Option<&str> {
        match &self.git_ref {
            Some(git_ref) if self.ref_is_commit() => Some(git_ref),
            _ => None,
        }
    }

    fn symbolic_ref(&self) -> Option<&str> {
        match &self.git_ref {
            Some(git_ref) if !self.ref_is_commit() => Some(git_ref),
            _ => None,
        }
    }
}

/// Useful APIs for interacting with all kinds of `uses:` clauses.
pub(crate) trait UsesExt {
    fn unpinned(&self) -> bool;
    fn unhashed(&self) -> bool;
}

impl UsesExt for Uses {
    /// Whether the `uses:` is unpinned.
    fn unpinned(&self) -> bool {
        match self {
            Uses::Docker(docker) => docker.hash.is_none() && docker.tag.is_none(),
            Uses::Repository(repo) => repo.git_ref.is_none(),
            // Local `uses:` are always unpinned; any `@ref` component
            // is actually part of the path.
            Uses::Local(_) => true,
        }
    }

    /// Whether the `uses:` is unhashed (but potentially pinned with a non-hash),
    fn unhashed(&self) -> bool {
        match self {
            // TODO: Handle this case. Right now it's not very important,
            // since we don't really analyze local action uses at all,
            // and the "hashedness" of a local action is mostly moot anyways
            // (since it's fully contained within the calling repo),
            Uses::Local(_) => false,
            Uses::Repository(repo) => !repo.ref_is_commit(),
            Uses::Docker(docker) => docker.hash.is_none(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use anyhow::anyhow;
    use github_actions_models::common::Uses;

    use crate::models::uses::RepositoryUsesExt;

    use super::RepositoryUsesPattern;

    #[test]
    fn test_repositoryuses_path_without_ref() {
        for (uses, expected_path) in [
            ("ACTIONS/CHECKOUT", "actions/checkout"),
            ("actions/checkout@v3", "actions/checkout"),
            ("actions/checkout/foo@v3", "actions/checkout/foo"),
            ("actions/checkout/fOO/Bar@v3", "actions/checkout/foo/bar"),
        ] {
            let Ok(Uses::Repository(uses)) = Uses::from_str(uses) else {
                panic!();
            };

            assert_eq!(uses.path_without_ref(), expected_path)
        }
    }

    #[test]
    fn test_repositoryuses_matches() {
        for (uses, template, matches) in [
            // OK: `uses:` is more specific than template
            ("actions/checkout@v3", "actions/checkout", true),
            ("actions/checkout/foo@v3", "actions/checkout/foo", true),
            // OK: equally specific
            ("actions/checkout@v3", "actions/checkout@v3", true),
            ("actions/checkout", "actions/checkout", true),
            ("actions/checkout/foo", "actions/checkout/foo", true),
            ("actions/checkout/foo@v3", "actions/checkout/foo@v3", true),
            // OK: case-insensitive
            ("actions/checkout@v3", "Actions/Checkout@v3", true),
            ("actions/checkout/foo", "actions/checkout/Foo", true),
            ("actions/checkout/foo@v3", "Actions/Checkout/Foo", true),
            ("actions/checkout@v3", "actions/checkout@V3", true),
            // NOT OK: owner/repo do not match
            ("actions/checkout@v3", "foo/checkout", false),
            ("actions/checkout@v3", "actions/bar", false),
            // NOT OK: subpath does not match
            ("actions/checkout/foo", "actions/checkout", false),
            ("actions/checkout/foo@v3", "actions/checkout@v3", false),
            // NOT OK: template is more specific than `uses:`
            ("actions/checkout", "actions/checkout@v3", false),
            ("actions/checkout/foo", "actions/checkout/foo@v3", false),
        ] {
            let Ok(Uses::Repository(uses)) = Uses::from_str(uses) else {
                panic!();
            };

            assert_eq!(uses.matches(template), matches)
        }
    }

    #[test]
    fn test_repositoryusespattern_parse() {
        for (pattern, expected) in [
            ("", None),      // Invalid, empty
            ("/", None),     // Invalid, not well formed
            ("//", None),    // Invalid, not well formed
            ("///", None),   // Invalid, not well formed
            ("owner", None), // Invalid, should be owner/*
            ("**", None),    // Invalid, should be *
            ("*", Some(RepositoryUsesPattern::Any)),
            (
                "owner/*",
                Some(RepositoryUsesPattern::InOwner("owner".into())),
            ),
            ("owner/*/", None),    // Invalid, should be owner/*
            ("owner/*/foo", None), // Invalid, not well formed
            ("owner/*/*", None),   // Invalid, not well formed
            (
                "owner/repo/*",
                Some(RepositoryUsesPattern::InRepo {
                    owner: "owner".into(),
                    repo: "repo".into(),
                }),
            ),
            (
                "owner/repo",
                Some(RepositoryUsesPattern::ExactRepo {
                    owner: "owner".into(),
                    repo: "repo".into(),
                }),
            ),
            (
                "owner/repo/subpath",
                Some(RepositoryUsesPattern::ExactPath {
                    owner: "owner".into(),
                    repo: "repo".into(),
                    subpath: "subpath".into(),
                }),
            ),
            // We don't do any subpath normalization at construction time.
            (
                "owner/repo//",
                Some(RepositoryUsesPattern::ExactPath {
                    owner: "owner".into(),
                    repo: "repo".into(),
                    subpath: "/".into(),
                }),
            ),
            // Weird, but we allow it (for now).
            (
                "owner/repo/**",
                Some(RepositoryUsesPattern::ExactPath {
                    owner: "owner".into(),
                    repo: "repo".into(),
                    subpath: "**".into(),
                }),
            ),
            (
                "owner/repo/subpath/",
                Some(RepositoryUsesPattern::ExactPath {
                    owner: "owner".into(),
                    repo: "repo".into(),
                    subpath: "subpath/".into(),
                }),
            ),
            (
                "owner/repo/subpath/very/nested////and/literal",
                Some(RepositoryUsesPattern::ExactPath {
                    owner: "owner".into(),
                    repo: "repo".into(),
                    subpath: "subpath/very/nested////and/literal".into(),
                }),
            ),
        ] {
            let pattern = RepositoryUsesPattern::from_str(pattern).ok();
            assert_eq!(pattern, expected);
        }
    }

    #[test]
    fn test_repositoryusespattern_ord() {
        let mut patterns = vec![
            RepositoryUsesPattern::Any,
            RepositoryUsesPattern::ExactRepo {
                owner: "owner".into(),
                repo: "repo".into(),
            },
            RepositoryUsesPattern::InOwner("owner".into()),
        ];

        patterns.sort();

        assert_eq!(
            patterns,
            vec![
                RepositoryUsesPattern::ExactRepo {
                    owner: "owner".into(),
                    repo: "repo".into()
                },
                RepositoryUsesPattern::InOwner("owner".into()),
                RepositoryUsesPattern::Any,
            ]
        );
    }

    #[test]
    fn test_repositoryusespattern_matches() -> anyhow::Result<()> {
        for (uses, pattern, matches) in [
            // owner/repo/subpath matches regardless of ref and casing
            // but only when the subpath matches.
            // the subpath must share the same case but might not be
            // normalized
            ("actions/checkout/foo", "actions/checkout/foo", true),
            ("ACTIONS/CHECKOUT/foo", "actions/checkout/foo", true),
            ("ACTIONS/CHECKOUT/foo@v3", "actions/checkout/foo", true),
            // TODO: See comment in `RepositoryUsesPattern::matches`
            // ("ACTIONS/CHECKOUT/foo@v3", "actions/checkout/foo/", true),
            // ("ACTIONS/CHECKOUT/foo@v3", "actions/checkout/foo//", true),
            // ("ACTIONS/CHECKOUT//foo////@v3", "actions/checkout/foo", true),
            ("actions/checkout/FOO", "actions/checkout/foo", false),
            ("actions/checkout/foo/bar", "actions/checkout/foo", false),
            // owner/repo matches regardless of ref and casing
            // but does not match subpaths
            ("actions/checkout", "actions/checkout", true),
            ("ACTIONS/CHECKOUT", "actions/checkout", true),
            ("actions/checkout@v3", "actions/checkout", true),
            ("actions/checkout/foo@v3", "actions/checkout", false),
            ("actions/somethingelse", "actions/checkout", false),
            ("whatever/checkout", "actions/checkout", false),
            // owner/repo/* matches regardless of ref and casing
            // including subpaths
            // but does not match when owner diverges
            ("actions/checkout", "actions/checkout/*", true),
            ("ACTIONS/CHECKOUT", "actions/checkout/*", true),
            ("actions/checkout@v3", "actions/checkout/*", true),
            ("actions/checkout/foo@v3", "actions/checkout/*", true),
            ("actions/checkout/foo/bar@v3", "actions/checkout/*", true),
            ("someoneelse/checkout", "actions/checkout/*", false),
            // owner/* matches regardless of ref, casing, and subpath
            // but rejects when owner diverges
            ("actions/checkout", "actions/*", true),
            ("ACTIONS/CHECKOUT", "actions/*", true),
            ("actions/checkout@v3", "actions/*", true),
            ("actions/checkout/foo@v3", "actions/*", true),
            ("someoneelse/checkout", "actions/*", false),
            // * matches everything
            ("actions/checkout", "*", true),
            ("actions/checkout@v3", "*", true),
            ("actions/checkout/foo@v3", "*", true),
            ("whatever/checkout", "*", true),
        ] {
            let Ok(Uses::Repository(uses)) = Uses::from_str(uses) else {
                return Err(anyhow!("invalid uses: {uses}"));
            };

            let pattern = RepositoryUsesPattern::from_str(pattern)?;

            assert_eq!(
                pattern.matches(&uses),
                matches,
                "pattern: {pattern:?}, uses: {uses:?}, matches: {matches}"
            );
        }

        Ok(())
    }
}
