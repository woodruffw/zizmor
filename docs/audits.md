# Audit Rules

This page documents each of the audits currently implemented in `zizmor`.

See each audit's section for its scope, behavior, and other information.

Please note that:

- _"Works offline"_ refers to audits that require a Github Token (`--gh-token <my-token>`)
- _"Enable by default"_ refers to non-pedantic audits (`--pedantic`)

## `artipacked`

| Type     | Examples         | Introduced in | Works offline?  | Enabled by default |
|----------|------------------|---------------|----------------|--------------------|
| Workflow  | [artipacked.yml] | v0.1.0        | ✅             | ✅                 |

[artipacked.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/artipacked.yml

### What

Unexpected credential use and potential credential persistence,
typically via GitHub Actions artifact creation or action logs.

### Why

The default checkout action is [`actions/checkout`].

By default, using `actions/checkout` causes a credential to be persisted
in the checked-out repo's `.git/config`, so that subsequent `git` operations
can be authenticated.

Subsequent steps may accidentally publicly persist `.git/config`, e.g. by
including it in a publicly accessible artifact via [`actions/upload-artifact`].

However, even without this, persisting the credential in the `.git/config`
is non-ideal and should be disabled with `persist-credentials: false` unless
the job actually needs the persisted credential.

### Other resources

* <https://unit42.paloaltonetworks.com/github-repo-artifacts-leak-tokens/>

[`actions/checkout`]: https://github.com/actions/checkout

[`actions/upload-artifact`]: https://github.com/actions/upload-artifact

## `dangerous-triggers`

| Type     | Examples                  | Introduced in | Works offline?  | Enabled by default |
|----------|---------------------------|---------------|----------------|--------------------|
| Workflow  | [pull-request-target.yml] | v0.1.0        | ✅             | ✅                 |

[pull-request-target.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/pull-request-target.yml

### What

Fundamentally dangerous GitHub Actions workflow triggers.

### Why

Many of GitHub's workflow triggers are difficult to use securely.
This audit checks for some of the biggest offenders:

* `pull_request_target`
* `workflow_run`

These triggers are dangerous because they run in the context of the
*target repository* rather than the *fork repository*, while also being
typically triggerable by the latter. This can lead to attacker controlled
code execution or unexpected action runs with context controlled by a malicious
fork.

### Other resources

* <https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/>

## `excessive-permissions`

| Type     | Examples                    | Introduced in | Works offline?  | Enabled by default |
|----------|-----------------------------|---------------|----------------|--------------------|
| Workflow  | [excessive-permissions.yml] | v0.1.0        | ✅             | ✅                 |

[excessive-permissions.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/excessive-permissions.yml

### What

Looks for excessive permissions in workflows, both at
the workflow level and individual job levels.

### Why

Users frequently over-scope their workflow and job permissions,
or set broad workflow-level permissions without realizing that
all jobs inherit those permissions.

## `hardcoded-container-credentials`

| Type     | Examples                    | Introduced in | Works offline?  | Enabled by default |
|----------|-----------------------------|---------------|----------------|--------------------|
| Workflow  | [hardcoded-credentials.yml] | v0.1.0        | ✅             | ✅                 |

[hardcoded-credentials.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/hardcoded-credentials.yml

### What

GitHub Actions allows Docker credentials (usernames and passwords)
to be hardcoded in various places within workflows.

### Why

Hardcoding credentials is bad.

## `impostor-commit`

| Type     | Examples              | Introduced in | Works offline?  | Enabled by default |
|----------|-----------------------|---------------|----------------|--------------------|
| Workflow  | [impostor-commit.yml] | v0.1.0        | ❌             | ✅                 |

[impostor-commit.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/impostor-commit.yml

### What

GitHub represents a repository and its forks as a "network" of commits.
This results in ambiguity about where a commit comes from: a commit
that exists only in a fork can be referenced via its parent's
`owner/repo` slug, and vice versa.

### Why

GitHub's network-of-forks design can be used to obscure a commit's true origin
in a fully-pinned `uses:` workflow reference. This can be used by an attacker
to surreptitiously introduce a backdoored action into a victim's workflows(s).

### Other resources

* <https://www.chainguard.dev/unchained/what-the-fork-imposter-commits-in-github-actions-and-ci-cd>

## `known-vulnerable-actions`

| Type     | Examples                       | Introduced in | Works offline?  | Enabled by default |
|----------|--------------------------------|---------------|----------------|--------------------|
| Workflow  | [known-vulnerable-actions.yml] | v0.1.0        | ❌             | ✅                 |

[known-vulnerable-actions.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/known-vulnerable-actions.yml

### What

Actions with known, publicly disclosed vulnerabilities are tracked in the
[GitHub Advisories database]. Examples of commonly disclosed vulnerabilities
in GitHub Actions include [credential disclosure] and code injection
via [template injection].

### Why

You shouldn't use actions with known vulnerabilities.

[GitHub Advisories database]: https://github.com/advisories

[credential disclosure]: #artipacked

[template injection]: #template-injection

## `ref-confusion`

| Type     | Examples            | Introduced in | Works offline?  | Enabled by default |
|----------|---------------------|---------------|----------------|--------------------|
| Workflow  | [ref-confusion.yml] | v0.1.0        | ❌             | ✅                 |

[ref-confusion.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/ref-confusion.yml

### What

Like with [impostor commits], actions that are used with a symbolic ref
in their `uses:` are subject to a degree of ambiguity: a ref like
`@v1` might refer to either a branch or tag ref.

### Why

An attacker can exploit this ambiguity to publish a branch or tag ref that
takes precedence over a legitimate one, delivering a malicious action to
pre-existing consumers of that action without having to modify those consumers.

[impostor commits]: #impostor-commit

## `self-hosted-runner`

| Type     | Examples            | Introduced in | Works offline?  | Enabled by default |
|----------|---------------------|---------------|----------------|--------------------|
| Workflow  | [ref-confusion.yml] | v0.1.0        | ✅             | ❌                 |

[self-hosted.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/self-hosted.yml

### What

GitHub supports self-hosted runners, which behave similarly to GitHub-hosted
runners but use client-managed compute resources.

### Why

Self-hosted runners are very hard to secure by default, which is why
GitHub does not recommend their use in public repositories.

### Other resources

* <https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security>

## `template-injection`

| Type     | Examples                 | Introduced in | Works offline?  | Enabled by default |
|----------|--------------------------|---------------|----------------|--------------------|
| Workflow  | [template-injection.yml] | v0.1.0        | ✅             | ✅                 |

[template-injection.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/template-injection.yml

### What

GitHub Actions allows workflows to define *template expansions*, which
occur within special `${{ ... }}` delimiters. These expansions happen
before workflow and job execution, meaning the expansion
of a given expression appears verbatim in whatever context it was performed in.

### Why

Template expansions aren't syntax-aware, meaning that they can result in
unintended shell injection vectors. This is especially true when they're
used with attacker-controllable expression contexts, such as
`github.event.issue.title` (which the attacker can fully control by supplying
a new issue title).

### Other resources

* <https://securitylab.github.com/resources/github-actions-untrusted-input/>

## `use-trusted-publishing`

| Type     | Examples                     | Introduced in | Works offline?  | Enabled by default |
|----------|------------------------------|---------------|----------------|--------------------|
| Workflow  | [pypi-manual-credential.yml] | v0.1.0        | ✅             | ✅                 |

[pypi-manual-credential.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/pypi-manual-credential.yml

### What

Some packaging ecosystems/indices (like PyPI and RubyGems) support
"Trusted Publishing," which is an OIDC-based "tokenless" authentication
mechanism for uploading to the index from within a CI/CD workflow.

### Why

This "tokenless" flow has significant security benefits over a traditional
manually configured API token, and should be preferred wherever supported
and possible.

### Other resources

* <https://docs.pypi.org/trusted-publishers/>
* <https://guides.rubygems.org/trusted-publishing/>
* <https://blog.trailofbits.com/2023/05/23/trusted-publishing-a-new-benchmark-for-packaging-security/>
