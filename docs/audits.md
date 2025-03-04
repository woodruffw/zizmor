---
description: Audit rules, examples, and remediations.
---

# Audit Rules

This page documents each of the audits currently implemented in `zizmor`.

See each audit's section for its scope, behavior, and other information.

Legend:

| Type     | Examples         | Introduced in | Works offline  | Enabled by default |
|----------|------------------|---------------|----------------|--------------------|
| The kind of audit ("Workflow" or "Action") | Links to vulnerable examples | Added to `zizmor` in this version | The audit works with `--offline` | The audit needs to be explicitly enabled with `--pedantic` |

## `artipacked`

| Type     | Examples         | Introduced in | Works offline  | Enabled by default |
|----------|------------------|---------------|----------------|--------------------|
| Workflow  | [artipacked.yml] | v0.1.0        | ✅             | ✅                 |

[artipacked.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/artipacked.yml

Detects local filesystem `git` credential storage on GitHub Actions, as well as
potential avenues for unintentional persistence of credentials in artifacts.

By default, using @actions/checkout causes a credential to be persisted
in the checked-out repo's `.git/config`, so that subsequent `git` operations
can be authenticated.

Subsequent steps may accidentally publicly persist `.git/config`, e.g. by
including it in a publicly accessible artifact via @actions/upload-artifact.

However, even without this, persisting the credential in the `.git/config`
is non-ideal unless actually needed.

Other resources:

* [ArtiPACKED: Hacking Giants Through a Race Condition in GitHub Actions Artifacts]

### Remediation

Unless needed for `git` operations, @actions/checkout should be used with
`#!yaml persist-credentials: false`.

If the persisted credential is needed, it should be made explicit
with `#!yaml persist-credentials: true`.

=== "Before :warning:"

    ```yaml title="artipacked.yml" hl_lines="7"
    on: push

    jobs:
      artipacked:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4
    ```

=== "After :white_check_mark:"

    ```yaml title="artipacked.yml" hl_lines="7-9"
    on: push

    jobs:
      artipacked:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4
            with:
              persist-credentials: false
    ```

## `dangerous-triggers`

| Type     | Examples                  | Introduced in | Works offline  | Enabled by default |
|----------|---------------------------|---------------|----------------|--------------------|
| Workflow  | [pull-request-target.yml] | v0.1.0        | ✅             | ✅                 |

[pull-request-target.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/pull-request-target.yml

Detects fundamentally dangerous GitHub Actions workflow triggers.

Many of GitHub's workflow triggers are difficult to use securely.
This audit checks for some of the biggest offenders:

* `pull_request_target`
* `workflow_run`

These triggers are dangerous because they run in the context of the
*target repository* rather than the *fork repository*, while also being
typically triggerable by the latter. This can lead to attacker controlled
code execution or unexpected action runs with context controlled by a malicious
fork.

Other resources:

* [Keeping your GitHub Actions and workflows secure Part 1: Preventing pwn requests]
* [Vulnerable GitHub Actions Workflows Part 1: Privilege Escalation Inside Your CI/CD Pipeline]

### Remediation

The use of dangerous triggers can be difficult to remediate, since they don't
always have an immediate replacement.

Replacing a dangerous trigger with a safer one (or keeping the dangerous
trigger, but eliminating the risk of code execution) requires case-by-case
consideration.

Some general pointers:

* Replace `workflow_run` triggers with `workflow_call`: this will require
  re-tooling the workflow to be a [reusable workflow].
* Replace `pull_request_target` with `pull_request`, unless you *absolutely*
  need repository write permissions (e.g. to leave a comment or make
  other changes to the upstream repo).
* Never run PR-controlled code in the context of a
  `pull_request_target`-triggered workflow.
* Avoid attacker-controllable flows into `GITHUB_ENV` in both `workflow_run`
  and `pull_request_target` workflows, since these can lead to arbitrary
  code execution.

[reusable workflow]: https://docs.github.com/en/actions/sharing-automations/reusing-workflows

## `excessive-permissions`

| Type     | Examples                    | Introduced in | Works offline  | Enabled by default |
|----------|-----------------------------|---------------|----------------|--------------------|
| Workflow  | [excessive-permissions.yml] | v0.1.0        | ✅             | ✅                 |

[excessive-permissions.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/excessive-permissions.yml

Detects excessive permissions in workflows, both at the workflow level and
individual job levels.

Users frequently over-scope their workflow and job permissions,
or set broad workflow-level permissions without realizing that
all jobs inherit those permissions.

Furthermore, users often don't realize that the
[*default* `GITHUB_TOKEN` permissions can be very broad](https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication#permissions-for-the-github_token),
meaning that workflows that don't configure any permissions at all can *still*
provide excessive credentials to their individual jobs.

### Remediation

In general, permissions should be declared as minimally as possible, and
as close to their usage site as possible.

In practice, this means that workflows should almost always set
`#!yaml permissions: {}` at the workflow level to disable all permissions
by default, and then set specific job-level permissions as needed.

For example:

=== "Before :warning:"

    ```yaml title="excessive-permissions.yml" hl_lines="8-9"
    on:
      release:
        types:
          - published

    name: release

    permissions:
      id-token: write # trusted publishing + attestations

    jobs:
      build:
        name: Build distributions 📦
        runs-on: ubuntu-latest
        steps:
          - # omitted for brevity

      publish:
        name: Publish Python 🐍 distributions 📦 to PyPI
        runs-on: ubuntu-latest
        needs: [build]

        steps:
          - name: Download distributions
            uses: actions/download-artifact@fa0a91b85d4f404e444e00e005971372dc801d16 # v4
            with:
              name: distributions
              path: dist/

          - name: publish
            uses: pypa/gh-action-pypi-publish@release/v1
    ```

=== "After :white_check_mark:"

    ```yaml title="excessive-permissions.yml" hl_lines="8 21-22"
    on:
      release:
        types:
          - published

    name: release

    permissions: {}

    jobs:
      build:
        name: Build distributions 📦
        runs-on: ubuntu-latest
        steps:
          - # omitted for brevity

      publish:
        name: Publish Python 🐍 distributions 📦 to PyPI
        runs-on: ubuntu-latest
        needs: [build]
        permissions:
          id-token: write # trusted publishing + attestations

        steps:
          - name: Download distributions
            uses: actions/download-artifact@fa0a91b85d4f404e444e00e005971372dc801d16 # v4
            with:
              name: distributions
              path: dist/

          - name: publish
            uses: pypa/gh-action-pypi-publish@release/v1
    ```

## `hardcoded-container-credentials`

| Type     | Examples                    | Introduced in | Works offline  | Enabled by default |
|----------|-----------------------------|---------------|----------------|--------------------|
| Workflow  | [hardcoded-credentials.yml] | v0.1.0        | ✅             | ✅                 |

[hardcoded-credentials.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/hardcoded-credentials.yml

Detects Docker credentials (usernames and passwords) hardcoded in various places
within workflows.

### Remediation

Use [encrypted secrets] instead of hardcoded credentials.

[encrypted secrets]: https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions

=== "Before :warning:"

    ```yaml title="hardcoded-container-credentials.yml" hl_lines="11 17"
    on:
      push:

    jobs:
      test:
        runs-on: ubuntu-latest
        container:
          image: fake.example.com/example
          credentials:
            username: user
            password: hackme
        services:
          service-1:
            image: fake.example.com/anotherexample
            credentials:
              username: user
              password: hackme
        steps:
          - run: echo 'hello!'
    ```

=== "After :white_check_mark:"

    ```yaml title="hardcoded-container-credentials.yml" hl_lines="11 17"
    on:
      push:

    jobs:
      test:
        runs-on: ubuntu-latest
        container:
          image: fake.example.com/example
          credentials:
            username: user
            password: ${{ secrets.REGISTRY_PASSWORD }}
        services:
          service-1:
            image: fake.example.com/anotherexample
            credentials:
              username: user
              password: ${{ secrets.REGISTRY_PASSWORD }} # (1)!
        steps:
          - run: echo 'hello!'
    ```

    1. This may or may not be the same credential as above, depending on your configuration.


## `impostor-commit`

| Type     | Examples              | Introduced in | Works offline  | Enabled by default |
|----------|-----------------------|---------------|----------------|--------------------|
| Workflow, Action  | [impostor-commit.yml] | v0.1.0        | ❌             | ✅                 |

[impostor-commit.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/impostor-commit.yml

Detects commits within a repository action's network that are not present on
the repository itself, also known as "impostor" commits.

GitHub represents a repository and its forks as a "network" of commits.
This results in ambiguity about where a commit comes from: a commit
that exists only in a fork can be referenced via its parent's
`owner/repo` slug, and vice versa.

GitHub's network-of-forks design can be used to obscure a commit's true origin
in a fully-pinned `uses:` workflow reference. This can be used by an attacker
to surreptitiously introduce a backdoored action into a victim's workflows(s).

A notable historical example of this is github/dmca@565ece486c7c1652754d7b6d2b5ed9cb4097f9d5,
which appears to be on @github/dmca is but really on a fork (with an impersonated
commit author).

Other resources:

* [What the fork? Imposter commits in GitHub Actions and CI/CD]

### Remediation

Impostor commits are **visually indistinguishable** from normal best-practice
hash-pinned actions.

Always **carefully review** external PRs that add or change
hash-pinned actions by consulting the claimant repository and confirming that
the commit actually exists within it.

The only remediation, once discovered, is to replace the impostor commit
within an authentic commit (or an authentic tag/branch reference).

## `known-vulnerable-actions`

| Type             | Examples                       | Introduced in | Works offline  | Enabled by default |
|------------------|--------------------------------|---------------|----------------|--------------------|
| Workflow, Action | [known-vulnerable-actions.yml] | v0.1.0        | ❌             | ✅                 |

[known-vulnerable-actions.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/known-vulnerable-actions.yml

Detects actions with known, publicly disclosed vulnerabilities that are tracked
in the [GitHub Advisories database]. Examples of commonly disclosed
vulnerabilities in GitHub Actions include [credential disclosure] and code
injection via [template injection].

[GitHub Advisories database]: https://github.com/advisories

[credential disclosure]: #artipacked

[template injection]: #template-injection

### Remediation

If the vulnerability is applicable to your use: upgrade to a fixed version of
the action if one is available, or remove the action's usage entirely.

## `ref-confusion`

| Type             | Examples            | Introduced in | Works offline  | Enabled by default |
|------------------|---------------------|---------------|----------------|--------------------|
| Workflow, Action | [ref-confusion.yml] | v0.1.0        | ❌             | ✅                 |


[ref-confusion.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/ref-confusion.yml

Detects actions that are pinned to confusable symbolic refs (i.e. branches
or tags).

Like with [impostor commits], actions that are used with a symbolic ref
in their `uses:` are subject to a degree of ambiguity: a ref like
`@v1` might refer to either a branch or tag ref.

An attacker can exploit this ambiguity to publish a branch or tag ref that
takes precedence over a legitimate one, delivering a malicious action to
pre-existing consumers of that action without having to modify those consumers.

[impostor commits]: #impostor-commit

### Remediation

Switch to hash-pinned actions.

## `self-hosted-runner`

| Type     | Examples            | Introduced in | Works offline  | Enabled by default |
|----------|---------------------|---------------|----------------|--------------------|
| Workflow  | [self-hosted.yml] | v0.1.0        | ✅             | ❌                 |

[self-hosted.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/self-hosted.yml

!!! note

    This is a `--pedantic` only audit, due to `zizmor`'s limited ability
    to analyze runner configurations themselves. See #34 for more details.

Detects self-hosted runner usage within workflows.

GitHub supports self-hosted runners, which behave similarly to GitHub-hosted
runners but use client-managed compute resources.

Self-hosted runners are very hard to secure by default, which is why
GitHub does not recommend their use in public repositories.

Other resources:

* [Self-hosted runner security]

### Remediation

In general, self-hosted runners should only be used on private repositories.
Exposing self-hosted runners to potential public use is *always* a security
risk.

In practice, there are many cases (such as custom host configurations) where
a self-hosted runner is needed on a public repository. In these cases,
there are steps you can take to minimize their risk:

1. Require manual approval on workflows for all external contributors.
   This can be configured at repository, workflow, or enterprise-wide
   levels. See [GitHub's docs] for more information.
1. Use only [ephemeral ("just-in-time") runners]. These runners are
   created just-in-time to perform one job and are destroyed immediately
   afterwards, making it harder (but not impossible) for an attacker to
   maintain persistence.

[GitHub's docs]: https://docs.github.com/en/actions/managing-workflow-runs-and-deployments/managing-workflow-runs/approving-workflow-runs-from-public-forks

[ephemeral ("just-in-time") runners]: https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#using-just-in-time-runners

## `template-injection`

| Type     | Examples                 | Introduced in | Works offline  | Enabled by default |
|----------|--------------------------|---------------|----------------|--------------------|
| Workflow, Action  | [template-injection.yml] | v0.1.0        | ✅             | ✅                 |

[template-injection.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/template-injection.yml

Detects potential sources of code injection via template expansion.

GitHub Actions allows workflows to define *template expansions*, which
occur within special `${{ ... }}` delimiters. These expansions happen
before workflow and job execution, meaning the expansion
of a given expression appears verbatim in whatever context it was performed in.

Template expansions aren't syntax-aware, meaning that they can result in
unintended shell injection vectors. This is especially true when they're
used with attacker-controllable expression contexts, such as
`github.event.issue.title` (which the attacker can fully control by supplying
a new issue title).

Other resources:

* [Keeping your GitHub Actions and workflows secure Part 2: Untrusted input]

### Remediation

The most common forms of template injection are in `run:` and similar
code-execution blocks. In these cases, an inline template expansion
can typically be replaced by an environment variable whose value comes
from the expanded template.

This avoids the vulnerability, since variable expansion is subject to normal
shell quoting/expansion rules.

!!! tip

    To fully remediate the vulnerability, you **should not** use
    `${{ env.VARNAME }}`, since that is still a template expansion.
    Instead, you should use `${VARNAME}` to ensure that the shell *itself*
    performs the variable expansion.


!!! tip

    When switching to `${VARNAME}`, keep in mind that different shells have
    different environment variable syntaxes. In particular, Powershell (the
    default shell on Windows runners) uses `${env:VARNAME}`.

    To avoid having to specialize your handling for different runners,
    you can set `shell: sh` or `shell: bash`.

=== "Before :warning:"

    ```yaml title="template-injection.yml" hl_lines="3"
    - name: Check title
      run: |
        title="${{ github.event.issue.title }}"
        if [[ ! $title =~ ^.*:\ .*$ ]]; then
          echo "Bad issue title"
          exit 1
        fi
    ```

=== "After :white_check_mark:"

    ```yaml title="template-injection.yml" hl_lines="3 8-9"
    - name: Check title
      run: |
        title="${ISSUE_TITLE}"
        if [[ ! $title =~ ^.*:\ .*$ ]]; then
          echo "Bad issue title"
          exit 1
        fi
      env:
        ISSUE_TITLE: ${{ github.event.issue.title }}
    ```

## `use-trusted-publishing`

| Type     | Examples                     | Introduced in | Works offline  | Enabled by default |
|----------|------------------------------|---------------|----------------|--------------------|
| Workflow  | [pypi-manual-credential.yml] | v0.1.0        | ✅             | ✅                 |

[pypi-manual-credential.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/pypi-manual-credential.yml

Detects packaging workflows that could use [Trusted Publishing].

Some packaging ecosystems/indices (like [PyPI] and [RubyGems]) support
"Trusted Publishing," which is an OIDC-based "tokenless" authentication
mechanism for uploading to the index from within a CI/CD workflow.

This "tokenless" flow has significant security benefits over a traditional
manually configured API token, and should be preferred wherever supported
and possible.

[Trusted Publishing]: https://repos.openssf.org/trusted-publishers-for-all-package-repositories.html

[PyPI]: https://pypi.org

[RubyGems]: https://rubygems.org

Other resources:

* [Trusted Publishers for All Package Repositories]
* [Publishing to PyPI with a Trusted Publisher]
* [Trusted Publishing - RubyGems Guides]
* [Trusted publishing: a new benchmark for packaging security]

### Remediation

In general, enabling Trusted Publishing requires a one-time change to your
package's configuration on its associated index (e.g. PyPI or RubyGems).

Once your Trusted Publisher is registered, see @pypa/gh-action-pypi-publish
or @rubygems/release-gem for canonical examples of using it.

## `unpinned-uses`

| Type             | Examples                     | Introduced in | Works offline  | Enabled by default |
|------------------|------------------------------|---------------|----------------|--------------------|
| Workflow, Action | [unpinned.yml]              | v0.4.0        | ✅             | ✅                 |

[unpinned.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/unpinned.yml

Detects "unpinned" `uses:` clauses.

When a `uses:` clause is not pinned by branch, tag, or SHA reference,
GitHub Actions will use the latest commit on the referenced repository
(or, in the case of Docker actions, the `:latest` tag).

This can represent a (small) security risk, as it leaves the calling workflow
at the mercy of the callee action's default branch.

When used with `--pedantic`, this audit will also flag pinned-but-unhashed
`uses:`. For example, `actions/checkout@v4` will not be flagged by default,
but would be flagged with `--pedantic`.

### Remediation

For repository actions (like @actions/checkout): add a branch, tag, or SHA
reference.

For Docker actions (like `docker://ubuntu`): add an appropriate
`:{version}` suffix.

A before/after example is shown below.

=== "Before :warning:"

    ```yaml title="unpinned-uses.yml" hl_lines="8 12"
    name: unpinned-uses
    on: [push]

    jobs:
    unpinned-uses:
        runs-on: ubuntu-latest
        steps:
        - uses: actions/checkout
          with:
          persist-credentials: false

        - uses: docker://ubuntu
          with:
          entrypoint: /bin/echo
          args: hello!
    ```

=== "After :white_check_mark:"

    ```yaml title="unpinned-uses.yml" hl_lines="8 12"
    name: unpinned-uses
    on: [push]

    jobs:
    unpinned-uses:
        runs-on: ubuntu-latest
        steps:
        - uses: actions/checkout@v4 # (1)!
          with:
          persist-credentials: false

        - uses: docker://ubuntu:24.04
          with:
          entrypoint: /bin/echo
          args: hello!
    ```

    1. Or `actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683` for a SHA-pinned action.


## `insecure-commands`

| Type     | Examples                | Introduced in | Works offline  | Enabled by default |
|----------|-------------------------|---------------|----------------|--------------------|
| Workflow, Action  | [insecure-commands.yml] | v0.5.0        | ✅             | ✅                 |

[insecure-commands.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/insecure-commands.yml

Detects opt-in for executing insecure workflow commands.

Workflow commands (like `::set-env` and `::add-path`)
[were deprecated by GitHub] in 2020 due to their inherent weaknesses
(e.g., allowing any command with the ability to emit to `stdout`
to inject environment variables and therefore obtain code execution).

However, users can explicitly re-enable them by setting the
`ACTIONS_ALLOW_UNSECURE_COMMANDS` environment variable at the workflow,
job, or step level.

Other resources:

* [Semgrep audit]

### Remediation

In general, users should use for [GitHub Actions environment files]
(like `GITHUB_PATH` and `GITHUB_OUTPUT`) instead of using workflow commands.

=== "Before :warning:"

    ```yaml title="insecure-commands" hl_lines="3"
    - name: Setup my-bin
      run: |
        echo "::add-path::$HOME/.local/my-bin"
      env:
        ACTIONS_ALLOW_UNSECURE_COMMANDS: true
    ```

=== "After :white_check_mark:"

    ```yaml title="insecure-commands" hl_lines="3"
    - name: Setup my-bin
      run: |
        echo "$HOME/.local/my-bin" >> "$GITHUB_PATH"
    ```

## `github-env`

| Type     | Examples           | Introduced in | Works offline  | Enabled by default |
|----------|--------------------|---------------|----------------|--------------------|
| Workflow, Action  | [github-env.yml]   | v0.6.0        | ✅             | ✅                 |

[github-env.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/github-env.yml

Detects dangerous writes to the `GITHUB_ENV` and `GITHUB_PATH` environment variables.

When used in workflows with dangerous triggers (such as `pull_request_target` and `workflow_run`),
`GITHUB_ENV` and `GITHUB_PATH` can be an arbitrary code execution risk:

* If the attacker is able to set arbitrary variables or variable contents via
  `GITHUB_ENV`, they may be able to set `LD_PRELOAD` or otherwise induce code
  execution implicitly within subsequent steps.
* If the attacker is able to add an arbitrary directory to the `$PATH` via
  `GITHUB_PATH`, they may be able to execute arbitrary code by shadowing
  ordinary system executables (such as `ssh`).

Other resources:

* [GitHub Actions exploitation: environment manipulation]
* [GHSL-2024-177: Environment Variable injection in an Actions workflow of Litestar]
* [Google & Apache Found Vulnerable to GitHub Environment Injection]
* [Hacking with Environment Variables]

### Remediation

In general, you should avoid modifying `GITHUB_ENV` and `GITHUB_PATH` within
sensitive workflows that are attacker-triggered, like `pull_request_target`.

If you absolutely must use `GITHUB_ENV` or `GITHUB_PATH`, avoid passing
attacker-controlled values into either. Stick with literal strings and
values computed solely from trusted sources.

If you need to pass state between steps, consider using `GITHUB_OUTPUT` instead.

## `cache-poisoning`

| Type     | Examples                | Introduced in | Works offline  | Enabled by default |
|----------|-------------------------|---------------|----------------|--------------------|
| Workflow  | [cache-poisoning.yml]   | v0.10.0       | ✅             | ✅                 |

[cache-poisoning.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/cache-poisoning.yml

Detects potential cache-poisoning scenarios in release workflows.

Caching and restoring build state is a process eased by utilities provided
by GitHub, in particular @actions/cache and its "save" and "restore"
sub-actions. In addition, many of the setup-like actions provided
by GitHub come with built-in caching functionality, like @actions/setup-node,
@actions/setup-java and others.

Furthermore, there are many examples of community-driven Actions with built-in
caching functionality, like @ruby/setup-ruby, @astral-sh/setup-uv,
@Swatinem/rust-cache. In general, most of them build on top of @actions/toolkit
for the sake of easily integrate with GitHub cache server at Workflow runtime.

This vulnerability happens when release workflows leverage build state cached
from previous workflow executions, in general on top of the aforementioned
actions or  similar ones. The publication of artifacts usually happens driven
by trigger events like `release` or events with path filters like `push`
(e.g. for tags).

In such scenarios, an attacker with access to a valid `GITHUB_TOKEN` can use it
to poison the repository's GitHub Actions caches. That compounds with the
default behavior of @actions/toolkit during cache restorations, allowing an
attacker to retrieve payloads from poisoned cache entries, hence achieving code
execution at Workflow runtime, potentially compromising ready-to-publish
artifacts.

Other resources:

* [The Monsters in Your Build Cache – GitHub Actions Cache Poisoning]
* [Cacheract: The Monster in your Build Cache]

### Remediation

In general, you should avoid using previously cached CI state within workflows
intended to publish build artifacts:

* Remove cache-aware actions like @actions/cache from workflows that produce
  releases, *or*
* Disable cache-aware actions with an `if:` condition based on the trigger at
  the step level, *or*
* Set an action-specific input to disable cache restoration when appropriate,
  such as `lookup-only` in @Swatinem/rust-cache.

## `secrets-inherit`

| Type     | Examples                | Introduced in | Works offline  | Enabled by default |
|----------|-------------------------|---------------|----------------|--------------------|
| Workflow  | [secrets-inherit.yml]   | v1.1.0      | ✅             | ✅                 |

[secrets-inherit.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/secrets-inherit.yml

Detects excessive secret inheritance between calling workflows and reusable
(called) workflows.

[Reusable workflows] can be given secrets by their calling workflow either
explicitly, or in a blanket fashion with `secrets: inherit`. The latter
should almost never be used, as it makes it violates the
[Principle of Least Authority] and makes it impossible to determine which exact
secrets a reusable workflow was executed with.

### Remediation

In general, `secrets: inherit` should be replaced with a `secrets:` block
that explicitly forwards each secret actually needed by the reusable workflow.

=== "Before :warning:"

    ```yaml title="reusable.yml" hl_lines="4"
    jobs:
      pass-secrets-to-workflow:
        uses: ./.github/workflows/called-workflow.yml
        secrets: inherit
    ```

=== "After :white_check_mark:"

    ```yaml title="reusable.yml" hl_lines="4-6"
    jobs:
      pass-secrets-to-workflow:
        uses: ./.github/workflows/called-workflow.yml
        secrets:
          forward-me: ${{ secrets.forward-me }}
          me-too: ${{ secrets.me-too }}
    ```

## `bot-conditions`

| Type     | Examples                | Introduced in | Works offline  | Enabled by default |
|----------|-------------------------|---------------|----------------|--------------------|
| Workflow  | [bot-conditions.yml]   | v1.2.0      | ✅             | ✅                 |

[bot-conditions.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/bot-conditions.yml

Detects potentially spoofable bot conditions.

Many workflows allow trustworthy bots (such as [Dependabot](https://github.com/dependabot))
to bypass checks or otherwise perform privileged actions. This is often done
with a `github.actor` check, e.g.:

```yaml
if: github.actor == 'dependabot[bot]'
```

However, this condition is spoofable: `github.actor` refers to the *last* actor
to perform an "action" on the triggering context, and not necessarily
the actor actually causing the trigger. An attacker can take
advantage of this discrepancy to create a PR where the `HEAD` commit
has `github.actor == 'dependabot[bot]'` but the rest of the branch history
contains attacker-controlled code, bypassing the actor check.

Other resources:

* [GitHub Actions exploitations: Dependabot]

### Remediation

In general, checking a trigger's authenticity via `github.actor` is
insufficient. Instead, most users should use `github.event.pull_request.user.login`
or similar, since that context refers to the actor that *created* the Pull Request
rather than the last one to modify it.

More generally,
[GitHub's documentation recommends](https://docs.github.com/en/code-security/dependabot/working-with-dependabot/automating-dependabot-with-github-actions)
not using `pull_request_target` for auto-merge workflows.

=== "Before :warning:"

    ```yaml title="bot-conditions.yml" hl_lines="1 6"
    on: pull_request_target

    jobs:
      automerge:
        runs-on: ubuntu-latest
        if: github.actor == 'dependabot[bot]' && github.repository == github.event.pull_request.head.repo.full_name
        steps:
          - run: gh pr merge --auto --merge "$PR_URL"
            env:
              PR_URL: ${{ github.event.pull_request.html_url }}
              GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    ```

=== "After :white_check_mark:"

    ```yaml title="bot-conditions.yml" hl_lines="1 6"
    on: pull_request

    jobs:
      automerge:
        runs-on: ubuntu-latest
        if: github.event.pull_request.user.login == 'dependabot[bot]' && github.repository == github.event.pull_request.head.repo.full_name
        steps:
          - run: gh pr merge --auto --merge "$PR_URL"
            env:
              PR_URL: ${{ github.event.pull_request.html_url }}
              GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    ```

## `bypassable-contains-conditions`

| Type     | Examples                                       | Introduced in | Works offline | Enabled by default |
|----------|------------------------------------------------|---------------|---------------|--------------------|
| Workflow | [bypassable-contains-conditions.yml]           | v1.5.0        | ✅            | ✅                 |

[bypassable-contains-conditions.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/bypassable-contains-conditions.yml

Detects conditions that use the `contains()` function in a way that make it possible to bypassing.

Some workflows use `contains()` to check if a context variable is in a list of
values (e.g., if the the `push` that triggered the job targeted a certain
branch), and then bypass checks or otherwise perform privileged actions:

```yaml
if: contains('refs/heads/main refs/heads/develop', github.ref)
```

However, this condition will not only evaluate to `true` if either
`refs/heads/main` or `refs/heads/develop` is passed, but also for substrings of
those values. For example, if someone pushes to a branch named `mai`, then
`github.ref` would contain the string `refs/heads/mai` and the job would also
execute.

### Remediation

To check if a value is contained in a list of strings, the first argument to
`contains()` should be an actual list, not a string. This can be done by using
the `fromJSON()` function:

```yaml
if: contains(fromJSON('["refs/heads/main", "refs/heads/develop"]'), github.ref)
```

Alternative, it's possible to check for equality individually and combine the
results using the logical "or" operator:

```yaml
if: github.ref == "refs/heads/main" || github.ref == "refs/heads/develop"
```

Other resources:

* [GitHub Docs: Evaluate expressions in workflows and actions - Example matching an array of strings]

=== "Before :warning:"

    ```yaml title="bypassable-contains-conditions.yml" hl_lines="9 10"
    on: push

    jobs:
      tf-deploy:
        runs-on: ubuntu-latest
        steps:
          - run: terraform init -input=false
          - run: terraform plan -out=tfplan -input=false
          - run: terraform apply -input=false tfplan
            if: contains('refs/heads/main refs/heads/develop', github.ref)
    ```

=== "After :white_check_mark:"

    ```yaml title="bot-conditions.yml" hl_lines="1 6"
    on: push

    jobs:
      tf-deploy:
        runs-on: ubuntu-latest
        steps:
          - run: terraform init -input=false
          - run: terraform plan -out=tfplan -input=false
          - run: terraform apply -input=false tfplan
            if: contains(fromJSON('["refs/heads/main", "refs/heads/develop"]'), github.ref)
    ```

## `overprovisioned-secrets`

| Type     | Examples                | Introduced in | Works offline  | Enabled by default |
|----------|-------------------------|---------------|----------------|--------------------|
| Workflow, Action  | [overprovisioned-secrets.yml]   | v1.3.0      | ✅             | ✅                 |

[overprovisioned-secrets.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/overprovisioned-secrets.yml

Detects excessive sharing of the `secrets` context.

Typically, users access the `secrets` context via its individual members:

```yaml
env:
  SECRET_ONE: ${{ secrets.SECRET_ONE }}
  SECRET_TWO: ${{ secrets.SECRET_TWO }}
```

This allows the Actions runner to only expose the secrets actually used by
the workflow to the job environment.

However, if the user instead accesses the *entire* `secrets` context:

```yaml
env:
  SECRETS: ${{ toJson(secrets) }}
```

...then the entire `secrets` context is exposed to the runner, even if
only a single secret is actually needed.

### Remediation

In general, users should avoid loading the entire `secrets` context.
Secrets should be accessed individually by name.

=== "Before :warning:"

    ```yaml title="overprovisioned.yml" hl_lines="7"
    jobs:
      deploy:
        runs-on: ubuntu-latest
        steps:
          - run: ./deploy.sh
            env:
              SECRETS: ${{ toJSON(secrets) }}
    ```

=== "After :white_check_mark:"

    ```yaml title="overprovisioned.yml" hl_lines="7-8"
    jobs:
      deploy:
        runs-on: ubuntu-latest
        steps:
          - run: ./deploy.sh
            env:
              SECRET_ONE: ${{ secrets.SECRET_ONE }}
              SECRET_TWO: ${{ secrets.SECRET_TWO }}
    ```

## `unredacted-secrets`

| Type     | Examples                | Introduced in | Works offline  | Enabled by default |
|----------|-------------------------|---------------|----------------|--------------------|
| Workflow, Action  | [unredacted-secrets.yml]   | v1.4.0      | ✅             | ✅                 |

[unredacted-secrets.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/unredacted-secrets.yml

Detects potential secret leakage via redaction failures.

Typically, users access the `secrets` context via its individual members:

```yaml
env:
  PASSWORD: ${{ secrets.PASSWORD }}
```

This allows the Actions runner to redact the secret values from the job logs,
as it knows the exact string value of each secret.

However, if the user instead treats the secret as a structured value,
e.g. JSON:

```yaml
env:
  PASSWORD: ${{ fromJSON(secrets.MY_SECRET).password }}
```

...then the `password` field is not redacted, as the runner does not
treat arbitrary substrings of secrets as secret values.

Other resources:

* [Using secrets in GitHub Actions]

### Remediation

In general, users should avoid treating secrets as structured values.
For example, instead of storing a JSON object in a secret, store the
individual fields as separate secrets.

=== "Before :warning:"

    ```yaml title="unredacted-secrets.yml" hl_lines="7-8"
    jobs:
      deploy:
        runs-on: ubuntu-latest
        steps:
          - run: ./deploy.sh
            env:
              USERNAME: ${{ fromJSON(secrets.MY_SECRET).username }}
              PASSWORD: ${{ fromJSON(secrets.MY_SECRET).password }}
    ```

=== "After :white_check_mark:"

    ```yaml title="unredacted-secrets.yml" hl_lines="7-8"
    jobs:
      deploy:
        runs-on: ubuntu-latest
        steps:
          - run: ./deploy.sh
            env:
              USERNAME: ${{ secrets.MY_SECRET_USERNAME }}
              PASSWORD: ${{ secrets.MY_SECRET_PASSWORD }}
    ```


[ArtiPACKED: Hacking Giants Through a Race Condition in GitHub Actions Artifacts]: https://unit42.paloaltonetworks.com/github-repo-artifacts-leak-tokens/
[Keeping your GitHub Actions and workflows secure Part 1: Preventing pwn requests]: https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/
[What the fork? Imposter commits in GitHub Actions and CI/CD]: https://www.chainguard.dev/unchained/what-the-fork-imposter-commits-in-github-actions-and-ci-cd
[Self-hosted runner security]: https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security
[Keeping your GitHub Actions and workflows secure Part 2: Untrusted input]: https://securitylab.github.com/resources/github-actions-untrusted-input/
[Publishing to PyPI with a Trusted Publisher]: https://docs.pypi.org/trusted-publishers/
[Trusted Publishing - RubyGems Guides]: https://guides.rubygems.org/trusted-publishing/
[Trusted publishing: a new benchmark for packaging security]: https://blog.trailofbits.com/2023/05/23/trusted-publishing-a-new-benchmark-for-packaging-security/
[Trusted Publishers for All Package Repositories]: https://repos.openssf.org/trusted-publishers-for-all-package-repositories.html
[were deprecated by GitHub]: https://github.blog/changelog/2020-10-01-github-actions-deprecating-set-env-and-add-path-commands/
[GitHub Actions environment files]: https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/workflow-commands-for-github-actions#environment-files
[Semgrep audit]: https://semgrep.dev/r?q=yaml.github-actions.security.allowed-unsecure-commands.allowed-unsecure-commands
[GitHub Actions exploitation: environment manipulation]: https://www.synacktiv.com/en/publications/github-actions-exploitation-repo-jacking-and-environment-manipulation
[GitHub Docs: Evaluate expressions in workflows and actions - Example matching an array of strings]: https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/evaluate-expressions-in-workflows-and-actions#example-matching-an-array-of-strings
[GHSL-2024-177: Environment Variable injection in an Actions workflow of Litestar]: https://securitylab.github.com/advisories/GHSL-2024-177_Litestar/
[Vulnerable GitHub Actions Workflows Part 1: Privilege Escalation Inside Your CI/CD Pipeline]: https://www.legitsecurity.com/blog/github-privilege-escalation-vulnerability
[Google & Apache Found Vulnerable to GitHub Environment Injection]: https://www.legitsecurity.com/blog/github-privilege-escalation-vulnerability-0
[Hacking with Environment Variables]: https://www.elttam.com/blog/env/
[The Monsters in Your Build Cache – GitHub Actions Cache Poisoning]: https://adnanthekhan.com/2024/05/06/the-monsters-in-your-build-cache-github-actions-cache-poisoning/
[reusable workflows]: https://docs.github.com/en/actions/sharing-automations/reusing-workflows
[Principle of Least Authority]: https://en.wikipedia.org/wiki/Principle_of_least_privilege
[Cacheract: The Monster in your Build Cache]: https://adnanthekhan.com/2024/12/21/cacheract-the-monster-in-your-build-cache/
[GitHub Actions exploitations: Dependabot]: https://www.synacktiv.com/publications/github-actions-exploitation-dependabot
[Using secrets in GitHub Actions]: https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions
