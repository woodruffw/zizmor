---
description: Audit rules, examples, and remediations.
---

# Audit Rules

This page documents each of the audits currently implemented in `zizmor`.

See each audit's section for its scope, behavior, and other information.

Legend:

| Type     | Examples         | Introduced in | Works offline  | Enabled by default | Configurable |
|----------|------------------|---------------|----------------|--------------------|--------------|
| The kind of audit ("Workflow" or "Action") | Links to vulnerable examples | Added to `zizmor` in this version | The audit works with `--offline` | The audit needs to be explicitly enabled via configuration or an API token | The audit supports custom configuration |

## `artipacked`

| Type     | Examples         | Introduced in | Works offline  | Enabled by default | Configurable |
|----------|------------------|---------------|----------------|--------------------| -------------|
| Workflow  | [artipacked.yml] | v0.1.0        | ✅             | ✅               | ❌           |

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


## `bot-conditions`

| Type     | Examples                | Introduced in | Works offline  | Enabled by default | Configurable |
|----------|-------------------------|---------------|----------------|--------------------| ---------------|
| Workflow  | [bot-conditions.yml]   | v1.2.0      | ✅             | ✅                 | ❌  |

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

!!! example

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


## `cache-poisoning`

| Type     | Examples                | Introduced in | Works offline  | Enabled by default | Configurable |
|----------|-------------------------|---------------|----------------|--------------------| ---------------|
| Workflow  | [cache-poisoning.yml]   | v0.10.0       | ✅             | ✅               | ❌  |

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
* Disable cache-aware actions with an `#!yaml if:` condition based on the trigger at
  the step level, *or*
* Set an action-specific input to disable cache restoration when appropriate,
  such as `lookup-only` in @Swatinem/rust-cache.

## `dangerous-triggers`

| Type     | Examples                  | Introduced in | Works offline  | Enabled by default | Configurable |
|----------|---------------------------|---------------|----------------|--------------------|--------------|
| Workflow  | [pull-request-target.yml] | v0.1.0        | ✅             | ✅                 | ❌         |

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

    `pull_request_target` is only needed to perform privileged actions on
    pull requests from external forks. If you only expect pull requests from
    branches within the same repository, or if you are fine with some functionality
    not working for external pull requests, prefer `pull_request`.

* Automation for Dependabot pull requests can be implemented using `pull_request`,
  but requires setting dedicated [Dependabot secrets]
  and [explicitly specifying needed permissions].

* **Never** run PR-controlled code in the context of a
  `pull_request_target`-triggered workflow.

* Avoid attacker-controllable flows into `GITHUB_ENV` in both `workflow_run`
  and `pull_request_target` workflows, since these can lead to arbitrary
  code execution.

* If you really have to use `pull_request_target`, consider adding a
  [branch filter] to only run the workflow for matching target branches.
  `pull_request_target` uses the workflow file of the target branch of the pull
  request, therefore restricting the target branches reduces the risk of
  a vulnerable `pull_request_target` in a stale or abandoned branch.

* If you have to use a dangerous trigger, consider adding a `github.repository == ...`
  check to only run for your repository but not in forks of your repository
  (in case the user has enabled Actions there). This avoids exposing forks
  to danger in case you fix a vulnerability in the workflow but the fork still
  contains an old vulnerable version.

[reusable workflow]: https://docs.github.com/en/actions/sharing-automations/reusing-workflows

## `excessive-permissions`

| Type     | Examples                    | Introduced in | Works offline  | Enabled by default | Configurable |
|----------|-----------------------------|---------------|----------------|--------------------|---------------|
| Workflow  | [excessive-permissions.yml] | v0.1.0        | ✅             | ✅                 | ❌         |

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

!!! tip

    @GitHubSecurityLab/actions-permissions can help find the minimally required
    permissions.

!!! example

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

## `forbidden-uses`

| Type     | Examples                | Introduced in | Works offline  | Enabled by default | Configurable |
|----------|-------------------------|---------------|----------------|--------------------| ---------------|
| Workflow, Action  | N/A            | v1.6.0        | ✅             | ❌                |  ✅ |

An *opt-in* audit for denylisting/allowlisting specific `#!yaml uses:` clauses.
This is not enabled by default; you must
[configure it](#forbidden-uses-configuration) to use it.

!!! warning

    This audit comes with several limitations that are important to understand:

    * This audit is *opt-in*. You must configure it to use it; it
      **does nothing** by default.
    * This audit (currently) operates on *repository* `#!yaml uses:` clauses,
      e.g. `#!yaml uses: actions/checkout@v4`. It does not operate on Docker
      `#!yaml uses:` clauses, e.g. `#!yaml uses: docker://ubuntu:24.04`. This limitation
      may be lifted in the future.
    * This audit operates on `#!yaml uses:` clauses *as they appear* in the workflow
      and action files. In other words, in *cannot* detect
      [impostor commits](#impostor-commit) or indirect usage of actions
      via manual `git clone` and local path usage.
    * This audit's configuration operates on patterns, just like
      [unpinned-uses](#unpinned-uses). That means that you can't (yet)
      define *exact* matches. For example, you can't forbid `actions/checkout@v4`,
      you have to forbid `actions/checkout`, which forbids all versions.

### Configuration { #forbidden-uses-configuration }

#### `rules.forbidden-uses.config.<allow|deny>`

_Type_: `list`

The `forbidden-uses` audit operates on either an allowlist or denylist
basis:

* In allowlist mode, only the listed `#!yaml uses:` patterns are allowed. All
  non-matching `#!yaml uses:` clauses result in a finding.

    Intended use case: only allowing "known good" actions to be used,
    and forbidding everything else.

* In denylist mode, only the listed `#!yaml uses:` patterns are disallowed. All
  matching `#!yaml uses:` clauses result in a finding.

    Intended use case: permitting all `#!yaml uses:` by default, but explicitly
    forbidding "known bad" actions.

Regardless of the mode used, the patterns allowed are the same as those
in [unpinned-uses](#unpinned-uses-configuration).

!!! example

    The following configuration would allow only actions owned by
    the @actions organization, plus any actions defined in @github/codeql-action:

    ```yaml title="zizmor.yml"
    rules:
      forbidden-uses:
        config:
          allow:
            - actions/*
            - github/codeql-action/*
    ```

!!! example

    The following would allow all actions except for those in the
    @actions organization or defined in @github/codeql-action:

    ```yaml title="zizmor.yml"
    rules:
      forbidden-uses:
        config:
          deny:
            - actions/*
            - github/codeql-action/*
    ```

### Remediation

Either remove the offending `#!yaml uses:` clause or, if intended, add it to
your [configuration](#forbidden-uses-configuration).

## `github-env`

| Type     | Examples           | Introduced in | Works offline  | Enabled by default | Configurable |
|----------|--------------------|---------------|----------------|--------------------| --------------|
| Workflow, Action  | [github-env.yml]   | v0.6.0        | ✅             | ✅       | ❌  |

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


## `hardcoded-container-credentials`

| Type     | Examples                    | Introduced in | Works offline  | Enabled by default | Configurable |
|----------|-----------------------------|---------------|----------------|--------------------|---------------|
| Workflow  | [hardcoded-credentials.yml] | v0.1.0        | ✅             | ✅               | ❌         |

[hardcoded-credentials.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/hardcoded-credentials.yml

Detects Docker credentials (usernames and passwords) hardcoded in various places
within workflows.

### Remediation

Use [encrypted secrets] instead of hardcoded credentials.

[encrypted secrets]: https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions

!!! example

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

| Type     | Examples              | Introduced in | Works offline  | Enabled by default | Configurable |
|----------|-----------------------|---------------|----------------|--------------------|---------------|
| Workflow, Action  | [impostor-commit.yml] | v0.1.0        | ❌             | ✅                 | ❌  |

[impostor-commit.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/impostor-commit.yml

Detects commits within a repository action's network that are not present on
the repository itself, also known as "impostor" commits.

GitHub represents a repository and its forks as a "network" of commits.
This results in ambiguity about where a commit comes from: a commit
that exists only in a fork can be referenced via its parent's
`owner/repo` slug, and vice versa.

GitHub's network-of-forks design can be used to obscure a commit's true origin
in a fully-pinned `#!yaml uses:` workflow reference. This can be used by an attacker
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

## `insecure-commands`

| Type     | Examples                | Introduced in | Works offline  | Enabled by default | Configurable |
|----------|-------------------------|---------------|----------------|--------------------| ---------------|
| Workflow, Action  | [insecure-commands.yml] | v0.5.0        | ✅             | ✅       | ❌  |

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

!!! example

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

## `known-vulnerable-actions`

| Type             | Examples                       | Introduced in | Works offline  | Enabled by default | Configurable |
|------------------|--------------------------------|---------------|----------------|--------------------| ---------------|
| Workflow, Action | [known-vulnerable-actions.yml] | v0.1.0        | ❌             | ✅                 | ❌  |

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

## `obfuscation`

| Type     | Examples                | Introduced in | Works offline  | Enabled by default | Configurable |
|----------|-------------------------|---------------|----------------|--------------------| ---------------|
| Workflow, Action  | N/A   | v1.7.0        | ✅             | ✅                 | ❌  |

Checks for obfuscated usages of GitHub Actions features.

This audit primarily serves to "unstick" other audits, which may fail to detect
functioning but obfuscated usages of GitHub Actions features.

This audit detects a variety of obfuscated usages, including:

* Obfuscated paths within `#!yaml uses:` clauses, including redundant `/`
  separators and uses of `.` or `..` in path segments.
* Obfuscated GitHub expressions, including no-op patterns like
  `fromJSON(toJSON(...))` and calls to `format(...)` where all
  arguments are literal values.

### Remediation

Address the source of obfuscation by simplifying the expression,
`#!yaml uses:` clause, or other obfuscated feature.

!!! example

    === "Before :warning:"

        ```yaml title="obfuscation.yml" hl_lines="8"
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - name: Checkout
                uses: actions/checkout@v4
                with:
                  repository: ${{ format('{0}/{1}', 'octocat', 'hello-world') }}
        ```

    === "After :white_check_mark:"

        ```yaml title="obfuscation.yml" hl_lines="8"
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - name: Checkout
                uses: actions/checkout@v4
                with:
                  repository: octocat/hello-world
        ```


## `overprovisioned-secrets`

| Type     | Examples                | Introduced in | Works offline  | Enabled by default | Configurable |
|----------|-------------------------|---------------|----------------|--------------------| ---------------|
| Workflow, Action  | [overprovisioned-secrets.yml]   | v1.3.0      | ✅     | ✅         | ❌  |

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

!!! example

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


## `ref-confusion`

| Type             | Examples            | Introduced in | Works offline  | Enabled by default | Configurable |
|------------------|---------------------|---------------|----------------|--------------------| ---------------|
| Workflow, Action | [ref-confusion.yml] | v0.1.0        | ❌             | ✅                 | ❌  |


[ref-confusion.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/ref-confusion.yml

Detects actions that are pinned to confusable symbolic refs (i.e. branches
or tags).

Like with [impostor commits], actions that are used with a symbolic ref
in their `#!yaml uses:` are subject to a degree of ambiguity: a ref like
`@v1` might refer to either a branch or tag ref.

An attacker can exploit this ambiguity to publish a branch or tag ref that
takes precedence over a legitimate one, delivering a malicious action to
pre-existing consumers of that action without having to modify those consumers.

[impostor commits]: #impostor-commit

### Remediation

Switch to hash-pinned actions.

## `secrets-inherit`

| Type     | Examples                | Introduced in | Works offline  | Enabled by default | Configurable |
|----------|-------------------------|---------------|----------------|--------------------| ---------------|
| Workflow  | [secrets-inherit.yml]   | v1.1.0      | ✅             | ✅                 | ❌  |

[secrets-inherit.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/secrets-inherit.yml

Detects excessive secret inheritance between calling workflows and reusable
(called) workflows.

[Reusable workflows] can be given secrets by their calling workflow either
explicitly, or in a blanket fashion with `#!yaml secrets: inherit`. The latter
should almost never be used, as it makes it violates the
[Principle of Least Authority] and makes it impossible to determine which exact
secrets a reusable workflow was executed with.

### Remediation

In general, `#!yaml secrets: inherit` should be replaced with a `#!yaml secrets:` block
that explicitly forwards each secret actually needed by the reusable workflow.

!!! example

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



## `self-hosted-runner`

| Type     | Examples            | Introduced in | Works offline  | Enabled by default | Configurable |
|----------|---------------------|---------------|----------------|--------------------| ---------------|
| Workflow  | [self-hosted.yml] | v0.1.0        | ✅             | ❌                 | ❌  |

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

## `stale-action-refs`

| Type     | Examples                | Introduced in | Works offline  | Enabled by default | Configurable |
|----------|-------------------------|---------------|----------------|--------------------|--------------|
| Workflow, Action  | N/A            | v1.7.0        | ❌            | ✅                | ❌          |

Checks for `#!yaml uses:` clauses which pin an action using a SHA reference,
but where that reference does not point to a Git tag.

When using an action commit which is not a Git tag / release version, that commit
might contain bugs or vulnerabilities which have not been publicly documented
because they might have been fixed before the subsequent release. Additionally,
because changelogs are usually only published for releases, it is difficult to
tell which changes of the subsequent release the pinned commit includes.

!!! note

    This is a `--pedantic` only audit because the detected situation is not
    a vulnerability per se. But it might be worth investigating which commit
    the SHA reference points to, and why not a SHA reference pointing to a
    Git tag is used.

    Some action repositories use a "rolling release branch" strategy where
    all commits on a certain branch are considered releases. In such a case
    findings of this audit can likely be ignored.

### Remediation

Change the `#!yaml uses:` clause to pin the action using a SHA reference
which points to a Git tag.


## `template-injection`

| Type     | Examples                 | Introduced in | Works offline  | Enabled by default | Configurable |
|----------|--------------------------|---------------|----------------|--------------------| ---------------|
| Workflow, Action  | [template-injection.yml] | v0.1.0        | ✅             | ✅        | ❌  |

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

The list of action inputs which are vulnerable to injection attacks is
based on [GitHub's CodeQL models](https://github.com/github/codeql/blob/main/actions/ql/lib/ext).

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
    you can set `#!yaml shell: sh` or `#!yaml shell: bash`.

!!! example

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

## `unpinned-images`

| Type     | Examples                | Introduced in | Works offline  | Enabled by default | Configurable |
|----------|-------------------------|---------------|----------------|--------------------|--------------|
| Workflow, Action  | [unpinned-images.yml] | v1.7.0        | ✅            | ✅                | ❌          |

[unpinned-images.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/unpinned-images.yml

Checks for `container.image` values where the image is not pinned by either a tag (other than `latest`) or SHA256.

When image references are unpinned or are pinned to a mutable tag, the
workflow is at risk because the image used will be unpredictable over time.
Changes made to the OCI registry used to source the image may result in untrusted
images gaining access to your workflow.

This can be a security risk:

1. Registries may not consistently enforce immutable image tags
2. Completely unpinned images can be changed at any time by the OCI registry.

By default, this audit applies the following policy:

* Regular findings are created for all image references missing a tag

    ```yaml
    container:
      image: foo/bar
    ```

    or using the `latest` tag:

    ```yaml
    container:
      image: foo/bar:latest
    ```

* Pedantic findings are created for all image references using a tag (`!= latest`) rather than SHA256 hash.

    ```yaml
    container:
      image: foo/bar:not-a-sha256
    ```

Other resources:

- [Aqua: The Challenges of Uniquely Identifying Your Images]
- [GitHub: Safeguard your containers with new container signing capability in GitHub Actions]



### Remediation

Pin the `#!yaml container.image:` value to a specific SHA256 image registry hash.

Many popular registries will display the hash value in their web console or you
can use the command line to determine the hash of an image you have previously pulled
by running `#!bash docker inspect redis:7.4.3 --format='{{.RepoDigests}}'`.

!!! example

    === "Before :warning:"

        ```yaml title="unpinned-images.yml" hl_lines="7-8"
        name: unpinned-images
        on: [push]

        jobs:
          unpinned-image:
            runs-on: ubuntu-latest
            container:
              image: fake.example.com/example
            steps:
              - run: "echo unpinned container!"
        ```

    === "After :white_check_mark:"

        ```yaml title="unpinned-images.yml" hl_lines="7-8"
        name: unpinned-images
        on: [push]

        jobs:
          unpinned-image:
            runs-on: ubuntu-latest
            container:
              image: fake.example.com/example@sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b
            steps:
              - run: "echo pinned container!"
        ```

## `unpinned-uses`

| Type             | Examples         | Introduced in | Works offline  | Enabled by default | Configurable |
|------------------|------------------|---------------|----------------|--------------------|--------------|
| Workflow, Action | [unpinned.yml]   | v0.4.0        | ✅             | ✅                | ✅           |

[unpinned.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/unpinned.yml

Detects "unpinned" `#!yaml uses:` clauses.

When a `#!yaml uses:` clause is not pinned by branch, tag, or SHA reference,
GitHub Actions will use the latest commit on the referenced repository's
default branch (or, in the case of Docker actions, the `:latest` tag).

Similarly, if a `#!yaml uses:` clause is pinned via branch or tag (i.e. a "symbolic
reference") instead of a SHA reference, GitHub Actions will use whatever
commit is at the tip of that branch or tag. GitHub does not have immutable
branches or tags, meaning that the action can change without the symbolic
reference changing.

This can be a security risk:

1. Completely unpinned actions can be changed at any time by the upstream
   repository.
2. Tag- or branch-pinned actions can be changed by the upstream repository,
   either by force-pushing over the tag or updating the branch.

If the upstream repository is trusted, then symbolic references are
often suitable. However, if the upstream repository is not trusted, then
actions should be pinned by SHA reference.

By default, this audit applies the following policy:

* Official GitHub actions namespaces can be pinned by branch or tag.
  In other words, `actions/checkout@v4` is acceptable, but `actions/checkout`
  is not.
* All other actions must be pinned by SHA reference.

This audit can be configured with a custom set of rules, e.g. to
allow symbolic references for trusted repositories or entire namespaces
(e.g. `foocorp/*`). See
[`unpinned-uses` - Configuration](#unpinned-uses-configuration) for details.

Specifying a configuration overrides the default policy above.

Other resources:

* [Palo Alto Networks Unit42: tj-actions/changed-files incident]

### Configuration { #unpinned-uses-configuration }

!!! note

    `unpinned-uses` is configurable in `v1.6.0` and later.

If the default `unpinned-uses` rules isn't suitable for your use case,
you can override it with a custom set of policies.

#### `rules.unpinned-uses.config.policies`

_Type_: `object`

The `rules.unpinned-uses.config.policies` object defines your `unpinned-uses`
policies.

Each member is a `#!yaml pattern: policy` rule, where `pattern` describes which
`#!yaml uses:` clauses to match and `policy` describes how to treat them.

The valid patterns are (in order of specificity):

* `owner/repo/subpath`: match all `#!yaml uses:` clauses that are **exact** matches
  for the `owner/repo/subpath` pattern. The `subpath` can be an arbitrarily
  deep subpath.

    !!! example

        `github/codeql-action/init` matches only `github/codeql-action/init`.

* `owner/repo`: match all `#!yaml uses:` clauses that are **exact** matches for the
  `owner/repo` pattern.

    !!! example

        `actions/cache` matches only @actions/cache,
        **not** `actions/cache/save` or `actions/cache/restore`.

* `owner/repo/*`: match all `#!yaml uses:` clauses that come from the given
  `owner/repo` repository with *any* subpath, including the empty subpath.

    !!! example

        `github/codeql-action/*` matches `github/codeql-action/init`,
        `github/codeql-action/upload-sarif`, and @github/codeql-action itself.

* `owner/*`: match all `#!yaml uses:` clauses that have the given `owner`.

    !!! example

        `actions/*` matches both @actions/checkout and @actions/setup-node.

* `*`: match all `#!yaml uses:` clauses.

    !!! example

        `*` matches @actions/checkout and @pypa/gh-action-pypi-publish.

The valid policies are:

* `hash-pin`: any `#!yaml uses:` clauses that match the associated pattern must be
  fully pinned by SHA reference.
* `ref-pin`: any `#!yaml uses:` clauses that match the associated pattern must be
  pinned either symbolic or SHA reference.
* `any`: no pinning is required for any `#!yaml uses:` clauses that match the associated
  pattern.

If a `#!yaml uses:` clauses matches multiple rules, the most specific one is used
regardless of definition order.

!!! example

    The following configuration contains two rules that could match
    @actions/checkout, but the first one is more specific and therefore gets applied:

    ```yaml title="zizmor.yml"
    rules:
      unpinned-uses:
        config:
          policies:
            actions/checkout: hash-pin
            actions/*: ref-pin
    ```

    In plain English, this policy set says "anything that `#!yaml uses: actions/*` must
    be at least ref-pinned, but @actions/checkout in particular must be hash-pinned."

!!! example

    ```yaml title="zizmor.yml"
    rules:
      unpinned-uses:
        config:
          policies:
            "example/*": hash-pin
            "*": ref-pin
    ```

    In plain English, this policy set says "anything that `#!yaml uses: example/*` must
    be hash-pinned, and anything else must be at least ref-pinned."


!!! important

    If a `#!yaml uses:` clause does not match any rules, then an implicit
    `#!yaml "*": hash-pin` rule is applied. Users can override this implicit rule
    by adding their own `*` rule or a more precise rule, e.g.
    `#!yaml "github/*": ref-pin` for actions under the @github organization.

### Remediation

For repository actions (like @actions/checkout): add a branch, tag, or SHA
reference.

For Docker actions (like `docker://ubuntu`): add an appropriate
`:{version}` suffix.

!!! example

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




## `unredacted-secrets`

| Type     | Examples                | Introduced in | Works offline  | Enabled by default | Configurable |
|----------|-------------------------|---------------|----------------|--------------------| ---------------|
| Workflow, Action  | [unredacted-secrets.yml]   | v1.4.0      | ✅   | ✅                 | ❌  |

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

!!! example

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


## `unsound-contains`

| Type     | Examples                            | Introduced in | Works offline | Enabled by default | Configurable |
|----------|-------------------------------------|---------------|---------------|--------------------|--------------|
| Workflow | [unsound-contains.yml]              | v1.7.0        | ✅            | ✅                 | ❌           |

[unsound-contains.yml]: https://github.com/woodruffw/gha-hazmat/blob/main/.github/workflows/unsound-contains.yml

Detects conditions that use the `contains()` function in a way that can be bypassed.

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

Alternatively, it's possible to check for equality individually and combine the
results using the logical "or" operator:

```yaml
if: github.ref == "refs/heads/main" || github.ref == "refs/heads/develop"
```

Other resources:

* [GitHub Docs: Evaluate expressions in workflows and actions - Example matching an array of strings]

!!! example

    === "Before :warning:"

        ```yaml title="unsound-contains.yml" hl_lines="9 10"
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

        ```yaml title="unsound-contains.yml" hl_lines="9 10"
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


## `use-trusted-publishing`

| Type     | Examples                     | Introduced in | Works offline  | Enabled by default | Configurable |
|----------|------------------------------|---------------|----------------|--------------------| ---------------|
| Workflow  | [pypi-manual-credential.yml] | v0.1.0        | ✅             | ✅                 | ❌  |

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
[Palo Alto Networks Unit42: tj-actions/changed-files incident]: https://unit42.paloaltonetworks.com/github-actions-supply-chain-attack/
[Dependabot secrets]: https://docs.github.com/en/code-security/dependabot/troubleshooting-dependabot/troubleshooting-dependabot-on-github-actions#accessing-secrets
[explicitly specifying needed permissions]: https://docs.github.com/en/code-security/dependabot/troubleshooting-dependabot/troubleshooting-dependabot-on-github-actions#changing-github_token-permissions
[branch filter]: https://docs.github.com/en/actions/writing-workflows/choosing-when-your-workflow-runs/events-that-trigger-workflows#running-your-pull_request_target-workflow-based-on-the-head-or-base-branch-of-a-pull-request
[Aqua: The Challenges of Uniquely Identifying Your Images]: https://www.aquasec.com/blog/docker-image-tags/
[GitHub: Safeguard your containers with new container signing capability in GitHub Actions]: https://github.blog/security/supply-chain-security/safeguard-container-signing-capability-actions/
