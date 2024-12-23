---
description: Usage recipes for running zizmor locally and in CI/CD.
---

# Usage Recipes

## Input collection

Before auditing, `zizmor` performs an input collection phase.

There are three input sources that `zizmor` knows about:

1. Individual workflow and composite action files, e.g. `foo.yml` and
   `my-action/action.yml`;
2. "Local" GitHub repositories in the form of a directory, e.g. `my-repo/`;
3. "Remote" GitHub repositories in the form of a "slug", e.g.
   `pypa/sampleproject`.

    !!! tip

        By default, a remote repository will be audited from the `HEAD`
        of the default branch. To control this, you can append a `git`
        reference to the slug:

        ```bash
        # audit at HEAD on the default branch
        zizmor example/example

        # audit at branch or tag `v1`
        zizmor example/example@v1

        # audit at a specific SHA
        zizmor example/example@abababab...
        ```

    !!! tip

        Remote auditing requires Internet access and a GitHub API token.
        See [Operating Modes](#operating-modes) for more information.

`zizmor` can audit multiple inputs in the same run, and different input
sources can be mixed and matched:

```bash
# audit a single local workflow, an entire local repository, and
# a remote repository all in the same run
zizmor ../example.yml ../other-repo/ example/example
```

When auditing local and/or remote repositories, `zizmor` will collect both
workflows (e.g. `.github/workflows/ci.yml`) **and** action definitions
(e.g. `custom-action/foo.yml`) by default. To disable one or the other,
you can use the `--collect=...` option.

```bash
# collect everything (the default)
zizmor --collect=all example/example

# collect only workflows
zizmor --collect=workflows-only example/example

# collect only actions
zizmor --collect=actions-only example/example
```

!!! tip

    `--collect=...` only controls input collection from repository input
    sources. In other words, `zizmor --collect=actions-only workflow.yml`
    *will* audit `workflow.yml`, since it was passed explicitly and not
    collected indirectly.

## Operating Modes

Some of `zizmor`'s audits require access to GitHub's API.
`zizmor` will perform online audits by default *if* the user has a `GH_TOKEN`
specified in their environment. If no `GH_TOKEN` is present, then `zizmor`
will operate in offline mode by default.

Both of these can be made explicit through their respective command-line flags:

```bash
# force offline, even if a GH_TOKEN is present
# this disables all online actions, including repository fetches
zizmor --offline workflow.yml

# passing a token explicitly will enable online mode
zizmor --gh-token ghp-... workflow.yml

# online for the purpose of fetching the input (example/example),
# but all audits themselves are offline
zizmor --no-online-audits --gh-token ghp-... example/example
```

## Output formats

`zizmor` always produces output on `stdout`.

By default, `zizmor` produces `cargo`-style diagnostic output. This output
will be colorized by default when sent to a supporting terminal and
uncolorized by default when piped to another program. Users can also explicitly
disable output colorization by setting `NO_COLOR=1` in their environment.

Apart from the default, `zizmor` supports JSON and [SARIF] as machine-readable
output modes. These can be selected via the `--format` option:

Output formats can be controlled explicitly via the `--format` option:

```bash
# use the default diagnostic output explicitly
zizmor --format plain

# emit zizmor's own JSON format
zizmor --format json

# emit SARIF JSON instead of normal JSON
zizmor --format sarif
```

See [Integration](#integration) for suggestions on when to use each format.

## Exit codes

!!! note

    Exit codes 10 and above are **not used** if `--no-exit-codes` or
    `--format sarif` is passed.

`zizmor` uses various exit codes to summarize the results of a run:

| Code | Meaning |
| ---- | ------- |
| 0    | Successful audit; no findings to report (or SARIF mode enabled). |
| 1    | Error during audit; consult output. |
| 10   | One or more findings found; highest finding is "unknown" level. |
| 11   | One or more findings found; highest finding is "informational" level. |
| 12   | One or more findings found; highest finding is "low" level. |
| 13   | One or more findings found; highest finding is "medium" level. |
| 14   | One or more findings found; highest finding is "high" level. |

All other exit codes are currently reserved.

## Using personas

!!! tip

    `--persona=...` is available in `v0.7.0` and later.

`zizmor` comes with three pre-defined "personas," which dictate how
sensitive `zizmor`'s analyses are:

* The _regular persona_: the user wants high-signal, low-noise, actionable
  security findings. This persona is best for ordinary local use as well as use
  in most CI/CD setups, which is why it's the default.

    !!! note

        This persona can be made explicit with `--persona=regular`,
        although this is not required.


* The _pedantic persona_, enabled by `--persona=pedantic`: the user wants
  *code smells* in addition to regular, actionable security findings.

    This persona is ideal for finding things that are a good idea
    to clean up or resolve, but are likely not immediately actionable
    security findings (or are actionable, but suggest a intentional
    security decision by the workflow/action author).

    For example, using the pedantic persona will flag the following
    with an `unpinned-uses` finding, since it uses a symbolic reference
    as its pin instead of a hashed pin:

    ```yaml
    uses: actions/checkout@v3
    ```

    produces:

    ```console
    $ zizmor --pedantic tests/test-data/unpinned-uses.yml
    help[unpinned-uses]: unpinned action reference
      --> tests/test-data/unpinned-uses.yml:14:9
       |
    14 |       - uses: actions/checkout@v3
       |         ------------------------- help: action is not pinned to a hash ref
       |
       = note: audit confidence → High
    ```

    !!! tip

        This persona can also be enabled with `--pedantic`, which is
        an alias for `--persona=pedantic`.

* The _auditor persona_, enabled by `--persona=auditor`: the user wants
  *everything* flagged by `zizmor`, including findings that are likely
  to be false positives.

    This persona is ideal for security auditors and code reviewers, who
    want to go through `zizmor`'s findings manually with a fine-toothed comb.

    Some audits, notably `self-hosted-runner`, *only* produce auditor-level
    results. This is because these audits require runtime context that `zizmor`
    lacks access to by design, meaning that their results are always
    subject to false positives.

    For example, with the default persona:

    ```console
    $ zizmor tests/test-data/self-hosted.yml
    🌈 completed self-hosted.yml
    No findings to report. Good job! (1 suppressed)
    ```

    and with `--persona=auditor`:

    ```console
    $ zizmor --persona=auditor tests/test-data/self-hosted.yml
    note[self-hosted-runner]: runs on a self-hosted runner
      --> tests/test-data/self-hosted.yml:8:5
        |
      8 |     runs-on: [self-hosted, my-ubuntu-box]
        |     ------------------------------------- note: self-hosted runner used here
        |
        = note: audit confidence → High

      1 finding: 1 unknown, 0 informational, 0 low, 0 medium, 0 high
    ```

## Filtering results

There are two straightforward ways to filter `zizmor`'s results:

1. If all you need is severity or confidence filtering (e.g. "I want only
   medium-severity and/or medium-confidence and above results"), then you can use
   the `--min-severity` and `--min-confidence` flags:

    !!! tip

        `--min-severity` and `--min-confidence` are available in `v0.6.0` and later.

     ```bash
     # filter unknown, informational, and low findings with unknown, low confidence
     zizmor --min-severity=medium --min-confidence=medium ...
     ```

2. If you need more advanced filtering (with nontrivial conditions or
   state considerations), then consider using `--format=json` and using
   `jq` (or a script) to perform your filtering.

     As a starting point, here's how you can use `jq` to filter `zizmor`'s
     JSON output to only results that are marked as "high confidence":

     ```bash
     zizmor --format=json ... | jq 'map(select(.determinations.confidence == "High"))'
     ```

## Ignoring results

`zizmor`'s defaults are not always 100% right for every possible use case.

If you find that `zizmor` produces findings that aren't right for you
(and **aren't** false positives, which should be reported!), then you can
choose to *selectively ignore* results via either special ignore comments
*or* a `zizmor.yml` configuration file.

### With comments

!!! note

    Ignore comment support was added in `v0.6.0`.

Findings can be ignored inline with `# zizmor: ignore[rulename]` comments.
This is ideal for one-off ignores, where a whole `zizmor.yml` configuration
file would be too heavyweight.

Multiple different audits can be ignored with a single comment by
separating each rule with a comma, e.g.
`# zizmor: ignore[artipacked,ref-confusion]`.

These comments can be placed anywhere in any span identified by a finding.

For example, to ignore a single `artipacked` finding:

```yaml title="example.yml"
uses: actions/checkout@v3 # zizmor: ignore[artipacked]
```

### With `zizmor.yml`

When ignoring multiple findings (or entire files), a `zizmor.yml` configuration
file is easier to maintain than one-off comments.

Here's what a `zizmor.yml` file might look like:

```yaml title="zizmor.yml"
rules:
  template-injection:
    ignore:
      - safe.yml
      - somewhat-safe.yml:123
      - one-exact-spot.yml:123:456
```

Concretely, this `zizmor.yml` configuration declares three ignore rules,
all for the [`template-injection`](./audits.md#template-injection) audit:

1. Ignore all findings in `safe.yml`, regardless of line/column location
2. Ignore *any* findings in `somewhat-safe.yml` that occur on line 123
3. Ignore *one* finding in `one-exact-spot.yml` that occurs on line 123, column 456

More generally, the filename ignore syntax is `workflow.yml:line:col`, where
`line` and `col` are both optional and 1-based (meaning `foo.yml:1:1`
is the start of the file, not `foo.yml:0:0`).

To pass a configuration to `zizmor`, you can either place `zizmor.yml`
somewhere where `zizmor` [will discover it], or pass it explicitly via
the `--config` argument. With `--config`, the file can be named anything:

```bash
zizmor --config my-zizmor-config.yml /dir/to/audit
```

[will discover it]: ./configuration.md#precedence

See [Configuration: `rules.<id>.ignore`](./configuration.md#rulesidignore) for
more details on writing ignore rules.

## Caching between runs

!!! tip

    Persistent caching (between runs of `zizmor`) is available in `v0.10.0` and later.

!!! warning

    Caches can contain sensitive metadata, especially when auditing private
    repositories! Think twice before sharing your cache or reusing
    it across machine/visibility boundaries.

`zizmor` caches HTTP responses from GitHub's REST APIs to speed up individual
audits. This HTTP cache is persisted and re-used between runs as well.

By default `zizmor` will cache to an appropriate user-level caching directory:

* Linux and macOS: `$XDG_CACHE_DIR` (`~/.cache/zizmor` by default)
* Windows: `~\AppData\Roaming\woodruffw\zizmor`.

To override the default caching directory, pass `--cache-dir`:

```bash
# cache in /tmp instead
zizmor --cache-dir /tmp/zizmor ...
```

## Integration

### Use in GitHub Actions

`zizmor` is designed to integrate with GitHub Actions. In particular,
`zizmor --format sarif` specifies [SARIF] as the output format, which GitHub's
code scanning feature uses.

You can integrate `zizmor` into your CI/CD however you please, but one
easy way to do it is with a workflow that connects to
[GitHub's code scanning functionality].

!!! important

    The workflow below performs a [SARIF] upload, which is available for public
    repositories and for GitHub Enterprise Cloud organizations that have
    [Advanced Security]. If neither of these apply to you, then you can
    adapt the workflow to emit JSON or diagnostic output via `--format json`
    or `--format plain` respectively.

```yaml title="zizmor.yml"
name: GitHub Actions Security Analysis with zizmor 🌈

on:
  push:
    branches: ["main"]
  pull_request:
    branches: ["**"]

jobs:
  zizmor:
    name: zizmor latest via PyPI
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      # required for workflows in private repositories
      contents: read
      actions: read
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
        with:
          persist-credentials: false

      - name: Install the latest version of uv
        uses: astral-sh/setup-uv@v5

      - name: Run zizmor 🌈
        run: uvx zizmor --format sarif . > results.sarif # (2)!
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }} # (1)!

      - name: Upload SARIF file
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
          category: zizmor
```

1. Optional: Remove the `env:` block to only run `zizmor`'s offline audits.

2. This installs the [zizmor package from PyPI], since it's pre-compiled
   and therefore completes much faster. You could instead compile `zizmor`
   within CI/CD with `cargo install zizmor`.

For more inspiration, see `zizmor`'s own [repository workflow scan], as well
as GitHub's example of [running ESLint] as a security workflow.

[zizmor package from PyPI]: https://pypi.org/p/zizmor

[SARIF]: https://sarifweb.azurewebsites.net/

[GitHub's code scanning functionality]: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/uploading-a-sarif-file-to-github

[repository workflow scan]: https://github.com/woodruffw/zizmor/blob/main/.github/workflows/zizmor.yml

[running ESLint]: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/uploading-a-sarif-file-to-github#example-workflow-that-runs-the-eslint-analysis-tool

[Advanced Security]: https://docs.github.com/en/get-started/learning-about-github/about-github-advanced-security

### Use with `pre-commit`

`zizmor` can be used with the [`pre-commit`](https://pre-commit.com/) framework.
To do so, add the following to your `.pre-commit-config.yaml` `repos` section:

```yaml
-   repo: https://github.com/woodruffw/zizmor-pre-commit
    rev: v0.10.0 # (1)!
    hooks:
    - id: zizmor
```

1. Don't forget to update this version to the latest `zizmor` release!

This will run `zizmor` on every commit. If you want to run `zizmor` only on
specific files, you can use the `files` option:

```yaml
-   repo:
    ...
    hooks:
    - id: zizmor
      files: ^path/to/audit/.*\.yml$
```

See [`pre-commit`](https://pre-commit.com/) documentation for more information on how to configure
`pre-commit`.
