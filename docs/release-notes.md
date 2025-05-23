---
description: Abbreviated change notes about each zizmor release.
---

# Release Notes

This page contains _abbreviated_, user-focused release notes for each version
of `zizmor`.

## Next (UNRELEASED)

### New Features 🌈

* `zizmor` now supports generating completions for Nushell (#838)

### Enhancements 🌱

* The [template-injection] audit has been rewritten, and is now significantly
  more precise and general over contexts supplied via GitHub's webhook
  payloads (i.e. `github.event.*`) (#745)
* The [template-injection] audit now detects vulnerable template injections
  in more actions inputs, thanks to an integration with CodeQL's
  sink metadata (#849)

### Bug Fixes 🐛

* The [insecure-commands] now correctly detects different truthy
  values in `ACTIONS_ALLOW_UNSECURE_COMMANDS` (#840)
* The [template-injection] audit now correctly emits pedantic findings
  in a blanket manner, rather than filtering them based on the presence
  of other findings (#745)

## v1.8.0

### Announcements 📣

* `zizmor`'s website has changed! The new website is hosted at
  [docs.zizmor.sh](https://docs.zizmor.sh/). The old website will
  redirect to the new one for a while, but users should update any
  old links in preparation for the v1.8.0 release, which will likely
  remove the redirects entirely (#769)

* `zizmor` is now hosted under the @zizmorcore GitHub organization
  as @zizmorcore/zizmor. The old repository at @woodruffw/zizmor
  will redirect to the new one, but users should update any old
  links to limit confusion

### New Features 🌈

* `zizmor` now supports the `ZIZMOR_CONFIG` environment variable as an
  alternative to `--config` (#789)

### Bug Fixes 🐛

* The [template-injection] audit no longer produces false positive findings
  on alternative representations of the same context pattern.
  For example, `github.event.pull_request.head.sha` is considered safe
  but `github['event']['pull_request']['head']['sha']` was not previously
  detected as equivalent to it (#800, #806)

## v1.7.0

This release comes with **four** new audits: [obfuscation], [stale-action-refs],
[unsound-contains], and [unpinned-images]. It also includes several
improvements to existing audits and zizmor's output formats and error
reporting behavior.

Additionally, this release comes with bugfixes for the SARIF output format
as well as input collection in some edge cases when collecting
from remote repositories.

### New Features 🌈

* **New audit**: The [obfuscation] audit detects obfuscatory patterns in
  GitHub Actions usages. These patterns are not themselves dangerous,
  but may indicate an attempt to obscure malicious behavior (#683)

* **New audit**: The [stale-action-refs] pedantic audit detects pinned
  action references which don't point to a Git tag (#713)

    Many thanks to @Marcono1234 for proposing and implementing this audit!

* **New audit**: The [unsound-contains] audit detects uses of
  the `contains()` function that can be bypassed (#577)

    Many thanks to @Holzhaus for proposing and implementing this audit!

* **New audit**: The [unpinned-images] audit detects uses of
  Docker images that are unpinned or pinned to `:latest` (#733)

    Many thanks to @trumant for proposing and implementing this audit!

* `zizmor` now reports much clearer error messages when auditing fails
  due to an invalid workflow or action definition (#719)

    Many thanks to @reandreev for implementing these improvements!

* `zizmor` now has a `--strict-collection` flag that turns skipped
  workflow or action definition warnings into errors. Passing this
  flag changes `zizmor`'s behavior back to the default in v1.6.0 and earlier,
  which was to terminate the audit if any collected input could
  not be parsed (#734)

* The [forbidden-uses] audit can now be configured with patterns that
  match exact `uses:` clauses, including refs. For example,
  exactly `actions/checkout@v4` can now be explicitly allowed or forbidden,
  rather than every ref that matches `actions/checkout` (#750)

* `zizmor` now has a `--completions=<shell>` flag that generates
  shell completion scripts (#765)

### Bug Fixes 🐛

* The SARIF output format now uses `zizmor/{id}` for rule IDs instead
  of bare IDs, reducing the chance of conflict or confusion with other tools
  (#710)
* The SARIF output format now includes a rule name for each rule descriptor,
  which should improve rendering behavior in SARIF viewers like the
  VS Code SARIF Viewer extension (#710)
* Fixed a bug where `zizmor` would fail to collection actions defined
  within subdirectories of `.github/workflows` when collecting from
  a remote source (#731)

### Upcoming Changes 🚧

* Starting with v1.8.0, `zizmor` will migrate from @woodruffw
  on GitHub to @zizmorcore. This should not cause any breakage
  as GitHub will handle redirects, but users who explicitly reference
  @woodruffw/zizmor should consider updating their references to
  @zizmorcore/zizmor once the migration occurs. See #758 for details.

## v1.6.0

### New Features 🌈

* **New audit**: The [forbidden-uses] audit is a configurable audit
  that allows allow- or denylisting of entire orgs, repos, or specific
  action patterns. This audit must be configured; by default it has
  no effect (#664)

    Many thanks to @Holzhaus for proposing and initiating this new audit!

* `zizmor` now supports `--format=github` as an output format.
  This format produces check annotations via GitHub workflow commands,
  e.g. `::warning` and `::error`. See the
  [Output formats](./usage.md#output-formats) documentation for more information
  on annotations, including key limitations (#634)
* The [unpinned-uses] audit has been completely rewritten, with two key
  changes:

    * The audit now has
      [configurable policies](./audits.md#unpinned-uses-configuration)
      that give users more control over the audit's behavior. In particular,
      users can now define policies that mirror their actual threat model,
      such as trusting their own GitHub organizations while leaving
      others untrusted.
    * The audit's default policy is more precise and conservative:
      official GitHub actions (e.g. those under `actions/*` and similar)
      are allowed to be pinned by branch or tag, but all other actions
      are required to be pinned by SHA. This is a change from the previous
      policy, which was to only flag completely unpinned actions by default.

    Many thanks to @Holzhaus for motivating this change! (#663, #574)

### Improvements 🌱

* The SARIF output format now marks each rule as a "security" rule,
  which helps GitHub's presentation of the results (#631)
* The [template-injection] audit is now performs dataflow analysis
  to determine whether contexts actually expand in an unsafe manner,
  making it significantly more accurate (#640)
* The [cache-poisoning] audit is now aware of @jdx/mise-action (#645)
* The [cache-poisoning] audit is now significantly more accurate
  when analyzing workflows that use @docker/setup-buildx-action (#644)
* `--format=json` is now an alias for `--format=json-v1`, enabling
  future JSON formats. The policy for the `--format=json` alias is
  documented under [Output formats - JSON](./usage.md#json) (#657)
* Configuration file loading is now stricter, and produces a more useful
  error message when the configuration file is invalid (#663)

### Bug Fixes 🐛

* The [template-injection] audit no longer considers
  `github.event.pull_request.head.sha` dangerous (#636)
* Fixed a bug where `zizmor` would fail to parse workflows
  with `workflow_call` triggers that specified inputs without the
  `required` field being present (#646)
* Fixed a bug where `zizmor` would fail to parse workflows with
  `pull_request` or `pull_request_target` triggers that specified
  `types` as a scalar value (#653)
* Fixed a crash where `zizmor` would fail to generate correct concrete
  location spans for YAML inputs with comments inside block sequences (#660)
* The [template-injection] audit no longer considers
  `github.job` dangerous (#661)
* The [template-injection] audit no longer considers
  `github.event.pull_request.head.repo.fork` dangerous (#675)

## v1.5.2

### Bug Fixes 🐛

* Fixed a bug where `zizmor` would over-eagerly parse invalid and
  commented-out expressions, resulting in spurious warnings (#570)
* Fixed a bug where `zizmor` would fail to honor `# zizmor: ignore[rule]`
  comments in unintuitive cases (#612)
* Fixed a regression in `zizmor`'s SARIF output format that caused suboptimal
  presentation of findings on GitHub (#621)

### Upcoming Changes 🚧

* The official [PyPI builds](./installation.md#pypi) for `zizmor`
  will support fewer architectures in the next release, due to
  cross-compilation and testing difficulties. This should have
  **no effect** on the overwhelming majority of users.
  See #603 for additional details.

## v1.5.1

### Bug Fixes 🐛

* Fixed a bug where `zizmor` would fail to honor `.gitignore` files
  when a `.git/` directory is not present (#598)

## v1.5.0

### New Features 🌈

* The [overprovisioned-secrets] audit now detects indexing operations
  on the `secrets` context that result in overprovisioning (#573)
* `zizmor` now ignores patterns in `.gitignore` (and related files,
  like `.git/info/exclude`) by default when performing input collection.
  This makes input collection significantly faster for users
  with local development state and more closely reflects typical
  user expectations. Users who wish to explicitly collect everything
  regardless of ignore patterns can continue to use `--collect=all`
  (#575)
* `zizmor` now has a `--no-progress` flag that disables
  progress bars, even if the terminal supports them (#589)
* `zizmor` now has a `--color` flag that controls when `zizmor`'s
  output is colorized (beyond basic terminal detection) (#586)

### Bug Fixes 🐛

* Fixed `zizmor`'s path presentation behavior to correctly present
  unambiguous paths in both SARIF and "plain" outputs when
  multiple input directories are given (#572)

## v1.4.1

This is a small corrective release for v1.4.0.

### Bug Fixes 🐛

* Findings produced by ([unredacted-secrets]) now use the correct ID and
  link to the correct URL in the audit documentation (#566)

## v1.4.0

This release comes with one new audit ([unredacted-secrets]), plus a handful
of bugfixes and analysis improvements to existing audits. It also comes
with improvements to SARIF presentation, ignore comments, as well as an
[official Docker image](https://ghcr.io/zizmorcore/zizmor)!

### New Features 🌈

* `zizmor` now has official Docker images! You can find them on the
  GitHub Container Registry under
  [`ghcr.io/zizmorcore/zizmor`](https://ghcr.io/zizmorcore/zizmor) (#532)
* **New audit**: [unredacted-secrets] detects secret accesses that
  are not redacted in logs (#549)

### Improvements 🌱

* SARIF outputs are now slightly more aligned with GitHub Code Scanning
  expectations (#528)
* `# zizmor: ignore[rule]` comments can now have trailing explanations,
  e.g. `# zizmor: ignore[rule] because reasons` (#531)
* The [bot-conditions] audit now detects `github.triggering_actor`
  as another spoofable actor check (#559)

### Bug Fixes 🐛

* Fixed a bug where `zizmor` would fail to parse workflows with
  `workflow_dispatch` triggers that contained non-string inputs
  (#563)

### Upcoming Changes 🚧

* The next minor release of `zizmor` will be built with
  [Rust 2024](https://blog.rust-lang.org/2025/02/20/Rust-1.85.0.html).
  This should have no effect on most users, but may require users
  who build `zizmor` from source to update their Rust toolchain.

## v1.3.1

### Improvements 🌱

* Passing both `--offline` and a GitHub token (either implicitly with
  `GH_TOKEN` or explicitly with `--gh-token`) no longer results in an
  error. `--offline` is now given precedence, regardless of
  any other flags or environment settings (#519)

### Bug Fixes 🐛

* Fixed a bug where `zizmor` would fail to parse composite actions with
  inputs/outputs that are missing descriptions (#502)
* Expressions that contain indices with non-semantic whitespace are now parsed
  correctly (#511)
* Fixed a false positive in [ref-confusion] where partial tag matches were
  incorrectly considered confusable (#519)
* Fixed a bug where `zizmor` would fail to parse workflow definitions with
  an expression inside `strategy.max-parallel` (#522)

## v1.3.0

This release comes with one new audit ([overprovisioned-secrets]), plus a
handful of bugfixes and analysis improvements to existing audits. It also
comes with a special easter egg for those who wish to *kvell* about their
audit results.

### New Features 🌈

* **New audit**: [overprovisioned-secrets] detects uses of the `secrets`
  context that result in excessive secret provisioning (#485)
* Added a special naches mode for when you're feeling particularly proud of
  your audit results (#490)

### Improvements 🌱

* `zizmor` produces slightly more informative error messages when given
  an invalid input file (#482)
* Case insensitivity in contexts is now handled more consistently
  and pervasively (#491)

### Bug Fixes 🐛

* Fixed a bug where `zizmor` would fail to discover actions within
  subdirectories of `.github/workflows` (#477)
* Fixed a bug where `zizmor` would fail to parse composite action definitions
  with no `name` field (#487)

## v1.2.2

### Bug Fixes 🐛

* The [excessive-permissions] audit is now more precise about both
  reusable workflows and reusable workflow calls (#473)

### Improvements 🌱

* Fetch failures when running `zizmor org/repo` are now more informative (#475)

## v1.2.1

This is a small corrective release for some SARIF behavior that
changed with v1.2.0.

### Bug Fixes 🐛

* SARIF outputs now use relative paths again, but more correctly
  than before [v1.2.0](#v120) (#469)

## v1.2.0

This release comes with one new audit ([bot-conditions]), plus a handful
of bugfixes and analysis improvements to existing audits.

One bugfix in this release is also a slight behavior change: `zizmor`
now emits SARIF outputs with absolute paths. This should not affect most
users, but may make it slightly harder to share SARIF outputs between
machines without fully reproducing exact file paths. If this affects
you, [please let us know](https://github.com/zizmorcore/zizmor/issues/new?template=bug-report.yml)!

### New Features 🌈

* **New audit**: [bot-conditions] detects spoofable uses of `github.actor`
  within dangerous triggers (#460)

### Improvements 🌱

* The [unpinned-uses] audit no longer flags local reusable workflows or actions
  as unpinned/unhashed (#439)
* The [excessive-permissions] audit has been refactored, and better captures
  both true positive and true negative cases (#441)
* The SARIF output mode (`--format=sarif`) now always returns absolute paths
  in its location information, rather than attempting to infer a (sometimes
  incorrect) repository-relative path (#453)
* `zizmor` now provides `manylinux` wheel builds for `aarch64` (#457)

### Bug Fixes 🐛

* The [template-injection] audit no longer considers `github.event.pull_request.base.sha`
  dangerous (#445)
* The [artipacked] audit now correctly handles the strings `'true'` and `'false'`
  as their boolean counterparts (#448)
* Expressions that span multiple source lines are now parsed correctly (#461)
* Workflows that contain `timeout-minutes: ${{ expr }}` are now parsed
  correctly (#462)

## v1.1.1

### Bug Fixes 🐛

* Fixed a regression where workflows with calls to unpinned reusable workflows
  would fail to parse (#437)

## v1.1.0

This release comes with one new audit ([secrets-inherit]), plus a slew
of bugfixes and internal refactors that unblock future improvements!

### New Features 🌈

* **New audit**: [secrets-inherit] detects use of `secrets: inherit` with
  reusable workflow calls (#408)

### Improvements 🌱

* The [template-injection] audit now detects injections in calls
  to @azure/cli and @azure/powershell (#421)

### Bug Fixes 🐛

* The [template-injection] audit no longer consider `github.server_url`
  dangerous (#412)
* The [template-injection] audit no longer crashes when evaluating
  the static-ness of an environment for a `uses:` step (#420)

## v1.0.1

This is a small quality and bugfix release. Thank you to everybody
who helped by reporting and shaking out bugs from our first stable release!

### Improvements 🌱

* The [github-env] audit now detects dangerous writes to `GITHUB_PATH`,
  is more precise, and can produce multiple findings per run block (#391)

### Bug Fixes 🐛

* `workflow_call.secrets` keys with missing values are now parsed correctly (#388)
* The [cache-poisoning] audit no longer incorrectly treats `docker/build-push-action` as
  a publishing workflow is `push: false` is explicitly set (#389)
* The [template-injection] audit no longer considers `github.action_path`
  to be a potentially dangerous expansion (#402)
* The [github-env] audit no longer skips `run:` steps with non-trivial
  `shell:` stanzas (#403)

## v1.0.0

This is the first stable release of `zizmor`!

Starting with this release, `zizmor` will use [Semantic Versioning] for
its versioning scheme. In short, this means that breaking changes will only
happen with a new major version.

[Semantic Versioning]: https://semver.org/

This stable release comes with a large number of new features as well
as stability commitments for existing features; read more below!

### New Features 🌈

* Composite actions (i.e. `action.yml` where the action is *not* a Docker
  or JavaScript action) are now supported, and are audited by default
  when running `zizmor` on a directory or remote repository (#331)

    !!! tip

        Composite action discovery and auditing can be disabled by passing
        `--collect=workflows-only`. Conversely, workflow discovery and auditing
        can be disabled by passing `--collect=actions-only`.

    See #350 for the status of each audit's support for analyzing
    composite actions.

* The GitHub host to connect to can now be configured with `--gh-hostname`
  or `GH_HOST` in the environment (#371)

    This can be used to connect to a GitHub Enterprise (GHE) instance
    instead of the default `github.com` instance.

### Improvements 🌱

* The [cache-poisoning] audit is now aware of common publishing actions
  and uses then to determine whether to produce a finding (#338, #341)
* The [cache-poisoning] audit is now aware of configuration-free caching
  actions, such as @Mozilla-Actions/sccache-action (#345)
* The [cache-poisoning] audit is now aware of even more caching actions
  (#346)
* The [cache-poisoning] audit is now aware of common publishing triggers
  (such as pushing to a release branch) and uses them to determine whether
  to produce a finding (#352)
* The [github-env] audit is now significantly more precise on `bash` and `pwsh`
  inputs (#354)

### Bug Fixes 🐛

* The [excessive-permissions] audit is now less noisy on single-job workflows (#337)
* Expressions like `function().foo.bar` are now parsed correctly (#340)
* The [cache-poisoning] defaults for `setup-go` were fixed (#343)
* `uses:` matching is now case-insensitive where appropriate (#353)
* Quoted YAML keys (like `'on': foo`) are now parsed correctly (#368)

## v0.10.0

**Full Changelog**: https://github.com/zizmorcore/zizmor/compare/v0.9.2...v0.10.0

### New Features 🌈
* feat: handle powershell in github-env audit by @woodruffw in #227
* feat: template-injection: filter static envs by @woodruffw in #318
* feat: add 'primary' locations by @woodruffw in #328
* feat: initial cache-poisoning audit by @ubiratansoares in #294
* feat: Fix Sarif schema and add rules to Sarif files  by @fcasal in #330

### Bug Fixes 🐛
* fix: template-injection: more safe contexts by @woodruffw in #309
* fix: expands_to_static_values considers expressions inside strings by @woodruffw in #317
* fix: sarif: add result and kind by @woodruffw in #68
* fix: sarif: use ResultKind for kind by @woodruffw in #326

### Performance Improvements 🚄
* refactor: use http-cache for caching, optimize network calls by @woodruffw in #304

### Documentation Improvements 📖
* docs: support commits in trophy case by @woodruffw in #303
* docs: Fix typo in development.md by @JustusFluegel in #305

### New Contributors
* @jsoref made their first contribution in #299
* @JustusFluegel made their first contribution in #305
* @fcasal made their first contribution in #330

## v0.9.2

**Full Changelog**: https://github.com/zizmorcore/zizmor/compare/v0.9.1...v0.9.2

### Bug Fixes 🐛
* fix: template-injection: consider runner.tool_cache safe by @woodruffw in #297

### Documentation Improvements 📖
* docs: more trophies by @woodruffw in #296

## v0.9.1

**Full Changelog**: https://github.com/zizmorcore/zizmor/compare/v0.9.0...v0.9.1

### Bug Fixes 🐛

* fix: dont crash when an expression does not expand a matrix by @ubiratansoares in #284

## v0.9.0

**Full Changelog**: https://github.com/zizmorcore/zizmor/compare/v0.8.0...v0.9.0

### New Features 🌈
* refactor: experiment with tracing by @woodruffw in #232
* feat: remove --no-progress by @woodruffw in #248

### Bug Fixes 🐛
* fix: handle non-static env: in job steps by @woodruffw in #246
* fix: template-injection: ignore another safe context by @woodruffw in #254
* fix: download both .yml and .yaml from repos by @woodruffw in #265
* fix: bump annotate-snippets to fix crash by @woodruffw in #264
* fix: move artipacked pendantic finding to auditor by @woodruffw in #272
* fix: template-injection: ignore runner.temp by @woodruffw in #277

### Performance Improvements 🚄
* feat: evaluates a matrix expansion only once by @ubiratansoares in #274

### Documentation Improvements 📖
* docs: document installing with PyPI by @woodruffw in #242
* docs: add a trophy case by @woodruffw in #243
* docs: update pre-commit docs to point to new repo by @woodruffw in #247
* docs: switch GHA example to uvx by @woodruffw in #255
* docs: add template-injection tips by @woodruffw in #259
* docs: audits: add another env hacking reference by @woodruffw in #266
* docs: Rename "unsecure" to insecure by @szepeviktor in #270
* docs: more trophies by @woodruffw in #276
* docs: make the trophy case prettier by @woodruffw in #279

## New Contributors
* @szepeviktor made their first contribution in #270

## v0.8.0

**Full Changelog**: https://github.com/zizmorcore/zizmor/compare/v0.7.0...v0.8.0

### New Features 🌈
* feat: remote auditing by @woodruffw in #230

### Bug Fixes 🐛
* fix: template-injection: ignore issue/PR numbers by @woodruffw in #238

### Documentation Improvements 📖
* docs: restore search plugin by @lazka in #239

## New Contributors
* @lazka made their first contribution in #239

## v0.7.0

**Full Changelog**: https://github.com/zizmorcore/zizmor/compare/v0.6.0...v0.7.0

### New Features 🌈
* Split unpinned-uses into two separate checks by @funnelfiasco in #205
* feat: even more precision for bash steps in github-env by @ubiratansoares in #208
* feat: add Step::default_shell by @woodruffw in #213
* feat: handle `shell: sh` in github-env by @woodruffw in #216
* feat: primitive Windows batch handling in github-env by @woodruffw in #217
* feat: unpinned-uses: make unhashed check pedantic for now by @woodruffw in #219
* feat: add personas by @woodruffw in #226

### Bug Fixes 🐛
* fix: bump github-actions-models by @woodruffw in #211

### Documentation Improvements 📖
* docs: tweak installation layout by @woodruffw in #223

## v0.6.0

**Full Changelog**: https://github.com/zizmorcore/zizmor/compare/v0.5.0...v0.6.0

This is one of `zizmor`'s bigger recent releases! Key enhancements include:

* A new `github-env` audit that detects dangerous `GITHUB_ENV` writes,
  courtesy of @ubiratansoares
* The `--min-severity` and `--min-confidence` flags for filtering results,
  courtest (in part) of @Ninja3047
* Support for `# zizmor: ignore[rule]` comments, courtesy of @ubiratansoares

### New Features 🌈

* feat: adds support to inlined ignores by @ubiratansoares in #187
* feat: add `--min-severity` by @woodruffw in #193
* feat: add `--min-confidence` by @Ninja3047 in #196
* feat: adds new github-env audit by @ubiratansoares in #192
* feat: improve precision for github-env by @woodruffw in #199
* feat: generalized ignore comments by @woodruffw in #200

### Documentation Improvements 📖

* docs: document ignore comments by @woodruffw in #190
* docs: usage: add note about support for ignore comments by @woodruffw in #191
* docs: add page descriptions by @woodruffw in #194
* docs: add more useful 3p references by @woodruffw in #198

## New Contributors

* @Ninja3047 made their first contribution in #196

## v0.5,0

**Full Changelog**: https://github.com/zizmorcore/zizmor/compare/v0.4.0...v0.5.0

### New Features 🌈
* feat: improve workflow registry error by @woodruffw in #172
* feat: unsecure-commands-allowed audit by @ubiratansoares in #176

### Documentation Improvements 📖
* docs: rewrite audit docs by @woodruffw in #167
* docs: enable social card generation by @miketheman in #175
* docs: more badges by @woodruffw in #180
* docs: adds recommentations on how to add or change audits by @ubiratansoares in #182

## New Contributors
* @chenrui333 made their first contribution in #90

## v0.4.0

**Full Changelog**: https://github.com/zizmorcore/zizmor/compare/v0.3.2...v0.4.0

### New Features 🌈
* Fix singular and plural for 'findings' by @hugovk in #162
* feat: unpinned-uses audit by @woodruffw in #161

### Bug Fixes 🐛
* Fix typos including `github.repostoryUrl` -> `github.repositoryUrl` by @hugovk in #164

## v0.3.2

**Full Changelog**: https://github.com/zizmorcore/zizmor/compare/v0.3.1...v0.3.2

### What's Changed
* fix(cli): remove '0 ignored' from another place by @woodruffw in #157
* perf: speed up impostor-commit's fast path by @woodruffw in #158
* fix(cli): fixup error printing by @woodruffw in #159

## v0.3.1

**Full Changelog**: https://github.com/zizmorcore/zizmor/compare/v0.3.0...v0.3.1

### What's Changed
* feat(cli): don't render "0 ignored" by @woodruffw in #148
* feat: --no-exit-codes + sarif tweaks by @woodruffw in #154

### New Contributors
* @baggiponte made their first contribution in #150

## v0.3.0

**Full Changelog**: https://github.com/zizmorcore/zizmor/compare/v0.2.1...v0.3.0

### What's Changed

* feat: exit code support by @woodruffw in #133
* fix: github.event.merge_group.base_sha is a safe context by @woodruffw in #137
* fix: exclude information about the repo and owner by @funnelfiasco in #136
* feat: add `--no-config` by @woodruffw in #142

## v0.2.1

**Full Changelog**: https://github.com/zizmorcore/zizmor/compare/v0.2.0...v0.2.1

### What's Changed
* refactor: clean up expr APIs slightly by @woodruffw in #126
* feat: Exclude safe values from template injection rule by @funnelfiasco in #128
* fix: bump github-actions-models by @woodruffw in #131
* feat: analyze expressions for safety by @woodruffw in #127

## v0.2.0

**Full Changelog**: https://github.com/zizmorcore/zizmor/compare/v0.1.6...v0.2.0

### What's Changed
* chore: add description to `--help` by @woodruffw in #111
* fix: bump github-actions-models by @woodruffw in #112
* feat: improves plain output with audit confidence by @ubiratansoares in #119
* fix: bump github-actions-models by @woodruffw in #120
* docs: improve usage page and options for sarif and code scanning by @tobiastornros in #121
* feat: configuration file support by @woodruffw in #116

### New Contributors
* @dependabot made their first contribution in #118
* @tobiastornros made their first contribution in #121

## v0.1.6

**Full Changelog**: https://github.com/zizmorcore/zizmor/compare/v0.1.5...v0.1.6

### What's Changed
* feat: accept multiple arguments as inputs by @miketheman in #104

## v0.1.5

**Full Changelog**: https://github.com/zizmorcore/zizmor/compare/v0.1.4...v0.1.5

### What's Changed
* Exclude `github.run_*` from template injection check by @funnelfiasco in #92
* fix(ci): move read permissions to job scope by @miketheman in #95
* fix: links in README.md by @dmwyatt in #96
* test: adds acceptance tests on top of json-formatted output by @ubiratansoares in #97
* docs: add an example GHA workflow by @woodruffw in #98
* docs: update readme by @miketheman in #100
* docs: show example for usage in private repos by @miketheman in #99

### New Contributors
* @funnelfiasco made their first contribution in #92
* @dmwyatt made their first contribution in #96
* @ubiratansoares made their first contribution in #97

## v0.1.4

**Full Changelog**: https://github.com/zizmorcore/zizmor/compare/v0.1.3...v0.1.4

### What's Changed
* perf: Enable Link-Time Optimization (LTO) by @zamazan4ik in #81
* feat: begin prepping zizmor's website by @woodruffw in #78
* fix: Always use the plain formatter even when the output is not a terminal by @asmeurer in #83
* feat: show version by @miketheman in #84
* fix: finding url link to audits doc by @amenasria in #87

### New Contributors
* @zamazan4ik made their first contribution in #81
* @asmeurer made their first contribution in #83
* @amenasria made their first contribution in #87

## v0.1.3

**Full Changelog**: https://github.com/zizmorcore/zizmor/compare/v0.1.2...v0.1.3

### What's Changed
* fix: use relative workflow paths in SARIF output by @woodruffw in #77

## v0.1.2

**Full Changelog**: https://github.com/zizmorcore/zizmor/compare/v0.1.1...v0.1.2

### What's Changed
* feat: github.ref_name is always an injection risk by @woodruffw in #67
* Create workflow that runs zizmor latest by @colindean in #71
* Link to GitHub workflow examples by @ncoghlan in #70
* docs: add homebrew install by @miketheman in #74
* fix: bump github-actions-models by @woodruffw in #75

### New Contributors
* @colindean made their first contribution in #71
* @ncoghlan made their first contribution in #70

## v0.1.1

**Full Changelog**: https://github.com/zizmorcore/zizmor/compare/v0.1.0...v0.1.1

### What's Changed
* Fix typo: security -> securely by @hugovk in #61
* fix: bump github-action-models by @woodruffw in #65

### New Contributors
* @hugovk made their first contribution in #61

<!-- useful shortlinks -->

[artipacked]: ./audits.md#artipacked
[excessive-permissions]: ./audits.md#excessive-permissions
[cache-poisoning]: ./audits.md#cache-poisoning
[github-env]: ./audits.md#github-env
[template-injection]: ./audits.md#template-injection
[secrets-inherit]: ./audits.md#secrets-inherit
[unpinned-uses]: ./audits.md#unpinned-uses
[bot-conditions]: ./audits.md#bot-conditions
[overprovisioned-secrets]: ./audits.md#overprovisioned-secrets
[unredacted-secrets]: ./audits.md#unredacted-secrets
[forbidden-uses]: ./audits.md#forbidden-uses
[obfuscation]: ./audits.md#obfuscation
[stale-action-refs]: ./audits.md#stale-action-refs
[unsound-contains]: ./audits.md#unsound-contains
[unpinned-images]: ./audits.md#unpinned-images
[insecure-commands]: ./audits.md#insecure-commands
