use assert_cmd::Command;
use common::workflow_under_test;
use serde_json::Value;
use serde_json_path::JsonPath;

mod common;

// Acceptance tests for zizmor, on top of Json output
// For now we don't cover tests that depends on GitHub API under the hood

fn zizmor() -> Command {
    let mut cmd = Command::cargo_bin("zizmor").expect("Cannot create executable command");
    // All tests are currently offline, and we always need JSON output.
    cmd.args(["--offline", "--format", "json"]);
    cmd
}

fn assert_value_match(json: &Value, path_pattern: &str, value: &str) {
    let json_path = JsonPath::parse(path_pattern).expect("Cannot evaluate json path");
    let queried = json_path
        .query(json)
        .exactly_one()
        .expect("Cannot query json path");

    // Don't bother about surrounding formatting
    assert!(queried.to_string().contains(value));
}

#[test]
fn catches_inlined_ignore() -> anyhow::Result<()> {
    let auditable = workflow_under_test("inlined-ignores.yml");

    let cli_args = [&auditable];

    let execution = zizmor().args(cli_args).output()?;

    assert_eq!(execution.status.code(), Some(0));

    let findings = String::from_utf8(execution.stdout)?;

    assert_eq!(&findings, "[]");

    Ok(())
}

#[test]
fn audit_artipacked() -> anyhow::Result<()> {
    let auditable = workflow_under_test("artipacked.yml");
    let cli_args = [&auditable];

    let execution = zizmor().args(cli_args).output()?;

    assert_eq!(execution.status.code(), Some(13));

    let findings = serde_json::from_slice(&execution.stdout)?;

    assert_value_match(&findings, "$[0].determinations.confidence", "Low");
    assert_value_match(
        &findings,
        "$[0].locations[0].concrete.feature",
        "uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
    );

    Ok(())
}

#[test]
fn audit_excessive_permission() -> anyhow::Result<()> {
    let auditable = workflow_under_test("excessive-permissions.yml");
    let cli_args = [&auditable];

    let execution = zizmor().args(cli_args).output()?;

    assert_eq!(execution.status.code(), Some(14));

    let findings = serde_json::from_slice(&execution.stdout)?;

    assert_value_match(&findings, "$[0].determinations.confidence", "High");
    assert_value_match(
        &findings,
        "$[0].locations[0].concrete.feature",
        "permissions: write-all",
    );

    Ok(())
}

#[test]
fn audit_hardcoded_credentials() -> anyhow::Result<()> {
    let auditable = workflow_under_test("hardcoded-credentials.yml");
    let cli_args = [&auditable];

    let execution = zizmor().args(cli_args).output()?;

    assert_eq!(execution.status.code(), Some(14));

    let findings = serde_json::from_slice(&execution.stdout)?;

    assert_value_match(&findings, "$[0].determinations.confidence", "High");
    assert_value_match(
        &findings,
        "$[0].locations[0].concrete.feature",
        "password: hackme",
    );

    Ok(())
}

#[test]
fn audit_template_injection() -> anyhow::Result<()> {
    let auditable = workflow_under_test("template-injection.yml");
    let cli_args = [&auditable];

    let execution = zizmor().args(cli_args).output()?;

    assert_eq!(execution.status.code(), Some(14));

    let findings = serde_json::from_slice(&execution.stdout)?;

    assert_value_match(&findings, "$[0].determinations.confidence", "High");
    assert_value_match(
        &findings,
        "$[0].locations[0].concrete.feature",
        "${{ github.event.issue.title }}",
    );

    Ok(())
}

#[test]
fn audit_use_trusted_publishing() -> anyhow::Result<()> {
    let auditable = workflow_under_test("use-trusted-publishing.yml");
    let cli_args = [&auditable];

    let execution = zizmor().args(cli_args).output()?;

    assert_eq!(execution.status.code(), Some(11));

    let findings = serde_json::from_slice(&execution.stdout)?;

    assert_value_match(&findings, "$[0].determinations.confidence", "High");
    assert_value_match(
        &findings,
        "$[0].locations[0].concrete.feature",
        "uses: pypa/gh-action-pypi-publish@release/v1",
    );

    Ok(())
}

#[test]
fn audit_self_hosted() -> anyhow::Result<()> {
    let auditable = workflow_under_test("self-hosted.yml");

    // Note: self-hosted audit is auditor-only
    let cli_args = ["--persona=auditor", &auditable];

    let execution = zizmor().args(cli_args).output()?;

    assert_eq!(execution.status.code(), Some(10));

    let findings = serde_json::from_slice(&execution.stdout)?;

    assert_value_match(&findings, "$[0].determinations.confidence", "High");
    assert_value_match(
        &findings,
        "$[0].locations[0].concrete.feature",
        "runs-on: [self-hosted, my-ubuntu-box]",
    );

    Ok(())
}

#[test]
fn audit_unpinned_uses() -> anyhow::Result<()> {
    let auditable = workflow_under_test("unpinned-uses.yml");

    let cli_args = [&auditable];

    let execution = zizmor().args(cli_args).output()?;

    assert_eq!(execution.status.code(), Some(13));

    let findings = serde_json::from_slice(&execution.stdout)?;

    assert_value_match(&findings, "$[0].determinations.confidence", "High");
    assert_value_match(&findings, "$[0].determinations.severity", "Medium");
    assert_value_match(
        &findings,
        "$[0].locations[0].concrete.feature",
        "uses: actions/checkout",
    );
    assert_value_match(
        &findings,
        "$[1].locations[0].concrete.feature",
        "uses: github/codeql-action/upload-sarif",
    );
    assert_value_match(
        &findings,
        "$[2].locations[0].concrete.feature",
        "uses: docker://ubuntu",
    );
    assert_value_match(
        &findings,
        "$[3].locations[0].concrete.feature",
        "uses: docker://ghcr.io/pypa/gh-action-pypi-publish",
    );

    Ok(())
}

#[test]
fn audit_insecure_commands_allowed() -> anyhow::Result<()> {
    let auditable = workflow_under_test("insecure-commands.yml");

    let cli_args = [&auditable];

    let execution = zizmor().args(cli_args).output()?;

    assert_eq!(execution.status.code(), Some(14));

    let findings = serde_json::from_slice(&execution.stdout)?;

    assert_value_match(&findings, "$[0].determinations.confidence", "High");
    assert_value_match(
        &findings,
        "$[0].locations[0].concrete.feature",
        "ACTIONS_ALLOW_UNSECURE_COMMANDS",
    );

    Ok(())
}

#[test]
fn audit_github_env_injection() -> anyhow::Result<()> {
    let auditable = workflow_under_test("github_env.yml");

    let cli_args = [&auditable];

    let execution = zizmor().args(cli_args).output()?;

    assert_eq!(execution.status.code(), Some(14));

    let findings = serde_json::from_slice(&execution.stdout)?;

    assert_value_match(&findings, "$[0].determinations.confidence", "Low");
    assert_value_match(
        &findings,
        "$[0].locations[0].concrete.feature",
        "GITHUB_ENV",
    );

    Ok(())
}
