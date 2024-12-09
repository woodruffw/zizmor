use anyhow::Result;
use assert_cmd::Command;
use common::workflow_under_test;

mod common;

#[allow(dead_code)]
enum OutputMode {
    Stdout,
    Stderr,
    Both,
}

struct Zizmor {
    cmd: Command,
    offline: bool,
    workflow: Option<String>,
    output: OutputMode,
}

impl Zizmor {
    /// Create a new zizmor runner.
    fn new() -> Self {
        let cmd = Command::cargo_bin("zizmor").unwrap();

        Self {
            cmd,
            offline: true,
            workflow: None,
            output: OutputMode::Stdout,
        }
    }

    fn args<'a>(mut self, args: impl IntoIterator<Item = &'a str>) -> Self {
        self.cmd.args(args);
        self
    }

    fn setenv(mut self, key: &str, value: &str) -> Self {
        self.cmd.env(key, value);
        self
    }

    fn unsetenv(mut self, key: &str) -> Self {
        self.cmd.env_remove(key);
        self
    }

    fn workflow(mut self, workflow: impl Into<String>) -> Self {
        self.workflow = Some(workflow.into());
        self
    }

    fn offline(mut self, flag: bool) -> Self {
        self.offline = flag;
        self
    }

    #[allow(dead_code)]
    fn output(mut self, output: OutputMode) -> Self {
        self.output = output;
        self
    }

    fn run(mut self) -> Result<String> {
        if self.offline {
            self.cmd.arg("--offline");
        }

        if let Some(workflow) = &self.workflow {
            self.cmd.arg(workflow);
        }

        let output = self.cmd.output()?;

        let mut raw = String::from_utf8(match self.output {
            OutputMode::Stdout => output.stdout,
            OutputMode::Stderr => output.stderr,
            OutputMode::Both => [output.stdout, output.stderr].concat(),
        })?;

        if let Some(workflow) = &self.workflow {
            raw = raw.replace(workflow, "@@INPUT@@");
        }

        Ok(raw)
    }
}

fn zizmor() -> Zizmor {
    Zizmor::new()
}

#[test]
fn test_cant_retrieve() -> Result<()> {
    insta::assert_snapshot!(zizmor()
        .output(OutputMode::Stderr)
        .offline(true)
        .unsetenv("GH_TOKEN")
        .args(["pypa/sampleproject"])
        .run()?);

    Ok(())
}

#[test]
fn test_conflicting_online_options() -> Result<()> {
    insta::assert_snapshot!(zizmor()
        .output(OutputMode::Stderr)
        .setenv("GH_TOKEN", "phony")
        .offline(true)
        .run()?);

    insta::assert_snapshot!(zizmor()
        .output(OutputMode::Stderr)
        .offline(true)
        .args(["--gh-token=phony"])
        .run()?);

    insta::assert_snapshot!(zizmor()
        .output(OutputMode::Stderr)
        .setenv("ZIZMOR_OFFLINE", "true")
        .setenv("GH_TOKEN", "phony")
        .offline(false) // explicitly disable so that we test ZIZMOR_OFFLINE above
        .run()?);

    Ok(())
}

#[test]
fn artipacked() -> Result<()> {
    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test("artipacked.yml"))
        .args(["--persona=pedantic"])
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test("artipacked.yml"))
        .run()?);

    Ok(())
}

#[test]
fn self_hosted() -> Result<()> {
    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test("self-hosted.yml"))
        .args(["--persona=auditor"])
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test("self-hosted.yml"))
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test(
            "self-hosted/self-hosted-runner-label.yml"
        ))
        .args(["--persona=auditor"])
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test(
            "self-hosted/self-hosted-runner-group.yml"
        ))
        .args(["--persona=auditor"])
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test(
            "self-hosted/self-hosted-matrix-dimension.yml"
        ))
        .args(["--persona=auditor"])
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test(
            "self-hosted/self-hosted-matrix-inclusion.yml"
        ))
        .args(["--persona=auditor"])
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test(
            "self-hosted/self-hosted-matrix-exclusion.yml"
        ))
        .args(["--persona=auditor"])
        .run()?);

    Ok(())
}

#[test]
fn unpinned_uses() -> Result<()> {
    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test("unpinned-uses.yml"))
        .args(["--pedantic"])
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test("unpinned-uses.yml"))
        .run()?);

    Ok(())
}

#[test]
fn insecure_commands() -> Result<()> {
    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test("insecure-commands.yml"))
        .args(["--persona=auditor"])
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test("insecure-commands.yml"))
        .run()?);

    Ok(())
}

#[test]
fn template_injection() -> Result<()> {
    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test(
            "template-injection/template-injection-static-matrix.yml"
        ))
        .args(["--persona=auditor"])
        .run()?);

    insta::assert_snapshot!(zizmor()
        .workflow(workflow_under_test(
            "template-injection/template-injection-dynamic-matrix.yml"
        ))
        .args(["--persona=auditor"])
        .run()?);

    Ok(())
}
