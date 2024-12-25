use super::{audit_meta, WorkflowAudit};
use crate::finding::{Confidence, Finding, Severity};
use crate::models::Step;
use crate::state::AuditState;
use anyhow::{Context, Result};
use github_actions_models::workflow::job::StepBody;
use regex::Regex;
use std::cell::RefCell;
use std::ops::{Deref, Range};
use std::sync::LazyLock;
use streaming_iterator::StreamingIterator;
use tree_sitter::{Parser, Query, QueryCursor, QueryMatches, Tree};

static GITHUB_ENV_WRITE_CMD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?mi)^.+\s*>>?\s*"?%GITHUB_ENV%"?.*$"#).unwrap());

pub(crate) struct GitHubEnv {
    // NOTE: interior mutability used since Parser::parse requires &mut self
    bash_parser: RefCell<Parser>,
    pwsh_parser: RefCell<Parser>,

    // cached queries
    bash_redirect_query_span_idx: u32,
    bash_redirect_query: Query,

    bash_pipeline_query_span_idx: u32,
    bash_pipeline_query: Query,
}

audit_meta!(GitHubEnv, "github-env", "dangerous use of GITHUB_ENV");

const BASH_REDIRECT_QUERY: &str = r#"
(redirected_statement
 (
   (command (command_name) @cmd (_)* @args)
 )
 (file_redirect (
   [
     (string (_ (variable_name)))
     (expansion (variable_name))
     (simple_expansion (variable_name))
   ] @destination
 ))
 (#match? @destination "GITHUB_ENV")
) @span
"#;

const BASH_PIPELINE_QUERY: &str = r#"
(pipeline
  (command
    name: (command_name) @cmd
    argument: [
      (string (_ (variable_name)))
      (expansion)
      (simple_expansion)
    ] @arg
  )
  (#match? @cmd "tee")
  (#match? @arg "GITHUB_ENV")
) @span
"#;

impl GitHubEnv {
    fn query<'a>(
        &self,
        query: &'a Query,
        cursor: &'a mut QueryCursor,
        tree: &'a Tree,
        source: &'a str,
    ) -> QueryMatches<'a, 'a, &'a [u8], &'a [u8]> {
        cursor.matches(query, tree.root_node(), source.as_bytes())
    }

    fn bash_uses_github_env(&self, script_body: &str) -> Result<Vec<Range<usize>>> {
        let mut cursor = QueryCursor::new();

        let tree = self
            .bash_parser
            .borrow_mut()
            .parse(script_body, None)
            .context("failed to parse `run:` body as bash")?;

        let queries = [
            // matches the `foo >> $GITHUB_ENV` pattern
            (&self.bash_redirect_query, self.bash_redirect_query_span_idx),
            // matches the `cmd | cmd | tee $GITHUB_ENV` pattern
            (&self.bash_pipeline_query, self.bash_pipeline_query_span_idx),
        ];
        let mut matching_spans = vec![];

        for (query, span_idx) in queries {
            let matches = self.query(&query, &mut cursor, &tree, script_body);

            matches.for_each(|mat| {
                for cap in mat.captures {
                    if cap.index == span_idx {
                        matching_spans.push(cap.node.byte_range());
                    }
                }
            });
        }

        Ok(matching_spans)
    }

    fn pwsh_uses_github_env(&self, script_body: &str) -> Result<bool> {
        let tree = &self
            .pwsh_parser
            .borrow_mut()
            .parse(script_body, None)
            .context("failed to parse `run:` body as pwsh")?;

        let mut stack = vec![tree.root_node()];

        while let Some(node) = stack.pop() {
            match node.kind() {
                "pipeline" => {
                    // A pipeline has one or more "command" children.
                    for command in node
                        .named_children(&mut node.walk())
                        .filter(|c| c.kind() == "command")
                    {
                        let command =
                            &script_body[command.start_byte()..command.end_byte()].to_lowercase();

                        // TODO: We can be more precise here by checking
                        // `command_parameter` and `variable`.
                        if (command.contains("out-file")
                            || command.contains("add-content")
                            || command.contains("set-content"))
                            && command.contains("github_env")
                        {
                            return Ok(true);
                        }
                    }
                }
                "redirection" => {
                    // A redirection has a redirection_operator and a redirected_file_name.
                    let redirection =
                        &script_body[node.start_byte()..node.end_byte()].to_lowercase();

                    // TODO: Is it worth checking that the operator is >/>>?

                    if redirection.to_lowercase().contains("github_env") {
                        return Ok(true);
                    }
                }
                _ => (),
            }

            for child in node.named_children(&mut node.walk()) {
                stack.push(child);
            }
        }

        Ok(false)
    }

    fn uses_github_env(&self, run_step_body: &str, shell: &str) -> anyhow::Result<bool> {
        match shell {
            "bash" | "sh" => self
                .bash_uses_github_env(run_step_body)
                // NOTE: discard the spans for now.
                .map(|r| !r.is_empty()),
            "cmd" => Ok(GITHUB_ENV_WRITE_CMD.is_match(run_step_body)),
            "pwsh" | "powershell" => self.pwsh_uses_github_env(run_step_body),
            // TODO: handle python.
            &_ => {
                tracing::warn!(
                    "'{}' shell not supported when evaluating usage of GITHUB_ENV",
                    shell
                );
                Ok(false)
            }
        }
    }
}

impl WorkflowAudit for GitHubEnv {
    fn new(_: AuditState) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        let bash = tree_sitter_bash::LANGUAGE;
        let mut bash_parser = Parser::new();
        bash_parser
            .set_language(&bash.into())
            .context("failed to load bash parser")?;

        let pwsh = tree_sitter_powershell::language();
        let mut pwsh_parser = Parser::new();
        pwsh_parser
            .set_language(&pwsh)
            .context("failed to load powershell parser")?;

        let bash_redirect_query = Query::new(&bash.into(), BASH_REDIRECT_QUERY)?;
        let bash_pipeline_query = Query::new(&bash.into(), BASH_PIPELINE_QUERY)?;

        Ok(Self {
            bash_parser: RefCell::new(bash_parser),
            pwsh_parser: RefCell::new(pwsh_parser),
            bash_redirect_query_span_idx: bash_redirect_query
                .capture_index_for_name("span")
                .unwrap(),
            bash_redirect_query,
            bash_pipeline_query_span_idx: bash_pipeline_query
                .capture_index_for_name("span")
                .unwrap(),
            bash_pipeline_query,
        })
    }

    fn audit_step<'w>(&self, step: &Step<'w>) -> anyhow::Result<Vec<Finding<'w>>> {
        let mut findings = vec![];

        let workflow = step.workflow();

        let has_dangerous_triggers =
            workflow.has_workflow_run() || workflow.has_pull_request_target();

        if !has_dangerous_triggers {
            return Ok(findings);
        }

        if let StepBody::Run { run, .. } = &step.deref().body {
            let shell = step.shell().unwrap_or_else(|| {
                tracing::warn!(
                    "github-env: couldn't determine shell type for {workflow}:{job} step {stepno}",
                    workflow = step.workflow().filename(),
                    job = step.parent.id,
                    stepno = step.index
                );

                // If we can't infer a shell for this `run:`, assume that it's
                // bash. This won't be correct on self-hosted Windows runners
                // that don't use the default routing labels, but there's
                // nothing we can do about that.
                "bash"
            });
            if self.uses_github_env(run, shell)? {
                findings.push(
                    Self::finding()
                        .severity(Severity::High)
                        .confidence(Confidence::Low)
                        .add_location(
                            step.location()
                                .primary()
                                .with_keys(&["run".into()])
                                .annotated("GITHUB_ENV write may allow code execution"),
                        )
                        .build(step.workflow())?,
                )
            }
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use crate::audit::github_env::{GitHubEnv, GITHUB_ENV_WRITE_CMD};
    use crate::audit::WorkflowAudit;
    use crate::state::AuditState;

    #[test]
    fn test_exploitable_bash_patterns() {
        for (case, expected) in &[
            // Common cases
            ("echo foo >> $GITHUB_ENV", true),
            ("echo foo >> \"$GITHUB_ENV\"", true),
            ("echo foo >> ${GITHUB_ENV}", true),
            ("echo foo >> \"${GITHUB_ENV}\"", true),
            // Single > is buggy most of the time, but still exploitable
            ("echo foo > $GITHUB_ENV", true),
            ("echo foo > \"$GITHUB_ENV\"", true),
            ("echo foo > ${GITHUB_ENV}", true),
            ("echo foo > \"${GITHUB_ENV}\"", true),
            // No spaces
            ("echo foo>>$GITHUB_ENV", true),
            ("echo foo>>\"$GITHUB_ENV\"", true),
            ("echo foo>>${GITHUB_ENV}", true),
            ("echo foo>>\"${GITHUB_ENV}\"", true),
            // Continuations over newlines are OK
            ("echo foo >> \\\n $GITHUB_ENV", true),
            // tee cases
            ("something | tee $GITHUB_ENV", true),
            ("something | tee $GITHUB_ENV | something-else", true),
            ("something | tee \"$GITHUB_ENV\"", true),
            ("something | tee ${GITHUB_ENV}", true),
            ("something | tee \"${GITHUB_ENV}\"", true),
            ("something|tee $GITHUB_ENV", true),
            ("something |tee $GITHUB_ENV", true),
            ("something| tee $GITHUB_ENV", true),
            // negative cases (comments should not be detected)
            ("echo foo >> $OTHER_ENV # not $GITHUB_ENV", false),
            ("something | tee \"${$OTHER_ENV}\" # not $GITHUB_ENV", false),
            ("echo foo >> GITHUB_ENV", false), // FP: GITHUB_ENV is not a variable
            ("echo foo | tee GITHUB_ENV", false), // FP: GITHUB_ENV is not a variable
        ] {
            let audit_state = AuditState {
                no_online_audits: false,
                cache_dir: "/tmp/zizmor".into(),
                gh_token: None,
            };

            let sut = GitHubEnv::new(audit_state).expect("failed to create audit");

            let uses_github_env = sut.uses_github_env(case, "bash").unwrap();
            assert_eq!(uses_github_env, *expected, "failed: {case}");
        }
    }

    #[test]
    fn test_exploitable_cmd_patterns() {
        for (case, expected) in &[
            // Common cases
            ("echo LIBRARY=%LIBRARY%>>%GITHUB_ENV%", true),
            ("echo LIBRARY=%LIBRARY%>> %GITHUB_ENV%", true),
            ("echo LIBRARY=%LIBRARY% >> %GITHUB_ENV%", true),
            ("echo LIBRARY=%LIBRARY% >> \"%GITHUB_ENV%\"", true),
            ("echo>>\"%GITHUB_ENV%\" %%a=%%b", true),
            (
                "echo SERVER=${{ secrets.SQL19SERVER }}>> %GITHUB_ENV%",
                true,
            ),
        ] {
            assert_eq!(GITHUB_ENV_WRITE_CMD.is_match(case), *expected);
        }
    }

    #[test]
    fn test_exploitable_pwsh_patterns() {
        for (case, expected) in &[
            // Common cases
            ("foo >> ${env:GITHUB_ENV}", true),
            ("foo >> $env:GITHUB_ENV", true),
            ("echo \"UV_CACHE_DIR=$UV_CACHE_DIR\" >> $env:GITHUB_ENV", true),
            // Case insensitivity
            ("foo >> ${ENV:GITHUB_ENV}", true),
            ("foo >> ${ENV:github_env}", true),
            ("foo >> $ENV:GITHUB_ENV", true),
            ("foo >> $ENV:GitHub_Env", true),
            // Out-File cases
            ("echo \"CUDA_PATH=$env:CUDA_PATH\" | Out-File -FilePath $env:GITHUB_ENV -Encoding utf8 -Append", true),
            ("\"PYTHON_BIN=$PYTHON_BIN\" | Out-File -FilePath $env:GITHUB_ENV -Append", true),
            ("echo \"SOLUTION_PATH=${slnPath}\" | Out-File $env:GITHUB_ENV -Encoding utf8 -Append", true),
            // Add-Content cases
            ("Add-Content -Path $env:GITHUB_ENV -Value \"RELEASE_VERSION=$releaseVersion\"", true),
            ("Add-Content $env:GITHUB_ENV \"DOTNET_ROOT=$Env:USERPROFILE\\.dotnet\"", true),
            // Set-Content cases
            ("Set-Content -Path $env:GITHUB_ENV -Value \"tag=$tag\"", true),
            ("[System.Text.Encoding]::UTF8.GetBytes(\"RELEASE_NOTES<<EOF`n$releaseNotes`nEOF\") |\nSet-Content -Path $Env:GITHUB_ENV -NoNewline -Encoding Byte", true),
            // Case insensitivity
            ("echo \"foo\" | out-file $Env:GitHub_Env -Append", true),
            ("echo \"foo\" | out-File $Env:GitHub_Env -Append", true),
            ("echo \"foo\" | OUT-FILE $Env:GitHub_Env -Append", true),
            // Negative cases (comments should not be detected)
            ("foo >> bar # not $env:GITHUB_ENV", false),
            ("foo >> bar # not ${env:GITHUB_ENV}", false),
            ("echo \"foo\" | out-file bar -Append # not $env:GITHUB_ENV", false),
        ] {
            let audit_state = AuditState {
                no_online_audits: false,
                cache_dir: "/tmp/zizmor".into(),
                gh_token: None,
            };

            let sut = GitHubEnv::new(audit_state).expect("failed to create audit");

            let uses_github_env = sut.uses_github_env(case, "pwsh").unwrap();
            assert_eq!(uses_github_env, *expected);
        }
    }
}
