//! Helper routines.

use anyhow::{Error, anyhow};
use camino::Utf8Path;
use github_actions_models::common::{
    Env,
    expr::{ExplicitExpr, LoE},
};
use jsonschema::{
    BasicOutput::{Invalid, Valid},
    Validator,
    output::{ErrorDescription, OutputUnit},
    validator_for,
};
use std::{collections::VecDeque, ops::Range};
use std::{fmt::Write, sync::LazyLock};

use crate::audit::AuditInput;

static ACTION_VALIDATOR: LazyLock<Validator> = LazyLock::new(|| {
    validator_for(&serde_json::from_str(include_str!("../github-action.json")).unwrap()).unwrap()
});

static WORKFLOW_VALIDATOR: LazyLock<Validator> = LazyLock::new(|| {
    validator_for(&serde_json::from_str(include_str!("../github-workflow.json")).unwrap()).unwrap()
});

pub(crate) fn validate_action(contents: String) -> Error {
    match serde_yaml::from_str(&contents) {
        Ok(workflow) => match ACTION_VALIDATOR.apply(&workflow).basic() {
            Valid(_) => anyhow!("valid action but failed unmarshaling"),
            Invalid(errors) => parse_validation_errors(errors),
        },
        Err(_) => anyhow!("invalid yaml"),
    }
}

pub(crate) fn validate_workflow(contents: String) -> Error {
    match serde_yaml::from_str(&contents) {
        Ok(workflow) => match WORKFLOW_VALIDATOR.apply(&workflow).basic() {
            Valid(_) => anyhow!("valid workflow but failed unmarshaling"),
            Invalid(errors) => parse_validation_errors(errors),
        },
        Err(_) => anyhow!("invalid yaml"),
    }
}

fn parse_validation_errors(errors: VecDeque<OutputUnit<ErrorDescription>>) -> Error {
    let mut message = String::new();

    for error in errors {
        let description = error.error_description().to_string();
        if !description.starts_with("{") {
            let mut location = error.instance_location().to_string();
            if location.is_empty() {
                writeln!(message, "{}", description,).unwrap();
            } else {
                location = location.replace("/", ".").get(1..).unwrap().to_string();

                writeln!(message, "{}: {}", location, description,).unwrap();
            }
        }
    }

    anyhow!(message)
}

/// Convenience trait for inline transformations of `Self`.
///
/// This is similar to the `tap` crate's `Pipe` trait, except that
/// it's a little less general (`pipe<T>(T) -> T``, instead of
/// `pipe<T, U>(T) -> U`).
pub(crate) trait PipeSelf<F> {
    fn pipe(self, f: F) -> Self
    where
        F: FnOnce(Self) -> Self,
        Self: Sized,
    {
        f(self)
    }
}

impl<T, F> PipeSelf<F> for T where T: Sized {}

/// Splits the given `patterns` string into one or more patterns, using
/// approximately the same rules as GitHub's `@actions/glob` package.
pub(crate) fn split_patterns(patterns: &str) -> impl Iterator<Item = &str> {
    // GitHub's pattern splitting is very basic: each line is processed in sequence,
    // with empty or comment (#) lines removed. Everything remaining is considered
    // a pattern.
    // See: https://github.com/actions/toolkit/blob/6c4e082c181a/packages/glob/src/internal-globber.ts#L161-L190

    patterns
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
}

/// Parse an expression from the given free-form text, starting
/// at the given offset. The returned span is absolute.
///
/// Returns `None` if no expression is found, or an span past
/// the end of the text if parsing is successful but exhausted.
///
/// Adapted roughly from GitHub's `parseScalar`:
/// See: <https://github.com/actions/languageservices/blob/3a8c29c2d/workflow-parser/src/templates/template-reader.ts#L448>
fn extract_expression(text: &str, offset: usize) -> Option<(ExplicitExpr, Range<usize>)> {
    let view = &text[offset..];
    let start = view.find("${{")?;

    let mut end = None;
    let mut in_string = false;

    for (idx, char) in view.bytes().enumerate().skip(start) {
        if char == b'\'' {
            in_string = !in_string;
        } else if !in_string && view.as_bytes()[idx] == b'}' && view.as_bytes()[idx - 1] == b'}' {
            end = Some(idx);
            break;
        }
    }

    end.map(|end| {
        (
            ExplicitExpr::from_curly(&view[start..=end]).unwrap(),
            start + offset..end + offset + 1,
        )
    })
}

/// Extract zero or more expressions from the given free-form text.
pub(crate) fn extract_expressions(text: &str) -> Vec<(ExplicitExpr, Range<usize>)> {
    let mut exprs = vec![];
    let mut offset = 0;

    while let Some((expr, span)) = extract_expression(text, offset) {
        exprs.push((expr, (span.start..span.end)));

        if span.end >= text.len() {
            break;
        } else {
            offset = span.end;
        }
    }

    exprs
}

/// Like `extract_expressions`, but over an entire audit input (e.g. workflow
/// or action definition).
///
/// Unlike `extract_expressions`, this function performs some semantic
/// filtering over the raw input. For example, it skip ignore expressions
/// that are inside comments.
pub(crate) fn parse_expressions_from_input(
    input: &AuditInput,
) -> Vec<(ExplicitExpr, Range<usize>)> {
    let text = input.document().source();
    let doc = input.document();

    let mut exprs = vec![];
    let mut offset = 0;

    while let Some((expr, span)) = extract_expression(text, offset) {
        // Ignore expressions that are inside comments.
        if doc.offset_inside_comment(span.start) {
            // Don't jump the entire span, since we might have an
            // actual expression accidentally captured within it.
            // Instead, just resume searching from the next character.
            offset = span.start + 1;
            continue;
        }

        exprs.push((expr, (span.start..span.end)));

        if span.end >= text.len() {
            break;
        } else {
            offset = span.end;
        }
    }

    exprs
}

/// Returns whether the given `env.name` environment access is "static,"
/// i.e. is not influenced by another expression.
pub(crate) fn env_is_static(name: &str, envs: &[&LoE<Env>]) -> bool {
    for env in envs {
        match env {
            // Any `env:` that is wholly an expression cannot be static.
            LoE::Expr(_) => return false,
            LoE::Literal(env) => {
                let Some(value) = env.get(name) else {
                    continue;
                };

                // A present `env:` value is static if it has no interior expressions.
                // TODO: We could instead return the interior expressions here
                // for further analysis, to further eliminate false positives
                // e.g. `env.foo: ${{ something-safe }}`.
                return extract_expressions(&value.to_string()).is_empty();
            }
        }
    }

    // No `env:` blocks explicitly contain this name, so it's trivially static.
    // In practice this is probably an invalid workflow.
    true
}

/// Returns the name within the given `shell:` stanza.
pub(crate) fn normalize_shell(shell: &str) -> &str {
    let path = match shell.split_once(' ') {
        Some((path, _)) => path,
        None => shell,
    };

    Utf8Path::new(path).file_name().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use crate::{
        Action,
        models::Workflow,
        registry::InputKey,
        utils::{
            extract_expression, extract_expressions, normalize_shell, parse_expressions_from_input,
            validate_action, validate_workflow,
        },
    };

    #[test]
    fn split_patterns() {
        let patterns = "
        foo
        bar
        ${{ baz }}
        internal  spaces
        **
        *
        # comment
        ## more hashes
        # internal # hashes

        # another comment
        foo/*.txt
        ";

        let pats = super::split_patterns(patterns).collect::<Vec<_>>();
        assert_eq!(
            pats,
            &[
                "foo",
                "bar",
                "${{ baz }}",
                "internal  spaces",
                "**",
                "*",
                "foo/*.txt"
            ]
        )
    }

    #[test]
    fn test_extract_expression() {
        let exprs = &[
            ("${{ foo }}", "foo", 0..10),
            ("${{ foo }}${{ bar }}", "foo", 0..10),
            ("leading ${{ foo }} trailing", "foo", 8..18),
            (
                "leading ${{ '${{ quoted! }}' }} trailing",
                "'${{ quoted! }}'",
                8..31,
            ),
            ("${{ 'es''cape' }}", "'es''cape'", 0..17),
        ];

        for (text, expected_expr, expected_span) in exprs {
            let (actual_expr, actual_span) = extract_expression(text, 0).unwrap();
            assert_eq!(*expected_expr, actual_expr.as_bare());
            assert_eq!(*expected_span, actual_span);
        }
    }

    #[test]
    fn test_extract_expressions() {
        let multiple = r#"echo "OSSL_PATH=${{ github.workspace }}/osslcache/${{ matrix.PYTHON.OPENSSL.TYPE }}-${{ matrix.PYTHON.OPENSSL.VERSION }}-${OPENSSL_HASH}" >> $GITHUB_ENV"#;

        {
            let (raw, expected) = &(
                multiple,
                [
                    "${{ github.workspace }}",
                    "${{ matrix.PYTHON.OPENSSL.TYPE }}",
                    "${{ matrix.PYTHON.OPENSSL.VERSION }}",
                ]
                .as_slice(),
            );
            let exprs = extract_expressions(raw)
                .into_iter()
                .map(|(e, _)| e.as_curly().to_string())
                .collect::<Vec<_>>();

            assert_eq!(exprs, *expected)
        }
    }

    #[test]
    fn test_extract_expressions_from_input() -> Result<()> {
        // Repro cases for #569; ensures we handle broken expressions that
        // are commented out. Observe that the commented expression isn't
        // terminated correctly, so the naive parse continues to the next
        // expression.
        let action = r#"
name: >-  # ${{ '' } is a hack to nest jobs under the same sidebar category
  Windows MSI${{ '' }}

description: test

runs:
  using: composite
  steps:
    - name: foo
      run: echo hello
      shell: bash
"#;

        let action = Action::from_string(action.into(), InputKey::local("fake", None)?)?;

        let exprs = parse_expressions_from_input(&action.into());
        assert_eq!(exprs.len(), 1);
        assert_eq!(exprs[0].0.as_curly().to_string(), "${{ '' }}");

        let workflow = r#"
# ${{ 'don''t parse me' }}

# Observe that the expression in the comment below is invalid:
# it's missing a closing brace. This should not interfere with
# parsing the rest of the file's expressions
name: >- # ${{ 'oops' }
  custom-name-${{ github.sha }}

on:
  push:

permissions: {}

jobs:
  whops:
    runs-on: ubuntu-latest

    steps:
      - run: echo hello from ${{ github.actor }}
"#;

        let workflow = Workflow::from_string(workflow.into(), InputKey::local("fake", None)?)?;

        let exprs = parse_expressions_from_input(&workflow.into())
            .into_iter()
            .map(|(e, _)| e.as_raw().to_string())
            .collect::<Vec<_>>();

        assert_eq!(exprs, &["${{ github.sha }}", "${{ github.actor }}",]);

        Ok(())
    }

    #[test]
    fn test_normalize_shell() {
        for (actual, expected) in &[
            ("bash", "bash"),
            ("/bin/bash", "bash"),
            ("/bash", "bash"),
            ("./bash", "bash"),
            ("../bash", "bash"),
            ("/./../bash", "bash"),
            ("/bin/bash -e {0}", "bash"),
        ] {
            assert_eq!(normalize_shell(actual), *expected)
        }
    }

    #[test]
    fn test_action_validation_valid() {
        let action = "name: 'Action'
description: 'Description'
inputs:
  some-input:
    description: 'Input description'
    default: 'default'

outputs:
  some-output:
    description: 'Output description'

runs:
  using: docker
  image: Dockerfile
"
        .to_string();

        let err = validate_action(action);

        assert_eq!(format!("{}", err), "valid action but failed unmarshaling")
    }

    #[test]
    fn test_action_validation_invalid() {
        let action = "name: 'Action'

inputs:
  some-input:
    description: 'Input description'
    default: 'default'

outputs:
  some-output:
    description: 'Output description'

random:

runs:
  using: docker
  image: Dockerfile
"
        .to_string();

        let err = validate_action(action);

        assert_eq!(
            format!("{}", err),
            "Additional properties are not allowed ('random' was unexpected)\n\"description\" is a required property\n"
        )
    }

    #[test]
    fn test_workflow_validation_valid() {
        let workflow = "name: Valid

on:
  push:

permissions: {}

jobs:
  valid:
    runs-on: ubuntu-latest
    steps:
      - run: echo 'valid'
"
        .to_string();

        let err = validate_workflow(workflow);

        assert_eq!(format!("{}", err), "valid workflow but failed unmarshaling")
    }

    #[test]
    fn test_workflow_validation_invalid() {
        let workflow = "name: Invalid

boom:

on:
  workflow_call:
    inputs:
      input:
        description: Input

permissions: {}

jobs:
  valid:
    runs-on: ubuntu-latest
    steps:
      - run: echo 'invalid'
"
        .to_string();

        let err = validate_workflow(workflow);

        assert_eq!(
            format!("{}", err),
            "on.workflow_call.inputs.input: \"type\" is a required property\nAdditional properties are not allowed ('boom' was unexpected)\n"
        );
    }
}
