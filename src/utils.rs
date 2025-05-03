//! Helper routines.

use anyhow::{Context as _, Error, anyhow};
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

use crate::{audit::AuditInput, models::AsDocument, registry::InputError};

pub(crate) static ACTION_VALIDATOR: LazyLock<Validator> = LazyLock::new(|| {
    validator_for(&serde_json::from_str(include_str!("./data/github-action.json")).unwrap())
        .unwrap()
});

pub(crate) static WORKFLOW_VALIDATOR: LazyLock<Validator> = LazyLock::new(|| {
    validator_for(&serde_json::from_str(include_str!("./data/github-workflow.json")).unwrap())
        .unwrap()
});

fn parse_validation_errors(errors: VecDeque<OutputUnit<ErrorDescription>>) -> Error {
    let mut message = String::new();

    for error in errors {
        let description = error.error_description().to_string();
        // HACK: error descriptions are sometimes a long rats' nest
        // of JSON objects. We should render this in a palatable way
        // but doing so is nontrivial, so we just skip them for now.
        // NOTE: Experimentally, this seems to mostly happen when
        // the error for an unmatched "oneOf", so these errors are
        // typically less useful anyways.
        if !description.starts_with("{") {
            let location = error.instance_location().as_str();
            if location.is_empty() {
                writeln!(message, "{description}").unwrap();
            } else {
                // Convert paths like `/foo/bar/baz` to `foo.bar.baz`,
                // removing the leading separator.
                let dotted_location = &location[1..].replace("/", ".");

                writeln!(message, "{dotted_location}: {description}").unwrap();
            }
        }
    }

    anyhow!(message)
}

/// Like `serde_yaml::from_str`, but with a JSON schema validator
/// and an error type that distinguishes between syntax and semantic
/// errors.
pub(crate) fn from_str_with_validation<'de, T>(
    contents: &'de str,
    validator: &'static Validator,
) -> Result<T, InputError>
where
    T: serde::Deserialize<'de>,
{
    match serde_yaml::from_str::<T>(contents) {
        Ok(value) => Ok(value),
        Err(e) => {
            // Something a little wonky happens here: we want
            // to distinguish between syntax and semantic errors,
            // but serde-yaml doesn't give us an API to do that.
            // To approximate it, we re-parse the input as a
            // `Value` and use that as an oracle -- a successful
            // re-parse indicates that the input is valid YAML and
            // that our error is semantic, while a failed re-parse
            // indicates a syntax error.
            //
            // We do this in a nested fashion to avoid re-parsing
            // the input twice if we can help it, and because the
            // more obvious trick (`serde_yaml::from_value`) doesn't
            // work due to a lack of referential transparency.
            //
            // See: https://github.com/dtolnay/serde-yaml/issues/170
            // See: https://github.com/dtolnay/serde-yaml/issues/395

            match serde_yaml::from_str(contents) {
                // We know we have valid YAML, so one of two things happened here:
                // 1. The input is semantically valid, but we have a bug in
                //    `github-actions-models`.
                // 2. The input is semantically invalid, and the user
                //    needs to fix it.
                // We the JSON schema `validator` to separate these.
                Ok(raw_value) => match validator.apply(&raw_value).basic() {
                    Valid(_) => Err(e)
                        .context("this strongly suggests a bug in zizmor; please report it!")
                        .map_err(|e| InputError::Model(e)),
                    Invalid(errors) => Err(InputError::Schema(parse_validation_errors(errors))),
                },
                // Syntax error.
                Err(e) => Err(InputError::Syntax(e.into())),
            }
        }
    }
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
    let text = input.as_document().source();
    let doc = input.as_document();

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
        models::{Action, Workflow},
        registry::InputKey,
        utils::{
            extract_expression, extract_expressions, normalize_shell, parse_expressions_from_input,
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
}
