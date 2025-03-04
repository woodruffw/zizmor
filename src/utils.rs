//! Helper routines.

use std::ops::Range;

use camino::Utf8Path;
use github_actions_models::common::{
    expr::{ExplicitExpr, LoE},
    Env,
};

use crate::audit::AuditInput;

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

// /// Like `extract_expressions`, but over an entire audit input (e.g. workflow
// /// or action definition).
// ///
// /// Unlike `extract_expressions`, this function performs some semantic
// /// filtering over the raw input. For example, it skip ignore expressions
// /// that are inside comments.
// pub(crate) fn extract_expressions_raw(input: &AuditInput) -> Vec<(ExplicitExpr, Range<usize>)> {
//     let text = input.document().source();
//     let doc = input.document();

//     let mut exprs = vec![];
//     let mut offset = 0;

//     while let Some((expr, span)) = extract_expression(text, offset) {
//         exprs.push((expr, (span.start..span.end)));

//         if span.end >= text.len() {
//             break;
//         } else {
//             offset = span.end;
//         }
//     }

//     exprs
// }

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
    use crate::utils::{extract_expression, extract_expressions, normalize_shell};

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
    fn test_parse_expression() {
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
    fn test_parse_expressions() {
        let multiple = r#"echo "OSSL_PATH=${{ github.workspace }}/osslcache/${{ matrix.PYTHON.OPENSSL.TYPE }}-${{ matrix.PYTHON.OPENSSL.VERSION }}-${OPENSSL_HASH}" >> $GITHUB_ENV"#;

        // See #569 -- we should ignore the broken expression since it's inside a comment.
        let incomplete = r#"
name: >-  # ${{ '' } is a hack to nest jobs under the same sidebar category
  Windows MSI${{ '' }}
        "#;

        for (raw, expected) in &[
            (
                multiple,
                [
                    "${{ github.workspace }}",
                    "${{ matrix.PYTHON.OPENSSL.TYPE }}",
                    "${{ matrix.PYTHON.OPENSSL.VERSION }}",
                ]
                .as_slice(),
            ),
            (incomplete, ["${{ '' }"].as_slice()),
        ] {
            let exprs = extract_expressions(raw)
                .into_iter()
                .map(|(e, _)| e.as_curly().to_string())
                .collect::<Vec<_>>();

            assert_eq!(exprs, *expected)
        }
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
