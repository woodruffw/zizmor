//! Helper routines.

use github_actions_models::common::{
    expr::{ExplicitExpr, LoE},
    Env,
};

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

/// Parse an expression from the given free-form text, returning the
/// expression and the next offset at which to resume parsing.
///
/// Returns `None` if no expression is found, or an index past
/// the end of the text if parsing is successful but exhausted.
///
/// Adapted roughly from GitHub's `parseScalar`:
/// See: <https://github.com/actions/languageservices/blob/3a8c29c2d/workflow-parser/src/templates/template-reader.ts#L448>
fn extract_expression(text: &str) -> Option<(ExplicitExpr, usize)> {
    let start = text.find("${{")?;

    let mut end = None;
    let mut in_string = false;

    for (idx, char) in text.bytes().enumerate().skip(start) {
        if char == b'\'' {
            in_string = !in_string;
        } else if !in_string && text.as_bytes()[idx] == b'}' && text.as_bytes()[idx - 1] == b'}' {
            end = Some(idx);
            break;
        }
    }

    end.map(|end| {
        (
            ExplicitExpr::from_curly(&text[start..=end]).unwrap(),
            end + 1,
        )
    })
}

/// Extract zero or more expressions from the given free-form text.
pub(crate) fn extract_expressions(text: &str) -> Vec<ExplicitExpr> {
    let mut exprs = vec![];
    let mut view = text;

    while let Some((expr, next)) = extract_expression(view) {
        exprs.push(expr);

        if next >= text.len() {
            break;
        } else {
            view = &view[next..];
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

#[cfg(test)]
mod tests {
    use crate::utils::{extract_expression, extract_expressions};

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
            ("${{ foo }}", "foo", 10),
            ("${{ foo }}${{ bar }}", "foo", 10),
            ("leading ${{ foo }} trailing", "foo", 18),
            (
                "leading ${{ '${{ quoted! }}' }} trailing",
                "'${{ quoted! }}'",
                31,
            ),
            ("${{ 'es''cape' }}", "'es''cape'", 17),
        ];

        for (text, expected_expr, expected_idx) in exprs {
            let (actual_expr, actual_idx) = extract_expression(text).unwrap();
            assert_eq!(*expected_expr, actual_expr.as_bare());
            assert_eq!(*expected_idx, actual_idx);
        }
    }

    #[test]
    fn test_parse_expressions() {
        let expressions = r#"echo "OSSL_PATH=${{ github.workspace }}/osslcache/${{ matrix.PYTHON.OPENSSL.TYPE }}-${{ matrix.PYTHON.OPENSSL.VERSION }}-${OPENSSL_HASH}" >> $GITHUB_ENV"#;
        let exprs = extract_expressions(expressions)
            .into_iter()
            .map(|e| e.as_curly().to_string())
            .collect::<Vec<_>>();

        assert_eq!(
            exprs,
            &[
                "${{ github.workspace }}",
                "${{ matrix.PYTHON.OPENSSL.TYPE }}",
                "${{ matrix.PYTHON.OPENSSL.VERSION }}",
            ]
        )
    }
}
