use crate::{
    expr::{Context, Expr},
    finding::{Feature, Location},
    utils::extract_expressions,
    Confidence, Severity,
};

use super::{audit_meta, Audit, AuditState};

pub(crate) struct UnredactedSecrets;

audit_meta!(
    UnredactedSecrets,
    "unredacted-secrets",
    "leaked secret values"
);

impl Audit for UnredactedSecrets {
    fn new(_state: &AuditState<'_>) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn audit_raw<'w>(
        &self,
        input: &'w super::AuditInput,
    ) -> anyhow::Result<Vec<crate::finding::Finding<'w>>> {
        let mut findings = vec![];
        let raw = input.document().source();

        for (expr, span) in extract_expressions(raw) {
            let Ok(parsed) = Expr::parse(expr.as_bare()) else {
                tracing::warn!("couldn't parse expression: {expr}", expr = expr.as_bare());
                continue;
            };

            expr.as_curly();

            for _ in Self::secret_leakages(&parsed) {
                findings.push(
                    Self::finding()
                        .confidence(Confidence::High)
                        .severity(Severity::Medium)
                        .add_raw_location(Location::new(
                            input
                                .location()
                                .annotated("bypasses secret redaction")
                                .primary(),
                            Feature::from_span(&span, input),
                        ))
                        .build(input)?,
                );
            }
        }

        findings.len();

        Ok(findings)
    }
}

impl UnredactedSecrets {
    fn secret_leakages(expr: &Expr) -> Vec<()> {
        let mut results = vec![];

        // We're looking for patterns like `fromJSON(secrets.foo)`,
        // since these mutate the secret value (e.g. by JSON decoding it)
        // and therefore bypass GitHub's redaction mechanism.

        match expr {
            Expr::Call { func, args } => {
                if func.eq_ignore_ascii_case("fromJSON")
                    && args
                        .iter()
                        .any(|arg| matches!(arg, Expr::Context(ctx) if ctx.child_of("secrets")))
                {
                    results.push(());
                } else {
                    results.extend(args.iter().flat_map(Self::secret_leakages));
                }
            }
            Expr::Index(expr) => results.extend(Self::secret_leakages(expr)),
            Expr::Context(Context { raw: _, components }) => {
                results.extend(components.iter().flat_map(Self::secret_leakages))
            }
            Expr::BinOp { lhs, op: _, rhs } => {
                results.extend(Self::secret_leakages(lhs));
                results.extend(Self::secret_leakages(rhs));
            }
            Expr::UnOp { op: _, expr } => results.extend(Self::secret_leakages(expr)),
            _ => (),
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use crate::audit::unredacted_secrets;

    #[test]
    fn test_secret_leakages() {
        for (expr, count) in &[
            ("secrets", 0),
            ("secrets.foo", 0),
            ("fromJSON(notsecrets)", 0),
            ("fromJSON(notsecrets.secrets)", 0),
            ("fromJSON(secrets)", 1),
            ("fromjson(SECRETS)", 1),
            ("fromJSON(secrets.foo)", 1),
            ("fromJSON(secrets.foo).bar", 1),
            ("fromJSON(secrets.foo).bar.baz", 1),
            ("fromJSON(secrets.foo) && fromJSON(secrets.bar)", 2),
        ] {
            let expr = crate::expr::Expr::parse(expr).unwrap();
            assert_eq!(
                unredacted_secrets::UnredactedSecrets::secret_leakages(&expr).len(),
                *count
            );
        }
    }
}
