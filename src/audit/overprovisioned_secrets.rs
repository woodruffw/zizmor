use crate::{
    expr::Expr,
    finding::{Confidence, Feature, Location, Severity},
    utils::extract_expressions,
};

use super::{audit_meta, Audit, AuditInput, AuditState};

pub(crate) struct OverprovisionedSecrets;

audit_meta!(
    OverprovisionedSecrets,
    "overprovisioned-secrets",
    "excessively provisioned secrets"
);

impl Audit for OverprovisionedSecrets {
    fn new(_state: &AuditState) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn audit_raw<'w>(&self, input: &'w AuditInput) -> anyhow::Result<Vec<super::Finding<'w>>> {
        let mut findings = vec![];
        let raw = input.document().source();

        for (expr, span) in extract_expressions(raw) {
            let Ok(parsed) = Expr::parse(expr.as_bare()) else {
                tracing::warn!("couldn't parse expression: {expr}", expr = expr.as_bare());
                continue;
            };

            expr.as_curly();

            for _ in Self::secrets_expansions(&parsed) {
                findings.push(
                    Self::finding()
                        .confidence(Confidence::High)
                        .severity(Severity::Medium)
                        .add_raw_location(Location::new(
                            input
                                .location()
                                .annotated("injects the entire secrets context into the runner")
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

impl OverprovisionedSecrets {
    fn secrets_expansions(expr: &Expr) -> Vec<()> {
        let mut results = vec![];

        match expr {
            Expr::Call { func, args } => {
                // TODO: Consider any function call that accepts bare `secrets`
                // to be a finding? Are there any other functions that users
                // would plausibly call with the entire `secrets` object?
                if func.eq_ignore_ascii_case("toJSON")
                    && args
                        .iter()
                        .any(|arg| matches!(arg, Expr::Context(ctx) if ctx == "secrets"))
                {
                    results.push(());
                } else {
                    results.extend(args.iter().flat_map(Self::secrets_expansions));
                }
            }
            Expr::Index(expr) => results.extend(Self::secrets_expansions(expr)),
            Expr::Context(ctx) => {
                match (ctx.components().first(), ctx.components().get(1)) {
                    // Look for `secrets[...]` accesses where the index component
                    // is not a string literal.
                    (Some(Expr::Identifier(ident)), Some(Expr::Index(idx)))
                        if ident == "secrets" && !matches!(idx.as_ref(), Expr::String(_)) =>
                    {
                        results.push(())
                    }
                    _ => results.extend(ctx.components.iter().flat_map(Self::secrets_expansions)),
                }
            }
            Expr::BinOp { lhs, op: _, rhs } => {
                results.extend(Self::secrets_expansions(lhs));
                results.extend(Self::secrets_expansions(rhs));
            }
            Expr::UnOp { op: _, expr } => results.extend(Self::secrets_expansions(expr)),
            _ => (),
        }

        results
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_secrets_expansions() {
        for (expr, count) in &[
            ("secrets", 0),
            ("toJSON(secrets.foo)", 0),
            ("toJSON(secrets)", 1),
            ("tojson(secrets)", 1),
            ("toJSON(SECRETS)", 1),
            ("tOjSoN(sECrEtS)", 1),
            ("false || toJSON(secrets)", 1),
            ("toJSON(secrets) || toJSON(secrets)", 2),
            ("format('{0}', toJSON(secrets))", 1),
            ("secrets[format('GH_PAT_%s', matrix.env)]", 1),
            ("SECRETS[format('GH_PAT_%s', matrix.env)]", 1),
            ("SECRETS[something.else]", 1),
            ("SECRETS['literal']", 0),
        ] {
            let expr = crate::expr::Expr::parse(expr).unwrap();
            assert_eq!(
                super::OverprovisionedSecrets::secrets_expansions(&expr).len(),
                *count
            );
        }
    }
}
