use crate::{
    expr::Expr,
    finding::{ConcreteLocation, Confidence, Feature, Location, Severity},
    utils::extract_expressions,
};

use super::{audit_meta, Audit, AuditInput};

pub(crate) struct OverprovisionedSecrets;

audit_meta!(
    OverprovisionedSecrets,
    "overprovisioned-secrets",
    "excessively provisioned secrets"
);

impl Audit for OverprovisionedSecrets {
    fn new(_state: super::AuditState) -> anyhow::Result<Self>
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

            dbg!(expr.as_curly());

            for _ in Self::secrets_expansions(&parsed) {
                let start_point = input.line_index().line_col((span.start as u32).into());
                let end_point = input.line_index().line_col((span.end as u32).into());

                findings.push(
                    Self::finding()
                        .confidence(Confidence::High)
                        .severity(Severity::Medium)
                        .add_raw_location(Location::new(
                            input
                                .location()
                                .annotated("injects the entire secrets context into the runner")
                                .primary(),
                            Feature {
                                location: ConcreteLocation::new(
                                    start_point.into(),
                                    end_point.into(),
                                    span.start..span.end,
                                ),
                                feature: dbg!(&raw[span.start..span.end]),
                                comments: vec![], // TODO: extract comments
                            },
                        ))
                        .build(input)?,
                );
            }
        }

        dbg!(findings.len());

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
                // would plausible call with the entire `secrets` object?
                if func == "toJSON"
                    && args
                        .iter()
                        .any(|arg| matches!(arg, Expr::Context { raw, components: _ } if raw == "secrets"))
                {
                    results.push(());
                } else {
                    results.extend(args.iter().flat_map(Self::secrets_expansions));
                }
            }
            Expr::Index(expr) => results.extend(Self::secrets_expansions(expr)),
            Expr::Context { raw: _, components } => {
                results.extend(components.iter().flat_map(Self::secrets_expansions))
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
            ("false || toJSON(secrets)", 1),
            ("toJSON(secrets) || toJSON(secrets)", 2),
            ("format('{0}', toJSON(secrets))", 1),
        ] {
            let expr = crate::expr::Expr::parse(expr).unwrap();
            assert_eq!(
                super::OverprovisionedSecrets::secrets_expansions(&expr).len(),
                *count
            );
        }
    }
}
