use github_actions_models::{
    common::{
        Env, EnvValue,
        expr::{ExplicitExpr, LoE},
    },
    workflow::job::StepBody,
};

use super::{Audit, audit_meta};
use crate::{AuditLoadError, AuditState, Persona, finding::Confidence, models::StepCommon};

pub(crate) struct SecretWithoutEnv;

audit_meta!(
    SecretWithoutEnv,
    "secret-without-env",
    "secret used without an environment to gate it"
);

impl Audit for SecretWithoutEnv {
    fn new(_state: &AuditState<'_>) -> Result<Self, AuditLoadError>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn audit_step<'w>(
        &self,
        step: &crate::models::Step<'w>,
    ) -> anyhow::Result<Vec<crate::finding::Finding<'w>>> {
        let mut findings = vec![];

        if step.parent.environment().is_some() {
            return Ok(findings);
        }

        let eenv: &Env;
        match &step.body {
            StepBody::Uses { uses: _, with } => {
                eenv = with;
            }
            StepBody::Run {
                run: _,
                shell: _,
                env,
                working_directory: _,
            } => match env {
                LoE::Expr(e) => {
                    Self::check_secrets_access(e.as_bare(), step, &mut findings)?;
                    return Ok(findings);
                }
                LoE::Literal(env) => eenv = env,
            },
        }

        for v in eenv.values() {
            if let EnvValue::String(s) = v {
                if let Some(expr) = ExplicitExpr::from_curly(s) {
                    Self::check_secrets_access(expr.as_bare(), step, &mut findings)?;
                } else {
                    Self::check_secrets_access(s, step, &mut findings)?
                }
            }
        }

        Ok(findings)
    }
}

impl SecretWithoutEnv {
    fn check_secrets_access<'w>(
        s: &str,
        step: &crate::models::Step<'w>,
        findings: &mut Vec<crate::finding::Finding<'w>>,
    ) -> anyhow::Result<()> {
        // See https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication
        // for `secrets.github_token`
        if s.contains("secrets") && s.trim() != "secrets.github_token" {
            findings.push(
                Self::finding()
                    .add_location(step.location().primary())
                    .confidence(Confidence::High)
                    .severity(crate::finding::Severity::High)
                    .persona(Persona::Pedantic)
                    .build(step.workflow())?,
            );
        }

        Ok(())
    }
}
