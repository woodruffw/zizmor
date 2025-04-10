use github_actions_models::{
    common::{Env, EnvValue, expr::LoE},
    workflow::job::StepBody,
};

use super::{Audit, audit_meta};
use crate::finding::Confidence;

pub(crate) struct SecretsOutsideEnvironment;

audit_meta!(
    SecretsOutsideEnvironment,
    "secrets-outside-environment",
    "secrets used without an environment to gate them"
);

impl Audit for SecretsOutsideEnvironment {
    fn new(_state: super::AuditState) -> anyhow::Result<Self>
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
                Self::check_secrets_access(s, step, &mut findings)?
            }
        }

        Ok(findings)
    }
}

impl SecretsOutsideEnvironment {
    fn check_secrets_access<'w>(
        s: &str,
        step: &crate::models::Step<'w>,
        findings: &mut Vec<crate::finding::Finding<'w>>,
    ) -> anyhow::Result<()> {
        if s.contains("secrets") {
            findings.push(
                Self::finding()
                    .add_location(step.location().primary())
                    .confidence(Confidence::High)
                    .severity(crate::finding::Severity::High)
                    .build(step.workflow())?,
            );
        }

        Ok(())
    }
}
