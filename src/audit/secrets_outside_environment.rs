use github_actions_models::{
    common::{expr::LoE, Env, EnvValue},
    workflow::job::StepBody,
};

use super::{audit_meta, Audit};
use crate::{finding::Confidence, models::Job};

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

    fn audit_raw<'w>(
        &self,
        input: &'w super::AuditInput,
    ) -> anyhow::Result<Vec<crate::finding::Finding<'w>>> {
        let mut findings = vec![];

        if let super::AuditInput::Workflow(w) = input {
            for job in w.jobs() {
                if let Job::NormalJob(j) = job {
                    if j.environment().is_some() {
                        continue;
                    }

                    for step in j.steps() {
                        let body = &step.body;
                        let eenv: &Env;

                        match body {
                            StepBody::Uses { uses: _, with } => {
                                eenv = with;
                            }
                            StepBody::Run {
                                run: _,
                                shell: _,
                                env,
                                working_directory: _,
                            } => match env {
                                LoE::Expr(_) => {
                                    // TODO: Implement this.
                                    panic!("We don't handle Expr yet!")
                                }
                                LoE::Literal(env) => eenv = env,
                            },
                        }

                        for v in eenv.values() {
                            if let EnvValue::String(s) = v {
                                if s.contains("secrets") {
                                    findings.push(
                                        Self::finding()
                                            .add_location(step.location().primary())
                                            .confidence(Confidence::High)
                                            .severity(crate::finding::Severity::High)
                                            .build(input)?,
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(findings)
    }
}
