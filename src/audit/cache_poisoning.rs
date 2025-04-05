use std::str::FromStr;
use std::sync::LazyLock;

use github_actions_models::common::Uses;
use github_actions_models::workflow::Trigger;
use github_actions_models::workflow::event::{BareEvent, BranchFilters, OptionalBody};

use crate::audit::{Audit, audit_meta};
use crate::finding::{Confidence, Finding, Severity};
use crate::models::coordinate::{ActionCoordinate, ControlExpr, ControlFieldType, Toggle, Usage};
use crate::models::{JobExt as _, NormalJob, Step, StepCommon, Steps};
use crate::state::AuditState;

/// The list of know cache-aware actions
/// In the future we can easily retrieve this list from the static API,
/// since it should be easily serializable
static KNOWN_CACHE_AWARE_ACTIONS: LazyLock<Vec<ActionCoordinate>> = LazyLock::new(|| {
    vec![
        // https://github.com/actions/cache/blob/main/action.yml
        ActionCoordinate::Configurable {
            uses: Uses::from_str("actions/cache").unwrap(),
            control: ControlExpr::single(
                Toggle::OptOut,
                "lookup-only",
                ControlFieldType::Boolean,
                true,
            ),
        },
        // https://github.com/actions/setup-java/blob/main/action.yml
        ActionCoordinate::Configurable {
            uses: Uses::from_str("actions/setup-java").unwrap(),
            control: ControlExpr::single(Toggle::OptIn, "cache", ControlFieldType::String, false),
        },
        // https://github.com/actions/setup-go/blob/main/action.yml
        ActionCoordinate::Configurable {
            uses: Uses::from_str("actions/setup-go").unwrap(),
            control: ControlExpr::single(Toggle::OptIn, "cache", ControlFieldType::Boolean, true),
        },
        // https://github.com/actions/setup-node/blob/main/action.yml
        ActionCoordinate::Configurable {
            uses: Uses::from_str("actions/setup-node").unwrap(),
            control: ControlExpr::single(Toggle::OptIn, "cache", ControlFieldType::String, false),
        },
        // https://github.com/actions/setup-python/blob/main/action.yml
        ActionCoordinate::Configurable {
            uses: Uses::from_str("actions/setup-python").unwrap(),
            control: ControlExpr::single(Toggle::OptIn, "cache", ControlFieldType::String, false),
        },
        // https://github.com/actions/setup-dotnet/blob/main/action.yml
        ActionCoordinate::Configurable {
            uses: Uses::from_str("actions/setup-dotnet").unwrap(),
            control: ControlExpr::single(Toggle::OptIn, "cache", ControlFieldType::Boolean, false),
        },
        // https://github.com/astral-sh/setup-uv/blob/main/action.yml
        ActionCoordinate::Configurable {
            uses: Uses::from_str("astral-sh/setup-uv").unwrap(),
            control: ControlExpr::single(
                Toggle::OptOut,
                "enable-cache",
                ControlFieldType::String,
                true,
            ),
        },
        // https://github.com/Swatinem/rust-cache/blob/master/action.yml
        ActionCoordinate::Configurable {
            uses: Uses::from_str("Swatinem/rust-cache").unwrap(),
            control: ControlExpr::single(
                Toggle::OptOut,
                "lookup-only",
                ControlFieldType::Boolean,
                true,
            ),
        },
        // https://github.com/ruby/setup-ruby/blob/master/action.yml
        ActionCoordinate::Configurable {
            uses: Uses::from_str("ruby/setup-ruby").unwrap(),
            control: ControlExpr::single(
                Toggle::OptIn,
                "bundler-cache",
                ControlFieldType::Boolean,
                false,
            ),
        },
        // https://github.com/PyO3/maturin-action/blob/main/action.yml
        ActionCoordinate::Configurable {
            uses: Uses::from_str("PyO3/maturin-action").unwrap(),
            control: ControlExpr::single(
                Toggle::OptIn,
                "sccache",
                ControlFieldType::Boolean,
                false,
            ),
        },
        // https://github.com/mlugg/setup-zig/blob/main/action.yml
        ActionCoordinate::Configurable {
            uses: Uses::from_str("mlugg/setup-zig").unwrap(),
            control: ControlExpr::single(
                Toggle::OptIn,
                "use-cache",
                ControlFieldType::Boolean,
                true,
            ),
        },
        // https://github.com/oven-sh/setup-bun/blob/main/action.yml
        ActionCoordinate::Configurable {
            uses: Uses::from_str("oven-sh/setup-bun").unwrap(),
            control: ControlExpr::single(
                Toggle::OptOut,
                "no-cache",
                ControlFieldType::Boolean,
                true,
            ),
        },
        // https://github.com/DeterminateSystems/magic-nix-cache-action/blob/main/action.yml
        ActionCoordinate::Configurable {
            uses: Uses::from_str("DeterminateSystems/magic-nix-cache-action").unwrap(),
            control: ControlExpr::single(
                Toggle::OptIn,
                "use-gha-cache",
                ControlFieldType::Boolean,
                true,
            ),
        },
        // https://github.com/graalvm/setup-graalvm/blob/main/action.yml
        ActionCoordinate::Configurable {
            uses: Uses::from_str("graalvm/setup-graalvm").unwrap(),
            control: ControlExpr::single(Toggle::OptIn, "cache", ControlFieldType::String, false),
        },
        // https://github.com/gradle/actions/blob/main/setup-gradle/action.yml
        ActionCoordinate::Configurable {
            uses: Uses::from_str("gradle/actions/setup-gradle").unwrap(),
            control: ControlExpr::single(
                Toggle::OptOut,
                "cache-disabled",
                ControlFieldType::Boolean,
                true,
            ),
        },
        // https://github.com/docker/setup-buildx-action/blob/master/action.yml
        ActionCoordinate::Configurable {
            uses: Uses::from_str("docker/setup-buildx-action").unwrap(),
            control: ControlExpr::all([
                ControlExpr::single(
                    Toggle::OptIn,
                    "cache-binary",
                    ControlFieldType::Boolean,
                    true,
                ),
                ControlExpr::single(Toggle::OptIn, "version", ControlFieldType::String, false),
            ]),
        },
        // https://github.com/actions-rust-lang/setup-rust-toolchain/blob/main/action.yml
        ActionCoordinate::Configurable {
            uses: Uses::from_str("actions-rust-lang/setup-rust-toolchain").unwrap(),
            control: ControlExpr::single(Toggle::OptIn, "cache", ControlFieldType::Boolean, true),
        },
        // https://github.com/Mozilla-Actions/sccache-action/blob/main/action.yml
        ActionCoordinate::NotConfigurable(
            Uses::from_str("Mozilla-Actions/sccache-action").unwrap(),
        ),
        // https://github.com/nix-community/cache-nix-action/blob/main/action.yml
        ActionCoordinate::NotConfigurable(
            Uses::from_str("nix-community/cache-nix-action").unwrap(),
        ),
        // https://github.com/jdx/mise-action/blob/main/action.yml
        ActionCoordinate::Configurable {
            uses: Uses::from_str("jdx/mise-action").unwrap(),
            control: ControlExpr::single(Toggle::OptIn, "cache", ControlFieldType::Boolean, true),
        },
    ]
});

/// A list of well-know publisher actions
/// In the future we can retrieve this list from the static API
static KNOWN_PUBLISHER_ACTIONS: LazyLock<Vec<ActionCoordinate>> = LazyLock::new(|| {
    vec![
        // Public packages and/or binary distribution channels
        ActionCoordinate::NotConfigurable(Uses::from_str("pypa/gh-action-pypi-publish").unwrap()),
        ActionCoordinate::NotConfigurable(Uses::from_str("rubygems/release-gem").unwrap()),
        ActionCoordinate::NotConfigurable(Uses::from_str("jreleaser/release-action").unwrap()),
        ActionCoordinate::NotConfigurable(Uses::from_str("goreleaser/goreleaser-action").unwrap()),
        // Github releases
        ActionCoordinate::NotConfigurable(Uses::from_str("softprops/action-gh-release").unwrap()),
        ActionCoordinate::NotConfigurable(
            Uses::from_str("release-drafter/release-drafter").unwrap(),
        ),
        ActionCoordinate::NotConfigurable(
            Uses::from_str("googleapis/release-please-action").unwrap(),
        ),
        // Container registries
        ActionCoordinate::Configurable {
            uses: Uses::from_str("docker/build-push-action").unwrap(),
            control: ControlExpr::single(Toggle::OptIn, "push", ControlFieldType::Boolean, true),
        },
        ActionCoordinate::NotConfigurable(
            Uses::from_str("redhat-actions/push-to-registry").unwrap(),
        ),
        // Cloud + Edge providers
        ActionCoordinate::NotConfigurable(
            Uses::from_str("aws-actions/amazon-ecs-deploy-task-definition ").unwrap(),
        ),
        ActionCoordinate::NotConfigurable(
            Uses::from_str("aws-actions/aws-cloudformation-github-deploy").unwrap(),
        ),
        ActionCoordinate::NotConfigurable(Uses::from_str("Azure/aci-deploy").unwrap()),
        ActionCoordinate::NotConfigurable(
            Uses::from_str("Azure/container-apps-deploy-action").unwrap(),
        ),
        ActionCoordinate::NotConfigurable(Uses::from_str("Azure/functions-action").unwrap()),
        ActionCoordinate::NotConfigurable(Uses::from_str("Azure/sql-action").unwrap()),
        ActionCoordinate::NotConfigurable(Uses::from_str("cloudflare/wrangler-action").unwrap()),
        ActionCoordinate::NotConfigurable(
            Uses::from_str("google-github-actions/deploy-appengine").unwrap(),
        ),
        ActionCoordinate::NotConfigurable(
            Uses::from_str("google-github-actions/deploy-cloudrun").unwrap(),
        ),
        ActionCoordinate::NotConfigurable(
            Uses::from_str("google-github-actions/deploy-cloud-functions").unwrap(),
        ),
    ]
});

enum PublishingArtifactsScenario<'w> {
    UsingTypicalWorkflowTrigger,
    UsingWellKnowPublisherAction(Step<'w>),
}

pub(crate) struct CachePoisoning;

audit_meta!(
    CachePoisoning,
    "cache-poisoning",
    "runtime artifacts potentially vulnerable to a cache poisoning attack"
);

impl CachePoisoning {
    fn trigger_used_when_publishing_artifacts(&self, trigger: &Trigger) -> bool {
        match trigger {
            Trigger::BareEvent(event) => *event == BareEvent::Release,
            Trigger::BareEvents(events) => events.contains(&BareEvent::Release),
            Trigger::Events(events) => match &events.push {
                OptionalBody::Body(body) => {
                    let pushing_new_tag = &body.tag_filters.is_some();
                    let pushing_to_release_branch =
                        if let Some(BranchFilters::Branches(branches)) = &body.branch_filters {
                            branches
                                .iter()
                                .any(|branch| branch.to_lowercase().contains("release"))
                        } else {
                            false
                        };

                    *pushing_new_tag || pushing_to_release_branch
                }
                _ => false,
            },
        }
    }

    fn detected_well_known_publisher_step(steps: Steps) -> Option<Step> {
        steps.into_iter().find(|step| {
            // TODO: Specialize further here, and produce an appropriate
            // confidence/persona setting if the usage is conditional.
            KNOWN_PUBLISHER_ACTIONS
                .iter()
                .any(|publisher| publisher.usage(step).is_some())
        })
    }

    fn is_job_publishing_artifacts<'w>(
        &self,
        trigger: &Trigger,
        steps: Steps<'w>,
    ) -> Option<PublishingArtifactsScenario<'w>> {
        if self.trigger_used_when_publishing_artifacts(trigger) {
            return Some(PublishingArtifactsScenario::UsingTypicalWorkflowTrigger);
        };

        let well_know_publisher = CachePoisoning::detected_well_known_publisher_step(steps)?;

        Some(PublishingArtifactsScenario::UsingWellKnowPublisherAction(
            well_know_publisher,
        ))
    }

    fn evaluate_cache_usage<'s>(&self, step: &impl StepCommon<'s>) -> Option<Usage> {
        KNOWN_CACHE_AWARE_ACTIONS
            .iter()
            .find_map(|coord| coord.usage(step))
    }

    fn uses_cache_aware_step<'w>(
        &self,
        step: &Step<'w>,
        scenario: &PublishingArtifactsScenario<'w>,
    ) -> Option<Finding<'w>> {
        let cache_usage = self.evaluate_cache_usage(step)?;

        let (yaml_key, annotation) = match cache_usage {
            Usage::Always => ("uses", "caching always restored here"),
            Usage::DefaultActionBehaviour => ("uses", "cache enabled by default here"),
            Usage::DirectOptIn => ("with", "opt-in for caching here"),
            Usage::ConditionalOptIn => ("with", "opt-in for caching might happen here"),
        };

        let finding = match scenario {
            PublishingArtifactsScenario::UsingTypicalWorkflowTrigger => Self::finding()
                .confidence(Confidence::Low)
                .severity(Severity::High)
                .add_location(
                    step.workflow()
                        .location()
                        .with_keys(&["on".into()])
                        .annotated("generally used when publishing artifacts generated at runtime"),
                )
                .add_location(
                    step.location()
                        .primary()
                        .with_keys(&[yaml_key.into()])
                        .annotated(annotation),
                )
                .build(step.workflow()),
            PublishingArtifactsScenario::UsingWellKnowPublisherAction(publisher) => Self::finding()
                .confidence(Confidence::Low)
                .severity(Severity::High)
                .add_location(
                    publisher
                        .location()
                        .with_keys(&["uses".into()])
                        .annotated("runtime artifacts usually published here"),
                )
                .add_location(
                    step.location()
                        .primary()
                        .with_keys(&[yaml_key.into()])
                        .annotated(annotation),
                )
                .build(step.workflow()),
        };

        finding.ok()
    }
}

impl Audit for CachePoisoning {
    fn new(_state: &AuditState<'_>) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn audit_normal_job<'w>(&self, job: &NormalJob<'w>) -> anyhow::Result<Vec<Finding<'w>>> {
        let mut findings = vec![];
        let steps = job.steps();
        let trigger = &job.parent().on;

        let Some(scenario) = self.is_job_publishing_artifacts(trigger, steps) else {
            return Ok(findings);
        };

        for step in job.steps() {
            if let Some(finding) = self.uses_cache_aware_step(&step, &scenario) {
                findings.push(finding);
            }
        }

        Ok(findings)
    }
}
