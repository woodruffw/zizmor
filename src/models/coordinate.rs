//! Functionality for describing and matching `uses:` "coordinates."
//!
//! A "coordinate" is a set of conditions which a `uses:` step can match.
//! These conditions can be non-trivial, such as "match `actions/checkout`,
//! but only if `persist-credentials: false`" is present.
//!
//! Coordinates are useful building blocks for audits like `cache-poisoning`,
//! which need to check a diversity of different step "shapes" to accurately
//! flag potential cache poisoning patterns.

// TODO: We would ideally be even more expressive here and allow basic
// sentential logic and in-field matching. For example, we would ideally be
// able to express things like
// "match foo/bar if foo: A and not bar: B and baz: /abcd/"

use github_actions_models::common::{expr::ExplicitExpr, EnvValue};

use super::{StepCommon, Uses};

pub(crate) enum UsesCoordinate<'w> {
    Configurable {
        /// The `uses:` clause of the coordinate
        uses: Uses<'w>,
        /// The input that controls the coordinate
        control: Control,
        /// Whether or not the behavior is the default
        enabled_by_default: bool,
    },
    NotConfigurable(Uses<'w>),
}

impl UsesCoordinate<'_> {
    pub(crate) fn uses(&self) -> Uses {
        match self {
            UsesCoordinate::Configurable { uses, .. } => *uses,
            UsesCoordinate::NotConfigurable(inner) => *inner,
        }
    }

    /// Returns the "declared" usage from a `with:` field, modulo an expected field type.
    ///
    /// This is an incomplete usage, as the overall semantics can be inverted by the
    /// coordinate. For example, `foo: true` suggests opt-in, but the coordinate may specify
    /// that the `true` value is really an opt-out.
    ///
    /// Intuitively: `disable-cache: true` is an opt-in to `disable-cache`, but an opt-out
    /// of caching. So a coordinate that checks for cache usage inverts the naive result.
    fn declared_usage(&self, value: &EnvValue, field_type: &ControlFieldType) -> Option<Usage> {
        match value.to_string().as_str() {
            "true" if matches!(field_type, ControlFieldType::Boolean) => Some(Usage::DirectOptIn),
            "false" if matches!(field_type, ControlFieldType::Boolean) => {
                // Explicitly opts out from caching
                None
            }
            other => match ExplicitExpr::from_curly(other) {
                None if matches!(field_type, ControlFieldType::String) => Some(Usage::DirectOptIn),
                None => None,
                Some(_) => Some(Usage::ConditionalOptIn),
            },
        }
    }

    /// Returns the semantic "usage" of the given step relative to the current coordinate.
    ///
    /// `None` indicates that the step is "unused" from the perspective of the coordinate,
    /// while the `Some(_)` variants indicate various (potential) usages (such as being implicitly
    /// enabled, or explicitly enabled, or potentially enabled by a template expansion that
    /// can't be directly analyzed).
    pub(crate) fn usage(&self, step: &impl StepCommon) -> Option<Usage> {
        let Uses::Repository(template) = self.uses() else {
            return None;
        };
        let Uses::Repository(uses) = step.uses()? else {
            return None;
        };

        // If our coordinate's `uses:` template doesn't match the step's `uses:`,
        // then no usage semantics are possible.
        if !uses.matches(template) {
            return None;
        }

        match self {
            UsesCoordinate::Configurable {
                uses: _,
                control,
                enabled_by_default,
            } => {
                // We need to inspect this `uses:`'s configuration to determine its semantics.
                let with = step.with()?;
                match with.get(control.field_name) {
                    Some(field_value) => {
                        // The declared usage is whatever the user explicitly configured,
                        // which might be inverted if the semantics are opt-out instead.
                        let declared_usage =
                            self.declared_usage(field_value, &control.field_type)?;

                        match declared_usage {
                            Usage::DirectOptIn => match control.toggle {
                                Toggle::OptIn => Some(declared_usage),
                                Toggle::OptOut => None,
                            },
                            _ => Some(declared_usage),
                        }
                    }
                    None => {
                        // If the controlling field is not present, the default dictates the semantics.
                        if *enabled_by_default {
                            Some(Usage::DefaultActionBehaviour)
                        } else {
                            None
                        }
                    }
                }
            }
            // The mere presence of this `uses:` implies the expected usage semantics.
            UsesCoordinate::NotConfigurable(_) => Some(Usage::Always),
        }
    }
}

pub(crate) enum Toggle {
    /// Opt-in means that cache is **enabled** when the control value matches.
    OptIn,
    /// Opt-out means that cache is **disabled** when the control value matches.
    OptOut,
}

/// The value type that controls the activation/deactivation of caching
#[derive(PartialEq)]
pub(crate) enum ControlFieldType {
    /// The caching behavior is controlled by a boolean field, e.g. `cache: true`.
    Boolean,
    /// The caching behavior is controlled by a string field, e.g. `cache: "pip"`.
    String,
}

/// The input that controls the behavior of a configurable action.
pub(crate) struct Control {
    /// What kind of toggle the input is.
    pub(crate) toggle: Toggle,
    /// The field that controls the action's behavior.
    pub(crate) field_name: &'static str,
    /// The type of the field that controls the action's behavior.
    pub(crate) field_type: ControlFieldType,
}

impl Control {
    pub(crate) fn new(
        toggle: Toggle,
        field_name: &'static str,
        field_type: ControlFieldType,
    ) -> Self {
        Self {
            toggle,
            field_name,
            field_type,
        }
    }
}

#[derive(PartialEq, Debug)]
pub(crate) enum Usage {
    ConditionalOptIn,
    DirectOptIn,
    DefaultActionBehaviour,
    Always,
}
