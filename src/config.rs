use std::{collections::HashMap, fs, num::NonZeroUsize, str::FromStr};

use anyhow::{Context as _, Result, anyhow};
use serde::{
    Deserialize,
    de::{self, DeserializeOwned},
};

use crate::{App, finding::Finding};

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct WorkflowRule {
    /// The workflow filename.
    pub(crate) filename: String,
    /// The (1-based) line within [`Self::filename`] that the rule occurs on.
    pub(crate) line: Option<usize>,
    /// The (1-based) column within [`Self::filename`] that the rule occurs on.
    pub(crate) column: Option<usize>,
}

impl FromStr for WorkflowRule {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // A rule has three parts, delimited by `:`, two of which
        // are optional: `foobar.yml:line:col`, where `line` and `col`
        // are optional. `col` can only be provided if `line` is provided.
        let parts = s.rsplitn(3, ':').collect::<Vec<_>>();
        let mut parts = parts.iter().rev();

        let filename = parts
            .next()
            .ok_or_else(|| anyhow!("rule is missing a filename component"))?;

        if !filename.ends_with(".yml") && !filename.ends_with(".yaml") {
            return Err(anyhow!("invalid workflow filename: {filename}"));
        }

        let line = parts
            .next()
            .map(|line| NonZeroUsize::from_str(line).map(|line| line.get()))
            .transpose()
            .with_context(|| "invalid line number component (must be 1-based)")?;
        let column = parts
            .next()
            .map(|col| NonZeroUsize::from_str(col).map(|col| col.get()))
            .transpose()
            .with_context(|| "invalid column number component (must be 1-based)")?;

        Ok(Self {
            filename: filename.to_string(),
            line,
            column,
        })
    }
}

impl<'de> Deserialize<'de> for WorkflowRule {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        WorkflowRule::from_str(&raw).map_err(de::Error::custom)
    }
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct AuditRuleConfig {
    #[serde(default)]
    ignore: Vec<WorkflowRule>,
    #[serde(default)]
    config: Option<serde_yaml::Mapping>,
}

/// Runtime configuration, corresponding to a `zizmor.yml` file.
#[derive(Clone, Debug, Default, Deserialize)]
pub(crate) struct Config {
    rules: HashMap<String, AuditRuleConfig>,
}

impl Config {
    pub(crate) fn new(app: &App) -> Result<Self> {
        if app.no_config {
            return Ok(Self::default());
        }

        let config = match &app.config {
            Some(path) => serde_yaml::from_str(&fs::read_to_string(path)?)?,
            None => {
                // If the user didn't pass a config path explicitly with
                // `--config`, then we attempt to discover one relative to $CWD
                // Our procedure is to first look for `$CWD/.github/zizmor.yml`,
                // then `$CWD/zizmor.yml`, and then bail.
                let cwd = std::env::current_dir()
                    .with_context(|| "config discovery couldn't access CWD")?;

                let path = cwd.join(".github").join("zizmor.yml");
                if path.is_file() {
                    serde_yaml::from_str(&fs::read_to_string(path)?)?
                } else {
                    let path = cwd.join("zizmor.yml");
                    if path.is_file() {
                        serde_yaml::from_str(&fs::read_to_string(path)?)?
                    } else {
                        tracing::debug!("no config discovered; loading default");
                        Config::default()
                    }
                }
            }
        };

        tracing::debug!("loaded config: {config:?}");

        Ok(config)
    }

    /// Returns `true` if this [`Config`] has an ignore rule for the
    /// given finding.
    pub(crate) fn ignores(&self, finding: &Finding<'_>) -> bool {
        let Some(rule_config) = self.rules.get(finding.ident) else {
            return false;
        };

        let ignores = &rule_config.ignore;

        // If *any* location in the finding matches an ignore rule,
        // we consider the entire finding ignored.
        // This will hopefully minimize confusion when a finding spans
        // multiple files, as the first location is the one a user will
        // typically ignore, suppressing the rest in the process.
        for loc in &finding.locations {
            for rule in ignores
                .iter()
                .filter(|i| i.filename == loc.symbolic.key.filename())
            {
                match rule {
                    // Rule has a line and (maybe) a column.
                    WorkflowRule {
                        line: Some(line),
                        column,
                        ..
                    } => {
                        if *line == loc.concrete.location.start_point.row + 1
                            && column.is_none_or(|col| {
                                col == loc.concrete.location.start_point.column + 1
                            })
                        {
                            return true;
                        } else {
                            continue;
                        }
                    }
                    // Rule has no line/col, so we match by virtue of the filename matching.
                    WorkflowRule {
                        line: None,
                        column: None,
                        ..
                    } => return true,
                    _ => unreachable!(),
                }
            }
        }

        false
    }

    pub(crate) fn rule_config<T>(&self, ident: &str) -> Result<Option<T>>
    where
        T: DeserializeOwned,
    {
        Ok(self
            .rules
            .get(ident)
            .and_then(|rule_config| rule_config.config.as_ref())
            .map(|policy| serde_yaml::from_value::<T>(serde_yaml::Value::Mapping(policy.clone())))
            .transpose()?)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use anyhow::Result;

    use super::WorkflowRule;

    #[test]
    fn test_parse_workflow_rule() -> Result<()> {
        assert_eq!(
            WorkflowRule::from_str("foo.yml:1:2")?,
            WorkflowRule {
                filename: "foo.yml".into(),
                line: Some(1),
                column: Some(2)
            }
        );

        assert_eq!(
            WorkflowRule::from_str("foo.yml:123")?,
            WorkflowRule {
                filename: "foo.yml".into(),
                line: Some(123),
                column: None
            }
        );

        assert!(WorkflowRule::from_str("foo.yml:0:0").is_err());
        assert!(WorkflowRule::from_str("foo.yml:1:0").is_err());
        assert!(WorkflowRule::from_str("foo.yml:0:1").is_err());
        assert!(WorkflowRule::from_str("foo.yml:123:").is_err());
        assert!(WorkflowRule::from_str("foo.yml::").is_err());
        assert!(WorkflowRule::from_str("foo.yml::1").is_err());
        assert!(WorkflowRule::from_str("foo::1").is_err());
        assert!(WorkflowRule::from_str("foo.unrelated::1").is_err());
        // TODO: worth dealing with?
        // assert!(WorkflowRule::from_str(".yml:1:1").is_err());
        assert!(WorkflowRule::from_str("::1").is_err());
        assert!(WorkflowRule::from_str(":1:1").is_err());
        assert!(WorkflowRule::from_str("1:1").is_err());

        Ok(())
    }
}
