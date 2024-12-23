---
description: zizmor's configuration file and configurable behaviors.
---

# Configuration

!!! note

    Configuration support was added in `v0.2.0`.

`zizmor` supports a small amount of configuration via [YAML] config files,
typically named `zizmor.yml`.

[YAML]: https://learnxinyminutes.com/docs/yaml/

## Precedence

!!! note

    Configuration is *always* optional, and can always be disabled with
    `--no-config`. If `--no-config` is passed, no configuration is ever loaded.

`zizmor` will discover and load
configuration files in the following order of precedence:

1. Passed explicitly via `--config`, e.g. `--config my-config.yml`. When passed
   explicitly, the config file does *not* need to be named `zizmor.yml`.
1. `${CWD}/.github/zizmor.yml`
1. `${CWD}/zizmor.yml`

For the last two discovery methods, `${CWD}` is the current working directory,
i.e. the directory that `zizmor` was executed from.

Only one configuration file is ever loaded. In other words: if both
`${CWD}/.github/zizmor.yml` and `${CWD}/zizmor.yml` exist, only the former
will be loaded, per the precedence rules above.

## Settings

### `rules`

#### `rules.<id>`

##### `rules.<id>.ignore`

_Type_: `array`

Per-audit ignore rules, where `id` is the audit's name, e.g.
[`template-injection`](./audits.md#template-injection).

Each member of `rules.<id>.ignore` is a *workflow rule*, formatted as follows:

```
filename.yml:<line>?:<column>?
```

where `filename.yml` is the base filename of the workflow, and `line` and
`column` are both optional 1-based values indicating the exact line-and-column
location to ignore. If one or both are absent, then the rule applies to the
entire file or entire line.

!!! important

    Composite action findings cannot be ignored via `zizmor.yml` currently.

For example, here is a configuration file with two different audit ignore
rule groups:

```yaml title="zizmor.yml"
rules:
  template-injection:
    ignore:
      # ignore line 100 in ci.yml, any column
      - ci.yml:100
      # ignore all lines and columns in tests.yml
      - tests.yml
  use-trusted-publishing:
    ignore:
      # ignore line 12, column 10 on pypi.yml
      - pypi.yml:12:10
```
