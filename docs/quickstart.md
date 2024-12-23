# Quickstart

First, run `zizmor -h` to make sure your installation succeeded.

You should see something like this:

```console
--8<-- "help.txt"
```

!!! tip

    Run `zizmor --help` for a longer and more detailed version of `zizmor -h`.

## Running `zizmor`

Here are some different ways you can run `zizmor` locally:

=== "On one or more workflows"

    You can run `zizmor` on one or more workflows or composite actions as
    explicit inputs:

    ```bash
    zizmor ci.yml tests.yml lint.yml action.yml
    ```

    These can be in any directory as well:

    ```
    zizmor ./subdir/ci.yml ../sibling/tests.yml ./action/action.yml
    ```

=== "On one or more local repositories"

    !!! tip

        Composite action support was added in v1.0.0.

    !!! tip

        Pass `--collect=workflows-only` to disable collecting composite actions.

    When given one or more local directories, `zizmor` will treat each as a
    GitHub repository and attempt to discover workflows defined under the
    `.github/workflows` subdirectory for each. `zizmor` will also walk each
    directory to find composite action definitions (`action.yml` in any
    subdirectory).

    ```bash
    # repo-a/ contains .github/workflows/{ci,tests}.yml
    # as well as custom-action/action.yml
    zizmor repo-a/

    # or with multiple directories
    zizmor repo-a/ ../../repo-b/

    # collect only workflows, not composite actions
    zizmor --collect=workflows-only
    ```

=== "On one or more remote repositories"

    !!! tip

        Private repositories can also be audited remotely, as long
        as your GitHub API token has sufficient permissions.

    !!! tip

        Pass `--collect=workflows-only` to disable collecting composite actions.

    `zizmor` can also fetch workflows and actions directly from GitHub, if
    given a GitHub API token via `GH_TOKEN` or `--gh-token`:

    ```bash
    # audit all workflows and composite actions in woodruffw/zizmor
    # assumes you have `gh` installed
    zizmor --gh-token=$(gh auth token) woodruffw/zizmor
    ```

    Multiple repositories will also work:

    ```bash
    zizmor --gh-token=$(gh auth token) woodruffw/zizmor woodruffw/gha-hazmat
    ```

See [Usage](./usage.md) for more examples, including examples of configuration.
