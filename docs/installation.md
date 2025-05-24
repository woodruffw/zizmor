---
description: Installation instructions for zizmor.
---

# Installation

## From package managers

`zizmor` is available within several packaging ecosystems.

=== ":simple-rust: crates.io"

    ![Crates.io Version](https://img.shields.io/crates/v/zizmor)

    You can install `zizmor` from <https://crates.io> with `cargo`:

    ```bash
    cargo install --locked zizmor
    ```

=== ":simple-homebrew: Homebrew"

    ![Homebrew Formula Version](https://img.shields.io/homebrew/v/zizmor)

    `zizmor` is provided by [Homebrew](https://brew.sh/):

    ```bash
    brew install zizmor
    ```

=== ":simple-pypi: PyPI"

    ![PyPI - Version](https://img.shields.io/pypi/v/zizmor)

    `zizmor` is available on [PyPI](https://pypi.org) and can be installed
    with any Python package installer.

    !!! important

        Python wheels for `zizmor` are provided on a best-effort basis,
        with priority given to the most common architectures and host OSes.


    ```bash
    # with pip
    pip install zizmor

    # with pipx
    pipx install zizmor

    # with uv
    uv tool install zizmor

    # or, shortcut:
    uvx zizmor --help
    ```

=== ":simple-docker: Docker"

    An official `zizmor` image is available from the [GitHub Container Registry](https://ghcr.io/zizmorcore/zizmor):

    ```bash
    docker pull ghcr.io/zizmorcore/zizmor:latest
    ```

=== ":simple-anaconda: Conda"

    [![Anaconda-Server Badge](https://anaconda.org/conda-forge/zizmor/badges/version.svg)](https://anaconda.org/conda-forge/zizmor)
    [![Anaconda-Server Badge](https://anaconda.org/conda-forge/zizmor/badges/latest_release_date.svg)](https://anaconda.org/conda-forge/zizmor)
    [![Anaconda-Server Badge](https://anaconda.org/conda-forge/zizmor/badges/platforms.svg)](https://anaconda.org/conda-forge/zizmor)

    !!! note

        This is a community-maintained package.

    `zizmor` is available on Anaconda's conda-forge:

    ```bash
    conda install conda-forge::zizmor
    ```

    See [conda-forge/zizmor](https://anaconda.org/conda-forge/zizmor)
    for additional information.


=== ":material-nix: Nix"

    [![nixpkgs unstable package](https://repology.org/badge/version-for-repo/nix_unstable/zizmor.svg)](https://repology.org/project/zizmor/versions)

    !!! note

        This is a community-maintained package.

    ```bash
    # without flakes
    nix-env -iA nixos.zizmor

    # with flakes
    nix profile install nixpkgs#zizmor
    ```

=== ":simple-archlinux: Arch Linux"

    [![Arch Linux package](https://repology.org/badge/version-for-repo/arch/zizmor.svg)](https://repology.org/project/zizmor/versions)

    !!! note

        This is a community-maintained package.

    ```bash
    # zizmor-git is also available in the AUR
    pacman -S zizmor
    ```

=== "Chimera Linux"

    [![Chimera Linux package](https://repology.org/badge/version-for-repo/chimera/zizmor.svg)](https://repology.org/project/zizmor/versions)

    !!! note

        This is a community-maintained package.

    `zizmor` is available in [Chimera Linux' user repo](https://chimera-linux.org/docs/apk#repositories):

    ```bash
    # If you don't have the 'user' repo enabled yet, do that first
    apk add chimera-repo-user

    apk add zizmor
    ```

=== "Alpine Linux"

    [![Alpine Linux package](https://repology.org/badge/version-for-repo/alpine_edge/zizmor.svg)](https://repology.org/project/zizmor/versions)

    !!! note

        This is a community-maintained package.

    ```bash
    apk add zizmor
    ```

=== "Other ecosystems"

    !!! info

        Are you interested in packaging `zizmor` for another ecosystem?
        Let us know by [filing an issue](https://github.com/zizmorcore/zizmor/issues/new)!

    The badge below tracks `zizmor`'s overall packaging status.

    [![Packaging status](https://repology.org/badge/vertical-allrepos/zizmor.svg)](https://repology.org/project/zizmor/versions)

## From source

!!! warning

    Most ordinary users **should not** install directly from `zizmor`'s
    source repository. No stability or correctness guarantees are made about
    direct source installations.

You can install the latest unstable `zizmor` directly from GitHub with `cargo`:

```bash
cargo install --git https://github.com/zizmorcore/zizmor
```

## From GitHub release binaries

!!! warning

    Most ordinary users **should not** install the binaries from
    `zizmor`'s GitHub releases. Binaries are provided on a best-effort basis,
    and may be subject to libc and other compatibility issues.

`zizmor`'s GitHub releases contain pre-built binaries for several platforms
and architectures. You can find them at
<https://github.com/zizmorcore/zizmor/releases/latest>.
