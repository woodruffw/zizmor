#!/usr/bin/env -S uv run --script --only-group codegen

"""
Processes the CodeQL models from https://github.com/github/codeql/tree/main/actions/ql/lib/ext
and extracts the information needed by zizmor
"""

import json
import os
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Set

import yaml


def _debug(msg: str) -> None:
    print(f"[+] {msg}", file=sys.stderr)


def _git(args: List[str], cwd: Path = None) -> subprocess.CompletedProcess:
    """Run a git command and return the result."""
    result = subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, check=True
    )
    return result


def _clone_actions_codeql(temp_dir: Path) -> Path:
    """Clone the CodeQL repository with sparse checkout for only the needed directory."""
    repo_path = os.path.join(temp_dir, "codeql")

    _debug("Cloning CodeQL repository with sparse checkout...")

    repo_path = temp_dir / "codeql"

    _git(
        [
            "clone",
            "--filter=tree:0",
            "--no-checkout",
            "--depth=1",
            "--sparse",
            "https://github.com/github/codeql.git",
        ],
        cwd=temp_dir,
    )

    _git(
        [
            "sparse-checkout",
            "add",
            "actions/ql/lib/ext/",
        ],
        cwd=repo_path,
    )

    _git(
        [
            "checkout",
        ],
        cwd=repo_path,
    )

    _debug("Successfully cloned CodeQL repository")
    return repo_path


def _process_yaml_file(
    file_path: Path,
    relevant_kinds: Set[str],
    only_manual_models: bool,
    code_injection_sinks: Dict[str, List[str]],
) -> None:
    """Process a single YAML file and extract sink information."""
    with file_path.open() as f:
        content = yaml.safe_load(f)

    extensions = content.get("extensions")
    if extensions is None:
        raise ValueError(f"Missing extensions: {content}")

    for extension in extensions:
        adds_to = extension.get("addsTo")
        if adds_to is None:
            raise ValueError(f"Missing addsTo: {content}")

        extensible = adds_to.get("extensible")
        if extensible != "actionsSinkModel":
            continue

        pack = adds_to.get("pack")
        # Fail if CodeQL starts using other packs, have to examine then what this means,
        # e.g. whether it has lower accuracy or severity
        if pack != "codeql/actions-all":
            raise ValueError(f"Unexpected pack: {pack}")

        data = extension.get("data")
        if data is None:
            raise ValueError(f"Missing data: {content}")

        for data_entry in data:
            if len(data_entry) != 5:
                raise ValueError(f"Contains malformed data entry: {data_entry}")

            # See https://github.com/github/codeql/blob/codeql-cli/v2.21.2/actions/ql/lib/codeql/actions/dataflow/internal/ExternalFlowExtensions.qll#L22-L24
            action, version, input_param, kind, provenance = data_entry

            if kind not in relevant_kinds:
                continue

            if only_manual_models and provenance != "manual":
                continue

            # TODO: Look at reusable workflows as sinks as well.
            # This might require some data cleaning, since CodeQL appears to
            # incorrectly duplicate these across both 'composite-actions'
            # and 'reusable-workflows'. Maybe something we can fix upstream?
            if "/.github/workflows/" in action:
                continue

            # Currently all models use only '*' as affected version, so for simplicity only
            # support that for now
            if version != "*":
                raise ValueError(
                    f"Non-wildcard versions are not supported yet: {version}"
                )

            input_prefix = "input."
            if not input_param.startswith(input_prefix):
                raise ValueError(
                    f"Contains input with unexpected format: {input_param}"
                )

            input_name = input_param[len(input_prefix) :]

            code_injection_sinks[action].append(input_name)


def _process_models(codeql_dir: Path) -> None:
    """Process all CodeQL model files and generate the output."""
    code_injection_sinks: Dict[str, List[str]] = defaultdict(list)

    models_dir = codeql_dir / "actions/ql/lib/ext"

    relevant_kinds = {"code-injection"}
    # For now only include models manually curated by the CodeQL developers
    only_manual_models = True

    processed_count = 0

    for file in models_dir.glob("**/*.yml"):
        if file.suffix in [".yml", ".yaml"]:
            processed_count += 1
            try:
                _process_yaml_file(
                    file,
                    relevant_kinds,
                    only_manual_models,
                    code_injection_sinks,
                )
            except Exception as e:
                raise RuntimeError(f"Failed processing file: {file}") from e

    _debug(f"Processed {processed_count} files")

    print(json.dumps(code_injection_sinks, indent=2))


def main():
    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            codeql_dir = _clone_actions_codeql(Path(temp_dir))
            _process_models(codeql_dir)

        except subprocess.CalledProcessError as e:
            _debug(f"Git command failed: {e}")
            _debug(f"Command: {e.cmd}")
            _debug(f"Return code: {e.returncode}")
            _debug(f"Stdout: {e.stdout}")
            _debug(f"Stderr: {e.stderr}")
            raise
        except Exception as e:
            _debug(f"Error: {e}")
            raise


if __name__ == "__main__":
    main()
