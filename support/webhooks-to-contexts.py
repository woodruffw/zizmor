#!/usr/bin/env -S uv run --script --only-group codegen

# Retrieves the latest OpenAPI spec for GitHub's webhooks from
# @octokit/openapi-webhooks and walks the schemas to produce a
# mapping of context patterns to their expected expansion capabilities.
#
# For example, `github.event.pull_request.title` would be `arbitrary`
# because it can contain arbitrary attacker-controlled content, while
# `github.event.pull_request.user.id` would be `fixed` because `id`
# is a fixed numeric value. These patterns can include wildcards
# for arrays, e.g. `github.event.pull_request.labels.*.name`
# matches any context that indexes through the `labels` array.

import json
import os
import sys
from collections import defaultdict
from collections.abc import Iterator
from pathlib import Path
from typing import Literal

import requests
from prance import ResolvingParser

_REF = os.environ.get("WEBHOOKS_REF", "main")

if _REF.startswith("v"):
    _REF = f"refs/tags/{_REF}"
else:
    _REF = f"refs/heads/{_REF}"

_WEBHOOKS_JSON_URL = f"https://github.com/octokit/openapi-webhooks/raw/{_REF}/packages/openapi-webhooks/generated/api.github.com.json"

_HERE = Path(__file__).parent

_SRC = _HERE.parent / "src"
assert _SRC.is_dir(), f"Missing {_SRC}"

_OUT = _SRC / "data" / "context-capabilities.json"

# A mapping of workflow trigger event names to subevents.
# Keep in sync with: https://docs.github.com/en/actions/writing-workflows/choosing-when-your-workflow-runs/events-that-trigger-workflows
_WORKFLOW_TRIGGERS_TO_EVENTS: dict[str, list[str]] = {
    "branch_protection_rule": ["created", "edited", "deleted"],
    "check_run": [
        "created",
        "rerequested",
        "completed",
        "requested_action",
    ],
    "check_suite": [
        "completed",
    ],
    "create": [],  # no subevents
    "delete": [],  # no subevents
    # GitHub's doesn't specify the subevent for `deployment` or `deployment_status`,
    # but the docs imply that the subevent is `created`.
    "deployment": ["created"],
    "deployment_status": ["created"],
    "discussion": [
        "created",
        "edited",
        "deleted",
        "transferred",
        "pinned",
        "unpinned",
        "labeled",
        "unlabeled",
        "locked",
        "unlocked",
        "category_changed",
        "answered",
        "unanswered",
    ],
    "discussion_comment": [
        "created",
        "edited",
        "deleted",
    ],
    "fork": [],  # no subevents
    "gollum": [],  # no subevents
    "issue_comment": [
        "created",
        "edited",
        "deleted",
    ],
    "issues": [
        "opened",
        "edited",
        "deleted",
        "transferred",
        "pinned",
        "unpinned",
        "closed",
        "reopened",
        "assigned",
        "unassigned",
        "labeled",
        "unlabeled",
        "locked",
        "unlocked",
        "milestoned",
        "demilestoned",
        "typed",
        "untyped",
    ],
    "label": [
        "created",
        "edited",
        "deleted",
    ],
    "merge_group": ["checks_requested"],
    "milestone": [
        "created",
        "closed",
        "opened",
        "edited",
        "deleted",
    ],
    "page_build": [],  # no subevents
    "public": [],  # no subevents
    "pull_request": [
        "assigned",
        "unassigned",
        "labeled",
        "unlabeled",
        "opened",
        "edited",
        "closed",
        "reopened",
        "synchronize",
        "converted_to_draft",
        "locked",
        "unlocked",
        "enqueued",
        "dequeued",
        "milestoned",
        "demilestoned",
        "ready_for_review",
        "review_requested",
        "review_request_removed",
        "auto_merge_enabled",
        "auto_merge_disabled",
    ],
    # Unused.
    # "pull_request_comment": []
    "pull_request_review": [
        "submitted",
        "edited",
        "dismissed",
    ],
    "pull_request_review_comment": [
        "created",
        "edited",
        "deleted",
    ],
    # Not a real webhook; same contents as `pull_request`.
    # "pull_request_target": [],
    "push": [],  # no subevents
    "registry_package": [
        "published",
        "updated",
    ],
    "release": [
        "published",
        "unpublished",
        "created",
        "edited",
        "deleted",
        "prereleased",
        "released",
    ],
    # NOTE: GitHub's OpenAPI spec uses `sample` to provide an example payload.
    "repository_dispatch": ["sample"],  # custom subevents
    # Not a webhook.
    # "schedule": [],
    "status": [],  # no subevents
    "watch": ["started"],
    # Not a webhook; inherits its payload from the calling workflow.
    # "workflow_call": [],
    "workflow_dispatch": [],  # no subevents
    "workflow_run": [
        "completed",
        "in_progress",
        "requested",
    ],
}


def log(msg: str) -> None:
    print(f"[+] {msg}", file=sys.stderr)


# Represents the capability of an expanded expression from a
# webhook's payload.
# For example, `github.pull_request.title` would be `arbitrary` because
# it can contain arbitrary attacker-controlled content, while
# `github.pull_request.base.sha` would be `fixed` because the attacker
# can't influence its value in a structured manner. `structured` is a middle
# ground where the attacker can influence the value, but only in a limited way.
Capability = Literal["arbitrary"] | Literal["structured"] | Literal["fixed"]


def walk_schema(
    schema: dict,
    top: str,
    *,
    typ: str | None = None,
) -> Iterator[tuple[str, Capability]]:
    """
    Walks the schema and returns a list of tuples of the form
    (path, capability).
    """

    if typ is None:
        typ = schema.get("type")

    # We might have a schema with a type like `["string", "null"]`.
    # When this happens, we walk the schema for each type,
    # returning capabilities for all variants for subsequent unification.
    if isinstance(typ, list):
        for subtype in typ:
            yield from walk_schema(schema, top, typ=subtype)
            return

    # Similarly for allOf/anyOf/oneOf: we try each listed subtype.
    subschemas = ["allOf", "anyOf", "oneOf"]
    for subschema in subschemas:
        if subschema in schema:
            for subtype in schema[subschema]:
                yield from walk_schema(subtype, top)
            return

    match typ:
        case "object":
            properties = schema.get("properties", {})

            if not properties:
                yield top, "arbitrary"
            else:
                for prop, prop_schema in properties.items():
                    yield from walk_schema(
                        prop_schema,
                        f"{top}.{prop}",
                    )

            additional_properties = schema.get("additionalProperties")
            match additional_properties:
                case True | {}:
                    yield f"{top}.*", "arbitrary"
                case False | None:
                    pass
                case _:
                    # TODO: In principle additionalProperties can be a schema,
                    # which we should handle. However GitHub's OpenAPI spec
                    # doesn't appear to do this at the moment, so we
                    # churlishly ignore it.
                    assert False, (
                        f"Unknown additionalProperties: {additional_properties}"
                    )

        case "array":
            items = schema.get("items", {})
            if not items:
                assert False, f"Empty array schema: {schema}"
            else:
                yield from walk_schema(
                    items,
                    f"{top}.[*]",
                )
        case "boolean" | "integer" | "number" | "null":
            yield (top, "fixed")
        case "string":
            format = schema.get("format")
            match format:
                case "date-time":
                    yield (top, "fixed")
                case "uri" | "uri-template" | "email":
                    yield (top, "structured")
                case None:
                    if "enum" in schema:
                        yield (top, "fixed")
                    else:
                        # No format and no enum means we can't make any assumptions.
                        yield (top, "arbitrary")
                case _:
                    assert False, f"Unknown string format: {format}"
        case _:
            assert False, f"Unknown schema type: {typ}"


def unify_capabilities(old: Capability, new: Capability) -> Capability:
    """
    Unify two capabilities in favor of the more permissive one.
    """
    caps = {old, new}
    if "arbitrary" in caps:
        return "arbitrary"
    if "structured" in caps:
        return "structured"
    return old


def process_schemas(
    event: str, schemas: list[dict], patterns_to_capabilities: dict[str, Capability]
) -> dict[str, Capability]:
    top = "github.event"
    for schema in schemas:
        for pattern, cap in walk_schema(schema, top):
            if old_cap := patterns_to_capabilities.get(pattern):
                cap = unify_capabilities(old_cap, cap)
            patterns_to_capabilities[pattern] = cap

    return patterns_to_capabilities


if __name__ == "__main__":
    log(f"downloading OpenAPI spec (ref={_REF})...")
    webhooks_json = requests.get(_WEBHOOKS_JSON_URL).text

    log("resolving refs in OpenAPI spec, this will take a moment...")
    # TODO: Optimize; this is ridiculously slow.
    parser = ResolvingParser(spec_string=webhooks_json)
    spec = parser.specification
    log("  ...done")

    # We only care about webhook payload schemas.
    schemas = {
        name: schema
        for (name, schema) in spec["components"]["schemas"].items()
        if name.startswith("webhook-")
    }
    log(f"isolated {len(schemas)} webhook payload schemas")

    schemas_for_event: dict[str, list[dict]] = defaultdict(list)
    for event, subevents in _WORKFLOW_TRIGGERS_TO_EVENTS.items():
        if not subevents:
            webhook_key = f"webhook-{event.replace('_', '-')}"
            schemas_for_event[event].append(schemas[webhook_key])
        for subevent in subevents:
            webhook_key = (
                f"webhook-{event.replace('_', '-')}-{subevent.replace('_', '-')}"
            )
            schemas_for_event[event].append(schemas[webhook_key])

    patterns_to_capabilities: dict[str, Capability] = {}
    for event, schemas in schemas_for_event.items():
        log(f"  {event} -> {len(schemas)} schemas")
        process_schemas(event, schemas, patterns_to_capabilities)

    with _OUT.open("w") as io:
        json.dump(
            patterns_to_capabilities,
            io,
            indent=2,
        )
