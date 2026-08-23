#!/usr/bin/env python3
"""Validate a JSON document against the JSON Schema subset this repository uses.

scripts/publish-live-results-fixture.sh has to check the records the publisher
writes against schema/live-results-v1.json, and the CI runners carry no
third-party validator. This implements only the keywords the published schemas
use and rejects any other keyword instead of ignoring it, so a schema that grows
a construct this checker cannot enforce fails loudly rather than passing
silently.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
import re
import sys
from typing import Any


ANNOTATIONS = {"$schema", "$id", "$defs", "title", "description", "default", "examples"}
SUPPORTED = {
    "$ref",
    "anyOf",
    "type",
    "const",
    "enum",
    "required",
    "properties",
    "additionalProperties",
    "items",
    "minItems",
    "uniqueItems",
    "minimum",
    "maximum",
    "minLength",
    "pattern",
    "format",
}
REF_PREFIX = "#/$defs/"


class SchemaError(Exception):
    """A validation failure or an unsupported schema construct."""


def fail(path: str, message: str) -> None:
    raise SchemaError(f"{path}: {message}")


def is_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def same(left: Any, right: Any) -> bool:
    if isinstance(left, bool) != isinstance(right, bool):
        return False
    return left == right


def check_type(name: Any, instance: Any, path: str) -> None:
    checks = {
        "object": lambda value: isinstance(value, dict),
        "array": lambda value: isinstance(value, list),
        "string": lambda value: isinstance(value, str),
        "boolean": lambda value: isinstance(value, bool),
        "integer": is_integer,
        "number": is_number,
        "null": lambda value: value is None,
    }
    if name not in checks:
        fail(path, f"unsupported schema type {name!r}")
    if not checks[name](instance):
        fail(path, f"is {type(instance).__name__}, want {name}")


def check_format(name: Any, instance: str, path: str) -> None:
    if name != "date-time":
        fail(path, f"unsupported format {name!r}")
    try:
        parsed = dt.datetime.fromisoformat(instance.replace("Z", "+00:00"))
    except ValueError:
        fail(path, f"{instance!r} is not an RFC 3339 date-time")
    if parsed.tzinfo is None:
        fail(path, f"{instance!r} has no timezone")


def validate(document: Any, instance: Any, root: dict[str, Any], path: str) -> None:
    if not isinstance(document, dict):
        fail(path, "schema node is not an object")
    unknown = sorted(set(document) - SUPPORTED - ANNOTATIONS)
    if unknown:
        fail(path, f"unsupported schema keywords {unknown}")

    if "$ref" in document:
        reference = document["$ref"]
        if not isinstance(reference, str) or not reference.startswith(REF_PREFIX):
            fail(path, f"unsupported reference {reference!r}")
        name = reference[len(REF_PREFIX) :]
        definitions = root.get("$defs")
        if not isinstance(definitions, dict) or name not in definitions:
            fail(path, f"unknown definition {name!r}")
        validate(definitions[name], instance, root, path)
        return

    if "anyOf" in document:
        reasons = []
        for index, option in enumerate(document["anyOf"]):
            try:
                validate(option, instance, root, f"{path}(anyOf[{index}])")
                break
            except SchemaError as exc:
                reasons.append(str(exc))
        else:
            fail(path, "matches no anyOf branch: " + "; ".join(reasons))

    if "const" in document and not same(instance, document["const"]):
        fail(path, f"is {instance!r}, want constant {document['const']!r}")
    if "enum" in document and not any(same(instance, choice) for choice in document["enum"]):
        fail(path, f"is {instance!r}, not one of {document['enum']!r}")
    if "type" in document:
        check_type(document["type"], instance, path)

    if isinstance(instance, dict):
        for name in document.get("required", []):
            if name not in instance:
                fail(path, f"is missing required property {name!r}")
        properties = document.get("properties", {})
        additional = document.get("additionalProperties", True)
        for name, value in sorted(instance.items()):
            child = f"{path}.{name}"
            if name in properties:
                validate(properties[name], value, root, child)
            elif additional is False:
                fail(path, f"has unexpected property {name!r}")
            elif additional is not True:
                validate(additional, value, root, child)
    elif isinstance(instance, list):
        if "minItems" in document and len(instance) < document["minItems"]:
            fail(path, f"has {len(instance)} items, want at least {document['minItems']}")
        if document.get("uniqueItems") and len(instance) != len({json.dumps(item, sort_keys=True) for item in instance}):
            fail(path, "has duplicate items")
        if "items" in document:
            for index, value in enumerate(instance):
                validate(document["items"], value, root, f"{path}[{index}]")
    elif isinstance(instance, str):
        if "minLength" in document and len(instance) < document["minLength"]:
            fail(path, f"is shorter than {document['minLength']} characters")
        if "pattern" in document and re.search(document["pattern"], instance) is None:
            fail(path, f"{instance!r} does not match {document['pattern']!r}")
        if "format" in document:
            check_format(document["format"], instance, path)
    elif is_number(instance):
        if "minimum" in document and instance < document["minimum"]:
            fail(path, f"is {instance}, below minimum {document['minimum']}")
        if "maximum" in document and instance > document["maximum"]:
            fail(path, f"is {instance}, above maximum {document['maximum']}")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--schema", required=True, type=Path)
    parser.add_argument("--instance", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    schema = json.loads(args.schema.read_text(encoding="utf-8"))
    instance = json.loads(args.instance.read_text(encoding="utf-8"))
    if not isinstance(schema, dict):
        print("validate-json-schema: schema root is not an object", file=sys.stderr)
        return 2
    try:
        validate(schema, instance, schema, "$")
    except SchemaError as exc:
        print(f"validate-json-schema: {args.instance.name} does not match {args.schema.name}: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
