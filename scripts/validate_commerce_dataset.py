"""Validate the review JSONL contract without loading model or secret material."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

LABELS = {"normal", "sqli", "xss", "cmdi", "path_traversal"}
REQUIRED_ROOT_KEYS = {
    "sample_id",
    "request",
    "label",
}
OPTIONAL_ROOT_KEYS = {"template_family"}
ROOT_KEYS = REQUIRED_ROOT_KEYS | OPTIONAL_ROOT_KEYS
REQUEST_KEYS = {"method", "path", "query", "headers", "body"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validate_record(record: dict[str, Any], line_number: int) -> None:
    prefix = f"line {line_number}"
    record_keys = set(record)
    require(
        REQUIRED_ROOT_KEYS <= record_keys <= ROOT_KEYS,
        f"{prefix}: unexpected or missing root fields",
    )
    require(
        isinstance(record["sample_id"], str) and bool(record["sample_id"]),
        f"{prefix}: invalid sample_id",
    )
    require(
        record.get("template_family") is None
        or isinstance(record.get("template_family"), str)
        and bool(record["template_family"]),
        f"{prefix}: invalid template_family",
    )
    request = record["request"]
    require(isinstance(request, dict), f"{prefix}: request must be an object")
    require(set(request) == REQUEST_KEYS, f"{prefix}: invalid request fields")
    require(
        isinstance(request["method"], str)
        and request["method"].isalpha()
        and request["method"].isupper(),
        f"{prefix}: invalid method",
    )
    require(
        isinstance(request["path"], str) and request["path"].startswith("/"),
        f"{prefix}: invalid path",
    )
    require(isinstance(request["query"], str), f"{prefix}: query must be a string")
    require(isinstance(request["headers"], dict), f"{prefix}: invalid headers")
    require(
        all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in request["headers"].items()
        ),
        f"{prefix}: header keys and values must be strings",
    )
    require(
        request["body"] is None or isinstance(request["body"], str),
        f"{prefix}: body must be a string or null",
    )
    require(record["label"] in LABELS, f"{prefix}: invalid label")
    require("outcome" not in record, f"{prefix}: outcome is prohibited")


def validate(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    require(not raw.startswith(b"\xef\xbb\xbf"), "UTF-8 BOM is not allowed")
    text = raw.decode("utf-8")
    require(bool(text), "dataset is empty")
    require(text.endswith("\n"), "JSONL must end with a newline")

    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        require(bool(line.strip()), f"line {line_number}: blank lines are not allowed")
        parsed = json.loads(line)
        require(
            isinstance(parsed, dict), f"line {line_number}: record must be an object"
        )
        validate_record(parsed, line_number)
        records.append(parsed)

    sample_ids = [record["sample_id"] for record in records]
    request_fingerprints = [
        hashlib.sha256(
            json.dumps(
                record["request"],
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        for record in records
    ]
    duplicate_ids = sorted(
        value for value, count in Counter(sample_ids).items() if count > 1
    )
    duplicate_requests = sorted(
        value for value, count in Counter(request_fingerprints).items() if count > 1
    )
    require(not duplicate_ids, f"duplicate sample_id values: {duplicate_ids}")
    require(not duplicate_requests, "duplicate canonical requests found")

    return {
        "path": path.as_posix(),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "records": len(records),
        "labels": dict(sorted(Counter(record["label"] for record in records).items())),
        "duplicate_sample_ids": len(duplicate_ids),
        "duplicate_canonical_requests": len(duplicate_requests),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "path",
        nargs="?",
        type=Path,
        default=Path("datasets/commerce/review-v1/requests.jsonl"),
    )
    args = parser.parse_args()
    print(json.dumps(validate(args.path), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
