"""Stream and verify the 300k master against the preserved input snapshots."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

from build_commerce_100k import structure
from build_commerce_300k import file_hash
from expand_commerce_dataset import fingerprint
from generate_commerce_dataset import LABELS, ROOT
from validate_commerce_dataset import validate_record

OPTIONAL_KEYS = {
    "gift_wrap",
    "delivery_note",
    "gift_message",
    "packaging",
    "contact_preferences",
    "personalization",
    "gift_recipients",
    "preferences",
}


def record_hash(row: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(row, ensure_ascii=False, sort_keys=True).encode()
    ).hexdigest()


def core_structure(request: dict[str, Any]) -> str:
    """Diagnostic only: remove eight combinatorial background metadata keys."""
    copy_request = dict(request)
    if request["body"] is not None:
        body = json.loads(request["body"])
        for key in ("metadata", "data"):
            if isinstance(body.get(key), dict):
                body[key] = {
                    k: v for k, v in body[key].items() if k not in OPTIONAL_KEYS
                }
        copy_request["body"] = json.dumps(body)
    return structure(copy_request)


def regression_checks() -> None:
    a = {
        "method": "POST",
        "path": "/store/carts/cart_first",
        "query": "limit=12&q=linen%20shirt",
        "headers": {"user-agent": "one"},
        "body": json.dumps({"metadata": {"note": "amber_cardigan"}}),
    }
    b = copy.deepcopy(a)
    b.update(
        path="/store/carts/cart_second",
        query="q=cotton+jacket&limit=48",
        headers={"user-agent": "two"},
        body=json.dumps({"metadata": {"note": "bronze_blazer"}}),
    )
    if structure(a) != structure(b):
        raise ValueError("Name/number/encoding/identity normalization regression")
    b["body"] = json.dumps({"metadata": {"note": {"message": "bronze_blazer"}}})
    if structure(a) == structure(b):
        raise ValueError("Nested structure differences are lost")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dataset-dir", type=Path, default=ROOT / "datasets/commerce/curated-300k-v1"
    )
    args = parser.parse_args()
    base = args.dataset_dir
    manifest_path = base / "validation.json"
    report = json.loads(manifest_path.read_text(encoding="utf-8"))
    prior_shapes: set[str] = set()
    prior_exact: set[str] = set()
    prior_relaxed: set[str] = set()
    prior_ids: set[str] = set()
    baseline: dict[str, str] = {}
    for entry in report["prior_datasets"]:
        p = ROOT / entry["path"]
        if file_hash(p) != entry["sha256"]:
            raise ValueError(f"Prior snapshot changed: {entry['path']}")
        with p.open(encoding="utf-8") as stream:
            for line in stream:
                row = json.loads(line)
                request = row["request"]
                prior_ids.add(row["sample_id"])
                prior_shapes.add(structure(request))
                prior_exact.add(fingerprint(request, relaxed=False))
                prior_relaxed.add(fingerprint(request, relaxed=True))
                if p.parent.name == "curated-100k-v1":
                    baseline[row["sample_id"]] = record_hash(row)
    print("Prior snapshots verified", flush=True)
    ids: set[str] = set()
    shapes: set[str] = set()
    exact: set[str] = set()
    relaxed: set[str] = set()
    counts: Counter[str] = Counter()
    new_hashes: dict[str, str] = {}
    retained = 0
    core_counts: Counter[str] = Counter()
    new_core_counts: Counter[str] = Counter()
    context_distribution: dict[str, Counter[str]] = {
        label: Counter() for label in LABELS
    }
    with (base / "requests.jsonl").open(encoding="utf-8") as stream:
        for i, line in enumerate(stream, 1):
            row = json.loads(line)
            validate_record(row, i)
            if set(row) != {"sample_id", "template_family", "request", "label"}:
                raise ValueError(f"Unexpected metadata at {i}")
            request = row["request"]
            key = structure(request)
            raw_key = fingerprint(request, relaxed=False)
            relaxed_key = fingerprint(request, relaxed=True)
            if (
                row["sample_id"] in ids
                or key in shapes
                or raw_key in exact
                or relaxed_key in relaxed
            ):
                raise ValueError(f"Duplicate at row {i}")
            ids.add(row["sample_id"])
            shapes.add(key)
            exact.add(raw_key)
            relaxed.add(relaxed_key)
            digest = record_hash(row)
            if row["sample_id"] in baseline:
                if digest != baseline[row["sample_id"]]:
                    raise ValueError("Retained baseline record changed")
                retained += 1
            else:
                if (
                    row["sample_id"] in prior_ids
                    or key in prior_shapes
                    or raw_key in prior_exact
                    or relaxed_key in prior_relaxed
                ):
                    raise ValueError("New sample overlaps a prior snapshot")
                new_hashes[row["sample_id"]] = digest
                new_core_counts[core_structure(request)] += 1
            if request["body"] is not None:
                json.loads(request["body"])
            if {"cookie", "authorization"}.intersection(
                k.lower() for k in request["headers"]
            ):
                raise ValueError("Reusable authentication header present")
            if any("\r" in v or "\n" in v for v in request["headers"].values()):
                raise ValueError("Raw newline in header")
            counts[row["label"]] += 1
            context_distribution[row["label"]][
                request["method"] + " " + request["path"]
            ] += 1
            core_counts[core_structure(request)] += 1
            if i % 50000 == 0:
                print(f"Checked {i}/300000", flush=True)
    if (
        counts != Counter({label: 60000 for label in LABELS})
        or retained != 100000
        or len(new_hashes) != 200000
    ):
        raise ValueError("Unexpected dataset composition")
    new_ids: set[str] = set()
    with (base / "new-records.jsonl").open(encoding="utf-8") as stream:
        for line in stream:
            row = json.loads(line)
            if row["sample_id"] in new_ids or new_hashes.get(
                row["sample_id"]
            ) != record_hash(row):
                raise ValueError("New subset differs from master")
            new_ids.add(row["sample_id"])
    if new_ids != set(new_hashes):
        raise ValueError("New subset incomplete")
    for filename, field in [
        ("requests.jsonl", "requests_sha256"),
        ("new-records.jsonl", "new_records_sha256"),
    ]:
        if file_hash(base / filename) != report[field]:
            raise ValueError("Generated dataset hash mismatch")
    regression_checks()
    report["independent_verification"] = {
        "records": len(ids),
        "labels": dict(counts),
        "baseline_100k_retained_unchanged": retained,
        "new_subset_verified": len(new_ids),
        "exact_duplicates": 0,
        "normalized_duplicates": 0,
        "heuristic_structure_duplicates": 0,
        "new_vs_prior_duplicates_all_three_checks": 0,
        "sample_id_duplicates": 0,
        "json_body_validation": "passed",
        "removed_metadata_absent": True,
        "authentication_headers_absent": True,
        "header_newlines_absent": True,
        "prior_snapshot_hashes_unchanged": True,
        "name_number_encoding_regression": "passed",
        "nested_structure_regression": "passed",
    }
    report["metadata_ablation_diagnostic"] = {
        "removed_top_level_metadata_or_data_keys": sorted(OPTIONAL_KEYS),
        "master_unique_core_structures": len(core_counts),
        "master_max_records_per_core_structure": max(core_counts.values()),
        "new_unique_core_structures": len(new_core_counts),
        "new_max_records_per_core_structure": max(new_core_counts.values()),
        "meaning": "Heuristic correlation diagnostic, not an accuracy metric. Many full-structure-unique records differ only in these optional metadata combinations.",
    }
    report["observed_method_path_distribution"] = {
        k: dict(v) for k, v in context_distribution.items()
    }
    report["verifier_sha256"] = file_hash(Path(__file__))
    manifest_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(report["independent_verification"], indent=2))
    print(json.dumps(report["metadata_ablation_diagnostic"], indent=2))


if __name__ == "__main__":
    main()
