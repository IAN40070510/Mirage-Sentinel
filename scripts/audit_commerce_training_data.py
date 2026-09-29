"""Read-only corpus audit; no fitted classifier, HTTP requests or data rewriting."""

from __future__ import annotations

import asyncio
import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from verify_commerce_300k import core_structure

from services.commerce.detection import Detector


async def audit() -> None:
    base = ROOT / "datasets/commerce/curated-300k-v1"
    path = base / "requests.jsonl"
    with path.open("rb") as stream:
        sha = hashlib.file_digest(stream, "sha256").hexdigest()
    manifest = json.loads((base / "validation.json").read_text(encoding="utf-8"))
    if sha != manifest["requests_sha256"]:
        raise ValueError("Dataset has changed since generation verification")
    detector = Detector()
    classes: dict[str, Counter[str]] = defaultdict(Counter)
    families: Counter[str] = Counter()
    paths: Counter[str] = Counter()
    normal_paths: Counter[str] = Counter()
    groups: dict[str, Counter[str]] = defaultdict(Counter)
    vectors: dict[tuple[Any, ...], Counter[str]] = defaultdict(Counter)
    samples: dict[str, list[dict[str, Any]]] = defaultdict(list)
    rule_names: dict[str, Counter[str]] = defaultdict(Counter)
    with path.open(encoding="utf-8") as stream:
        for i, line in enumerate(stream, 1):
            row = json.loads(line)
            label, request = row["label"], row["request"]
            stats = classes[label]
            stats["records"] += 1
            stats[request["method"]] += 1
            paths[request["method"] + " " + request["path"]] += 1
            if label == "normal":
                normal_paths[request["method"] + " " + request["path"]] += 1
            families[row["template_family"]] += 1
            body = request["body"] or ""
            raw_input = json.dumps(request, ensure_ascii=False)
            stats["contains_placeholder"] += int("PLACEHOLDER" in raw_input)
            stats["contains_probe_marker"] += int("probe" in raw_input.lower())
            stats["body_nonempty"] += int(bool(body))
            stats["content_type_json"] += int(
                "json" in request["headers"].get("content-type", "")
            )
            stats["non_ascii_body"] += int(any(ord(c) > 127 for c in body))
            if label == "normal" and body:
                parsed = json.loads(body)
                name = parsed.get("first_name", parsed.get("last_name", ""))
                if len(name) > 40:
                    stats["top_level_name_over_40_chars"] += 1
                    if len(samples["long_normal_name"]) < 3:
                        samples["long_normal_name"].append(
                            {
                                "sample_id": row["sample_id"],
                                "path": request["path"],
                                "name": name,
                            }
                        )
            # History cannot be reconstructed: clear it for every row, then OMIT
            # the two neutral temporal fields from collision analysis.
            detector.history.clear()
            decision = await detector.assess(
                "audit",
                request["method"],
                request["path"],
                request["query"],
                request["headers"],
                body.encode("utf-8"),
            )
            stats["current_rule_positive"] += int(decision["attack"])
            rule_names[label].update(decision["rules"])
            key = tuple(
                v
                for k, v in decision["features"].items()
                if k not in {"request_count_60s", "interval_ms"}
            )
            vectors[key][label] += 1
            split_value = (
                int(
                    hashlib.sha256(
                        ("audit-split:" + row["sample_id"]).encode()
                    ).hexdigest()[:8],
                    16,
                )
                % 10000
            )
            split = (
                "train"
                if split_value < 7000
                else ("validation" if split_value < 8500 else "test")
            )
            groups[core_structure(request)][split] += 1
            stats["simulated_" + split] += 1
            if (
                not decision["attack"]
                and label != "normal"
                and len(samples[label + "_rule_miss"]) < 2
            ):
                samples[label + "_rule_miss"].append(
                    {
                        "sample_id": row["sample_id"],
                        "family": row["template_family"],
                        "request": request,
                    }
                )
            if i % 50000 == 0:
                print(f"Audited {i}/300000", flush=True)
    conflicts = [c for c in vectors.values() if len(c) > 1]
    test_total = sum(c["test"] for c in groups.values())
    test_shared = sum(c["test"] for c in groups.values() if c["train"])
    result = {
        "dataset_sha256": sha,
        "records": sum(c["records"] for c in classes.values()),
        "classes": {k: dict(v) for k, v in classes.items()},
        "family_count": len(families),
        "families": dict(families),
        "method_paths": dict(paths),
        "normal_method_paths": dict(normal_paths),
        "current_rule_hits_by_label": {k: dict(v) for k, v in rule_names.items()},
        "rule_evaluation_note": "Executed existing Detector in rules-only mode on corpus requests. This is signature coverage against generated labels, not XGBoost accuracy or real-world performance.",
        "static_feature_collision": {
            "fields": 10,
            "temporal_features_excluded": ["request_count_60s", "interval_ms"],
            "unique_vectors": len(vectors),
            "cross_label_vectors": len(conflicts),
            "records_in_cross_label_vectors": sum(sum(c.values()) for c in conflicts),
            "unavoidable_errors_for_deterministic_classifier_on_these_vectors": sum(
                sum(c.values()) - max(c.values()) for c in conflicts
            ),
            "note": "Exact float-value collisions only; no trained model and no accuracy estimate. Non-collision does not establish useful features.",
        },
        "simulated_row_split": {
            "policy": "SHA256(sample_id with fixed prefix), 70/15/15 thresholds; diagnostic only; no split files or model produced",
            "core_groups": len(groups),
            "test_rows": test_total,
            "test_rows_with_core_group_in_training": test_shared,
            "test_overlap_percent": 100 * test_shared / test_total,
            "core_note": "Eight optional metadata keys removed and prior structural normalizer applied. Heuristic near-duplicate risk, not formal semantic equivalence.",
        },
        "illustrative_examples": dict(samples),
    }
    out = base / "training-audit.json"
    out.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                k: result[k]
                for k in (
                    "records",
                    "classes",
                    "family_count",
                    "static_feature_collision",
                    "simulated_row_split",
                )
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    asyncio.run(audit())
