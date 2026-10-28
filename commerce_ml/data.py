"""Strict JSONL loading and conservative connected-component leakage audit."""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from .runtime import LABELS, request_text, sha


@dataclass(slots=True)
class Record:
    sample_id: str
    text: str
    label: int
    source: str
    session: str | None
    family: str | None
    reviewed: bool
    exact: str
    near: str


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def near_key(text: str) -> str:
    """Heuristic, not exhaustive semantic similarity; deliberately conservative.

    Decode three times; collapse case, whitespace, numbers and quoted literals.
    This is ONLY a grouping key; it never replaces feature text.
    """
    for _ in range(3):
        text = unquote(text)
    text = re.sub(r"""(['"])(?:\\.|(?!\1).)*?\1""", "<literal>", text.lower())
    text = re.sub(r"\d+", "<number>", text)
    return digest(re.sub(r"\s+", " ", text).strip())


def files_for(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    files = sorted(path.glob("part-*.jsonl"))
    if not files:
        files = sorted(path.glob("*.jsonl"))
    if not files:
        raise ValueError(f"No JSONL found in {path}")
    return files


def load(path: Path) -> tuple[list[Record], list[dict[str, Any]]]:
    rows: list[Record] = []
    manifest = []
    seen: set[str] = set()
    for file in files_for(path):
        count = 0
        with file.open(encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, 1):
                try:
                    row = json.loads(line)
                    identifier = row["sample_id"]
                    if not isinstance(identifier, str) or not identifier or identifier in seen:
                        raise ValueError("Missing/duplicate sample_id")
                    seen.add(identifier)
                    if row["source"] not in ("ai", "human", "external") or row["label"] not in LABELS:
                        raise ValueError("Invalid label/source")
                    if "outcome" in row:
                        raise ValueError("outcome is not part of this dataset schema")
                    annotation = row["annotation"]
                    status = annotation["review_status"]
                    if status not in ("generated_unverified", "source_labeled_unverified", "reviewed") or not annotation.get("reason"):
                        raise ValueError("Invalid annotation")
                    if row["source"] == "external" and not all(
                        row.get("provenance", {}).get(key) for key in ("dataset", "revision", "file", "row")
                    ):
                        raise ValueError("External rows require dataset/revision/file/row provenance")
                    if status == "reviewed" and not annotation.get("reviewer"):
                        raise ValueError("Reviewed rows need a reviewer")
                    session, family = row.get("session_id"), row.get("template_family")
                    for value in (session, family):
                        if value is not None and (not isinstance(value, str) or not value.strip()):
                            raise ValueError("session/family must be nonempty strings or null")
                    text = request_text(row["request"])
                    rows.append(Record(identifier, text, LABELS.index(row["label"]),
                                       row["source"], session, family, status == "reviewed",
                                       digest(text), near_key(text)))
                    count += 1
                except (KeyError, TypeError, ValueError) as exc:
                    raise ValueError(f"{file.name}:{line_number}: {exc}") from exc
        manifest.append({"file": file.name, "sha256": sha(file), "rows": count})
    if not rows:
        raise ValueError("Empty dataset")
    return rows, manifest


def tokens(row: Record) -> list[tuple[str, str]]:
    result = [("sample_id", row.sample_id), ("exact", row.exact), ("near", row.near)]
    if row.session is not None:
        result.append(("session", row.session))
    if row.family is not None:
        result.append(("family", row.family))
    return result


def group_ids(rows: list[Record]) -> list[int]:
    parent = list(range(len(rows)))

    def root(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    owners: dict[tuple[str, str], int] = {}
    for i, row in enumerate(rows):
        for token in tokens(row):
            previous = owners.setdefault(token, i)
            parent[root(i)] = root(previous)
    return [root(i) for i in range(len(rows))]


def summary(rows: list[Record]) -> dict[str, Any]:
    return {"rows": len(rows), "labels": dict(Counter(LABELS[r.label] for r in rows)),
            "sources": dict(Counter(r.source for r in rows)),
            "reviewed": sum(r.reviewed for r in rows),
            "exact_duplicates": len(rows) - len({r.exact for r in rows}),
            "near_groups": len({r.near for r in rows})}


def audit_splits(splits: dict[str, list[Record]], *, allow_shared_families: bool = False,
                 allow_shared_normal_templates: bool = False) -> dict[str, Any]:
    owners: dict[tuple[str, str], str] = {}
    conflicts: Counter[str] = Counter()
    shared_families: Counter[str] = Counter()
    shared_normal: Counter[str] = Counter()
    near_labels: dict[str, set[int]] = {}
    for rows in splits.values():
        for row in rows:
            near_labels.setdefault(row.near, set()).add(row.label)
    for name, rows in splits.items():
        for row in rows:
            for token in tokens(row):
                previous = owners.setdefault(token, name)
                if previous != name:
                    if (token[0] == "near" and allow_shared_normal_templates
                            and near_labels[token[1]] == {0}):
                        shared_normal[f"{previous}/{name}"] += 1
                        continue
                    if token[0] == "family" and allow_shared_families:
                        shared_families[f"{previous}/{name}:{token[1]}"] += 1
                        continue
                    conflicts[f"{previous}/{name}:{token[0]}"] += 1
    return {"normalization": "decoded-case-number-quoted-literal-v1",
            "near_detection_limit": "Heuristic only; independent scenario review is still required",
            "cross_split_conflicts": dict(conflicts),
            "allow_shared_families": allow_shared_families,
            "shared_family_rows": dict(shared_families),
            "allow_shared_normal_templates": allow_shared_normal_templates,
            "shared_normal_template_rows": dict(shared_normal),
            "splits": {name: summary(rows) for name, rows in splits.items()},
            "ratios": {name: len(rows) / sum(map(len, splits.values()))
                       for name, rows in splits.items()}}
