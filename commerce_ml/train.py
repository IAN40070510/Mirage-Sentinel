"""Train portable XGBoost bundles; never silently split correlated rows."""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import importlib.metadata
from html import escape
import json
import math
from pathlib import Path
import platform
import shutil
import time
from typing import Any

import numpy as np
from scipy import sparse
from sklearn.metrics import (accuracy_score, average_precision_score,
                             classification_report, confusion_matrix, log_loss,
                             roc_auc_score)
import xgboost as xgb

from . import runtime
from .data import Record, audit_splits, load, summary
from .runtime import Features, LABELS, RULES, VERSION, Predictor, sha, rule_hits, write_json


def clean(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): clean(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [clean(v) for v in value]
    if isinstance(value, (float, np.floating)):
        return float(value) if math.isfinite(value) else None
    if isinstance(value, np.integer):
        return int(value)
    return value


def binary_metrics(truth: np.ndarray, predicted: np.ndarray) -> dict[str, Any]:
    cm = confusion_matrix(truth, predicted, labels=[0, 1])
    tn, fp, fn, tp = map(int, cm.ravel())
    return clean({
        "accuracy": accuracy_score(truth, predicted),
        "report": classification_report(truth, predicted, labels=[0, 1],
                                        target_names=["normal", "attack"],
                                        output_dict=True, zero_division=np.nan),
        "confusion_matrix": cm.tolist(),
        "normal_false_positive_rate": fp / (tn + fp) if tn + fp else None,
        "attack_false_negative_rate": fn / (fn + tp) if fn + tp else None,
        "balanced_accuracy": ((tn / (tn + fp)) + (tp / (tp + fn))) / 2
        if tn + fp and tp + fn else None,
    })


def metrics(rows: list[Record], probs: np.ndarray, threshold: float) -> dict[str, Any]:
    y = np.asarray([r.label for r in rows])
    pred = probs.argmax(axis=1)
    binary = (y != 0).astype(int)
    score = 1 - probs[:, 0]
    rule = np.asarray([bool(rule_hits(r.text)) for r in rows])
    model = score >= threshold
    report = classification_report(y, pred, labels=list(range(5)), target_names=LABELS,
                                   output_dict=True, zero_division=np.nan)
    cm = confusion_matrix(y, pred, labels=list(range(5)))
    # Macro-F1 unavailable for a full five-class claim when any class is absent.
    all_present = len(set(y)) == 5
    return clean({
        "support": len(rows), "accuracy": accuracy_score(y, pred),
        "macro_f1_all_five": report["macro avg"]["f1-score"] if all_present else None,
        "weighted_f1": report["weighted avg"]["f1-score"],
        "per_class_report": report, "confusion_matrix": cm.tolist(),
        "confusion_matrix_row_normalized": [
            (row / row.sum()).tolist() if row.sum() else [None] * 5 for row in cm],
        "log_loss": log_loss(y, probs, labels=list(range(5))),
        "attack_roc_auc": roc_auc_score(binary, score) if len(set(binary)) == 2 else None,
        "attack_average_precision": average_precision_score(binary, score)
        if len(set(binary)) == 2 else None,
        "brier_attack": float(np.mean((score - binary) ** 2)),
        "binary_comparison": {
            "model_argmax": binary_metrics(binary, (pred != 0).astype(int)),
            "model_threshold": binary_metrics(binary, model.astype(int)),
            "rules": binary_metrics(binary, rule.astype(int)),
            "rules_plus_model": binary_metrics(binary, (rule | model).astype(int)),
        },
        "rules_multiclass": None,
        "rules_multiclass_reason": "Baseline is binary; multi-hit rules have no unique class",
        "unavailable_value": "null means undefined/missing support, never zero-filled",
    })


def plot_matrices(report: dict[str, Any], directory: Path, prefix: str) -> None:
    matrices = {"multiclass": (report["confusion_matrix"], LABELS)}
    matrices["multiclass-normalized"] = (report["confusion_matrix_row_normalized"], LABELS)
    for name, item in report["binary_comparison"].items():
        matrices[name] = (item["confusion_matrix"], ["normal", "attack"])
    for name, (data, labels) in matrices.items():
        maximum = max((v for row in data for v in row if v is not None), default=1) or 1
        parts = ['<svg xmlns="http://www.w3.org/2000/svg" width="900" height="660" viewBox="0 0 900 660">',
                 '<rect width="900" height="660" fill="white"/>',
                 f'<text x="40" y="35" font-size="20">{escape(prefix + ": " + name)}</text>',
                 '<text x="360" y="65">Predicted label (columns); true label (rows)</text>']
        size = 480 / len(labels)
        for i, label in enumerate(labels):
            parts.append(f'<text x="25" y="{145 + i * size}" font-size="14">{escape(label)}</text>')
            parts.append(f'<text x="{220 + i * size}" y="95" font-size="12">{escape(label)}</text>')
        for i, row in enumerate(data):
            for j, value in enumerate(row):
                shade = int(255 - 100 * (value or 0) / maximum)
                text = "N/A" if value is None else f"{value:.3f}" if isinstance(value, float) else str(value)
                parts.append(f'<rect x="{210 + j * size}" y="{110 + i * size}" width="{size}" '
                             f'height="{size}" fill="rgb({shade},{shade},255)" stroke="white"/>')
                parts.append(f'<text x="{210 + (j + .5) * size}" y="{110 + (i + .5) * size}" '
                             f'text-anchor="middle" font-size="16">{text}</text>')
        parts.append("</svg>")
        with (directory / f"{prefix}-{name}.svg").open("x", encoding="utf-8") as stream:
            stream.write("\n".join(parts))


def plot_history(history: dict, path: Path) -> None:
    """Dependency-free SVG learning curves; source values also saved as JSON."""
    parts = ['<svg xmlns="http://www.w3.org/2000/svg" width="900" height="640">',
             '<rect width="900" height="640" fill="white"/>']
    for panel, metric in enumerate(("mlogloss", "merror")):
        top = 35 + panel * 310
        series = [(name, values[metric]) for name, values in history.items()]
        maximum = max(max(values) for _, values in series) or 1
        parts.append(f'<text x="65" y="{top}">{metric}: train (blue), validation (red)</text>')
        parts.append(f'<path d="M65 {top + 15} V{top + 250} H850" fill="none" stroke="black"/>')
        for (name, values), color in zip(series, ("blue", "red")):
            points = " ".join(f"{65 + i * 785 / max(len(values) - 1, 1):.2f},"
                              f"{top + 250 - v * 225 / maximum:.2f}"
                              for i, v in enumerate(values))
            parts.append(f'<polyline points="{points}" fill="none" stroke="{color}" stroke-width="2"/>')
        parts.append(f'<text x="400" y="{top + 275}">Boosting round</text>')
        parts.append(f'<text x="5" y="{top + 20}">{maximum:.3f}</text>')
        parts.append(f'<text x="30" y="{top + 250}">0</text>')
    parts.append("</svg>")
    with path.open("x", encoding="utf-8") as stream:
        stream.write("\n".join(parts))


def evaluate(rows: list[Record], probs: np.ndarray, threshold: float, output: Path,
             prefix: str) -> None:
    report = metrics(rows, probs, threshold)
    report["by_source"] = {}
    for source in ("ai", "human", "external"):
        indices = [i for i, row in enumerate(rows) if row.source == source]
        report["by_source"][source] = (
            metrics([rows[i] for i in indices], probs[indices], threshold)
            if indices else {"metrics": None, "reason": "No data; pending collection"})
    report["annotation_quality"] = summary(rows)
    report["evidence_scope"] = (
        "Offline labels; not proof of real-world performance or successful exploits. "
        "Generated/unverified annotations require independent review."
    )
    write_json(output / f"{prefix}-metrics.json", report)
    plot_matrices(report, output, prefix)
    with (output / f"{prefix}-predictions.jsonl").open("x", encoding="utf-8") as stream:
        for row, prob in zip(rows, probs):
            hits = rule_hits(row.text)
            score = float(1 - prob[0])
            stream.write(json.dumps({
                "sample_id": row.sample_id, "source": row.source,
                "true_label": LABELS[row.label], "predicted_label": LABELS[int(prob.argmax())],
                "probabilities": dict(zip(LABELS, map(float, prob))),
                "attack_score": score, "threshold": threshold,
                "model_attack": score >= threshold, "rule_hits": hits,
                "combined_attack": bool(hits) or score >= threshold,
            }, ensure_ascii=False, allow_nan=False) + "\n")


def weights(rows: list[Record]) -> np.ndarray:
    """Training-only class-balanced sqrt family counts, floor=100."""
    counts = Counter((r.label, r.family) for r in rows)
    raw = np.asarray([1 / math.sqrt(max(100, counts[r.label, r.family]))
                      if r.family else 1.0 for r in rows])
    y = np.asarray([r.label for r in rows])
    for label in range(5):
        mask = y == label
        raw[mask] *= len(rows) / 5 / raw[mask].sum()
    return raw.astype(np.float32)


def matrix(features: Features, rows: list[Record], batch: int) -> sparse.csr_matrix:
    return sparse.vstack([features.transform([r.text for r in rows[i:i + batch]])
                          for i in range(0, len(rows), batch)], format="csr")


def choose_threshold(y: np.ndarray, probs: np.ndarray, max_fpr: float) -> tuple[float, dict]:
    # Fixed candidate grid; validation only. Conservative tie-breaking.
    truth = (y != 0).astype(int)
    candidates = []
    for threshold in np.linspace(0, 1, 201):
        item = binary_metrics(truth, (1 - probs[:, 0] >= threshold).astype(int))
        fpr, fnr = item["normal_false_positive_rate"], item["attack_false_negative_rate"]
        if fpr is not None and fnr is not None and fpr <= max_fpr:
            candidates.append((1 - fnr, -fpr, float(threshold)))
    if not candidates:
        raise ValueError("No threshold meets validation FPR target; do not deploy")
    recall, negative_fpr, threshold = max(candidates)
    return threshold, {"method": "validation-grid-201-max-recall-under-fpr",
                       "max_fpr": max_fpr, "validation_fpr": -negative_fpr,
                       "validation_recall": recall,
                       "warning": "Probabilities are not calibrated; threshold is validation-selected"}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--train", type=Path, required=True)
    parser.add_argument("--validation", type=Path)
    parser.add_argument("--test", type=Path)
    parser.add_argument("--output", type=Path, required=True, help="New directory only")
    parser.add_argument("--fit-only", action="store_true", help="No performance claims/evaluation")
    parser.add_argument("--allow-unreviewed", action="store_true",
                        help="Explicit experimental use of generated labels")
    parser.add_argument("--audit-only", action="store_true")
    parser.add_argument("--allow-shared-families", action="store_true",
                        help="Within-family synthetic benchmark only; still rejects exact/near/session leakage")
    parser.add_argument("--allow-shared-normal-templates", action="store_true",
                        help="Report normal-only near-template overlap; exact/session and attack overlap still rejected")
    parser.add_argument("--rounds", type=int, default=600)
    parser.add_argument("--early-stopping", type=int, default=30)
    parser.add_argument("--max-features", type=int, default=8000)
    parser.add_argument("--batch-size", type=int, default=2048)
    parser.add_argument("--threads", type=int, default=2)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-fpr", type=float, default=0.01)
    args = parser.parse_args()
    if args.fit_only and (args.validation or args.test):
        parser.error("--fit-only cannot include validation/test")
    if not args.fit_only and not (args.validation and args.test):
        parser.error("Provide disjoint --validation and --test, or explicitly --fit-only")
    if min(args.rounds, args.early_stopping, args.max_features, args.batch_size, args.threads) < 1:
        parser.error("Numeric sizes must be positive")
    if not 0 <= args.max_fpr <= 1:
        parser.error("--max-fpr must be in [0,1]")
    args.output.mkdir(parents=True, exist_ok=False)
    splits, inputs, provenance = {}, {}, {}
    for name in ("train", "validation", "test"):
        path = getattr(args, name)
        if path:
            print(f"Loading {name}: {path}", flush=True)
            splits[name], inputs[name] = load(path)
            parent = path if path.is_dir() else path.parent
            provenance[name] = {}
            for filename in ("manifest.json", "quality-report.json", "training-contract.json"):
                sidecar = parent / filename
                if sidecar.is_file():
                    provenance[name][filename] = {
                        "sha256": sha(sidecar),
                        "content": json.loads(sidecar.read_text(encoding="utf-8")),
                    }
    audit = audit_splits(splits, allow_shared_families=args.allow_shared_families,
                         allow_shared_normal_templates=args.allow_shared_normal_templates)
    write_json(args.output / "data-audit.json", audit)
    write_json(args.output / "input-manifest.json", inputs)
    write_json(args.output / "dataset-provenance.json", provenance)
    if audit["cross_split_conflicts"]:
        raise ValueError("Cross-split leakage detected; see data-audit.json. No model trained.")
    for name, rows in splits.items():
        if audit["splits"][name]["exact_duplicates"]:
            raise ValueError(f"{name} contains duplicate feature text; review/deduplicate before training")
        if set(r.label for r in rows) != set(range(5)):
            raise ValueError(f"{name} must contain all five classes for this training workflow")
        if not args.allow_unreviewed and not all(r.reviewed for r in rows):
            raise ValueError("Unreviewed annotations: review first or opt into --allow-unreviewed")
    if args.audit_only:
        print("Audit passed; no training performed.")
        return
    rows = splits["train"]
    print("Fitting train-only TF-IDF; RAM depends on vocabulary and corpus size.", flush=True)
    features = Features(args.max_features)
    features.fit([r.text for r in rows])
    x_train = matrix(features, rows, args.batch_size)
    y_train = np.asarray([r.label for r in rows])
    dtrain = xgb.DMatrix(x_train, label=y_train, weight=weights(rows))
    del x_train
    evals = [(dtrain, "train")]
    dval = None
    if "validation" in splits:
        validation = splits["validation"]
        dval = xgb.DMatrix(matrix(features, validation, args.batch_size),
                          label=[r.label for r in validation])
        evals.append((dval, "validation"))
    params = {"objective": "multi:softprob", "num_class": 5,
              "eval_metric": ["mlogloss", "merror"], "tree_method": "hist",
              "device": "cpu", "max_depth": 6, "eta": 0.05,
              "min_child_weight": 3, "subsample": 0.8, "colsample_bytree": 0.8,
              "seed": args.seed, "nthread": args.threads}
    history: dict = {}
    started = time.perf_counter()
    model = xgb.train(params, dtrain, num_boost_round=args.rounds, evals=evals,
                      evals_result=history, verbose_eval=50,
                      early_stopping_rounds=args.early_stopping if dval is not None else None)
    if dval is not None:
        # Slice actual trees so later Booster.predict matches validation's best round.
        model = model[:model.best_iteration + 1]
        threshold, selection = choose_threshold(
            np.asarray([r.label for r in splits["validation"]]), model.predict(dval), args.max_fpr)
    else:
        threshold, selection = 0.5, {"method": "unvalidated-placeholder",
                                     "warning": "Fit-only; not a validated routing threshold"}
    bundle = args.output / "bundle"
    bundle.mkdir()
    model.save_model(bundle / "xgb.json")
    features.save(bundle / "features.json")
    shutil.copyfile(Path(runtime.__file__), bundle / "runtime.py")
    versions = {name: importlib.metadata.version(name)
                for name in ("numpy", "scipy", "scikit-learn", "xgboost")}
    with (bundle / "requirements.txt").open("x", encoding="utf-8") as stream:
        stream.write("\n".join(f"{k}=={v}" for k, v in versions.items()) + "\n")
    # Fixed synthetic probes; never export training rows or their personal data.
    probes = [runtime.request_text({
        "method": "GET", "path": "/store/products", "query": query,
        "headers": {}, "body": None,
    }) for query in ("q=cotton", "q=O%27Brien", "q=%27+OR+1%3D1--",
                     "q=%3Cscript%3Evoid(0)%3C/script%3E",
                     "q=%3Bprintf%20probe", "file=../../fixture.txt", "q=中文")]
    reference = model.predict(xgb.DMatrix(features.transform(probes)))
    write_json(bundle / "portability-probes.json", {
        "texts": probes, "probabilities": reference.tolist(), "rtol": 1e-6, "atol": 1e-7,
        "note": "Fixed harmless synthetic probes; not evaluation data",
    })
    write_json(bundle / "bundle.json", {
        "version": VERSION, "labels": LABELS, "rules": RULES, "threshold": threshold,
        "threshold_selection": selection, "validated_for_deployment": False,
        "sha256": {name: sha(bundle / name) for name in
                   ("xgb.json", "features.json", "runtime.py", "portability-probes.json")},
        "feature_count": model.num_features(), "versions": versions,
    })
    write_json(args.output / "training-history.json", history)
    plot_history(history, args.output / "learning-curves.svg")
    write_json(args.output / "run.json", {
        "created_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "python": platform.python_version(), "platform": platform.platform(),
        "versions": versions, "parameters": params, "seed": args.seed,
        "rounds_requested": args.rounds, "rounds_saved": model.num_boosted_rounds(),
        "early_stopping_metric": "validation-merror" if dval is not None else None,
        "fit_only": args.fit_only, "allow_unreviewed": args.allow_unreviewed,
        "allow_shared_families": args.allow_shared_families,
        "allow_shared_normal_templates": args.allow_shared_normal_templates,
        "evaluation_scope": "synthetic_within_family" if args.allow_shared_families else "family_disjoint",
        "elapsed_training_seconds": time.perf_counter() - started,
        "weight_policy": "train-only-class-balanced-sqrt-family-floor100",
        "source_sha256": {p.name: sha(p) for p in Path(__file__).parent.glob("*.py")},
        "inputs": inputs,
        "test_policy": "No test fit, threshold selection, early stopping or parameter tuning",
    })
    restored = Predictor(bundle)
    np.testing.assert_allclose(restored.probabilities(probes), reference, rtol=1e-6, atol=1e-7)
    if not args.fit_only:
        for name in ("validation", "test"):
            evaluated = splits[name]
            probs = np.concatenate([restored.probabilities([r.text for r in evaluated[i:i + args.batch_size]])
                                    for i in range(0, len(evaluated), args.batch_size)])
            evaluate(evaluated, probs, threshold, args.output, name)
    else:
        write_json(args.output / "metrics-unavailable.json", {
            "metrics": None, "reason": "Fit-only. No independent validation or test data supplied."})
    write_json(args.output / "checksums.json", {
        p.relative_to(args.output).as_posix(): sha(p)
        for p in args.output.rglob("*") if p.is_file()
    })
    print(f"Complete: {args.output.resolve()}", flush=True)


if __name__ == "__main__":
    main()
