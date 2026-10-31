"""Request-only features and JSON-only model bundles shared by train/inference."""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import math
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import numpy as np
from scipy import sparse
from sklearn.feature_extraction.text import TfidfVectorizer
import xgboost as xgb

VERSION = "commerce-text-five-v1"
LABELS = ["normal", "sqli", "xss", "cmdi", "path_traversal"]
NUMERIC = ["log_length", "entropy", "slash", "parent_path", "sql_chars",
           "html_chars", "shell_chars", "percent_encoding", "template",
           "exec_call", "obfuscation", "non_alnum", "question", "equals"]
# Frozen baseline, derived from services/commerce/detection.py contract v2.
# Rule hits are NOT ground truth. This is a binary comparison baseline only.
RULES = {
    "sqli": r"(?:\bunion\s+(?:all\s+)?select\b|\bor\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|\bsleep\s*\(|\bdrop\s+table\b)",
    "xss": r"<\s*script\b|javascript\s*:|\bonerror\s*=",
    "path_traversal": r"(?:\.\.[/\\]){2,}|/etc/(?:passwd|shadow)",
    "cmdi": r";\s*(?:cat|curl|wget|bash|sh|id|whoami)\b|\$\(|\b(?:exec|system)\s*\(",
}


def sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path: Path, value: Any) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)


def request_text(request: dict[str, Any]) -> str:
    """v1: preserve encoded text/body; only content-type enters from headers.

    Same explicit fixture masking as dataset v4.1. No metadata, UA, Cookie,
    Authorization, timestamps, responses or predictions enter the features.
    Dataset producers must redact body/query secrets before collection.
    """
    for key in ("method", "path", "query"):
        if not isinstance(request.get(key), str):
            raise ValueError(f"request.{key} must be a string")
    if request.get("body") is not None and not isinstance(request["body"], str):
        raise ValueError("body must be string or null; never auto-convert forms")
    headers = request.get("headers")
    if not isinstance(headers, dict) or any(
        not isinstance(k, str) or not isinstance(v, str) for k, v in headers.items()
    ):
        raise ValueError("headers must be a string-to-string object")
    lowered = {k.lower(): v for k, v in headers.items()}
    if len(lowered) != len(headers):
        raise ValueError("duplicate case-insensitive header names")
    text = "\n".join([request["method"], request["path"], request["query"],
                      lowered.get("content-type", ""), request.get("body") or ""])
    text = re.sub(r"\b[a-z]+_PLACEHOLDER(?:_\d+)?\b", "<ID>", text)
    return re.sub(r"fixture\d+@example\.invalid", "<SYNTHETIC_EMAIL>", text)


def numeric(texts: list[str]) -> np.ndarray:
    rows = []
    for text in texts:
        length = len(text)
        denominator = length + 1
        entropy = -sum((v / length) * math.log2(v / length)
                       for v in Counter(text).values()) if length else 0.0
        count = lambda pattern: len(re.findall(pattern, text))
        rows.append([
            math.log1p(length), entropy, text.count("/"),
            count(r"\.\./|\.\.\\"),
            count(r"""[;'"#-]""") / denominator,
            count(r"[<>{}]") / denominator,
            count(r"[|&`\\]") / denominator,
            count(r"%[0-9a-fA-F]{2}") / denominator,
            int(bool(re.search(r"\{\{|\}\}|\$\{", text))),
            int(bool(re.search(r"(system|exec|eval)\s*\(", text, re.I))),
            int(bool(re.search(r"%00|::|data:|javascript:|\\u[0-9a-f]{4}", text, re.I))),
            count(r"[^a-zA-Z0-9]") / denominator,
            text.count("?"), text.count("="),
        ])
    return np.asarray(rows, dtype=np.float32).reshape(-1, len(NUMERIC))


class Features:
    def __init__(self, max_features: int = 8000) -> None:
        self.vectorizer = TfidfVectorizer(
            analyzer="char", ngram_range=(2, 4), lowercase=False,
            max_features=max_features, dtype=np.float32,
        )
        self.scale = np.ones(len(NUMERIC), dtype=np.float32)

    def fit(self, texts: list[str]) -> None:
        self.vectorizer.fit(texts)
        for start in range(0, len(texts), 2048):
            self.scale = np.maximum(self.scale, np.abs(numeric(texts[start:start + 2048])).max(axis=0))

    def transform(self, texts: list[str]) -> sparse.csr_matrix:
        return sparse.hstack(
            [self.vectorizer.transform(texts), sparse.csr_matrix(numeric(texts) / self.scale)],
            format="csr", dtype=np.float32,
        )

    def save(self, path: Path) -> None:
        write_json(path, {
            "version": VERSION, "numeric_order": NUMERIC,
            "vocabulary": {k: int(v) for k, v in self.vectorizer.vocabulary_.items()},
            "idf": self.vectorizer.idf_.tolist(), "scale": self.scale.tolist(),
            "tfidf": {"analyzer": "char", "ngram_range": [2, 4], "lowercase": False,
                      "norm": "l2", "smooth_idf": True, "sublinear_tf": False},
        })

    @classmethod
    def load(cls, path: Path) -> Features:
        info = json.loads(path.read_text(encoding="utf-8"))
        expected = {"analyzer": "char", "ngram_range": [2, 4], "lowercase": False,
                    "norm": "l2", "smooth_idf": True, "sublinear_tf": False}
        if info["version"] != VERSION or info["numeric_order"] != NUMERIC or info["tfidf"] != expected:
            raise ValueError("Unsupported feature contract")
        vocabulary = info["vocabulary"]
        if sorted(vocabulary.values()) != list(range(len(vocabulary))):
            raise ValueError("Invalid vocabulary indices")
        result = cls()
        result.vectorizer = TfidfVectorizer(
            analyzer="char", ngram_range=(2, 4), lowercase=False,
            vocabulary=vocabulary, dtype=np.float32,
        )
        idf = np.asarray(info["idf"], dtype=np.float32)
        result.scale = np.asarray(info["scale"], dtype=np.float32)
        if (len(idf) != len(vocabulary) or result.scale.shape != (len(NUMERIC),)
                or not np.isfinite(idf).all() or not (idf > 0).all()
                or not np.isfinite(result.scale).all() or not (result.scale > 0).all()):
            raise ValueError("Invalid feature arrays")
        result.vectorizer.idf_ = idf
        return result


def rule_hits(text: str) -> list[str]:
    # Frozen request-text baseline, not a claim of byte-identical live gateway rules.
    for _ in range(3):
        text = unquote(text)
    return [label for label, pattern in RULES.items() if re.search(pattern, text, re.I)]


class Predictor:
    def __init__(self, bundle: Path) -> None:
        bundle = bundle.resolve()
        self.meta = json.loads((bundle / "bundle.json").read_text(encoding="utf-8"))
        if (self.meta["version"] != VERSION or self.meta["labels"] != LABELS
                or self.meta["rules"] != RULES):
            raise ValueError("Incompatible bundle")
        for package, expected in self.meta["versions"].items():
            if importlib.metadata.version(package) != expected:
                raise ValueError(f"Dependency mismatch: {package}; install bundle/requirements.txt")
        for name in ("xgb.json", "features.json", "runtime.py"):
            if sha(bundle / name) != self.meta["sha256"][name]:
                raise ValueError(f"Bundle checksum mismatch: {name}")
        if sha(Path(__file__)) != self.meta["sha256"]["runtime.py"]:
            raise ValueError("Runtime version differs; use the bundled runtime.py")
        self.features = Features.load(bundle / "features.json")
        self.model = xgb.Booster(params={"nthread": 1})
        self.model.load_model(bundle / "xgb.json")
        cfg = json.loads(self.model.save_config())["learner"]
        if (cfg["objective"]["name"] != "multi:softprob"
                or int(cfg["learner_model_param"]["num_class"]) != len(LABELS)
                or self.model.num_features() != len(self.features.vectorizer.vocabulary_) + len(NUMERIC)):
            raise ValueError("Model feature/class/objective mismatch")
        self.threshold = float(self.meta["threshold"])
        if not 0 <= self.threshold <= 1:
            raise ValueError("Invalid decision threshold")

    def probabilities(self, texts: list[str]) -> np.ndarray:
        probs = self.model.predict(xgb.DMatrix(self.features.transform(texts)))
        if (probs.shape != (len(texts), len(LABELS)) or not np.isfinite(probs).all()
                or (probs < 0).any() or (probs > 1).any()
                or not np.allclose(probs.sum(axis=1), 1, atol=1e-5)):
            raise ValueError("Invalid model probabilities")
        return probs

    def predict(self, requests: list[dict[str, Any]]) -> list[dict[str, Any]]:
        texts = [request_text(request) for request in requests]
        if not texts:
            return []
        output = []
        for text, prob in zip(texts, self.probabilities(texts)):
            score = float(1 - prob[0])
            hits = rule_hits(text)
            output.append({
                "predicted_label": LABELS[int(prob.argmax())],
                "probabilities": dict(zip(LABELS, map(float, prob))),
                "attack_score": score, "threshold": self.threshold,
                "model_attack": score >= self.threshold,
                "rule_hits": hits, "combined_attack": bool(hits) or score >= self.threshold,
                "contract_version": VERSION,
            })
        return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, default=Path(os.getenv(
        "SENTINEL_MODEL_DIR", str(Path(__file__).resolve().parent))))
    parser.add_argument("--input", type=Path, help="JSONL requests or dataset rows")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true", help="Check bundled portability probes")
    args = parser.parse_args()
    predictor = Predictor(args.bundle)
    if args.self_test:
        path = args.bundle / "portability-probes.json"
        if sha(path) != predictor.meta["sha256"]["portability-probes.json"]:
            raise ValueError("Probe checksum mismatch")
        probes = json.loads(path.read_text(encoding="utf-8"))
        np.testing.assert_allclose(predictor.probabilities(probes["texts"]),
                                   probes["probabilities"], rtol=probes["rtol"], atol=probes["atol"])
        print("Portability probes passed; this is NOT a model accuracy test.")
        return
    if not args.input or not args.output:
        parser.error("--input and --output are required unless --self-test is used")
    with args.input.open(encoding="utf-8") as source, args.output.open("x", encoding="utf-8") as out:
        for line in source:
            row = json.loads(line)
            result = predictor.predict([row.get("request", row)])[0]
            # ID only for traceability, never a model feature.
            if "sample_id" in row:
                result["sample_id"] = row["sample_id"]
            out.write(json.dumps(result, ensure_ascii=False, allow_nan=False) + "\n")


if __name__ == "__main__":
    main()
