import argparse
import json
import logging
import os
import re
from collections import Counter
from math import log2
from pathlib import Path
from urllib.parse import unquote

import joblib
import numpy as np
import pandas as pd
import scipy.sparse as sp
from sklearn.base import BaseEstimator, TransformerMixin
from xgboost import XGBClassifier  # type: ignore[import-not-found]


logger = logging.getLogger(__name__)


DEFAULT_LABELS = {
    0: "normal",
    1: "sqli",
    2: "xss",
    3: "lfi",
    4: "ssti",
    5: "cmdi",
    6: "path-traversal",
    7: "anomaly and other attacks",
}


class SecurityExtractor(BaseEstimator, TransformerMixin):
    _RE_SQL = re.compile(r"[;'\"\-#]")
    _RE_XSS = re.compile(r"[<>{}]")
    _RE_CMD = re.compile(r"[|&`\\]")
    _RE_PATH = re.compile(r"\.\./|\.\.\\\\|/\.\./")
    _RE_URLENCODE = re.compile(r"%[0-9a-fA-F]{2}")
    _RE_TEMPLATE = re.compile(r"\{\{|\}\}|\$\{")
    _RE_CMD_EXEC = re.compile(
        r"(?:system|exec|shell_exec|passthru|eval|assert|"
        r"create_function|preg_replace)\s*\(",
        re.IGNORECASE,
    )
    _RE_OBFUSCATION = re.compile(
        r"%00|::|data:|javascript:|\\u[0-9a-fA-F]{4}",
        re.IGNORECASE,
    )
    _RE_ALNUM = re.compile(r"[a-zA-Z0-9]")

    @staticmethod
    def _entropy(text: str) -> float:
        if not text:
            return 0.0
        counts = Counter(text)
        length = len(text)
        return -sum((count / length) * log2(count / length) for count in counts.values())

    def fit(self, x, y=None):
        return self

    def transform(self, x):
        if not isinstance(x, pd.Series):
            x = pd.Series(x)

        x_str = x.fillna("").astype(str)
        length_series = x_str.str.len() + 1

        features_df = pd.concat(
            [
                x_str.str.len().apply(np.log1p),
                x_str.apply(self._entropy),
                x_str.str.count("/"),
                x_str.str.count(self._RE_PATH.pattern),
                x_str.str.count(self._RE_SQL.pattern) / length_series,
                x_str.str.count(self._RE_XSS.pattern) / length_series,
                x_str.str.count(self._RE_CMD.pattern) / length_series,
                x_str.str.count(self._RE_URLENCODE.pattern) / length_series,
                x_str.str.contains(self._RE_TEMPLATE, regex=True).astype(int),
                x_str.str.contains(self._RE_CMD_EXEC, regex=True).astype(int),
                x_str.str.contains(self._RE_OBFUSCATION, regex=True).astype(int),
                (x_str.str.len() - x_str.str.count(self._RE_ALNUM.pattern)) / length_series,
                x_str.str.count(r"\?"),
                x_str.str.count("="),
            ],
            axis=1,
        )

        return sp.csr_matrix(features_df.values.astype(np.float32))


class SentinelXGBInference:
    def __init__(self, model_dir: Path):
        self.model_dir = model_dir
        self.extractor = SecurityExtractor()
        self._load()

    def _load(self):
        meta_path = self.model_dir / "meta.json"
        tfidf_path = self.model_dir / "tfidf.pkl"
        scaler_path = self.model_dir / "scaler.pkl"
        xgb_path = self.model_dir / "xgb.json"

        if not meta_path.exists() or not tfidf_path.exists() or not scaler_path.exists() or not xgb_path.exists():
            raise FileNotFoundError(
                "Missing model artifacts. Required: meta.json, tfidf.pkl, scaler.pkl, xgb.json"
            )

        with meta_path.open("r", encoding="utf-8") as f:
            meta = json.load(f)

        labels = meta.get("labels", DEFAULT_LABELS)
        self.labels = {int(k): v for k, v in labels.items()}
        self.default_block_threshold = float(meta.get("block_threshold", 0.7))
        self.default_review_threshold = float(meta.get("review_threshold", 0.3))

        self.tfidf = joblib.load(tfidf_path)
        self.scaler = joblib.load(scaler_path)
        self.model = XGBClassifier()
        self.model.load_model(str(xgb_path))

    @staticmethod
    def _safe_decode(text: str) -> str:
        if pd.isna(text):
            return ""
        value = str(text)
        try:
            return unquote(unquote(value))
        except Exception:
            return value

    def _build_features(self, payload_series: pd.Series):
        x_t = self.tfidf.transform(payload_series)
        x_s = self.scaler.transform(self.extractor.transform(payload_series))
        return sp.hstack([x_t, x_s], format="csr")

    def predict(
        self,
        payloads,
        block_threshold: float | None = None,
        review_threshold: float | None = None,
        review_action: str = "REVIEW",
    ) -> pd.DataFrame:
        if isinstance(payloads, (list, pd.Series)):
            df_input = pd.DataFrame({"payload": payloads})
        elif isinstance(payloads, pd.DataFrame):
            if "payload" not in payloads.columns:
                raise ValueError("Input DataFrame must include a 'payload' column")
            df_input = payloads.copy()
        else:
            raise TypeError("payloads must be list, pandas.Series, or pandas.DataFrame")

        block = self.default_block_threshold if block_threshold is None else float(block_threshold)
        review = self.default_review_threshold if review_threshold is None else float(review_threshold)

        if review > block:
            raise ValueError("review_threshold must be <= block_threshold")

        payload_series = df_input["payload"].apply(self._safe_decode)
        x = self._build_features(payload_series)

        probs = self.model.predict_proba(x)
        classes = list(self.model.classes_)

        if 0 not in classes:
            raise ValueError("Model classes do not include normal class id 0")

        normal_idx = classes.index(0)
        attack_score = 1.0 - probs[:, normal_idx]

        attack_probs = probs.copy()
        attack_probs[:, normal_idx] = 0
        top_idx = attack_probs.argmax(axis=1)
        top_type = [self.labels.get(classes[i], f"unknown({classes[i]})") for i in top_idx]
        top_prob = attack_probs.max(axis=1)

        decision = np.where(
            attack_score > block,
            "BLOCK",
            np.where(attack_score >= review, review_action, "PASS"),
        )

        return pd.DataFrame(
            {
                "attack_score": np.round(attack_score, 6),
                "decision": decision,
                "top_attack_type": top_type,
                "top_attack_prob": np.round(top_prob, 6),
                "payload": payload_series.values,
            }
        )


def _resolve_model_dir(explicit_model_dir: str | Path | None = None) -> Path:
    def _select_dir(base: Path) -> Path:
        # Prefer ./model when artifact bundle is stored under XGBoost/model.
        candidate = base / "model"
        if (candidate / "meta.json").exists() and (candidate / "xgb.json").exists():
            return candidate
        return base

    if explicit_model_dir:
        return _select_dir(Path(explicit_model_dir).expanduser().resolve())

    env_model_dir = os.getenv("SENTINEL_MODEL_DIR", "").strip()
    if env_model_dir:
        return _select_dir(Path(env_model_dir).expanduser().resolve())

    return _select_dir(Path(__file__).resolve().parent)


def load_sentinel_model(model_dir: str | Path | None = None) -> SentinelXGBInference | None:
    """Load Sentinel model for API runtime; returns None when artifacts are unavailable."""
    resolved_dir = _resolve_model_dir(model_dir)
    try:
        return SentinelXGBInference(resolved_dir)
    except Exception as exc:
        logger.warning("Sentinel model unavailable at %s: %s", resolved_dir, exc)
        return None


def _read_inputs(input_text: str | None, input_file: str | None, payload_col: str) -> pd.DataFrame:
    if input_text:
        return pd.DataFrame({"payload": [input_text]})

    if not input_file:
        raise ValueError("Use --input-text or --input-file")

    input_path = Path(input_file)
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    if input_path.suffix.lower() == ".csv":
        df = pd.read_csv(input_path)
        if payload_col not in df.columns:
            raise ValueError(f"CSV must include payload column: {payload_col}")
        return df[[payload_col]].rename(columns={payload_col: "payload"})

    payloads = [line.rstrip("\n") for line in input_path.open("r", encoding="utf-8") if line.strip()]
    return pd.DataFrame({"payload": payloads})


def main():
    parser = argparse.ArgumentParser(description="Sentinel XGBoost inference runner")
    parser.add_argument("--model-dir", default=".", help="Directory containing model artifacts")
    parser.add_argument("--input-text", default=None, help="Single payload string")
    parser.add_argument("--input-file", default=None, help="Input file (.csv or .txt)")
    parser.add_argument("--payload-col", default="payload", help="Payload column name for CSV input")
    parser.add_argument("--output-file", default=None, help="Optional output CSV path")
    parser.add_argument("--block-threshold", type=float, default=None, help="Block threshold override")
    parser.add_argument("--review-threshold", type=float, default=None, help="Review threshold override")
    parser.add_argument(
        "--review-action",
        default="REVIEW",
        choices=["REVIEW", "PASS", "BLOCK"],
        help="Action for score between review and block threshold",
    )

    args = parser.parse_args()

    runner = SentinelXGBInference(Path(args.model_dir))
    payload_df = _read_inputs(args.input_text, args.input_file, args.payload_col)

    result_df = runner.predict(
        payload_df,
        block_threshold=args.block_threshold,
        review_threshold=args.review_threshold,
        review_action=args.review_action,
    )

    if args.output_file:
        out_path = Path(args.output_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        result_df.to_csv(out_path, index=False)
        print(f"Saved output to: {out_path}")
    else:
        print(result_df.to_csv(index=False))


if __name__ == "__main__":
    main()
