from __future__ import annotations

import asyncio
import json
import logging
import math
import re
import time
from collections import Counter, OrderedDict, deque
from pathlib import Path
from typing import Any
from urllib.parse import unquote

FEATURES = [
    "path_length",
    "query_length",
    "body_length",
    "header_count",
    "header_bytes",
    "body_entropy",
    "special_ratio",
    "request_count_60s",
    "interval_ms",
    "method_write",
    "json_body",
    "rule_hits",
]
RULES = {
    "sqli": re.compile(
        r"(?:\bunion\s+(?:all\s+)?select\b|\bor\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|\bsleep\s*\(|\bdrop\s+table\b)",
        re.IGNORECASE,
    ),
    "xss": re.compile(r"<\s*script\b|javascript\s*:|\bonerror\s*=", re.IGNORECASE),
    "traversal": re.compile(r"(?:\.\.[/\\]){2,}|/etc/(?:passwd|shadow)", re.IGNORECASE),
    "command": re.compile(
        r";\s*(?:cat|curl|wget|bash|sh|id|whoami)\b|\$\(|\b(?:exec|system)\s*\(",
        re.IGNORECASE,
    ),
    "ssti": re.compile(r"\{\{.*?(?:__|\d+\s*\*\s*\d+).*?\}\}", re.DOTALL),
}


class Detector:
    """JSON-only XGBoost contract; incompatible legacy pickle artifacts are not loaded."""

    def __init__(self, model_dir: str = "", timeout: float = 0.15) -> None:
        self.model: Any = None
        self.timeout = timeout
        self.history: OrderedDict[str, deque[float]] = OrderedDict()
        self.busy = False
        self.model_status = "rules_only"
        if model_dir and (Path(model_dir) / "xgb.json").is_file():
            try:
                import xgboost as xgb

                metadata = json.loads((Path(model_dir) / "features.json").read_text())
                if metadata != {
                    "version": 1,
                    "features": FEATURES,
                    "objective": "binary:logistic",
                }:
                    raise ValueError("incompatible feature contract")
                self.model = xgb.Booster(params={"nthread": 1})
                self.model.load_model(Path(model_dir) / "xgb.json")
                config = json.loads(self.model.save_config())
                if (
                    self.model.num_features() != len(FEATURES)
                    or config["learner"]["objective"]["name"] != "binary:logistic"
                ):
                    raise ValueError("incompatible model")
                self.model_status = "ready"
            except Exception:
                logging.getLogger(__name__).exception(
                    "Commerce model unavailable; using rules"
                )
                self.model = None
                self.model_status = "unavailable_or_incompatible"

    async def assess(
        self,
        visitor: str,
        method: str,
        path: str,
        query: str,
        headers: dict[str, str],
        body: bytes,
    ) -> dict:
        stamp = time.monotonic()
        history = self.history.setdefault(visitor, deque(maxlen=1000))
        self.history.move_to_end(visitor)
        while len(self.history) > 10000:
            self.history.popitem(last=False)
        interval = (stamp - history[-1]) * 1000 if history else 60000.0
        history.append(stamp)
        while history and history[0] < stamp - 60:
            history.popleft()
        body_text = body.decode("utf-8", "replace")
        text = (
            path
            + "?"
            + query
            + "\n"
            + body_text
            + "\n"
            + "\n".join(
                f"{k}:{v}"
                for k, v in headers.items()
                if k.lower() not in {"cookie", "authorization"}
            )
        )
        for _ in range(3):
            text = unquote(text)
        hits = [name for name, pattern in RULES.items() if pattern.search(text)]
        counts = Counter(body)
        entropy = (
            -sum((n / len(body)) * math.log2(n / len(body)) for n in counts.values())
            if body
            else 0
        )
        values = [
            len(path),
            len(query),
            len(body),
            len(headers),
            sum(len(k) + len(v) for k, v in headers.items()),
            entropy,
            sum(not c.isalnum() and not c.isspace() for c in body_text)
            / max(len(body_text), 1),
            len(history),
            interval,
            int(method not in {"GET", "HEAD", "OPTIONS"}),
            int("json" in headers.get("content-type", "")),
            len(hits),
        ]
        probability = None
        source = "rule"
        fallback = self.model_status
        if self.model is not None and not self.busy:
            self.busy = True
            task = asyncio.create_task(asyncio.to_thread(self._predict, values))

            def done(future: asyncio.Task) -> None:
                self.busy = False
                if not future.cancelled():
                    future.exception()

            task.add_done_callback(done)
            try:
                probability = await asyncio.wait_for(asyncio.shield(task), self.timeout)
                source, fallback = "xgboost", None
            except (Exception, asyncio.TimeoutError):
                logging.getLogger(__name__).exception(
                    "Commerce model failed or timed out; using rules"
                )
                fallback = "model_error_or_timeout"
        elif self.model is not None:
            fallback = "model_busy"
        # High-confidence signatures remain a safety net even when the model is available.
        rule_score = 0.95 if hits else 0.05
        attack = bool(hits) or (probability is not None and probability >= 0.7)
        return {
            "attack": attack,
            "score": probability if probability is not None else rule_score,
            "model_probability": probability,
            "rule_score": rule_score,
            "decision_source": source,
            "fallback": fallback,
            "rules": hits,
            "features": dict(zip(FEATURES, values)),
        }

    def _predict(self, values: list[float]) -> float:
        import numpy as np
        import xgboost as xgb

        value = float(
            self.model.predict(
                xgb.DMatrix(
                    np.array([values], dtype=np.float32), feature_names=FEATURES
                )
            )[0]
        )
        if not math.isfinite(value) or not 0 <= value <= 1:
            raise ValueError("invalid model output")
        return value
