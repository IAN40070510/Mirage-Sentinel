from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import re
import time
from collections import Counter, OrderedDict, deque
from pathlib import Path
from typing import Any
from urllib.parse import unquote, parse_qsl

FEATURE_VERSION = 2

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
        r"(?:\bunion\s+(?:all\s+)?select\s+(?:\d|NULL\b|['\"`*(@]|[\w.]+\s*(?:,|\(|\bfrom\b))|\bor\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|\bsleep\s*\(|\bdrop\s+table\s+[\w`\"]+|\biif\s*\(\s*\d+\s*=\s*\d+\s*,\s*\d+\s*,\s*\d+\s*/\s*0\s*\))",
        re.IGNORECASE,
    ),
    "xss": re.compile(r"<\s*script\b|javascript\s*:\s*(?:[\w.$]+\s*[=(`]|[([]|(?:void|throw)\b)|\bonerror\s*=|<\s*[a-z][^>]{0,2048}\bon(?:load|mouseover|mouseenter|focus|focusin|click|input|animationstart|pointerover|begin)\s*=", re.IGNORECASE),
    "traversal": re.compile(r"(?:\.\.[/\\]){2,}(?!\.\.[/\\])(?=\S|$)|/etc/(?:passwd|shadow)", re.IGNORECASE),
    "command": re.compile(
        r";\s*(?:cat|curl|wget|bash|sh|id|whoami)\b|\$\(|\b(?:exec|system)\s*\(",
        re.IGNORECASE,
    ),
}


def request_values(query: str, body: str, headers: dict[str, str]) -> list[str]:
    """Decode bounded JSON values before signatures inspect application strings."""
    values = [v for _, v in parse_qsl(query, keep_blank_values=True)]
    values.extend(v for k,v in headers.items() if k.lower() not in {'cookie','authorization'})
    try:
        pending = [json.loads(body)] if body else []
        examined = 0
        while pending and examined < 1024:
            value = pending.pop(); examined += 1
            if isinstance(value,str): values.append(value)
            elif isinstance(value,dict): pending.extend(value.values())
            elif isinstance(value,list): pending.extend(value)
    except (ValueError, RecursionError):
        values.append(body)
    decoded = []
    for value in values:
        for _ in range(3): value=unquote(value)
        decoded.append(value)
    return decoded


def has_atomic_command(query: str, body: str, headers: dict[str, str]) -> bool:
    """Match complete command atoms, not explanatory prose containing code words."""
    for value in request_values(query, body, headers):
        if re.fullmatch(r"\s*(?:\|\s*(?:id|whoami)|`\s*(?:id|whoami)\s*`)\s*", value, re.I):
            return True
    return False


class Detector:
    """JSON-only XGBoost contract; incompatible legacy pickle artifacts are not loaded."""

    def __init__(self, model_dir: str = "", timeout: float = 0.15,
                 model_mode: str = "enforce", queue_timeout: float = 0.5,
                 queue_limit: int = 32) -> None:
        if model_mode not in {"shadow", "enforce"}:
            raise ValueError("model_mode must be shadow or enforce")
        self.model_mode = model_mode
        if min(timeout,queue_timeout,queue_limit) <= 0:
            raise ValueError('Inference deadlines and queue capacity must be positive')
        self.model_required = bool(model_dir)
        self.model_lock = asyncio.Lock()
        self.waiting = 0
        self.queue_timeout, self.queue_limit = queue_timeout, queue_limit
        self.stats: Counter[str] = Counter()
        self.model: Any = None
        self.predictor: Any = None
        self.threshold = 0.7
        self.timeout = timeout
        self.history: OrderedDict[str, deque[float]] = OrderedDict()
        self.busy = False
        self.model_status = "rules_only"
        self.model_bundle_sha256: str | None = None
        if model_dir and (Path(model_dir) / "xgb.json").is_file():
            try:
                if (Path(model_dir) / "bundle.json").is_file():
                    from .five_runtime import Predictor
                    self.predictor = Predictor(Path(model_dir))
                    self.model = self.predictor.model
                    self.threshold = self.predictor.threshold
                    self.model_bundle_sha256 = hashlib.sha256(
                        (Path(model_dir) / 'bundle.json').read_bytes()).hexdigest()
                    self.model_status = "ready_five_class"
                    return
                import xgboost as xgb

                metadata = json.loads((Path(model_dir) / "features.json").read_text())
                if metadata != {
                    "version": FEATURE_VERSION,
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
                    "Commerce model failed to load"
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
        # HTML form encoding uses plus for spaces; JSON and headers do not.
        query_text = query.replace("+", " ")
        content_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
        detection_body = (
            body_text.replace("+", " ")
            if content_type == "application/x-www-form-urlencoded"
            else body_text
        )
        text = (
            path
            + "?"
            + query_text
            + "\n"
            + detection_body
            + "\n"
            + "\n".join(
                f"{k}:{v}"
                for k, v in headers.items()
                if k.lower() not in {"cookie", "authorization"}
            )
        )
        for _ in range(3):
            text = unquote(text)
        # SQL comments can separate tokens without changing their meaning.
        text = re.sub(r'/\*.*?\*/', ' ', text, flags=re.DOTALL)
        decoded_values = request_values(query, body_text, headers)
        signature_texts = [text] + [re.sub(r'/\*.*?\*/', ' ', v, flags=re.DOTALL)
                                    for v in decoded_values]
        hits = [name for name, pattern in RULES.items()
                if any(pattern.search(value) for value in signature_texts)]
        if 'command' not in hits and has_atomic_command(query,body_text,headers):
            hits.append('command')
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
        prediction: dict[str, Any] | None = None
        probability = None
        source = "rule"
        fallback = self.model_status
        if self.model is not None and self.waiting < self.queue_limit:
            self.waiting += 1
            acquired = False
            phase = 'queue'
            try:
                await asyncio.wait_for(self.model_lock.acquire(), self.queue_timeout)
                acquired = True
                self.busy = True
                phase = 'inference'
                request = {"method": method, "path": path, "query": query,
                           "headers": headers, "body": body_text}
                task = asyncio.create_task(asyncio.to_thread(
                    self._predict_five if self.predictor is not None else self._predict,
                    request if self.predictor is not None else values))

                def done(future: asyncio.Task) -> None:
                    self.busy = False
                    self.model_lock.release()
                    if not future.cancelled(): future.exception()

                task.add_done_callback(done)
                acquired = False  # Worker owns the lock until completion, even after timeout.
                result = await asyncio.wait_for(asyncio.shield(task), self.timeout)
                if self.predictor is not None:
                    prediction = result
                    probability = prediction["attack_score"]
                else:
                    probability = result
                source, fallback = "xgboost", None
            except (Exception, asyncio.TimeoutError):
                logging.getLogger(__name__).warning("Commerce model unavailable during %s", phase)
                fallback = "model_queue_timeout" if phase == 'queue' else "model_error_or_timeout"
            finally:
                self.waiting -= 1
                if acquired:
                    self.busy = False
                    self.model_lock.release()
        elif self.model is not None:
            fallback = "model_queue_full"
        # High-confidence signatures remain a safety net even when the model is available.
        rule_score = 0.95 if hits else 0.05
        model_attack = probability is not None and probability >= self.threshold
        # Enforce model decisions by default; shadow remains an explicit diagnostic option.
        enforced = self.predictor is None or self.model_mode == "enforce"
        attack = bool(hits) or (enforced and model_attack)
        retry_required = (self.model_mode == 'enforce' and fallback is not None and not hits
                          and (self.model_required or self.model is not None))
        self.stats[fallback or 'predicted'] += 1
        if prediction is not None and not enforced:
            source = "rule_with_shadow_model"
        return {
            "attack": attack,
            "model_attack": model_attack if probability is not None else None,
            "model_mode": self.model_mode if self.predictor is not None else "legacy",
            "predicted_label": prediction["predicted_label"] if prediction else None,
            "class_probabilities": prediction["probabilities"] if prediction else None,
            "model_contract": prediction["contract_version"] if prediction else None,
            "model_threshold": self.threshold if probability is not None else None,
            "score": probability if probability is not None else rule_score,
            "model_probability": probability,
            "rule_score": rule_score,
            "decision_source": source,
            "fallback": fallback,
            "retry_required": retry_required,
            "rules": hits,
            "feature_version": FEATURE_VERSION,
            "features": dict(zip(FEATURES, values)),
        }

    def _predict_five(self, request: dict[str, Any]) -> dict[str, Any]:
        return self.predictor.predict([request])[0]

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
