# -*- coding: utf-8 -*-
"""LLaMA 欺敵資料生成模組。

重點：
1) 對外維持既有函式介面，避免破壞現有呼叫端
2) 輸出固定 JSON 結構，並附帶可用於多輪互動的 metadata
3) 失敗時快速降級為 deterministic fallback，避免阻塞主流程
"""

from __future__ import annotations

import json
import logging
import random
from datetime import datetime, timedelta, timezone

import httpx
import opencc

logger = logging.getLogger(__name__)

OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
OLLAMA_MODEL = "llama3.1:8b"

FALLBACK_NAMES = [
    "陳志豪",
    "林美華",
    "黃建宏",
    "張雅婷",
    "李俊賢",
    "王淑芬",
    "吳宗翰",
    "劉怡君",
    "蔡佳穎",
    "楊承恩",
    "許雅雯",
    "鄭文凱",
    "謝宜庭",
    "洪志偉",
    "邱雅琪",
]
COMMON_SURNAMES = tuple("陳林黃張李王吳劉蔡楊許鄭謝洪邱")
ALLOWED_CAPABILITIES = (
    "account_summary",
    "transaction_history",
    "transfer_review",
    "beneficiary_check",
    "auth_challenge",
)
converter = opencc.OpenCC("s2twp")


def _now_iso_ms() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _sanitize_query_id(query_id: str) -> str:
    candidate = (query_id or "").strip()
    return candidate if candidate else "CIF000000000"


def _extract_json_block(text: str) -> str:
    raw = (text or "").strip()
    if raw.startswith("```"):
        raw = raw.strip("`")
        if "\n" in raw:
            raw = raw.split("\n", 1)[1]
    start = raw.find("{")
    end = raw.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("LLM response does not contain a valid JSON object")
    return raw[slice(start, end + 1)]


def _normalize_name(name: str | None) -> str:
    source = converter.convert(str(name or ""))
    chars = [ch for ch in source if "\u4e00" <= ch <= "\u9fff"]
    clean_name = "".join(chars)

    if len(clean_name) >= 3:
        clean_name = clean_name[:3]
    elif len(clean_name) == 2:
        clean_name = clean_name + random.choice("志文豪婷涵恩")
    elif len(clean_name) == 1:
        clean_name = clean_name + random.choice("志文") + random.choice("豪婷")
    else:
        clean_name = random.choice(FALLBACK_NAMES)

    if clean_name[0] not in COMMON_SURNAMES:
        clean_name = random.choice(COMMON_SURNAMES) + clean_name[1:]
    return clean_name[:3]


def _normalize_balance(value: object) -> int:
    try:
        parsed = int(float(str(value)))
    except (TypeError, ValueError):
        parsed = random.randint(1000, 50000)
    return max(0, parsed)


def _resolve_capability(session_context: dict | None) -> str:
    raw = ""
    if isinstance(session_context, dict):
        raw = str(session_context.get("api_capability", "")).strip().lower()
    return raw if raw in ALLOWED_CAPABILITIES else "account_summary"


def _default_banking_context(user_id: str, balance: int, capability: str) -> dict:
    account_id = f"ACC{abs(hash(user_id)) % 10**12:012d}"
    base = {
        "capability": capability,
        "primary_account_id": account_id,
        "currency": "TWD",
    }
    if capability == "transaction_history":
        base["recent_transactions"] = [
            {
                "tx_id": "TX-REVIEW-001",
                "amount": 1200,
                "direction": "debit",
                "status": "PENDING_REVIEW",
                "created_at": _now_iso_ms(),
            }
        ]
    elif capability == "transfer_review":
        base["transfer_preview"] = {
            "amount": min(balance, 2400),
            "fee": 5,
            "status": "QUEUED_REVIEW",
            "risk_tag": "aml_screening",
        }
    elif capability == "beneficiary_check":
        base["beneficiaries"] = [
            {
                "alias": "電費",
                "account_id": "ACC000000000002",
                "bank_code": "812",
                "status": "VERIFICATION_PENDING",
            }
        ]
    elif capability == "auth_challenge":
        base["auth_challenge"] = {
            "stage": "otp",
            "hint": "請輸入六位數 OTP 以完成設備綁定",
            "expires_at": _now_iso_ms(),
        }
    else:
        base["available_balance"] = balance
        base["account_status"] = "Normal"
    return base


def _build_prompt(
    *, user_id: str, attack_vector: str, session_context: dict | None
) -> str:
    context = session_context or {}
    flow_id = str(context.get("flow_id", "N/A"))
    turn_index = int(context.get("turn_index", 0))
    stage = str(context.get("stage", "initial_probe"))
    recent_summary = str(context.get("recent_summary", "none"))
    capability = _resolve_capability(context)

    return f"""
你是老舊銀行核心系統 API 伺服器（Legacy Banking API Server）。
當前為欺敵場景，攻擊類型：{attack_vector}。

互動上下文：
- flow_id: {flow_id}
- turn_index: {turn_index}
- stage: {stage}
- recent_summary: {recent_summary}

請只輸出一個 JSON 物件，欄位必須完整：
{{
  "user_id": "{user_id}",
  "name": "繁體中文三字台灣姓名",
  "email": "看似合理的測試信箱",
  "balance": 12345,
  "status": "Normal",
  "account_created": "YYYY-MM-DD",
  "last_login": "YYYY-MM-DD",
    "banking_api_context": {{
        "capability": "{capability}",
        "primary_account_id": "ACC000000000001",
        "currency": "TWD"
    }},
  "deception_turn": {{
    "phase": "credential_probe|ledger_reconcile|review_queue",
    "objective": "delay|lure|verify|observe",
    "next_probe_hint": "一句可引導下一步探測的提示",
    "generated_at": "ISO8601 毫秒時間"
  }},
  "intelligence_signals": {{
    "attack_vector": "{attack_vector}",
    "likely_automation": true,
    "confidence": 0.0
  }}
}}

規則：
1. 不要輸出 Markdown 或說明文字。
2. 不得包含真實個資。
3. 欄位型別必須正確。
""".strip()


def _fallback_payload(*, user_id: str, attack_vector: str, reason: str) -> dict:
    now = datetime.now(timezone.utc)
    created_date = (now - timedelta(days=random.randint(180, 1200))).date().isoformat()
    last_login_date = (now - timedelta(days=random.randint(0, 10))).date().isoformat()
    balance = random.randint(1000, 50000)
    capability = "account_summary"
    return {
        "user_id": user_id,
        "name": random.choice(FALLBACK_NAMES),
        "email": f"user.{user_id.lower()}@example.com",
        "balance": balance,
        "status": "Normal",
        "account_created": created_date,
        "last_login": last_login_date,
        "banking_api_context": _default_banking_context(user_id, balance, capability),
        "deception_turn": {
            "phase": "review_queue",
            "objective": "observe",
            "next_probe_hint": "請重新提交裝置校驗資訊以完成對帳流程。",
            "generated_at": _now_iso_ms(),
        },
        "intelligence_signals": {
            "attack_vector": attack_vector,
            "likely_automation": True,
            "confidence": 0.42,
            "fallback_reason": reason,
        },
    }


def _coerce_payload(data: dict, *, user_id: str, attack_vector: str) -> dict:
    payload = dict(data)
    payload["user_id"] = user_id
    payload["name"] = _normalize_name(payload.get("name"))
    payload["email"] = str(
        payload.get("email") or f"user.{user_id.lower()}@example.com"
    )
    payload["balance"] = _normalize_balance(payload.get("balance"))
    payload["status"] = converter.convert(str(payload.get("status") or "Normal"))

    account_created = str(payload.get("account_created") or "")
    last_login = str(payload.get("last_login") or "")
    if len(account_created) != 10:
        account_created = datetime.now(timezone.utc)
        account_created = (account_created - timedelta(days=365)).date().isoformat()
    if len(last_login) != 10:
        last_login = datetime.now(timezone.utc).date().isoformat()
    payload["account_created"] = account_created
    payload["last_login"] = last_login

    banking_ctx = (
        payload.get("banking_api_context")
        if isinstance(payload.get("banking_api_context"), dict)
        else {}
    )
    capability = str(banking_ctx.get("capability") or "account_summary").strip().lower()
    if capability not in ALLOWED_CAPABILITIES:
        capability = "account_summary"
    default_ctx = _default_banking_context(user_id, payload["balance"], capability)
    normalized_banking_ctx = dict(default_ctx)
    primary_account_id = (
        banking_ctx.get("primary_account_id") or default_ctx["primary_account_id"]
    )
    normalized_banking_ctx["primary_account_id"] = str(primary_account_id)
    normalized_banking_ctx["currency"] = str(banking_ctx.get("currency") or "TWD")
    if capability == "account_summary":
        normalized_banking_ctx["available_balance"] = _normalize_balance(
            banking_ctx.get("available_balance", payload["balance"])
        )
        normalized_banking_ctx["account_status"] = str(
            banking_ctx.get("account_status") or payload["status"]
        )
    payload["banking_api_context"] = normalized_banking_ctx

    turn = (
        payload.get("deception_turn")
        if isinstance(payload.get("deception_turn"), dict)
        else {}
    )
    payload["deception_turn"] = {
        "phase": str(turn.get("phase") or "ledger_reconcile"),
        "objective": str(turn.get("objective") or "lure"),
        "next_probe_hint": str(
            turn.get("next_probe_hint") or "請補充最近一次交易摘要以完成核對。"
        ),
        "generated_at": str(turn.get("generated_at") or _now_iso_ms()),
    }

    signals = (
        payload.get("intelligence_signals")
        if isinstance(payload.get("intelligence_signals"), dict)
        else {}
    )
    try:
        confidence = float(signals.get("confidence", 0.5))
    except (TypeError, ValueError):
        confidence = 0.5
    payload["intelligence_signals"] = {
        "attack_vector": str(signals.get("attack_vector") or attack_vector),
        "likely_automation": bool(signals.get("likely_automation", True)),
        "confidence": max(0.0, min(1.0, confidence)),
    }
    return payload


def generate_fake_data_llama(
    query_id: str,
    attack_vector: str = "unknown",
    session_context: dict | None = None,
) -> dict:
    """Generate deception payload for suspicious traffic.

    保持向後相容：既有呼叫只傳 query_id / attack_vector 仍可運作。
    """
    safe_user_id = _sanitize_query_id(query_id)
    prompt = _build_prompt(
        user_id=safe_user_id,
        attack_vector=attack_vector,
        session_context=session_context,
    )

    try:
        with httpx.Client(timeout=12.0) as client:
            response = client.post(
                OLLAMA_URL,
                json={
                    "model": OLLAMA_MODEL,
                    "prompt": prompt,
                    "format": "json",
                    "stream": False,
                    "options": {"temperature": 0.55},
                },
            )
            response.raise_for_status()

        raw_content = response.json().get("response", "")
        json_block = _extract_json_block(raw_content)
        generated = json.loads(json_block)
        normalized = _coerce_payload(
            generated,
            user_id=safe_user_id,
            attack_vector=attack_vector,
        )
        logger.info(
            "[Ollama] deception payload generated user_id=%s phase=%s",
            safe_user_id,
            normalized["deception_turn"]["phase"],
        )
        return normalized
    except Exception as exc:
        logger.warning("[Ollama] generation failed, fallback used: %s", exc)
        return _fallback_payload(
            user_id=safe_user_id,
            attack_vector=attack_vector,
            reason=type(exc).__name__,
        )
