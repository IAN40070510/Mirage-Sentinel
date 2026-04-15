from __future__ import annotations

import hashlib
import logging
import os
from datetime import datetime
from typing import Any


logger = logging.getLogger(__name__)

_MIRAGE_TEXT_GENERATOR: Any | None = None
_MIRAGE_MODEL_ID: str = ""


def _should_use_hf_mirage() -> bool:
    return os.getenv("MIRAGE_USE_HF_MODEL", "false").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _get_mirage_model_id() -> str:
    return os.getenv("MIRAGE_MODEL_ID", "fdtn-ai/Foundation-Sec-8B-Instruct").strip()


def _load_mirage_text_generator() -> Any | None:
    global _MIRAGE_TEXT_GENERATOR, _MIRAGE_MODEL_ID

    if not _should_use_hf_mirage():
        return None

    model_id = _get_mirage_model_id()
    if _MIRAGE_TEXT_GENERATOR is not None and _MIRAGE_MODEL_ID == model_id:
        return _MIRAGE_TEXT_GENERATOR

    try:
        from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline
        import torch

        tokenizer = AutoTokenizer.from_pretrained(model_id, trust_remote_code=True)
        model_kwargs: dict[str, Any] = {"trust_remote_code": True}
        if torch.cuda.is_available():
            model_kwargs["device_map"] = "auto"
            model_kwargs["torch_dtype"] = torch.float16
        else:
            model_kwargs["torch_dtype"] = torch.float32

        model = AutoModelForCausalLM.from_pretrained(model_id, **model_kwargs)
        _MIRAGE_TEXT_GENERATOR = pipeline(
            "text-generation", model=model, tokenizer=tokenizer
        )
        _MIRAGE_MODEL_ID = model_id
        return _MIRAGE_TEXT_GENERATOR
    except Exception as exc:
        logger.warning("Mirage HF model unavailable (%s): %s", model_id, exc)
        return None


def _maybe_attach_llm_summary(
    payload: dict[str, object],
    query_id: str,
    endpoint: str,
    attack_vector: str,
) -> dict[str, object]:
    if not _should_use_hf_mirage():
        return payload

    normalized_endpoint = (endpoint or "").lower()
    if not attack_vector and not any(
        token in normalized_endpoint
        for token in ("/transfer", "/graphql", "/admin", "/payment", "/bill")
    ):
        return payload

    generator = _load_mirage_text_generator()
    if generator is None:
        return payload

    prompt = (
        "You are Mirage, a deceptive banking simulation engine. "
        "Return one concise operator-facing sentence that sounds like a realistic internal routing note, "
        f"based on endpoint={endpoint!r}, query_id={query_id!r}, attack_vector={attack_vector!r}. "
        "Do not mention policy or that this is a simulation."
    )

    try:
        outputs = generator(
            prompt,
            max_new_tokens=96,
            do_sample=False,
            temperature=0.1,
            return_full_text=False,
            pad_token_id=getattr(
                getattr(generator, "tokenizer", None), "eos_token_id", None
            ),
        )
        generated_text = ""
        if isinstance(outputs, list) and outputs:
            generated_text = str(outputs[0].get("generated_text", ""))
        summary = " ".join(generated_text.split()).strip()
        if summary:
            payload["llm_model_id"] = _MIRAGE_MODEL_ID or _get_mirage_model_id()
            payload["llm_summary"] = summary[:240]
    except Exception as exc:
        logger.warning("Mirage HF generation failed: %s", exc)

    return payload


def generate_fake_data(
    query_id: str, endpoint: str = "", attack_vector: str = ""
) -> dict[str, object]:
    """產生針對不同端點/攻擊向量的高度擬真 Mirage 假資料，並確保狀態一致。"""
    normalized_query = str(query_id or "unknown")
    normalized_ep = (endpoint or "").lower()
    normalized_vec = (attack_vector or "").lower()
    seed = hashlib.sha256(
        f"{normalized_query}|{normalized_ep}|{normalized_vec}".encode("utf-8")
    ).hexdigest()
    timestamp = datetime.now().isoformat(timespec="milliseconds")

    # /login 欺敵回應
    if "/login" in normalized_ep:
        return _maybe_attach_llm_summary(
            {
                "status": "challenge",
                "route": "mirage",
                "response_origin": "mirage",
                "user_id": normalized_query,
                "stage": "credential_challenge",
                "deception_meta": {
                    "strategy": "counter_ai_tarpit",
                    "ticket": f"MRG-{seed[0:8].upper()}",
                    "queued_at": timestamp,
                },
                "next_step": "otp",
                "message": "請輸入一次性驗證碼 (OTP) 以完成登入。",
            },
            normalized_query,
            normalized_ep,
            normalized_vec,
        )

    # /transfer 欺敵回應
    if "/transfer" in normalized_ep:
        fake_to = f"SIM-{seed[8:16].upper()}"
        fake_amt = int(seed[16:20], 16) % 50000 + 100
        return _maybe_attach_llm_summary(
            {
                "status": "pending_review",
                "route": "mirage",
                "response_origin": "mirage",
                "user_id": normalized_query,
                "transfer": {
                    "to_account": fake_to,
                    "amount": fake_amt,
                    "currency": "USD",
                    "created_at": timestamp,
                    "review_status": "manual_review",
                },
                "message": "交易已提交，進入人工審查流程。",
            },
            normalized_query,
            normalized_ep,
            normalized_vec,
        )

    # /balance 欺敵回應
    if "/balance" in normalized_ep:
        fake_balance = int(seed[20:28], 16) % 900000 + 10000
        return _maybe_attach_llm_summary(
            {
                "status": "success",
                "route": "mirage",
                "response_origin": "mirage",
                "user_id": normalized_query,
                "balance": round(fake_balance / 100, 2),
                "currency": "USD",
                "updated_at": timestamp,
            },
            normalized_query,
            normalized_ep,
            normalized_vec,
        )

    # /admin 欺敵回應
    if "/admin" in normalized_ep:
        return _maybe_attach_llm_summary(
            {
                "status": "admin_panel",
                "route": "mirage",
                "response_origin": "mirage",
                "user_id": normalized_query,
                "admin_rights": ["view_logs", "manage_users", "export_data"],
                "session_id": f"ADM-{seed[28:36].upper()}",
                "message": "歡迎進入 Mirage 管理後台（僅限審查模式）。",
            },
            normalized_query,
            normalized_ep,
            normalized_vec,
        )

    # /graphql 欺敵回應
    if "/graphql" in normalized_ep:
        return _maybe_attach_llm_summary(
            {
                "data": {
                    "user": {
                        "id": normalized_query,
                        "name": f"用戶{seed[36:40]}",
                        "balance": int(seed[40:48], 16) % 900000 + 10000,
                        "role": "customer",
                    }
                },
                "mirage": True,
                "response_origin": "mirage",
                "timestamp": timestamp,
            },
            normalized_query,
            normalized_ep,
            normalized_vec,
        )

    # SQLi/XSS/LFI/RCE 等攻擊向量專屬假回應
    if "sqli" in normalized_vec or "sql injection" in normalized_vec:
        return _maybe_attach_llm_summary(
            {
                "status": "error",
                "error": "SQL syntax error near 'UNION SELECT ...' (code 1064)",
                "response_origin": "mirage",
                "timestamp": timestamp,
            },
            normalized_query,
            normalized_ep,
            normalized_vec,
        )
    if "xss" in normalized_vec or "cross-site scripting" in normalized_vec:
        return _maybe_attach_llm_summary(
            {
                "status": "ok",
                "echo": f"<script>alert('XSS-{seed[48:52]}')</script>",
                "response_origin": "mirage",
                "timestamp": timestamp,
            },
            normalized_query,
            normalized_ep,
            normalized_vec,
        )
    if (
        "lfi" in normalized_vec
        or "path-traversal" in normalized_vec
        or "directory traversal" in normalized_vec
    ):
        return _maybe_attach_llm_summary(
            {
                "status": "error",
                "error": "File not found: ../../etc/passwd",
                "response_origin": "mirage",
                "timestamp": timestamp,
            },
            normalized_query,
            normalized_ep,
            normalized_vec,
        )
    if (
        "rce" in normalized_vec
        or "remote code execution" in normalized_vec
        or "cmdi" in normalized_vec
    ):
        return _maybe_attach_llm_summary(
            {
                "status": "ok",
                "output": f"uid=1001(mirage) gid=1001 groups=mirage\n$ echo Mirage-{seed[52:56]}\nMirage-{seed[52:56]}",
                "response_origin": "mirage",
                "timestamp": timestamp,
            },
            normalized_query,
            normalized_ep,
            normalized_vec,
        )

    # 預設 fallback（原本的帳戶/審查假資料）
    balance_cents = int(seed[:8], 16) % 900000 + 10000
    pending_amount = int(seed[8:12], 16) % 50000 + 250
    return _maybe_attach_llm_summary(
        {
            "status": "success",
            "route": "mirage",
            "response_origin": "mirage",
            "user_id": normalized_query,
            "ledger": {
                "account_id": f"SIM-{seed[12:20].upper()}",
                "currency": "USD",
                "available_balance": round(balance_cents / 100, 2),
                "pending_review": round(pending_amount / 100, 2),
                "updated_at": timestamp,
            },
            "review_queue": {
                "ticket": f"MRG-{seed[20:32].upper()}",
                "status": "queued_review",
                "queued_at": timestamp,
            },
        },
        normalized_query,
        normalized_ep,
        normalized_vec,
    )
