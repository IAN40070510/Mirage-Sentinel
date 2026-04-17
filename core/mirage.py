from __future__ import annotations

import hashlib
import logging
import os
import httpx
from datetime import datetime
from typing import Any


logger = logging.getLogger(__name__)

_MIRAGE_TEXT_GENERATOR: Any | None = None
_MIRAGE_MODEL_ID: str = ""


def _should_use_llm() -> bool:
    """判斷是否啟用 LLM (HuggingFace 或是 Ollama)。"""
    return (
        os.getenv("MIRAGE_USE_LLM", "false").strip().lower()
        in {
            "1",
            "true",
            "yes",
            "on",
        }
        or _should_use_hf_mirage()
    )


def _should_use_hf_mirage() -> bool:
    return os.getenv("MIRAGE_USE_HF_MODEL", "false").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _get_llm_provider() -> str:
    return os.getenv("MIRAGE_LLM_PROVIDER", "ollama").strip().lower()


def _get_ollama_url() -> str:
    return os.getenv("MIRAGE_OLLAMA_URL", "http://ollama:11434").strip().rstrip("/")


def _get_ollama_model_id() -> str:
    return os.getenv("MIRAGE_OLLAMA_MODEL", "foundation-sec:8b-q4").strip()


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
        from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline  # type: ignore[import-not-found]
        import torch  # type: ignore[import-not-found]

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


def _generate_with_ollama(prompt: str) -> str | None:
    """使用 Ollama API 生成文本。"""
    url = f"{_get_ollama_url()}/api/generate"
    model = _get_ollama_model_id()
    try:
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.1,
                "num_predict": 96,
                "stop": ["\n", "User:", "Assistant:"],
            },
        }
        with httpx.Client(timeout=60.0) as client:
            resp = client.post(url, json=payload)
            if resp.is_success:
                data = resp.json()
                return str(data.get("response", "")).strip()
            else:
                logger.warning(
                    "Ollama API error: %s (url=%s, model=%s)",
                    resp.status_code,
                    url,
                    model,
                )
    except Exception as exc:
        logger.warning("Ollama connection failed: %s", exc)
    return None


def _maybe_attach_llm_summary(
    payload: dict[str, object],
    principal_id: str,
    endpoint: str,
    attack_vector: str,
) -> dict[str, object]:
    if not _should_use_llm():
        return payload

    normalized_endpoint = (endpoint or "").lower()
    # 針對特定路徑或是攻擊行為才執行 LLM 摘要
    if not attack_vector and not any(
        token in normalized_endpoint
        for token in ("/transfer", "/graphql", "/admin", "/payment", "/bill")
    ):
        return payload

    prompt = (
        "You are Mirage, an AI honeypot simulating a vulnerable and poorly-configured financial API. "
        "Your goal is to keep the attacker engaged by returning a highly realistic JSON response. "
        f"Inputs: endpoint={endpoint!r}, attack_vector={attack_vector!r}. "
        "Rule 1: If the inputs suggest an 'admin', 'root', or system-level attack, generate a response leaking fake administrative data (e.g., auth_tokens, system configs, user lists, or debug paths). "
        "Rule 2: If the inputs suggest a standard user attack, leak fake financial data (balances, transactions). "
        "Rule 3: Output ONLY the raw JSON. Do not explain, do not mention AI or honeypots.\n"
        "Example (Admin Authentication Bypass):\n"
        '{"status": "success", "role": "SUPER_ADMIN", "session_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6Ikp...", "dashboard_url": "/admin/v2/metrics", "system_warning": "Debug mode is ON"}'
    )

    summary = None
    model_id = None

    # 優先嘗試 Ollama
    if _get_llm_provider() == "ollama":
        summary = _generate_with_ollama(prompt)
        if summary:
            model_id = _get_ollama_model_id()

    # 如果 Ollama 失敗或未過、且允許 HF，則嘗試舊版本地載入 (若資源允許)
    if not summary and _should_use_hf_mirage():
        generator = _load_mirage_text_generator()
        if generator is not None:
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
                    model_id = _MIRAGE_MODEL_ID or _get_mirage_model_id()
            except Exception as exc:
                logger.warning("Mirage HF generation failed: %s", exc)

    if summary:
        payload["llm_model_id"] = model_id or "unknown"

        # 嘗試解析 LLM 返回的內容是否為 JSON
        import json

        try:
            # 移除可能存在的 Markdown 代碼塊標記
            clean_summary = summary.strip()
            if clean_summary.startswith("```json"):
                clean_summary = clean_summary[7:].strip()
            if clean_summary.endswith("```"):
                clean_summary = clean_summary[:-3].strip()

            ai_data = json.loads(clean_summary)
            if isinstance(ai_data, dict):
                # 如果是有效的 dict，則合併到 payload 中 (覆蓋重複鍵以 LLM 為準)
                payload.update(ai_data)
                payload["response_origin"] = "mirage_llm"
        except Exception:
            # 解析失敗則維持原樣作為 summary
            payload["llm_summary"] = summary[:1000]

    return payload


def _build_endpoint_specific_prompt(
    endpoint: str, principal_id: str, attack_vector: str, seed: str
) -> str:
    """根據不同的 API 端點構建特定的 LLM prompt，確保回應與該端點的實際格式匹配。"""
    endpoint = (endpoint or "").lower().strip()
    attack_vector = (attack_vector or "").lower().strip()

    base_instruction = (
        "You are Mirage, a pure AI deception engine for a financial API honeypot. "
        "Generate only raw JSON and do not mention AI, LLMs, or honeypots. Keep attackers engaged. "
    )

    # 根據端點類型構建特定的格式要求
    if "/login" in endpoint or "/register" in endpoint:
        return (
            base_instruction
            + f"Endpoint: {endpoint}. Principal: {principal_id}. Attack vector: {attack_vector}. "
            + "Generate a believable authentication response (JSON). "
            + "Include: status (success/error/mfa_required), message, session_token (if successful), mfa_methods (if MFA), user_id, created_at. "
            + "For SQL injection: return plausible user record rows as if query succeeded. "
            + "For XSS: return sanitized user data with filtered content. "
            + "Output: single valid JSON object."
        )
    elif "/dashboard" in endpoint or "/transactions" in endpoint:
        return (
            base_instruction
            + f"Endpoint: {endpoint}. Principal: {principal_id}. "
            + "Generate a realistic financial dashboard/transaction history response (JSON). "
            + "Include: account_number, balance, currency, transactions (array with id, date, amount, recipient, status), account_type, created_at. "
            + "For SQL injection: return plausible transaction records as if database query succeeded. "
            + "For XSS: return HTML-escaped transaction data safely. "
            + "Output: single valid JSON object with transaction list."
        )
    elif "/transfer" in endpoint:
        return (
            base_instruction
            + f"Endpoint: {endpoint}. Principal: {principal_id}. "
            + "Generate a realistic transfer confirmation response (JSON). "
            + "Include: status (success/pending/failed), transaction_id, from_account, to_account, amount, currency, fee, total, timestamp, confirmation_code. "
            + "For SQL injection: return fake transfer record as if database insert succeeded. "
            + "For XSS: return confirmation data with safe HTML escaping. "
            + "Output: single valid JSON object with transaction details."
        )
    elif "/check_balance" in endpoint or "/balance" in endpoint:
        return (
            base_instruction
            + f"Endpoint: {endpoint}. Principal: {principal_id}. "
            + "Generate a realistic balance check response (JSON). "
            + "Include: account_number, account_holder, balance, available_balance, currency, last_update, account_status. "
            + "For SQL injection: return fake account record as if query succeeded. "
            + "For XSS: return balance data with safe formatting. "
            + "Output: single valid JSON object with account balance info."
        )
    elif "/graphql" in endpoint:
        return (
            base_instruction
            + f"Endpoint: {endpoint}. Principal: {principal_id}. "
            + "Generate a GraphQL response (JSON) to a financial query. "
            + "Include: data (with transactions array or account info), errors (if any), extensions. "
            + "For SQL injection: return fake transaction data as if GraphQL resolver succeeded. "
            + "For XSS: return safe GraphQL JSON response. "
            + "Output: single valid JSON object in GraphQL response format (data/errors structure)."
        )
    elif "/upload" in endpoint or "/profile" in endpoint or "/bio" in endpoint:
        return (
            base_instruction
            + f"Endpoint: {endpoint}. Principal: {principal_id}. "
            + "Generate a profile update response (JSON). "
            + "Include: status (success/error), message, user_id, profile_image_url, bio, updated_at. "
            + "For file upload attacks (LFI/path-traversal): return fake file metadata as if upload succeeded. "
            + "For XSS: return safe profile data with HTML escaping. "
            + "Output: single valid JSON object with profile update status."
        )
    elif "/internal" in endpoint or "/secret" in endpoint or "/config" in endpoint:
        return (
            base_instruction
            + f"Endpoint: {endpoint}. Principal: {principal_id}. Attack vector: {attack_vector}. "
            + "Generate a plausible internal API response (JSON) that appears to reveal internal data. "
            + "For security exploration: return fake configuration/secret data to keep attacker engaged (database host, mock credentials, etc.). "
            + "Include: version, environment, database_host (fake), api_keys (fake/redacted), feature_flags. "
            + "Do not reveal this is a honeypot. "
            + "Output: single valid JSON object."
        )
    else:
        # 通用默認 prompt
        return (
            base_instruction
            + f"Endpoint: {endpoint}. Principal: {principal_id}. Attack vector: {attack_vector}. "
            + "Generate a realistic API response (JSON) suitable for a financial system endpoint. "
            + "Include: status, message, user_id, data (relevant to endpoint), timestamp. "
            + "For SQL injection: return plausible data records as if database query succeeded. "
            + "For XSS: return safe JSON with HTML-escaped content. "
            + "For LFI/RCE: return realistic file/system output. "
            + "Output: single valid JSON object."
        )


def generate_fake_data(
    principal_id: str, endpoint: str = "", attack_vector: str = ""
) -> dict[str, object]:
    """以純 AI 方式產生 Mirage 假資料，讓 LLM 根據具體 API 端點生成符合格式的回應。"""
    normalized_query = str(principal_id or "unknown")
    normalized_ep = (endpoint or "").lower()
    normalized_vec = (attack_vector or "").lower()
    seed = hashlib.sha256(
        f"{normalized_query}|{normalized_ep}|{normalized_vec}".encode("utf-8")
    ).hexdigest()
    timestamp = datetime.now().isoformat(timespec="milliseconds")

    # 根據特定端點構建 prompt
    prompt = _build_endpoint_specific_prompt(
        endpoint=normalized_ep,
        principal_id=normalized_query,
        attack_vector=normalized_vec,
        seed=seed[:12]
    )

    summary = None
    model_id = None

    if _get_llm_provider() == "ollama":
        summary = _generate_with_ollama(prompt)
        if summary:
            model_id = _get_ollama_model_id()

    if not summary and _should_use_hf_mirage():
        generator = _load_mirage_text_generator()
        if generator is not None:
            try:
                outputs = generator(
                    prompt,
                    max_new_tokens=128,
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
                    model_id = _MIRAGE_MODEL_ID or _get_mirage_model_id()
            except Exception as exc:
                logger.warning("Mirage HF generation failed: %s", exc)

    payload: dict[str, object] = {
        "status": "ai_generated",
        "route": "mirage",
        "response_origin": "mirage_ai",
        "user_id": normalized_query,
        "endpoint": normalized_ep or "/",
        "attack_vector": normalized_vec or "unknown",
        "deception_meta": {
            "strategy": "pure_ai_response",
            "seed": seed[:12].upper(),
            "queued_at": timestamp,
        },
    }

    if summary:
        payload["llm_model_id"] = model_id or "unknown"
        import json

        try:
            clean_summary = summary.strip()
            if clean_summary.startswith("```json"):
                clean_summary = clean_summary[7:].strip()
            if clean_summary.endswith("```"):
                clean_summary = clean_summary[:-3].strip()

            ai_data = json.loads(clean_summary)
            if isinstance(ai_data, dict):
                payload.update(ai_data)
                payload["response_origin"] = "mirage_ai"
            else:
                payload["llm_summary"] = summary[:1000]
        except Exception:
            payload["llm_summary"] = summary[:1000]
    else:
        payload["response_origin"] = "mirage_ai_unavailable"
        payload["message"] = "Mirage AI model unavailable"

    return payload
