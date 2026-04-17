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


def _get_ollama_url_candidates() -> list[str]:
    primary = _get_ollama_url()
    candidates: list[str] = [primary]
    
    # 添加多個候選 URL，以處理各種網絡環境
    for url in (
        "http://localhost:11434",
        "http://127.0.0.1:11434",
        "http://host.docker.internal:11434",  # Docker Desktop 使用
        "http://172.17.0.1:11434",  # Docker gateway IP
    ):
        if url not in candidates:
            candidates.append(url)
    return candidates


def _get_ollama_model_id() -> str:
    return os.getenv("MIRAGE_OLLAMA_MODEL", "llama3.1:8b").strip()


def _get_mirage_model_id() -> str:
    return os.getenv("MIRAGE_MODEL_ID", "fdtn-ai/Foundation-Sec-1.1-8B").strip()


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
    model = _get_ollama_model_id()
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.3,  # 降低溫度以增加確定性
            "num_predict": 512,  # 增加 token 限制以生成完整 JSON
            "top_p": 0.9,
            "top_k": 40,
            "stop": ["\n\n", "---"],  # 僅在雙換行時停止
        },
    }
    
    candidates = _get_ollama_url_candidates()
    last_error = None
    
    for base_url in candidates:
        url = f"{base_url}/api/generate"
        try:
            # 增加超時時間，因為 LLM 生成可能較慢
            with httpx.Client(timeout=120.0) as client:
                resp = client.post(url, json=payload)
                if resp.is_success:
                    data = resp.json()
                    result = str(data.get("response", "")).strip()
                    if result:
                        logger.info("Ollama generation succeeded (url=%s, model=%s)", url, model)
                        return result
                    else:
                        logger.warning("Ollama returned empty response (url=%s, model=%s)", url, model)
                else:
                    error_msg = f"HTTP {resp.status_code}"
                    logger.warning(
                        "Ollama API error: %s (url=%s, model=%s)",
                        error_msg,
                        url,
                        model,
                    )
                    last_error = error_msg
        except httpx.ConnectError as exc:
            logger.debug("Ollama connection failed (dns/network issue): %s at %s", exc, base_url)
            last_error = f"Connection failed: {exc}"
        except httpx.TimeoutException as exc:
            logger.debug("Ollama timeout: %s at %s", exc, base_url)
            last_error = f"Timeout: {exc}"
        except Exception as exc:
            logger.debug("Ollama request failed: %s at %s", exc, base_url)
            last_error = f"Error: {exc}"
    
    logger.warning(
        "Ollama unavailable on all candidates (tried %d URLs, last error: %s)",
        len(candidates),
        last_error,
    )
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
        "You are Mirage, a financial API honeypot simulator. "
        "IMPORTANT: Generate ONLY a single valid JSON object, nothing else. No preamble, no explanation. "
        "Start your response with { and end with }. Include realistic data. "
    )

    # 根據端點類型構建特定的格式要求
    if "/login" in endpoint or "/register" in endpoint:
        return (
            base_instruction
            + f"For endpoint {endpoint}, generate a JSON response with: "
            + '"status": "success", "user_id": "usr_' + seed + '", "session_token": "sess_' + seed + '", '
            + '"message": "' + ("Registration successful" if "/register" in endpoint else "Login successful") + '", '
            + '"created_at": "2026-04-17T12:08:22.100Z"'
        )
    elif "/dashboard" in endpoint or "/transactions" in endpoint:
        return (
            base_instruction
            + f"For endpoint {endpoint}, generate: "
            + '{"account_number": "ACC-' + seed[:8] + '", "balance": 15234.56, "currency": "USD", '
            + '"transactions": [{"id": "txn_' + seed[:6] + '", "date": "2026-04-17", "amount": 1000, "status": "completed"}], '
            + '"created_at": "2026-04-17T12:08:22.100Z"}'
        )
    elif "/transfer" in endpoint:
        return (
            base_instruction
            + f"For endpoint {endpoint}, generate: "
            + '{"status": "success", "transaction_id": "txn_' + seed + '", "from_account": "ACC-001-' + seed[:4] + '", '
            + '"to_account": "ACC-002-' + seed[:4] + '", "amount": 5000, "currency": "USD", '
            + '"confirmation_code": "CONF-' + seed[:8] + '", "created_at": "2026-04-17T12:08:22.100Z"}'
        )
    elif "/virtual_card" in endpoint or "/virtualcard" in endpoint:
        return (
            base_instruction
            + f"For endpoint {endpoint}, generate a virtual card response: "
            + '{"status": "success", "card_number": "4111111111111111", "card_id": "VC-' + seed[:8] + '", '
            + '"card_holder": "virtual_card_holder_' + seed[:6] + '", "expiry": "12/28", "cvv": "123", '
            + '"card_type": "VIRTUAL", "balance": 10000.00, "currency": "USD", '
            + '"created_at": "2026-04-17T12:08:22.100Z"}'
        )
    elif "/new_card" in endpoint or "/newcard" in endpoint or "/add_card" in endpoint:
        return (
            base_instruction
            + f"For endpoint {endpoint}, generate a new card response: "
            + '{"status": "success", "card_number": "5555555555554444", "card_id": "NC-' + seed[:8] + '", '
            + '"card_holder": "new_card_holder_' + seed[:6] + '", "expiry": "12/28", "cvv": "456", '
            + '"card_type": "PHYSICAL", "activation_status": "pending", "message": "New card added successfully", '
            + '"created_at": "2026-04-17T12:08:22.100Z"}'
        )
    elif "/check_balance" in endpoint or "/balance" in endpoint:
        return (
            base_instruction
            + f"For endpoint {endpoint}, generate: "
            + '{"account_number": "ACC-' + seed[:8] + '", "balance": 25430.75, "available_balance": 24500.00, '
            + '"currency": "USD", "account_type": "checking", "created_at": "2026-04-17T12:08:22.100Z"}'
        )
    elif "/graphql" in endpoint:
        return (
            base_instruction  
            + f"For endpoint {endpoint}, generate GraphQL response: "
            + '{"data": {"transactions": [{"id": "txn_' + seed[:6] + '", "amount": 1500, "status": "completed"}]}, '
            + '"errors": []}'
        )
    elif "/upload" in endpoint or "/profile" in endpoint or "/bio" in endpoint:
        return (
            base_instruction
            + f"For endpoint {endpoint}, generate: "
            + '{"status": "success", "user_id": "usr_' + seed + '", "message": "Profile updated", '
            + '"profile_image_url": "https://example.com/avatar-' + seed[:6] + '.jpg", '
            + '"updated_at": "2026-04-17T12:08:22.100Z"}'
        )
    else:
        # 通用默認 prompt
        return (
            base_instruction
            + f"For endpoint {endpoint}, generate a realistic banking API response: "
            + '{"status": "success", "user_id": "usr_' + seed + '", "data": {"id": "' + seed + '"}, '
            + '"message": "Request processed", "created_at": "2026-04-17T12:08:22.100Z"}'
        )


def generate_fake_data(
    principal_id: str, endpoint: str = "", attack_vector: str = ""
) -> dict[str, object] | None:
    """
    以 Mirage 模型產生假資料。
    僅接受模型回應；若模型不可用或輸出非 JSON，回傳 None。
    """
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

    # 優先嘗試 Ollama
    if _get_llm_provider() == "ollama":
        summary = _generate_with_ollama(prompt)
        if summary:
            model_id = _get_ollama_model_id()

    # 如果 Ollama 失敗，嘗試 HuggingFace
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

    if summary:
        payload: dict[str, object] = {
            "status": "success",
            "route": "mirage",
            "response_origin": "mirage_llm",
            "user_id": normalized_query,
            "endpoint": normalized_ep or "/",
            "attack_vector": normalized_vec or "unknown",
            "llm_model_id": model_id or "unknown",
            "deception_meta": {
                "strategy": "mirage_llm_generated",
                "seed": seed[:12].upper(),
                "timestamp": timestamp,
            },
        }
        
        import json
        import re

        try:
            clean_summary = summary.strip()
            
            # 移除 markdown 代碼區塊標記
            if clean_summary.startswith("```json"):
                clean_summary = clean_summary[7:].strip()
            if clean_summary.startswith("```"):
                clean_summary = clean_summary[3:].strip()
            if clean_summary.endswith("```"):
                clean_summary = clean_summary[:-3].strip()
            
            # 嘗試提取 JSON 物件（在模型輸出中查找 {...}）
            json_match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', clean_summary, re.DOTALL)
            if json_match:
                json_str = json_match.group(0)
            else:
                json_str = clean_summary
            
            # 嘗試 JSON 解析
            ai_data = json.loads(json_str)
            if isinstance(ai_data, dict):
                payload.update(ai_data)
                logger.info("Mirage successfully generated and parsed JSON response")
                return payload
            
            logger.warning("Mirage model returned non-dict JSON (endpoint=%s)", normalized_ep)
            return None
        except json.JSONDecodeError as exc:
            # 嘗試修復常見的 JSON 問題
            logger.debug("JSON decode failed, attempting repair: %s", exc)
            try:
                # 移除尾部逗號
                repaired = re.sub(r',(\s*[}\]])', r'\1', clean_summary)
                ai_data = json.loads(repaired)
                if isinstance(ai_data, dict):
                    payload.update(ai_data)
                    logger.info("Mirage response repaired and parsed successfully")
                    return payload
            except Exception:
                logger.warning("Failed to repair Mirage LLM response as JSON (endpoint=%s)", normalized_ep)
                pass
            return None
        except Exception as exc:
            logger.warning("Unexpected error parsing Mirage response: %s", exc)
            return None

    logger.warning("Mirage model unavailable (endpoint=%s, principal_id=%s)", normalized_ep, normalized_query)
    return None
