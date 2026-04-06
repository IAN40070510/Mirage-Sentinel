"""
Mirage 欺敵資料生成層
負責生成虛假但真實感的回應資料，用於對攻擊者進行欺敵
使用 Groq AI 進行智能欺敵，而非虛假資料庫
"""

import json
import logging
import httpx
import opencc
import random
import uuid
from core.deception_db import get_memory, save_deception_state
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

# Groq API 配置
GROQ_API_KEY = "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"
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"


def generate_fake_data(
    query_id: str,
    language: str = "zh_TW",
    client_ip: str = "127.0.0.1",
    attack_vector: str = "unknown",
) -> dict:
    """
    使用 AI 欺敵系統生成虛假用戶資料

    Args:
        query_id: 查詢識別碼（通常為 user_id）
        language: 語言設置（'zh_TW' 或 'en_US'）
        client_ip: 攻擊者 IP（用於欺敵記憶）
        attack_vector: 攻擊類型

    Returns:
        包含 AI 生成的虛假用戶資料的字典
    """
    # [步驟 1] 比對欺敵記憶
    existing_mem = get_memory(client_ip, query_id)
    if existing_mem and existing_mem.get("payload"):
        logger.info(
            f"[欺敵記憶命中] IP:{client_ip} 曾存取過 ID:{query_id}，回傳舊資料。"
        )
        return existing_mem["payload"]

    # [步驟 2] 生成新欺敵資料
    final_payload_dict = None

    system_prompt = f"""
    你是一個網路安全欺敵系統。駭客正在進行攻擊。
    攻擊類型：{attack_vector}。
    請生成一筆「虛假用戶資料」，嚴格遵守 JSON 格式：
    {{
      "user_id": "{query_id}",
      "name": "隨機台灣人姓名，必須是繁體中文三個字，例如：吳力慶、李美華、張志豪",
      "email": "隨機Email",
      "balance": 隨機整數,
      "status": "Normal",
      "account_created": "日期",
      "last_login": "日期"
    }}
    注意：
    1. 只回傳 JSON，不准有任何解釋文字。
    2. name 欄位必須是繁體中文三個字的台灣人姓名，絕對不能用簡體中文。
    3. 姓氏必須是台灣常見姓氏，例如：陳、林、黃、張、李、王、吳、劉、蔡、楊。
    4. 姓名不用生僻字
    """

    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json",
    }
    data = {
        "model": "llama-3.1-8b-instant",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"為 user_id={query_id} 生成虛假資料"},
        ],
        "temperature": 0.7,
        "response_format": {"type": "json_object"},
    }

    try:
        # 嘗試呼叫 Groq AI
        with httpx.Client(timeout=10.0) as client:
            response = client.post(GROQ_URL, headers=headers, json=data)
            response.raise_for_status()

        ai_content = response.json()["choices"][0]["message"]["content"].strip()
        final_payload_dict = json.loads(ai_content)

        # 簡體轉繁體
        converter = opencc.OpenCC("s2twp")
        for key in ["name", "status"]:
            if key in final_payload_dict:
                final_payload_dict[key] = converter.convert(
                    str(final_payload_dict[key])
                )

        logger.info(f"[AI 欺敵] 成功生成誘餌資料：user_id={query_id}")

    except Exception as e:
        logger.error(f"[AI 故障] 無法生成欺敵資料: {e}，使用備援方案")
        # [步驟 3] 備援機制 - 硬 fallback
        final_payload_dict = {
            "user_id": str(query_id),
            "name": "系統預設用戶",
            "email": f"user.{query_id}@example.com",
            "balance": 5000,
            "status": "Active",
            "account_created": "2024-01-01",
            "last_login": "2026-04-02",
        }

    # [步驟 4] 存放欺敵記憶
    try:
        save_deception_state(
            client_ip=client_ip,
            query_id=query_id,
            vector=attack_vector,
            risk=75,
            payload=final_payload_dict,
        )
    except Exception as e:
        logger.warning(f"[欺敵記憶] 無法存入記憶: {e}")

    return final_payload_dict


def generate_fake_transaction(user_id: str, count: int = 1) -> list:
    """
    生成虛假交易記錄（備援資料）

    Args:
        user_id: 用戶 ID
        count: 交易筆數

    Returns:
        虛假交易列表
    """
    import random
    from datetime import datetime, timedelta

    transactions = []

    for _ in range(count):
        tx = {
            "transaction_id": f"TXN-{random.randint(100000, 999999)}",
            "user_id": user_id,
            "amount": random.randint(10, 50000),
            "type": random.choice(["transfer", "deposit", "withdrawal", "payment"]),
            "status": random.choice(["success", "pending", "completed"]),
            "timestamp": (
                datetime.now() - timedelta(days=random.randint(0, 30))
            ).isoformat(),
            "description": f"Transaction for user {user_id}",
        }
        transactions.append(tx)

    return transactions


def generate_fake_logs(user_id: str, count: int = 5) -> list:
    """
    生成虛假帳號活動日誌（備援資料）

    Args:
        user_id: 用戶 ID
        count: 日誌筆數

    Returns:
        虛假日誌列表
    """
    import random
    from datetime import datetime, timedelta

    logs = []

    action_types = [
        "login_success",
        "login_failed",
        "profile_update",
        "password_change",
        "api_access",
        "file_download",
        "permission_granted",
        "logout",
    ]

    for _ in range(count):
        log = {
            "log_id": f"LOG-{random.randint(100000, 999999)}",
            "user_id": user_id,
            "action": random.choice(action_types),
            "ip_address": f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "timestamp": (
                datetime.now() - timedelta(days=random.randint(0, 7))
            ).isoformat(),
            "status": random.choice(["success", "failure", "blocked"]),
        }
        logs.append(log)

    return logs


def _iso_ms_utc() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _build_login_stage_payload(
    *,
    flow_id: str,
    stage: str,
    reason: str,
    user_ref: str,
    challenge_hint: str,
) -> dict:
    issued_at = _iso_ms_utc()
    expires_at = (
        (datetime.now(timezone.utc) + timedelta(minutes=5))
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )
    return {
        "status": "challenge",
        "route": "deception_auth",
        "auth_flow_id": flow_id,
        "user_ref": user_ref,
        "stage": stage,
        "challenge_hint": challenge_hint,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "notice": f"(欺敵登入流程: {reason})",
    }


def start_deceptive_login_flow(
    *,
    client_ip: str,
    user_ref: str,
    reason: str,
) -> dict:
    """Start a multi-step fake login journey and persist state in mirage memory."""
    flow_id = f"AUTH-{uuid.uuid4().hex[:12].upper()}"
    otp = f"{random.randint(100000, 999999)}"
    question_bank = [
        "請輸入最近一次收款人暱稱前兩字",
        "請輸入預留手機末三碼",
        "請輸入最近一次轉帳備註前四字",
    ]
    challenge = _build_login_stage_payload(
        flow_id=flow_id,
        stage="credential_challenge",
        reason=reason,
        user_ref=user_ref,
        challenge_hint="請提交密碼與裝置指紋以完成第一階段驗證",
    )
    challenge["next_action"] = "POST /api/v1/banking/auth/login/{flow_id}/verify"

    state_payload = {
        "auth_flow_id": flow_id,
        "state_version": 1,
        "current_stage": "credential_challenge",
        "expected_otp": otp,
        "security_question": random.choice(question_bank),
        "attempts": 0,
        "last_challenge": challenge,
    }

    save_deception_state(
        client_ip=client_ip,
        query_id=f"auth:{flow_id}",
        vector="deceptive_login",
        risk=72,
        payload=state_payload,
    )
    return challenge


def advance_deceptive_login_flow(
    *,
    client_ip: str,
    flow_id: str,
    user_ref: str,
    reason: str,
    password: str | None,
    otp: str | None,
    security_answer: str | None,
) -> dict:
    """Advance fake login flow by one stage while preserving conversation consistency."""
    memory = get_memory(client_ip, f"auth:{flow_id}")
    if not memory or not isinstance(memory.get("payload"), dict):
        return _build_login_stage_payload(
            flow_id=flow_id,
            stage="expired",
            reason=reason,
            user_ref=user_ref,
            challenge_hint="流程逾時，請重新發起登入",
        )

    state = dict(memory["payload"])
    current_stage = state.get("current_stage", "credential_challenge")
    attempts = int(state.get("attempts", 0)) + 1
    state["attempts"] = attempts

    if current_stage == "credential_challenge":
        if not password:
            challenge = _build_login_stage_payload(
                flow_id=flow_id,
                stage="credential_challenge",
                reason=reason,
                user_ref=user_ref,
                challenge_hint="缺少密碼欄位，請重送 password",
            )
        else:
            challenge = _build_login_stage_payload(
                flow_id=flow_id,
                stage="otp_challenge",
                reason=reason,
                user_ref=user_ref,
                challenge_hint="請輸入 6 碼 OTP 驗證碼",
            )
            challenge["otp_delivery"] = "已發送至預留裝置"
            challenge["masked_contact"] = "09******87"
            state["current_stage"] = "otp_challenge"

    elif current_stage == "otp_challenge":
        if not otp:
            challenge = _build_login_stage_payload(
                flow_id=flow_id,
                stage="otp_challenge",
                reason=reason,
                user_ref=user_ref,
                challenge_hint="缺少 otp，請補送 6 碼驗證碼",
            )
        else:
            challenge = _build_login_stage_payload(
                flow_id=flow_id,
                stage="security_question",
                reason=reason,
                user_ref=user_ref,
                challenge_hint=state.get("security_question", "請回答安全問題"),
            )
            state["current_stage"] = "security_question"

    elif current_stage == "security_question":
        if not security_answer:
            challenge = _build_login_stage_payload(
                flow_id=flow_id,
                stage="security_question",
                reason=reason,
                user_ref=user_ref,
                challenge_hint=state.get("security_question", "請回答安全問題"),
            )
        else:
            challenge = _build_login_stage_payload(
                flow_id=flow_id,
                stage="manual_review",
                reason=reason,
                user_ref=user_ref,
                challenge_hint="驗證已提交，正在進行人工覆核",
            )
            challenge["status"] = "queued_review"
            challenge["review_eta_sec"] = 90
            state["current_stage"] = "manual_review"
    else:
        challenge = _build_login_stage_payload(
            flow_id=flow_id,
            stage="manual_review",
            reason=reason,
            user_ref=user_ref,
            challenge_hint="案件仍在覆核佇列，請稍後查詢",
        )
        challenge["status"] = "queued_review"
        challenge["review_eta_sec"] = 120

    state["last_challenge"] = challenge
    save_deception_state(
        client_ip=client_ip,
        query_id=f"auth:{flow_id}",
        vector="deceptive_login",
        risk=74,
        payload=state,
    )
    return challenge


if __name__ == "__main__":
    # 簡單測試
    print("=== Fake User Data ===")
    user_data = generate_fake_data("1001")
    print(json.dumps(user_data, ensure_ascii=False, indent=2))

    print("\n=== Fake Transactions ===")
    txs = generate_fake_transaction("1001", count=3)
    print(json.dumps(txs, ensure_ascii=False, indent=2))

    print("\n=== Fake Logs ===")
    logs = generate_fake_logs("1001", count=3)
    print(json.dumps(logs, ensure_ascii=False, indent=2))
