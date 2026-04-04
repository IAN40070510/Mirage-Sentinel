"""
Mirage 欺敵資料生成層
負責生成虛假但真實感的回應資料，用於對攻擊者進行欺敵
使用 Groq AI 進行智能欺敵，而非虛假資料庫
"""

import json
import logging
import httpx
from core.deception_db import get_memory, save_deception_state

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
      "name": "隨機中文姓名",
      "email": "隨機Email",
      "balance": 隨機整數,
      "status": "Normal",
      "account_created": "日期",
      "last_login": "日期"
    }}
    注意：只回傳 JSON，不准有任何解釋文字。
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
