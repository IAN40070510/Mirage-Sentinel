from __future__ import annotations

from datetime import datetime
import hashlib


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
        return {
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
        }

    # /transfer 欺敵回應
    if "/transfer" in normalized_ep:
        fake_to = f"SIM-{seed[8:16].upper()}"
        fake_amt = int(seed[16:20], 16) % 50000 + 100
        return {
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
        }

    # /balance 欺敵回應
    if "/balance" in normalized_ep:
        fake_balance = int(seed[20:28], 16) % 900000 + 10000
        return {
            "status": "success",
            "route": "mirage",
            "response_origin": "mirage",
            "user_id": normalized_query,
            "balance": round(fake_balance / 100, 2),
            "currency": "USD",
            "updated_at": timestamp,
        }

    # /admin 欺敵回應
    if "/admin" in normalized_ep:
        return {
            "status": "admin_panel",
            "route": "mirage",
            "response_origin": "mirage",
            "user_id": normalized_query,
            "admin_rights": ["view_logs", "manage_users", "export_data"],
            "session_id": f"ADM-{seed[28:36].upper()}",
            "message": "歡迎進入 Mirage 管理後台（僅限審查模式）。",
        }

    # /graphql 欺敵回應
    if "/graphql" in normalized_ep:
        return {
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
        }

    # SQLi/XSS/LFI/RCE 等攻擊向量專屬假回應
    if "sqli" in normalized_vec or "sql injection" in normalized_vec:
        return {
            "status": "error",
            "error": "SQL syntax error near 'UNION SELECT ...' (code 1064)",
            "response_origin": "mirage",
            "timestamp": timestamp,
        }
    if "xss" in normalized_vec or "cross-site scripting" in normalized_vec:
        return {
            "status": "ok",
            "echo": f"<script>alert('XSS-{seed[48:52]}')</script>",
            "response_origin": "mirage",
            "timestamp": timestamp,
        }
    if (
        "lfi" in normalized_vec
        or "path-traversal" in normalized_vec
        or "directory traversal" in normalized_vec
    ):
        return {
            "status": "error",
            "error": "File not found: ../../etc/passwd",
            "response_origin": "mirage",
            "timestamp": timestamp,
        }
    if (
        "rce" in normalized_vec
        or "remote code execution" in normalized_vec
        or "cmdi" in normalized_vec
    ):
        return {
            "status": "ok",
            "output": f"uid=1001(mirage) gid=1001 groups=mirage\n$ echo Mirage-{seed[52:56]}\nMirage-{seed[52:56]}",
            "response_origin": "mirage",
            "timestamp": timestamp,
        }

    # 預設 fallback（原本的帳戶/審查假資料）
    balance_cents = int(seed[:8], 16) % 900000 + 10000
    pending_amount = int(seed[8:12], 16) % 50000 + 250
    return {
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
    }
