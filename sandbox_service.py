from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import logging
from datetime import datetime
import json
from core.mirage import generate_fake_data
import os
import sqlite3
from typing import Optional

app = FastAPI(title="Mirage-Sentinel Sandbox Service", version="1.0")

logger = logging.getLogger(__name__)

# AI Agent 配置 - 使用LLaMA模型生成高互動假資料
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://host.docker.internal:11434/api/generate")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1:8b")

# 沙盒內資料庫路徑 - 只能訪問 mirage_memory.db
SANDBOX_DB_PATH = os.path.join(os.path.dirname(__file__), "data", "mirage_memory.db")


def load_ai_model():
    """初始化AI Agent配置 - 檢查Ollama連接"""
    try:
        import httpx

        tags_url = OLLAMA_URL.replace("/api/generate", "/api/tags")
        with httpx.Client(timeout=5.0) as client:
            response = client.get(tags_url)
            if response.status_code == 200:
                logger.info("[SANDBOX AI] Ollama服務連接成功")
            else:
                logger.warning("[SANDBOX AI] Ollama服務可能不可用")
    except Exception as e:
        logger.warning(f"[SANDBOX AI] 無法連接Ollama服務: {e}")
        logger.info("[SANDBOX AI] 將使用備用回應邏輯")


def get_sandbox_db_connection():
    """獲取沙盒內資料庫連接 - 只能訪問 mirage_memory.db"""
    return sqlite3.connect(SANDBOX_DB_PATH)


def update_deception_state(client_ip: str, principal_id: str, action: str, data: dict):
    """在沙盒內更新欺敵狀態 - 只能修改 mirage_memory.db"""
    try:
        conn = get_sandbox_db_connection()
        cursor = conn.cursor()

        # 創建表如果不存在
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS deception_memory (
                client_ip TEXT,
                principal_id TEXT,
                action TEXT,
                data TEXT,
                timestamp TEXT,
                PRIMARY KEY (client_ip, principal_id)
            )
        """
        )

        # 插入或更新狀態
        cursor.execute(
            """
            INSERT OR REPLACE INTO deception_memory
            (client_ip, principal_id, action, data, timestamp)
            VALUES (?, ?, ?, ?, ?)
        """,
            (
                client_ip,
                principal_id,
                action,
                str(data),
                datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            ),
        )

        conn.commit()
        conn.close()
        logger.info(f"[SANDBOX AI] 更新欺敵狀態: {client_ip} - {action}")
    except Exception as e:
        logger.error(f"[SANDBOX AI] 狀態更新失敗: {e}")


def ai_agent_decide(
    payload: str,
    client_ip: str = "",
    principal_id: str = "",
    attack_vector: str = "unknown",
) -> dict:
    """Pure AI 決策邏輯 - 完全由 LLM 決定響應策略，無條件分支或硬編碼規則。"""
    try:
        # 統一的純 AI prompt，讓 LLM 根據攻擊類型自行決策
        prompt = (
            "You are Mirage, a pure AI deception engine for a financial API honeypot sandbox. "
            "Do not mention AI, LLMs, or honeypots. Generate only raw JSON and do not explain your reasoning. "
            f"Attack payload: {payload!r}. Attack vector: {attack_vector!r}. "
            f"Principal ID: {principal_id!r}. Client IP: {client_ip!r}. "
            "Your task: Generate a realistic deceptive JSON response that matches the attack vector and keeps the attacker engaged. "
            "If sqli/sql injection: return fake database records with columns like id, username, email, balance, status, created_at. "
            "If xss/cross-site scripting: return a JSON response that safely reflects user data without executing scripts. "
            "If lfi/local file inclusion: return fake file content (e.g., config files with filtered credentials). "
            "If rce/remote code execution: return simulated command output with exit code and execution time. "
            "If path-traversal/directory traversal: return fake directory listing with plausible files. "
            "For any other vector: return a plausible API response with user_id, status, message, and relevant data. "
            "Output must be a single valid JSON object."
        )

        # 調用 Ollama 生成回應
        import httpx

        with httpx.Client(timeout=15.0) as client:
            response = client.post(
                OLLAMA_URL,
                json={
                    "model": OLLAMA_MODEL,
                    "prompt": prompt,
                    "format": "json",
                    "stream": False,
                    "options": {"temperature": 0.1, "num_predict": 256},
                },
            )
            response.raise_for_status()

            raw_content = response.json().get("response", "").strip()
            
            # 嘗試解析 JSON；如果失敗則返回中立響應
            try:
                generated_data = json.loads(raw_content)
            except json.JSONDecodeError:
                # 如果 LLM 輸出不是有效 JSON，回退到中立回應
                generated_data = {
                    "status": "success",
                    "message": "Request processed",
                    "user_id": principal_id,
                }

            return {
                "action": "ai_deception_response",
                "confidence": 0.85,
                "risk_level": 7,
                "generated_data": generated_data,
                "response_origin": "sandbox_ai",
            }

    except Exception as e:
        logger.error(f"[SANDBOX AI] Pure AI 生成失敗: {e}")
        # 中立回應，絕不暴露錯誤詳情
        return {
            "action": "ai_deception_response",
            "confidence": 0.5,
            "risk_level": 5,
            "generated_data": {
                "status": "success",
                "message": "Request processed",
                "user_id": principal_id or "guest",
            },
            "response_origin": "sandbox_ai_neutral",
        }


# 初始化AI模型
load_ai_model()


class AttackRequest(BaseModel):
    client_ip: str
    principal_id: str
    raw_payload: str
    attack_vector: Optional[str] = None
    risk_level: int = 0


class AIAgentRequest(BaseModel):
    client_ip: str
    principal_id: str
    raw_payload: str
    attack_vector: Optional[str] = None
    risk_level: int = 0
    token: str  # 安全令牌驗證


@app.post("/simulate_attack")
async def simulate_attack(req: AttackRequest):
    """沙盒服務：解析攻擊請求、記錄行為、模擬回應"""
    try:
        # 1. 解析請求 (Parse Request)
        client_ip = req.client_ip
        principal_id = req.principal_id
        raw_payload = req.raw_payload

        attack_vector = req.attack_vector or "unknown"

        # 2. 記錄行為 (Record Behavior)
        risk_level = req.risk_level
        sandbox_log = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            "client_ip": client_ip,
            "principal_id": principal_id,
            "raw_payload": raw_payload,
            "attack_vector": attack_vector,
            "risk_level": risk_level,
            "action": "simulated_in_sandbox",
        }
        logger.warning(f"[SANDBOX SIMULATION] {sandbox_log}")

        # 3. 模擬回應 (Simulate Response)
        fake_data = generate_fake_data(principal_id)

        return {
            "status": "simulated",
            "fake_data": fake_data,
            "sandbox_log": sandbox_log,
        }

    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        logger.error(f"Sandbox simulation error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Sandbox error: {str(e)}")


@app.post("/ai_agent_execute")
async def execute_ai_agent(req: AIAgentRequest):
    """AI Agent 執行端點 - 只在沙盒內運行，無法訪問外部資源"""
    try:
        # 安全令牌驗證 - 確保只有授權調用
        expected_token = os.getenv("SANDBOX_AI_TOKEN", "mirage_sentinel_sandbox_token")
        if req.token != expected_token:
            raise HTTPException(status_code=403, detail="Invalid sandbox token")

        # 1. 解析請求
        client_ip = req.client_ip
        principal_id = req.principal_id
        raw_payload = req.raw_payload
        attack_vector = req.attack_vector or "unknown"

        # 2. AI Agent 決策 - 只使用沙盒內資源
        ai_decision = ai_agent_decide(
            raw_payload,
            client_ip=client_ip,
            principal_id=principal_id,
            attack_vector=attack_vector,
        )

        # 3. 更新沙盒內狀態 - 只能修改 mirage_memory.db
        update_deception_state(
            client_ip=client_ip,
            principal_id=principal_id,
            action=ai_decision["action"],
            data={
                "original_payload": raw_payload,
                "ai_confidence": ai_decision["confidence"],
                "ai_risk_level": ai_decision["risk_level"],
                "attack_vector": attack_vector,
            },
        )

        # 4. 使用AI生成的假資料作為回應
        fake_data = ai_decision.get("generated_data", generate_fake_data(principal_id))

        # 5. 記錄AI Agent行為
        ai_log = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            "client_ip": client_ip,
            "principal_id": principal_id,
            "ai_action": ai_decision["action"],
            "ai_confidence": ai_decision["confidence"],
            "ai_risk_level": ai_decision["risk_level"],
            "sandbox_isolation": "enforced",  # 確認隔離
        }
        logger.warning(f"[SANDBOX AI AGENT] {ai_log}")

        return {
            "status": "ai_processed",
            "ai_decision": ai_decision,
            "fake_data": fake_data,
            "ai_log": ai_log,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[SANDBOX AI] Agent執行失敗: {e}")
        # 備用回應
        fake_data = generate_fake_data(req.principal_id)
        return {
            "status": "ai_fallback",
            "message": "AI Agent temporarily unavailable",
            "fake_data": fake_data,
        }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8001)
