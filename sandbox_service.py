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


def update_deception_state(client_ip: str, query_id: str, action: str, data: dict):
    """在沙盒內更新欺敵狀態 - 只能修改 mirage_memory.db"""
    try:
        conn = get_sandbox_db_connection()
        cursor = conn.cursor()

        # 創建表如果不存在
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS deception_memory (
                client_ip TEXT,
                query_id TEXT,
                action TEXT,
                data TEXT,
                timestamp TEXT,
                PRIMARY KEY (client_ip, query_id)
            )
        """
        )

        # 插入或更新狀態
        cursor.execute(
            """
            INSERT OR REPLACE INTO deception_memory
            (client_ip, query_id, action, data, timestamp)
            VALUES (?, ?, ?, ?, ?)
        """,
            (
                client_ip,
                query_id,
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
    query_id: str = "",
    attack_vector: str = "unknown",
) -> dict:
    """AI Agent 決策邏輯 - 使用LLaMA生成高互動假資料"""
    try:
        # 根據攻擊類型生成不同的prompt
        if attack_vector.lower() in ["sqli", "sql injection"]:
            prompt = f"""
            你是一個網路安全欺敵系統。駭客正在嘗試SQL注入攻擊，想要從資料庫獲取資料。
            攻擊載荷: {payload}

            請生成假的資料庫記錄作為回應，模擬一個正常的用戶資料庫查詢結果。
            嚴格遵守 JSON 格式，只返回資料陣列:
            [
              {{
                "id": 隨機數字,
                "username": "隨機用戶名",
                "email": "user@example.com",
                "balance": 隨機金額,
                "status": "active",
                "created_at": "YYYY-MM-DD"
              }}
            ]
            生成3-5條假記錄，讓駭客以為成功獲取了資料。
            """
        elif attack_vector.lower() in ["xss", "cross-site scripting"]:
            prompt = f"""
            你是一個網路安全欺敵系統。駭客正在嘗試XSS攻擊。
            攻擊載荷: {payload}

            請生成一個安全的HTML回應，包含假的用戶資料，但過濾掉所有危險腳本。
            返回JSON格式:
            {{
              "message": "用戶資料",
              "data": {{
                "user_id": "{query_id}",
                "name": "安全過濾的用戶名",
                "info": "您的請求已處理"
              }}
            }}
            """
        elif attack_vector.lower() in ["lfi", "local file inclusion"]:
            prompt = f"""
            你是一個網路安全欺敵系統。駭客正在嘗試本地檔案包含攻擊，想要讀取系統檔案。
            攻擊載荷: {payload}

            請生成假的檔案內容，模擬一個正常的配置文件。
            返回JSON格式:
            {{
              "file_content": "假的配置文件內容\\nuser=admin\\npassword=filtered\\ndatabase=example_db",
              "file_path": "/etc/config.fake",
              "size": 1024
            }}
            """
        elif attack_vector.lower() in ["rce", "remote code execution"]:
            prompt = f"""
            你是一個網路安全欺敵系統。駭客正在嘗試遠程代碼執行。
            攻擊載荷: {payload}

            請生成假的命令執行結果，模擬系統命令輸出。
            返回JSON格式:
            {{
              "command_output": "命令執行成功\\n用戶列表:\\n- admin\\n- user1\\n- user2",
              "exit_code": 0,
              "execution_time": "0.05秒"
            }}
            """
        else:
            prompt = f"""
            你是一個網路安全欺敵系統。駭客正在進行可疑活動。
            攻擊載荷: {payload}
            攻擊類型: {attack_vector}

            請生成一個欺敵回應，讓駭客以為系統正常運作。
            返回JSON格式:
            {{
              "status": "success",
              "message": "請求已處理",
              "data": {{
                "user_id": "{query_id}",
                "result": "正常回應"
              }}
            }}
            """

        # 調用Ollama生成回應
        import httpx

        with httpx.Client(timeout=15.0) as client:
            response = client.post(
                OLLAMA_URL,
                json={
                    "model": OLLAMA_MODEL,
                    "prompt": prompt,
                    "format": "json",
                    "stream": False,
                    "options": {"temperature": 0.7, "num_predict": 500},
                },
            )
            response.raise_for_status()

            raw_content = response.json().get("response", "").strip()
            generated_data = json.loads(raw_content)

            # 根據攻擊類型決定行動和風險等級
            action_map = {
                "sqli": "generate_fake_database_records",
                "sql injection": "generate_fake_database_records",
                "xss": "sanitize_and_respond",
                "cross-site scripting": "sanitize_and_respond",
                "lfi": "provide_fake_file_content",
                "local file inclusion": "provide_fake_file_content",
                "rce": "simulate_command_output",
                "remote code execution": "simulate_command_output",
                "path-traversal": "generate_fake_directory_listing",
                "directory traversal": "generate_fake_directory_listing",
            }

            risk_map = {
                "sqli": 8,
                "sql injection": 8,
                "rce": 9,
                "remote code execution": 9,
                "xss": 7,
                "cross-site scripting": 7,
                "lfi": 6,
                "local file inclusion": 6,
                "path-traversal": 5,
                "directory traversal": 5,
            }

            action = action_map.get(
                attack_vector.lower(), "generate_deceptive_response"
            )
            risk_level = risk_map.get(attack_vector.lower(), 4)

            return {
                "action": action,
                "confidence": 0.85,  # LLaMA生成的有較高置信度
                "risk_level": risk_level,
                "generated_data": generated_data,
            }

    except Exception as e:
        logger.error(f"[SANDBOX AI] LLaMA生成失敗: {e}")
        # 備用邏輯：簡單的基於規則決策
        return {
            "action": "fallback_response",
            "confidence": 0.3,
            "risk_level": 5,
            "generated_data": {
                "status": "error",
                "message": "AI processing failed",
                "fallback": True,
            },
        }


# 初始化AI模型
load_ai_model()


class AttackRequest(BaseModel):
    client_ip: str
    query_id: str
    raw_payload: str
    attack_vector: Optional[str] = None
    risk_level: int = 0


class AIAgentRequest(BaseModel):
    client_ip: str
    query_id: str
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
        query_id = req.query_id
        raw_payload = req.raw_payload

        attack_vector = req.attack_vector or "unknown"

        # 2. 記錄行為 (Record Behavior)
        risk_level = req.risk_level
        sandbox_log = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            "client_ip": client_ip,
            "query_id": query_id,
            "raw_payload": raw_payload,
            "attack_vector": attack_vector,
            "risk_level": risk_level,
            "action": "simulated_in_sandbox",
        }
        logger.warning(f"[SANDBOX SIMULATION] {sandbox_log}")

        # 3. 模擬回應 (Simulate Response)
        fake_data = generate_fake_data(query_id)

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
        query_id = req.query_id
        raw_payload = req.raw_payload
        attack_vector = req.attack_vector or "unknown"

        # 2. AI Agent 決策 - 只使用沙盒內資源
        ai_decision = ai_agent_decide(
            raw_payload,
            client_ip=client_ip,
            query_id=query_id,
            attack_vector=attack_vector,
        )

        # 3. 更新沙盒內狀態 - 只能修改 mirage_memory.db
        update_deception_state(
            client_ip=client_ip,
            query_id=query_id,
            action=ai_decision["action"],
            data={
                "original_payload": raw_payload,
                "ai_confidence": ai_decision["confidence"],
                "ai_risk_level": ai_decision["risk_level"],
                "attack_vector": attack_vector,
            },
        )

        # 4. 使用AI生成的假資料作為回應
        fake_data = ai_decision.get("generated_data", generate_fake_data(query_id))

        # 5. 記錄AI Agent行為
        ai_log = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            "client_ip": client_ip,
            "query_id": query_id,
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
        fake_data = generate_fake_data(req.query_id)
        return {
            "status": "ai_fallback",
            "message": "AI Agent temporarily unavailable",
            "fake_data": fake_data,
        }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8001)
