# core/ai_generation.py
import httpx
import json
import logging
from core.mirage import generate_fake_data
from core.deception_db import get_memory, save_deception_state

# --- 配置區 ---
GROQ_API_KEY = "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"
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

logger = logging.getLogger(__name__)

async def get_raw_ai_fake_data(attack_vector: str, payload: str, client_ip: str, query_id: str):
    """
    高階欺敵引擎邏輯：
    1. 比對記憶：若有舊資料，直接回傳，確保一致性。
    2. AI 生成：若無紀錄，呼叫 Llama 3.1 產出。
    3. 失敗備援：AI 故障時，改用本地 generate_fake_data。
    4. 存入記憶：將新產出的資料寫入資料庫。
    """
    # [步驟 1] 比對記憶 (Memory Lookup)
    existing_mem = get_memory(client_ip, query_id)
    if existing_mem and existing_mem.get("payload"):
        logger.info(f"[記憶命中] IP:{client_ip} 曾存取過 ID:{query_id}，回傳舊資料。")
        return json.dumps(existing_mem["payload"], ensure_ascii=False)

    # [步驟 2] 無記憶，準備生成新資料
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
      "status": "Normal"
    }}
    注意：只回傳 JSON，不准有任何解釋文字。
    """
    
    headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
    data = {
        "model": "llama-3.1-8b-instant",
        "messages": [{"role": "system", "content": system_prompt}, {"role": "user", "content": payload}],
        "temperature": 0.7,
        "response_format": {"type": "json_object"}
    }

    async with httpx.AsyncClient() as client:
        try:
            # 嘗試呼叫 Groq AI
            response = await client.post(GROQ_URL, headers=headers, json=data, timeout=10.0)
            response.raise_for_status()
            
            ai_content = response.json()['choices'][0]['message']['content'].strip()
            final_payload_dict = json.loads(ai_content)
            logger.info(f"[AI 生成] 成功產出誘餌：{final_payload_dict.get('name')}")

        except Exception as e:
            logger.error(f"[AI 故障] 進入備援流程: {e}")
            # [步驟 3] 備援機制 (Fallback)
            final_payload_dict = generate_fake_data(query_id)

    # [步驟 4] 存放記憶 (Save State)
    # 將新產出的資料 (AI 或 Fallback) 存入 mirage_memory.db
    save_deception_state(
        client_ip=client_ip,
        query_id=query_id,
        vector=attack_vector,
        risk=75, # 預設測試風險值
        payload=final_payload_dict
    )
    
    return json.dumps(final_payload_dict, ensure_ascii=False)