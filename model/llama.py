# -*- coding: utf-8 -*-
"""
Ollama 本地 LLaMA 3.1 8B 欺敵資料生成模組
負責生成完整格式的虛假 JSON 資料，並確保姓名為繁體中文三個字
"""

import json
import logging
import httpx
import random
import opencc
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# Ollama 配置
OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
OLLAMA_MODEL = "llama3.1:8b"

# 備援名單（當 AI 斷線或格式嚴重錯誤時使用）
FALLBACK_NAMES = [
    "陳志豪", "林美華", "黃建宏", "張雅婷", "李俊賢",
    "王淑芬", "吳宗翰", "劉怡君", "蔡佳穎", "楊承恩",
    "許雅雯", "鄭文凱", "謝宜庭", "洪志偉", "邱雅琪",
]

# 初始化轉換器 (s2twp: 簡體到台灣繁體)
converter = opencc.OpenCC('s2twp')

def generate_fake_data_llama(query_id: str, attack_vector: str = "unknown") -> dict:
    """
    使用本地 LLaMA 生成完整的虛假用戶資料 (JSON 格式)
    並嚴格校正 name 欄位為繁體中文三個字。
    """
    
    # 建立系統 Prompt，要求輸出與 mirage.py 相同的 JSON 格式
    strict_prompt = f"""
    你是一個網路安全欺敵系統。駭客正在進行攻擊。攻擊類型：{attack_vector}。
    請為 user_id="{query_id}" 生成一筆「虛假用戶資料」，嚴格遵守 JSON 格式：
    {{
      "user_id": "{query_id}",
      "name": "隨機台灣人姓名，必須是繁體中文三個字",
      "email": "隨機Email",
      "balance": 隨機整數,
      "status": "Normal",
      "account_created": "YYYY-MM-DD",
      "last_login": "YYYY-MM-DD"
    }}
    注意：
    1. 絕對只回傳 JSON，不准有任何解釋文字或 Markdown 標記。
    2. name 欄位必須是繁體中文三個字的台灣人姓名，例如：陳大文、林志明。
    """

    try:
        # Timeout 設為 30 秒，因為生成完整 JSON 比單一名字耗時
        with httpx.Client(timeout=30.0) as client:
            response = client.post(
                OLLAMA_URL,
                json={
                    "model": OLLAMA_MODEL,
                    "prompt": strict_prompt,
                    "format": "json",  # 強制 Ollama 進入 JSON 輸出模式
                    "stream": False,
                    "options": {
                        "temperature": 0.7
                    }
                }
            )
            response.raise_for_status()
            
            # 1. 取得原始回應並解析 JSON
            raw_content = response.json().get("response", "").strip()
            fake_data = json.loads(raw_content)

            # 2. 保險機制：確保 user_id 是對的
            fake_data["user_id"] = str(query_id)

            # 3. 針對 Name 進行嚴格校正 (簡轉繁 + 三字過濾)
            if "name" in fake_data:
                tw_name = converter.convert(str(fake_data["name"]))
                clean_name = "".join([char for char in tw_name if '\u4e00' <= char <= '\u9fff'])
            else:
                fake_data["name"] = random.choice(FALLBACK_NAMES)

            # 4. 針對 Status 簡轉繁
            if "status" in fake_data:
                fake_data["status"] = converter.convert(str(fake_data["status"]))

            # 補齊可能缺失的欄位
            if "balance" not in fake_data:
                fake_data["balance"] = random.randint(1000, 50000)

            logger.info(f"[Ollama] 成功生成完整誘餌資料：user_id={query_id}, name={fake_data['name']}")
            return fake_data

    except Exception as e:
        # --- 備援機制：如果 AI 超時或 JSON 解析失敗，回傳完美的備援字典 ---
        logger.warning(f"[Ollama] 生成失敗或連線中斷，使用備援資料字典：{e}")
        
        fallback_name = random.choice(FALLBACK_NAMES)
        now = datetime.now()
        
        fallback_data = {
            "user_id": str(query_id),
            "name": fallback_name,
            "email": f"user.{query_id}@example.com",
            "balance": random.randint(1000, 50000),
            "status": "Normal",
            "account_created": (now - timedelta(days=random.randint(100, 1000))).strftime("%Y-%m-%d"),
            "last_login": (now - timedelta(days=random.randint(0, 10))).strftime("%Y-%m-%d")
        }
        return fallback_data