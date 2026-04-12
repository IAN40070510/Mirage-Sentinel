import logging
import httpx
import asyncio
import os
from typing import Dict, Any
from datetime import datetime

logger = logging.getLogger(__name__)


class AIAgentOrchestrator:
    """協調沙盒內AI Agent的執行，確保隔離性和安全性"""

    def __init__(self):
        self.sandbox_url = os.getenv("SANDBOX_API_URL", "http://sandbox:8001")
        self.ai_token = os.getenv("SANDBOX_AI_TOKEN", "mirage_sentinel_sandbox_token_2024")
        self.timeout = 10  # AI agent執行超時時間

    async def execute_ai_agent(
        self,
        client_ip: str,
        query_id: str,
        raw_payload: str,
        attack_vector: str = None,
        risk_level: int = 0
    ) -> Dict[str, Any]:
        """在沙盒中執行AI Agent，處理攻擊請求並生成回應

        Args:
            client_ip: 客戶端IP
            query_id: 查詢ID
            raw_payload: 原始攻擊載荷
            attack_vector: 攻擊向量
            risk_level: 風險等級

        Returns:
            包含AI決策和假資料的回應
        """
        try:
            logger.debug(f"[AI ORCHESTRATOR] 開始執行AI Agent for {client_ip}")

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.sandbox_url}/ai_agent_execute",
                    json={
                        "client_ip": client_ip,
                        "query_id": query_id,
                        "raw_payload": raw_payload,
                        "attack_vector": attack_vector,
                        "risk_level": risk_level,
                        "token": self.ai_token
                    }
                )

                if response.status_code == 200:
                    result = response.json()
                    logger.info(f"[AI ORCHESTRATOR] AI Agent執行成功: {result.get('ai_decision', {}).get('action')}")
                    return result
                else:
                    logger.warning(f"[AI ORCHESTRATOR] AI Agent執行失敗: {response.status_code} {response.text}")
                    # 返回備用回應
                    return await self._fallback_response(query_id, raw_payload)

        except Exception as e:
            logger.error(f"[AI ORCHESTRATOR] AI Agent調用失敗: {e}")
            return await self._fallback_response(query_id, raw_payload)

    async def _fallback_response(self, query_id: str, raw_payload: str) -> Dict[str, Any]:
        """AI Agent失敗時的備用回應"""
        from core.mirage import generate_fake_data

        fake_data = generate_fake_data(query_id)

        return {
            "status": "ai_fallback",
            "message": "AI Agent unavailable, using fallback response",
            "ai_decision": {
                "action": "fallback_response",
                "confidence": 0.0,
                "risk_level": 5
            },
            "fake_data": fake_data,
            "ai_log": {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                "query_id": query_id,
                "ai_action": "fallback",
                "sandbox_isolation": "maintained"
            }
        }


# 全域實例
ai_orchestrator = AIAgentOrchestrator()


async def execute_sandbox_ai_agent(
    client_ip: str,
    query_id: str,
    raw_payload: str,
    attack_vector: str = None,
    risk_level: int = 0
) -> Dict[str, Any]:
    """便捷函數：執行沙盒AI Agent"""
    return await ai_orchestrator.execute_ai_agent(
        client_ip, query_id, raw_payload, attack_vector, risk_level
    )