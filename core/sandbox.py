import logging
import httpx

from core.mirage import generate_fake_data

logger = logging.getLogger(__name__)


async def run_attack_in_sandbox(request_payload: dict, timeout_seconds: int = 12) -> dict:
    """將惡意請求導向隔離 Docker container 處理，並回傳生成的假資料。

    目前實作為：
      1) 透過 HTTP 調用 sandbox service (FastAPI 中介) 來解析請求、記錄行為、模擬回應。
      2) 若 sandbox service 不可用，降級為本機 fake data。
    """
    client_ip = request_payload.get("client_ip", "unknown")
    query_id = request_payload.get("query_id", "unknown")

    # 優先使用 sandbox service 進行隔離模擬
    try:
        async with httpx.AsyncClient(timeout=timeout_seconds) as client:
            response = await client.post(
                "http://sandbox:8001/simulate_attack",
                json={
                    "client_ip": client_ip,
                    "query_id": query_id,
                    "raw_payload": request_payload.get("raw_payload", ""),
                    "attack_vector": request_payload.get("attack_vector"),
                    "risk_level": request_payload.get("risk_level", 0)
                }
            )
            if response.status_code == 200:
                result = response.json()
                logger.info(f"[SANDBOX HTTP] Success: {result.get('sandbox_log')}")
                return result.get("fake_data", generate_fake_data(query_id))
            else:
                logger.warning(f"[SANDBOX HTTP] Failed: {response.status_code} {response.text}")
    except Exception as e:
        logger.warning(f"[SANDBOX HTTP] Unavailable: {str(e)}")

    # Fallback: 本機生成假資料
    fake_data = generate_fake_data(query_id)
    logger.info(f"[SANDBOX FALLBACK] Generated fake data for {query_id}")
    return fake_data

