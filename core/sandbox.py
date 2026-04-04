import logging
import httpx
import asyncio
import os

from core.mirage import generate_fake_data

logger = logging.getLogger(__name__)


def _is_strict_isolation_mode() -> bool:
    """
    SANDBOX_ISOLATION_LEVEL:
      - 1 (default): 本機開發模式，sandbox 失敗可 fallback 本機欺敵
      - 2: 嚴格模式（建議雲端），sandbox 失敗不使用本機 fallback
    """
    return os.getenv("SANDBOX_ISOLATION_LEVEL", "1").strip() in {
        "2",
        "strict",
        "STRICT",
    }


def _strict_unavailable_payload(query_id: str, reason: str) -> dict:
    # 嚴格模式下，避免本機回退造成「未經沙盒隔離」的誤導
    return {
        "user_id": str(query_id),
        "status": "sandbox_unavailable",
        "message": "Attack was quarantined because isolated sandbox is unavailable",
        "reason": reason,
    }


async def run_attack_in_sandbox(
    request_payload: dict, timeout_seconds: int = 12, max_retries: int = 3
) -> dict:
    """將惡意請求導向隔離 Docker container 處理，並回傳生成的假資料。

    目前實作為：
      1) 透過 HTTP 調用 sandbox service (FastAPI 中介) 來解析請求、記錄行為、模擬回應。
      2) 若 sandbox service 不可用，使用指數退避重試機制。
      3) 若所有重試都失敗，降級為本機 fake data。

    Args:
        request_payload: 攻擊請求資料
        timeout_seconds: 每次請求的超時時間（秒）
        max_retries: 最大重試次數
    """
    client_ip = request_payload.get("client_ip", "unknown")
    query_id = request_payload.get("query_id", "unknown")
    strict_isolation = _is_strict_isolation_mode()

    configured_sandbox_url = os.getenv("SANDBOX_API_URL", "").strip()
    sandbox_api_url = configured_sandbox_url or "http://sandbox:8001/simulate_attack"

    if strict_isolation and not configured_sandbox_url:
        logger.error("[SANDBOX STRICT] SANDBOX_API_URL 未設定，拒絕本機 fallback。")
        return _strict_unavailable_payload(query_id, "missing_sandbox_api_url")

    # 在非嚴格模式下，若未提供 SANDBOX_API_URL，直接使用本機假資料。
    if (not strict_isolation) and "SANDBOX_API_URL" not in os.environ:
        fake_data = generate_fake_data(query_id)
        logger.info("[SANDBOX] SANDBOX_API_URL 未設定，直接使用本機假資料。")
        return fake_data

    # 帶有指數退避的重試邏輯
    for attempt in range(max_retries):
        try:
            logger.debug(
                f"[SANDBOX] Attempt {attempt + 1}/{max_retries} for {client_ip}"
            )

            async with httpx.AsyncClient(timeout=timeout_seconds) as client:
                response = await client.post(
                    sandbox_api_url,
                    json={
                        "client_ip": client_ip,
                        "query_id": query_id,
                        "raw_payload": request_payload.get("raw_payload", ""),
                        "attack_vector": request_payload.get("attack_vector"),
                        "risk_level": request_payload.get("risk_level", 0),
                    },
                )
                if response.status_code == 200:
                    result = response.json()
                    logger.info(
                        f"[SANDBOX HTTP] Success on attempt {attempt + 1}: {result.get('sandbox_log')}"
                    )
                    return result.get("fake_data", generate_fake_data(query_id))
                else:
                    logger.warning(
                        f"[SANDBOX HTTP] Failed: {response.status_code} {response.text}"
                    )

        except Exception as e:
            logger.warning(f"[SANDBOX HTTP] Attempt {attempt + 1} failed: {str(e)}")

        # 指數退避：等待 2^attempt 秒（1秒、2秒、4秒）
        if attempt < max_retries - 1:
            wait_time = 2**attempt
            logger.debug(f"[SANDBOX] Waiting {wait_time}s before retry...")
            await asyncio.sleep(wait_time)

    if strict_isolation:
        logger.error(
            "[SANDBOX STRICT] Sandbox 連線失敗且為嚴格模式，不執行本機 fallback。"
        )
        return _strict_unavailable_payload(query_id, "sandbox_unreachable")

    # Fallback: 本機生成假資料（僅開發模式）
    fake_data = generate_fake_data(query_id)
    logger.info(
        f"[SANDBOX FALLBACK] Generated fake data for {query_id} after {max_retries} failed attempts"
    )
    return fake_data
