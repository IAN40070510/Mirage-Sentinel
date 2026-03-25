from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import logging
from datetime import datetime
from core.mirage import generate_fake_data

app = FastAPI(title="Mirage-Sentinel Sandbox Service", version="1.0")

logger = logging.getLogger(__name__)

class AttackRequest(BaseModel):
    client_ip: str
    query_id: str
    raw_payload: str
    attack_vector: str = None
    risk_level: int = 0

@app.post("/simulate_attack")
async def simulate_attack(req: AttackRequest):
    """沙盒服務：解析攻擊請求、記錄行為、模擬回應"""
    try:
        # 1. 解析請求 (Parse Request)
        client_ip = req.client_ip
        query_id = req.query_id
        raw_payload = req.raw_payload
        attack_vector = req.attack_vector or "unknown"
        risk_level = req.risk_level

        # 2. 記錄行為 (Record Behavior)
        sandbox_log = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            "client_ip": client_ip,
            "query_id": query_id,
            "raw_payload": raw_payload,
            "attack_vector": attack_vector,
            "risk_level": risk_level,
            "action": "simulated_in_sandbox"
        }
        logger.warning(f"[SANDBOX SIMULATION] {sandbox_log}")

        # 3. 模擬回應 (Simulate Response)
        fake_data = generate_fake_data(query_id)

        return {
            "status": "simulated",
            "fake_data": fake_data,
            "sandbox_log": sandbox_log
        }

    except Exception as e:
        if isinstance(e, HTTPException):
            raise e
        logger.error(f"Sandbox simulation error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Sandbox error: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
