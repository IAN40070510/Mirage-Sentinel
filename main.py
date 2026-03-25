from fastapi import FastAPI, Request, Query, BackgroundTasks, Security, HTTPException
import uvicorn
import time
import os
from datetime import datetime
from contextlib import asynccontextmanager
from fastapi.security import APIKeyHeader
from dotenv import load_dotenv

# 核心模組匯入
from core.sentinel import analyze_intent
from core.deception_db import setup_deception_db, get_memory, save_deception_state
from core.deception_metrics import compute_interaction_metrics
from core.traffic_db import setup_traffic_db, log_traffic_event
from core.sandbox import run_attack_in_sandbox

# 前端API匯入
from api import dashboard

# 載入環境變數
load_dotenv()

# 定義 API 金鑰
API_KEY = os.getenv("API_KEY", "").strip()
DEFAULT_DEV_API_KEY = "dev-local-api-key-change-me"
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

def verify_api_key(api_key: str = Security(api_key_header)):
    if api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Unauthorized access")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """啟動時初始化雙軌資料庫，開啟全時監控"""
    global API_KEY
    if not API_KEY:
        API_KEY = DEFAULT_DEV_API_KEY
        print("[WARN] API_KEY 未設定，使用開發預設值。正式環境請務必設定 API_KEY。")
    setup_deception_db()
    setup_traffic_db()
    print("[SYSTEM] Mirage-Sentinel 全時哨兵監控模式已啟動。")
    yield

app = FastAPI(
    title="Mirage-Sentinel API Gateway", 
    version="1.6-FullSentinel", 
    lifespan=lifespan
)

# 掛載前端專用的 API 路徑
app.include_router(
    dashboard.router,
    prefix="/api/v1", 
    tags=["Dashboard"],
    dependencies=[Security(verify_api_key)]
)

@app.get("/api/v1/user/{user_id}")
async def get_user_data(
    user_id: str,
    payload: str = Query(None, description="指令測試區"),
    request: Request = None,
    background_tasks: BackgroundTasks = None,
):
    if request is None:
        raise HTTPException(status_code=400, detail="Request context is required")

    start_perf = time.perf_counter()
    request_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]  # 一進入口立即捕捉（毫秒）
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "Unknown")

    # 組合偵測目標
    current_payload = payload if payload else ""
    detection_target = f"{user_id} {current_payload}".strip()

    # --- [核心邏輯：全量哨兵審核] ---
    is_attack, confidence, attack_vector = analyze_intent(detection_target)
    print(f"[DEBUG] 請求：{detection_target} | 信心度：{confidence} | 命中：{attack_vector}")

    should_intercept = is_attack and confidence > 0.75

    process_ms = None
    response_at = None
    event_payload = {
        "request_at": request_at,
        "client_ip": client_ip,
        "location": "Cloud/Render",
        "is_proxy": 0,
        "user_agent": user_agent,
        "tls_fingerprint": "N/A",
        "raw_payload": detection_target,
        "query_id": user_id,
        "attack_vector": attack_vector if is_attack else None,
        "risk_level": int(confidence * 100) if is_attack else 0,
        "is_attack": 1 if should_intercept else 0,
    }

    if should_intercept:
        risk_score = int(confidence * 100)
        mem = get_memory(client_ip, user_id)

        metrics = compute_interaction_metrics(
            client_ip=client_ip,
            query_id=user_id,
            current_payload=detection_target,
            has_memory_hit=bool(mem),
        )

        dwell_time = float(metrics["dwell_seconds"])
        interaction_depth = int(metrics["depth_score"])
        hits = 1
        if mem:
            hits = mem["hits"] + 1
            fake_data = mem["payload"]
        else:
            fake_data = None

        process_ms = int((time.perf_counter() - start_perf) * 1000)
        response_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        # 只有第一次命中才導向沙盒；已有記憶則沿用同一份假資料
        if fake_data is None:
            fake_data = await run_attack_in_sandbox({
                **event_payload,
                "response_at": response_at,
                "process_ms": process_ms,
                "hits": hits,
                "interaction_depth": interaction_depth,
                "dwell_time": dwell_time,
            })


        event_payload.update({
            "response_at": response_at,
            "process_ms": process_ms,
            "response_payload": fake_data,
            "hits": hits,
            "interaction_depth": interaction_depth,
            "dwell_time": dwell_time,
            "mitigation_status": "Sandboxed",
            "risk_level": risk_score,
        })

        if background_tasks:
            background_tasks.add_task(log_traffic_event, event_payload)
        else:
            log_traffic_event(event_payload)

        save_deception_state(client_ip, user_id, attack_vector, risk_score, fake_data)
        print(
            f"[ALERT] 哨兵攔截：{attack_vector} (信心: {confidence}) | "
            f"深度分數: {interaction_depth} | 漏斗層級: {metrics['funnel_level']} | 隔離: Docker沙盒"
        )
        return fake_data

    else:
        process_ms = int((time.perf_counter() - start_perf) * 1000)
        response_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        event_payload.update({
            "response_at": response_at,
            "process_ms": process_ms,
            "response_payload": None,
            "hits": 0,
            "interaction_depth": 0,
            "dwell_time": 0.0,
            "mitigation_status": "normal",
            "risk_level": 0,
        })

        if background_tasks:
            background_tasks.add_task(log_traffic_event, event_payload)
        else:
            log_traffic_event(event_payload)

        return {"user_id": user_id, "name": "真實用戶", "status": "Normal"}

# 攻擊模擬端點
@app.post("/api/v1/simulate_attack", summary="模擬攻擊請求")
async def simulate_attack(
    user_id: str = Query(..., description="用戶 ID"),
    payload: str = Query("", description="""模擬的攻擊指令（選填，留空為正常請求）
    
常見攻擊模板：
  • SQL 注入: ' OR '1'='1 / DROP TABLE users / UNION SELECT * FROM admin
  • LFI: ../../../../etc/passwd / ../../config.php / /etc/shadow
  • XSS: <script>alert('xss')</script> / javascript:alert(1)
  • RCE: ; ls -la / $(whoami) / `id`
  • 目錄遍歷: ../../../ / ..\\..\\..\\
    """),
    client_ip: str = Query("192.168.0.1", description="攻擊者 IP（可選）"),
    background_tasks: BackgroundTasks = None
):
    """模擬攻擊請求，測試系統的攻擊檢測與沙盒隔離功能
    
可自定義攻擊者 IP 測試欺騙記憶庫追踪：
- 同 IP + 同 user_id → 返回相同的假資料
- 不同 IP + 同 user_id → 返回不同的假資料
- 不傳 payload 或留空 → 測試正常請求流程
    """
    start_perf = time.perf_counter()
    request_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    user_agent = "Simulated-Attack-Client"

    detection_target = f"{user_id} {payload}".strip()

    # 偵測攻擊意圖
    is_attack, confidence, attack_vector = analyze_intent(detection_target)
    should_intercept = is_attack and confidence > 0.75

    event_payload = {
        "request_at": request_at,
        "client_ip": client_ip,
        "location": "Simulated",
        "is_proxy": 0,
        "user_agent": user_agent,
        "tls_fingerprint": "N/A",
        "raw_payload": detection_target,
        "query_id": user_id,
        "attack_vector": attack_vector if is_attack else None,
        "risk_level": int(confidence * 100) if is_attack else 0,
        "is_attack": 1 if should_intercept else 0,
    }

    if should_intercept:
        risk_score = int(confidence * 100)
        mem = get_memory(client_ip, user_id)

        metrics = compute_interaction_metrics(
            client_ip=client_ip,
            query_id=user_id,
            current_payload=detection_target,
            has_memory_hit=bool(mem),
        )

        # 計算欺敵互動深度（四維度）與點擊次數
        dwell_time = float(metrics["dwell_seconds"])
        interaction_depth = int(metrics["depth_score"])
        hits = 1
        if mem:
            hits = mem["hits"] + 1
            fake_data = mem["payload"]
        else:
            fake_data = await run_attack_in_sandbox(event_payload)

        process_ms = int((time.perf_counter() - start_perf) * 1000)
        response_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        event_payload.update({
            "response_at": response_at,
            "process_ms": process_ms,
            "response_payload": fake_data,
            "mitigation_status": "Sandboxed",
            "hits": hits,
            "interaction_depth": interaction_depth,
            "dwell_time": dwell_time,
            "risk_level": risk_score,
        })

        if background_tasks:
            background_tasks.add_task(log_traffic_event, event_payload)
        else:
            log_traffic_event(event_payload)

        # 保存欺騙狀態到記憶庫
        save_deception_state(client_ip, user_id, attack_vector, risk_score, fake_data)
        latest_memory = get_memory(client_ip, user_id)

        return {
            "status": "attack_detected",
            "fake_data": fake_data,
            "event_log": event_payload,
            "mirage_memory": latest_memory,
            "deception_memory": {
                "dwell_time": dwell_time,
                "interaction_depth": interaction_depth,
                "hits": hits,
                "funnel_level": metrics["funnel_level"],
                "endpoint_coverage": metrics["endpoint_coverage"],
                "payload_evolution_score": metrics["payload_evolution_score"],
            },
        }

    return {
        "status": "normal_request",
        "message": "未檢測到攻擊行為",
        "event_log": event_payload
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
    
    # 私人開發環境使用 localhost
    # uvicorn.run("main:app", host="127.0.0.1", port=8000)