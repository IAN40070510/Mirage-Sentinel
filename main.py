from fastapi import FastAPI, Request, Query, BackgroundTasks
import uvicorn
import time
from datetime import datetime
from contextlib import asynccontextmanager

# 核心模組匯入
from core.sentinel import analyze_intent
from core.mirage import generate_fake_data
from core.deception_db import setup_deception_db, get_memory, save_deception_state
from core.traffic_db import setup_traffic_db, log_traffic_event

# 前端API匯入
from api import dashboard

@asynccontextmanager
async def lifespan(app: FastAPI):
    """啟動時初始化雙軌資料庫，開啟全時監控"""
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
app.include_router(dashboard.router, prefix="/api/v1/dashboard", tags=["Dashboard"])

@app.get("/api/v1/user/{user_id}")
async def get_user_data(
    user_id: str,
    payload: str = Query(None, description="惡意指令測試區"),
    request: Request = None,
    background_tasks: BackgroundTasks = None,
):
    start_perf = time.perf_counter()
    request_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")[:-3]  # 一進入口立即捕捉
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
        "attacker_ip": client_ip,
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

        dwell_time, interaction_depth, hits = 0.0, 1, 1
        if mem:
            last_seen_dt = datetime.strptime(mem["last_seen"], "%Y-%m-%d %H:%M:%S")
            dwell_time = round((datetime.now() - last_seen_dt).total_seconds(), 2)
            interaction_depth = mem["depth"] + 1
            hits = mem["hits"] + 1
            fake_data = mem["payload"]
        else:
            fake_data = generate_fake_data(user_id)

        process_ms = int((time.perf_counter() - start_perf) * 1000)
        response_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")[:-3]

        event_payload.update({
            "response_at": response_at,
            "process_ms": process_ms,
            "response_payload": fake_data,
            "hits": hits,
            "interaction_depth": interaction_depth,
            "dwell_time": dwell_time,
            "mitigation_status": "Camouflaged",
            "risk_level": risk_score,
        })

        if background_tasks:
            background_tasks.add_task(log_traffic_event, event_payload)
        else:
            log_traffic_event(event_payload)

        save_deception_state(client_ip, user_id, attack_vector, risk_score, fake_data)
        print(f"[ALERT] 哨兵攔截：{attack_vector} (信心: {confidence}) | 深度: {interaction_depth}")
        return fake_data

    else:
        process_ms = int((time.perf_counter() - start_perf) * 1000)
        response_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")[:-3]

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

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
    
    # 私人開發環境使用 localhost
    # uvicorn.run("main:app", host="127.0.0.1", port=8000)