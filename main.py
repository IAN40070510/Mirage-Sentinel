from fastapi import FastAPI, Request, Query
import uvicorn
import time
from datetime import datetime
from contextlib import asynccontextmanager

# 匯入核心偵測與幻象引擎
from core.sentinel import analyze_intent
from core.mirage import generate_fake_data
from core.deception_db import setup_deception_db, get_memory, save_deception_state
from core.traffic_db import setup_traffic_db, log_attack_event

# --- [隊長修正] 定義白名單，防止正常 ID 被誤抓 ---
ALLOWLIST_IDS = ["1001", "1002", "888", "test_user"]

@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_deception_db()
    setup_traffic_db()
    print("[SYSTEM] Mirage-Sentinel 雙核心資料庫啟動成功。")
    yield

app = FastAPI(title="Mirage-Sentinel API Gateway", version="1.4-Stability", lifespan=lifespan)

@app.get("/api/v1/user/{user_id}")
async def get_user_data(
    user_id: str, 
    payload: str = Query(None, description="模擬惡意指令"),
    request: Request = None
):
    start_perf = time.perf_counter()
    request_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "Unknown")
    
    # 組合乾淨的偵測目標
    current_payload = payload if payload else ""
    detection_target = f"{user_id} {current_payload}".strip()

    # --- [關鍵邏輯] 判斷是否應該放行 ---
    is_attack = False
    confidence = 0.0
    attack_vector = "None"

    # 規則 1：如果 user_id 在白名單內，且 payload 是空的，直接判定為正常
    if user_id in ALLOWLIST_IDS and not current_payload:
        is_attack = False
    # 規則 2：如果沒有任何輸入，判定為正常
    elif not detection_target:
        is_attack = False
    # 規則 3：其餘情況才送交 Sentinel 審查
    else:
        is_attack, confidence, attack_vector = analyze_intent(detection_target)

    if is_attack:
        # --- 進入防禦模式 (Mirage Mode) ---
        risk_score = int(confidence * 100)
        mem = get_memory(client_ip, user_id)
        
        dwell_time, interaction_depth, hits = 0.0, 1, 1
        if mem:
            last_seen_dt = datetime.strptime(mem['last_seen'], "%Y-%m-%d %H:%M:%S.%f")
            dwell_time = round((datetime.now() - last_seen_dt).total_seconds(), 2)
            interaction_depth = mem['depth'] + 1
            hits = mem['hits'] + 1
            fake_data = mem['payload']
        else:
            fake_data = generate_fake_data(user_id)

        process_ms = int((time.perf_counter() - start_perf) * 1000)
        response_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        log_data = {
            "request_at": request_at, "response_at": response_at, "process_ms": process_ms,
            "attacker_ip": client_ip, "location": "Local/Render", "is_proxy": 0,
            "user_agent": user_agent, "tls_fingerprint": "N/A", "raw_payload": detection_target,
            "response_payload": str(fake_data), "query_id": user_id, "attack_vector": attack_vector,
            "risk_level": risk_score, "hits": hits, "interaction_depth": interaction_depth,
            "dwell_time": dwell_time, "mitigation_status": "Camouflaged"
        }

        log_attack_event(log_data)
        save_deception_state(client_ip, user_id, attack_vector, risk_score, fake_data)

        print(f"[ALERT] 採證攔截！ 命中：{attack_vector} | 深度：{interaction_depth}")
        return fake_data

    else:
        # --- 進入正常模式 ---
        return {"user_id": user_id, "name": "真實用戶", "status": "Normal"}