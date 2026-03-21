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

@asynccontextmanager
async def lifespan(app: FastAPI):
    """啟動時初始化雙核心資料庫"""
    setup_deception_db()
    setup_traffic_db()
    print("[SYSTEM] Mirage-Sentinel 全時監控模式已啟動。")
    yield

app = FastAPI(title="Mirage-Sentinel API Gateway", version="1.6-FullSentinel", lifespan=lifespan)

@app.get("/api/v1/user/{user_id}")
async def get_user_data(
    user_id: str, 
    payload: str = Query(None, description="惡意指令測試區"),
    request: Request = None
):
    # --- T1: 記錄請求進入時間 ---
    start_perf = time.perf_counter()
    request_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "Unknown")
    
    # 組合偵測目標 (不帶標籤，保持數據純淨)
    current_payload = payload if payload else ""
    detection_target = f"{user_id} {current_payload}".strip()

    # --- [隊長指令：全量啟動哨兵] ---
    # 無論是誰，通通送交 Sentinel 進行意圖分析
    is_attack, confidence, attack_vector = analyze_intent(detection_target)

    # --- [決策層：精準防禦邏輯] ---
    # 為了讓正常查詢通過，我們設定：
    # 只有當哨兵「非常確定」是攻擊 (信心度 > 0.75) 時，才進入幻象模式
    # 如果只是單純的 ID 命中字典 (信心度通常較低)，則判定為誤報，予以放行
    
    final_decision = False
    if is_attack and confidence > 0.75:
        final_decision = True

    if final_decision:
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

        # 寫入流量日誌與欺敵記憶
        log_attack_event({
            "request_at": request_at, "response_at": response_at, "process_ms": process_ms,
            "attacker_ip": client_ip, "location": "Cloud/Render", "is_proxy": 0,
            "user_agent": user_agent, "tls_fingerprint": "N/A", "raw_payload": detection_target,
            "response_payload": str(fake_data), "query_id": user_id, "attack_vector": attack_vector,
            "risk_level": risk_score, "hits": hits, "interaction_depth": interaction_depth,
            "dwell_time": dwell_time, "mitigation_status": "Camouflaged"
        })
        save_deception_state(client_ip, user_id, attack_vector, risk_score, fake_data)

        print(f"[ALERT] 哨兵攔截：{attack_vector} (信心度: {confidence}) | 深度: {interaction_depth}")
        return fake_data

    else:
        # --- 進入正常模式 ---
        # 即使哨兵有小驚報，但信心度不足，一律視為正常查詢放行
        return {"user_id": user_id, "name": "真實用戶", "status": "Normal"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)