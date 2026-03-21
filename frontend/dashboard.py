from fastapi import FastAPI, Request
import uvicorn
from contextlib import asynccontextmanager

# 嚴格匯入 core 資料夾內鎖死的模組與函數
from core.sentinel import analyze_intent
from core.database import setup_mirage_database, get_memory, save_memory
from core.mirage import generate_fake_data

@asynccontextmanager
async def lifespan(app: FastAPI):
    """伺服器啟動時，自動初始化符合戰情室規格的 SQLite 記憶庫"""
    setup_mirage_database()
    # 更新：配合全新目錄結構與雙核資料庫設計
    print("[SYSTEM] 幻影雙核記憶庫 (data/mirage_memory.db & data/traffic_logs.db) 初始化完成，已掛載 11 大核心情報欄位。")
    yield

# 初始化 FastAPI 伺服器
app = FastAPI(title="Mirage-Sentinel API Gateway", version="1.0-MVP", lifespan=lifespan)

@app.get("/api/v1/user/{user_id}")
async def get_user_data(user_id: str, request: Request, payload: str = ""):
    
    # 1. 抓取攻擊者基礎情報 (Who & How)
    client_ip = request.client.host
    query_string = str(request.query_params)  # 這就是駭客的原始武器 raw_payload
    user_agent = request.headers.get("user-agent", "Unknown")  # 抓取設備指紋

    # 2. 呼叫哨兵進行意圖分析 (現在會多回傳一個 attack_vector)
    is_attack, confidence, attack_vector = analyze_intent(query_string)

    if is_attack:
        # ---  進入防禦模式 (Mirage Mode) ---
        risk_score = int(confidence * 100)
        print(f"\n[ALERT] 偵測到來自 {client_ip} 的惡意請求！(風險等級: {risk_score}, 手法: {attack_vector})")
        
        # 3. 檢查 SQLite 狀態記憶庫，確保資料一致性
        cached_data = get_memory(client_ip, user_id)
        if cached_data:
            print("[MEMORY] 快取命中！回傳歷史假資料 (Hits +1)。")
            return cached_data
            
        # 4. 若無快取，呼叫幻象引擎生成新資料，並寫入記憶庫
        print("[MIRAGE] 正在生成全新的幻象個資並寫入記憶體...")
        fake_data = generate_fake_data(user_id)
        
        # 5. 關鍵聯動：將蒐集到的 7 項情資全部傳給資料庫儲存！
        save_memory(client_ip, user_id, fake_data, risk_score, query_string, attack_vector, user_agent)
        
        return fake_data

    else:
        # ---  進入正常模式 (Real Mode) ---
        print(f"\n[INFO] 正常放行 {client_ip} 的請求。")
        
        # 正常情況下應查詢真實資料庫，此處以寫死資料作為 MVP 測試
        # 隱私設計 (Privacy by Design)：正常流量一律放行，不寫入資料庫！
        return {
            "user_id": user_id,
            "name": "王小明 (真實用戶)",
            "email": "wang.real@company.com",
            "balance": 150.0,
            "status": "Normal"
        }

if __name__ == "__main__":
    print("[SYSTEM] Mirage-Sentinel API Gateway 啟動中...")
    # 注意：推上 Render 時，Render 會忽略這行，改用 uvicorn 指令啟動
    uvicorn.run(app, host="0.0.0.0", port=8000)