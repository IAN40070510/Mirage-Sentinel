# Mirage-Sentinel

Mirage-Sentinel 是一個以 FastAPI 為核心的主動式防禦 API Gateway。
系統先進行攻擊意圖判斷，對高風險請求隔離沙盒並回傳一致假資料，同時記錄完整攻防軌跡。

**狀態**：v1.6.2 | 核心功能已成熟 | 支援本地與 Render 雲端部署

## 關鍵特性

**Sentinel 攻擊偵測**
- 特徵型快篩：19 個在地 fallback 簽名（SQLi、LFI、Path Traversal）
- 支援完整 SecLists 目錄結構自動尋找（若有部署）
- 安全降級模式：簽名缺失時仍可運作

**Mirage 欺敵生成**  
- 假資料一致性保證：同 IP + 目標的重複攻擊回傳相同資料
- 記憶機制：`mirage_memory.db` 快取欺敵狀態
- Faker 庫支持多語言場景（繁體中文、英文等）

**雙資料庫分離**
- `traffic_logs.db`：戰情室唯一查詢來源（所有攻防事件、風險分數、處置狀態）
- `mirage_memory.db`：欺敵流程內部狀態，不對外暴露

**儀表板與監控**
- 前端自動版面判斷（15/17/25 吋螢幕適配）
- 實時流量總覽、IP 追蹤、攻擊類型熱圖
- Dashboard API 提供唯讀查詢（需 API Key）

**安全架構**
- API Key 隱式驗證（Header `X-API-Key`）
- HTML XSS 風險緩解已修補
- 環境變數管理敏感配置

## 系統架構

```
客戶端請求
    ↓
[API Gateway] main.py
    ↓
[Sentinel 檢測] core/sentinel.py
├─ TF-IDF + 安全統計特徵 (AI Sentinel)
├─ 特徵型快篩（19 簽名或完整 SecLists）
└─ 風險評分
    ↓
    ├─ 低風險 → 正常回應
    ├─ 中風險 → 二階審查（預留 BERT）
    └─ 高風險 ↓
        [沙盒隔離] core/sandbox.py
            ↓
        [Mirage 生成] core/mirage.py
            ├─ 記憶檢查
            └─ 假資料回傳
    ↓
[流量日誌] traffic_logs.db
    ↓
[儀表板] frontend + api/dashboard.py
```

## 快速開始

### 本地開發

```bash
# 1. 環境準備
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# 或
.\.venv\Scripts\activate   # Windows

# 2. 安裝依賴
pip install -r requirements.txt

# 3. 啟動後端
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# 4. 在另一個終端啟動前端
npm --prefix frontend start

# 5. 開啟儀表板
# 後端 API：http://127.0.0.1:8000/docs
# 前端儀表板：http://127.0.0.1:3000
```

### Docker 部署（本地）

```bash
docker compose up --build
```

服務清單：
- API Gateway：http://127.0.0.1:8000
- Frontend Dashboard：http://127.0.0.1:3000
- Sandbox Service：http://127.0.0.1:8001

### Render 雲端部署

部署設定已內置於 `render.yaml`，包含：

1. **mirage-sentinel** (FastAPI)
   - Runtime: Python
   - Port: 環境變數 `$PORT`（預設 10000）
   - Health Check: `/healthz`
   
2. **detective-frontend** (Express)
   - Runtime: Node.js
   - 代理後端 API（注入 API Key）
   
3. **sentinel-cache** (Redis, 選用)

推送到遠端後自動部署：
```bash
git push
# Render 將自動觸發 build & deploy
```

## API 使用指南

### 攻擊檢測與模擬

```bash
# 1. 正常請求
curl "http://127.0.0.1:8000/api/v1/user/1001"

# 2. 攻擊測試（LFI）
curl "http://127.0.0.1:8000/api/v1/user/1001?payload=../../../../etc/passwd"

# 3. 模擬攻擊（切換攻擊者 IP）
curl -X POST "http://127.0.0.1:8000/api/v1/simulate_attack?user_id=1001&payload=' OR '1'='1&client_ip=10.10.10.1"

# 4. AI Sentinel 直連測試
curl "http://127.0.0.1:8000/api/v1/ai_sentinel?text=DROP%20TABLE%20users&method=POST"
```

### 儀表板 API（需 API Key）

```bash
# 設定 API Key
export API_KEY="dev-local-api-key-change-me"

# 1. Live IPs
curl -H "X-API-Key: $API_KEY" \
  "http://127.0.0.1:8000/api/v1/dashboard/live_ips?limit=50"

# 2. IP 詳細資訊
curl -H "X-API-Key: $API_KEY" \
  "http://127.0.0.1:8000/api/v1/dashboard/ip_details/10.10.10.1"

# 3. 流量比較
curl -H "X-API-Key: $API_KEY" \
  "http://127.0.0.1:8000/api/v1/dashboard/traffic_compare"

# 4. 自動更新檢查
curl -H "X-API-Key: $API_KEY" \
  "http://127.0.0.1:8000/api/v1/dashboard/auto_updates"
```

## 環境變數

```env
# .env 或 Render 環境變數

# API 認證（必填：正式環境）
API_KEY=replace-with-strong-random-key

# OpenAI（選用：功能尚在規劃）
OPENAI_API_KEY=sk-...

# Sandbox 服務（Docker Compose 時可用）
SANDBOX_API_URL=http://sandbox:8001/simulate_attack

# Redis（Render 自動注入）
REDIS_URL=redis://localhost:6379

# Port（Render 自動提供）
PORT=10000
```

## Sentinel 簽名機制

### 簽名來源優先級

1. **第一優先：完整 SecLists（若已部署）**
   - 支援遞迴尋找（位置任意）
   - 包含數千個已知攻擊模式

2. **第二優先：內建 Fallback 簽名（雲端預設）**
   - SQLi：6 個簽名（`' or '1'='1`, `union select` 等）
   - LFI：7 個簽名（`../../`, `/etc/passwd` 等）
   - Paths：6 個簽名（`/admin`, `/api/admin` 等）
   - **總計 19 個簽名**

### 部署時的簽名日誌

```
✅ Sentinel 核心已武裝！總計載入 19 筆簽名          # 雲端環境（fallback）
✅ Sentinel 核心已武裝！總計載入 2483 筆簽名       # 本地環境（完整 SecLists）
```

訊息「改用內建 fallback 字典」**不是錯誤**，而是雲端環境的預期行為。

## 資料庫結構

### traffic_logs.db（戰情室查詢來源）

```sql
-- 核心欄位
request_at              TEXT      -- 請求時間
response_at             TEXT      -- 回應時間
process_ms              INTEGER   -- 處理時間
client_ip               TEXT      -- 攻擊者 IP
raw_payload             TEXT      -- 原始請求內容
attack_vector           TEXT      -- 攻擊類型（SQLi、LFI 等）
risk_level              INTEGER   -- 風險分數 (0-100)
is_attack               INTEGER   -- 是否為攻擊 (0/1)
mitigation_status       TEXT      -- 處置狀態（Sandboxed/normal）
interaction_depth       INTEGER   -- 互動深度
dwell_time              REAL      -- 駭客停留時間
hits                    INTEGER   -- 命中次數
```

### mirage_memory.db（欺敵快取，不對外）

```sql
-- 快取 key: client_ip + query_id
payload                 JSON      -- 回傳的假資料
last_seen               TEXT      -- 最後使用時間
depth                   INTEGER   -- 互動深度
hits                    INTEGER   -- 累計命中次數
```

## 已知限制與修複狀態

| 項目 | 狀態 | 說明 |
|------|------|------|
| Sentinel 基礎檢測 | 完成 | 19 個簽名 + SecLists 支援 |
| 雙資料庫分離 | 完成 | traffic_logs + mirage_memory |
| 前端儀表板 | 完成 | 自動版面、XSS 防護已修補 |
| Render 部署 | 完成 | PORT 綁定、Health Check 已設置 |
| AI Sentinel (XGBoost) | 進行中 | 類名修正完成，模型載入測試待驗 |
| Mirage Agent (LLM) | 規劃中 | 需集成 Llama 3.1 8B 或 OpenAI API |
| 二階 BERT 審查 | 規劃中 | 中風險請求的進階判定 |

## 開發與貢獻

### 本機檢測流程

```bash
# 1. Sentinel 簽名測試
python3 -c "from core.sentinel import analyze_intent; print(analyze_intent('DROP TABLE'))"

# 2. 前端語法檢查
node --check frontend/public/main.js

# 3. Backend 單元測試（待實作）
pytest tests/

# 4. Docker 構建驗證
docker build -t mirage-sentinel:test .
```

### 部署檢查清單

- [ ] 所有修改已 `git add` 並 `git commit`
- [ ] 遠端分支已推送：`git push`
- [ ] `.env` 已配置正式 `API_KEY`（非預設值）
- [ ] Render 後台已設置環境變數
- [ ] Health Check 回傳 `{"status": "ok"}`
- [ ] Dashboard API 可正常查詢（帶有效 API Key）
- [ ] 前端儀表板可訪問並顯示數據

## 故障排查

### 啟動失敗：Port binding error

**原因**：Render 未能偵測到開啟的連接埠
**解決**：
- 確認 `render.yaml` 中 `startCommand` 包含 `--port ${PORT:-10000}`
- 確認 Dockerfile `CMD` 正確使用 `sh -c` 包裝
- 檢查本地 PORT 環境變數是否正確設置

### Sentinel 未載入簽名

**原因**：雲端 SecLists 未部署（預期行為）
**預期日誌**：
```
Sentinel 找不到簽名字典: LFI-Jhaddix.txt，改用內建 fallback 字典。
Sentinel 找不到簽名字典: common.txt，改用內建 fallback 字典。
Sentinel 找不到簽名字典: login_bypass.txt，改用內建 fallback 字典。
✅ Sentinel 核心已武裝！總計載入 19 筆簽名
```
**此為正常狀態，不會影響檢測**

### 前端儀表板無數據

**檢查項目**：
1. 後端 `/healthz` 是否回傳 `{"status": "ok"}`
2. API Key 是否正確（Header `X-API-Key`）
3. `traffic_logs.db` 是否存在且有記錄
4. 前端代理日誌是否有錯誤（`npm logs`）

### AttributeError: module 'model.ai_sentinel' has no attribute 'SentinelModuleV14'

**原因**：類名引用不一致
**解決**：已修正，確認 `main.py` 第 41 行為 `model.SentinelModule`

## 測試數據示例

```bash
# 製造攻擊事件（本地）
for i in {1..10}; do
  curl "http://127.0.0.1:8000/api/v1/user/$((1000+i))?payload=../../../../etc/passwd"
done

# 查詢儀表板
curl -H "X-API-Key: dev-local-api-key-change-me" \
  "http://127.0.0.1:8000/api/v1/dashboard/traffic_compare"
```

## 授權

此專案目前未附正式開源授權。若要對外釋出，建議補上 LICENSE。

---

**最後更新**：2026-04-02 | v1.6.2
- Sentinel Fallback 簽名系統
- 雙資料庫分離（traffic_logs + mirage_memory）
- Frontend 自動版面 + XSS 防護
- Render 部署完整支援
- API 健康檢查 (healthz)
- SentinelModule 類名統一