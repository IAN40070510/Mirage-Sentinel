# Mirage-Sentinel

Mirage-Sentinel 是一個基於人工智慧 (AI) 的主動防禦與欺敵系統 (Active Defense and Deception System)。

面對現代自動化與 AI 驅動的網路攻擊，傳統的靜態防禦與誘餌已難以發揮效用。本專案透過動態生成的沙盒誘餌網路、嚴格的實體資料庫解耦，以及 AI 驅動的動態響應與反制機制（Counter-AI），旨在精準捕獲駭客手法、消耗攻擊方資源，並為資安團隊提供即時且具備實用價值的威脅情報。
---

## 核心防禦目標 (Core Objectives)
本專案的核心目標在於建立一個具備高度感知與自適應能力的防禦體系，專注於以下三大技術維度：

1. 深度行為追蹤與威脅情報收集 (Threat Intelligence & Technique Capture)
不同於傳統僅記錄 IP 或連線時間的誘餌，本系統旨在完整還原攻擊者的操作行為鏈。

全封包與指令審計： 透過核心層級或反向代理層的監控，擷取攻擊者輸入的每一條指令、上傳的惡意載荷 (Payload) 以及採用的自動化工具特徵。

攻擊手法建模： 將捕獲的行為資料轉化為可分析的威脅情報，協助安全團隊理解當前最前線的入侵路徑與漏洞利用策略。

2. 高交互性與動態狀態保持 (Stateful Deception)
為了解決傳統靜態誘餌容易被識破的問題，本系統著重於建立「真假難辨」的虛擬環境。

動態環境響應： 系統具備狀態保持能力，能對攻擊者的操作給予邏輯連貫的回饋。例如，若攻擊者在誘餌環境中建立帳號或修改設定，系統後續的查詢結果將會如實反映這些變化，大幅延長攻擊者受困於誘餌中的時間。

環境拟真與延遲模擬： 透過精細的系統特徵模擬與隨機化的網路延遲注入，規避常見的欺敵偵測腳本。

3. AI 對抗性防禦與 AI API 攻擊抑制 (Counter-AI & API Security)
針對現代 AI 驅動的掃描器與自動化攻擊代理，本系統整合了對抗性的防禦機制。

AI 掃描器對抗： 利用動態變異的 API 結構與錯誤回應，破壞 AI 自動化分析工具的解析邏輯，並透過冗長回應技術 (Tarpitting) 消耗攻擊方 AI 的運算資源與 Token 額度。

反向提示注入防護： 在 API 回應中策略性地佈置防護機制，防範攻擊者利用 LLM 進行自動化的漏洞挖掘或 API 邏輯探測。

*(詳細的系統規格與非功能性需求，請參閱 [`docs/REQUIREMENTS.md`](docs/REQUIREMENTS.md))*

## 金融 API 攻擊場景矩陣 (Defense-First Roadmap)

以下場景以「可觀測、可欺敵、可回放」為實作原則，避免提供攻擊實作細節，同時強化 SOC 可用情報。

1. 身分與授權類 (Identity & Authorization)
- 帳號枚舉、暴力登入、憑證填充、弱密碼嘗試。
- Token 竊用、過期繞過、權限提升與橫向越權。
- 防禦重點：風險評分、速率限制、裝置指紋、JWT 驗證與 RBAC/ABAC。

2. 交易流程類 (Transaction Logic Abuse)
- 重放請求、冪等鍵濫用、同帳戶迴圈轉帳、拆單繞過。
- 金額邏輯與幣別轉換異常、手續費邊界繞過。
- 防禦重點：交易狀態機、風控閾值、行為序列分析、不可逆稽核鏈。

3. 資料層類 (Data Exfiltration & Tampering)
- 物件層級存取控制缺陷（BOLA/IDOR）。
- 大量查詢與批次匯出探測、假合法查詢濫用。
- 防禦重點：物件授權檢查、查詢配額、異常資料存取告警、資料最小揭露。

4. API 協議與輸入類 (Protocol & Input Abuse)
- 參數汙染、結構異常、Header 偽造與代理鏈混淆。
- 不正常序列化/反序列化負載、異常編碼與格式探測。
- 防禦重點：嚴格 Schema 驗證、標準化輸入管線、異常分級回應策略。

5. 自動化掃描與 AI 攻擊代理類 (Automation & AI-driven Probing)
- 高頻低噪探測、語義拼接探測、提示注入與策略測試。
- API 文件與錯誤訊息逆向推理。
- 防禦重點：動態回應擾動、欺敵分流、Tarpitting、提示防護與蜜標記。

6. 基礎設施與供應鏈類 (Infra & Supply Chain)
- 服務發現、健康檢查端點探測、容器權限邊界試探。
- 部署流程與 CI/CD 錯誤配置利用。
- 防禦重點：最小權限容器、內外網分層、部署後健康閘門、失敗自動取證。

### 實作優先順序 (Implementation Priority)

1. 先完成「身分/授權」與「交易流程」兩大場景，直接降低實害風險。
2. 再擴充「資料層」與「API 協議」場景，提升偵測精度與誤報控制。
3. 最後優化「AI 攻擊代理」與「基礎設施」場景，強化長期對抗能力。

### 驗收標準 (Definition of Done)

1. 每一種場景都能產生對應事件（包含毫秒時間戳、來源、策略、結果）。
2. 每一種場景都能被導入欺敵路徑，且不影響真實使用者流程。
3. SOC 可一鍵回放事件鏈，並輸出可行動的防禦建議。

### 兩週實作 Backlog (Actionable Backlog)

第 1 週（先建立可運行防禦閉環）

1. 身分分流骨架（P0）
- 目標：真實使用者走 real path，可疑請求走 deception path。
- 落點：`main.py`、`api/banking.py`。
- 完成條件：同一 API 可根據風險分數回傳不同路徑，且有事件紀錄。
- 目前進度（2026-04）：`/banking/accounts`、`/banking/accounts/{account_id}/balance`、`/banking/accounts/{account_id}/transactions`、`/banking/transfers` 已完成分流骨架與事件紀錄欄位（`route/risk_score/deception_reason`）。

2. 權限模型與最小授權（P0）
- 目標：補齊 object-level authorization 與角色控制。
- 落點：`api/banking.py`、`api/db/operations.py`。
- 完成條件：越權查詢必定被攔截並記錄（不可直接讀取他人資源）。
- 目前進度（2026-04）：新增 `X-Actor-Role`（customer/admin/soc）角色閘門；`/banking/beneficiaries` 與 `/banking/transfers` 已補齊 object-level authorization（目的帳戶需為本人帳戶或已授權受款人），且越權回應 403。

3. 交易風險規則第一版（P0）
- 目標：建立重放、短時間高頻、異常金額序列的規則偵測。
- 落點：`api/banking.py`、`core/sentinel.py`。
- 完成條件：可觸發 deception 分流，SOC 能看到觸發原因。
- 目前進度（2026-04）：已實裝三大規則引擎
  - 重放檢測（Replication Detection）：30 秒內偵測相同 payload
  - 高頻檢測（Rate-limiting Detection）：10 秒內 >20 個請求觸發
  - 異常金額檢測（Anomalous Amount Detection）：超過過往 24 小時平均 3 倍或最大 2 倍
  - 集成 `_compute_transfer_risk_score()`，轉帳端點優先套用
  - CI 迴歸新增 `scripts/ci/transaction-risk-smoke.sh` (3 個測試用例)


4. 鑑識事件欄位標準化（P0）
- 目標：事件結構統一，包含 `route`, `risk_score`, `deception_reason`。
- 落點：`core/traffic_db.py`、`services/dashboard_service.py`、`api/dashboard.py`。
- 完成條件：Dashboard 可按欄位篩選並回放攻擊鏈。
- 目前進度（2026-04）：已實裝查詢層與 API 端點
  - 查詢函數新增：
    - `get_events_by_route(route)` - 按 real/deception 路由篩選
    - `get_events_by_risk_score(min_score, max_score)` - 按風險分數範圍篩選
    - `get_deception_chain(query_id)` - 回放完整攻擊鏈（含時間軸、決策理由、風險評分）
  - API 端點新增：
    - `GET /dashboard/events/by_route/{route}` - 路由查詢
    - `GET /dashboard/events/by_risk_score` - 風險分數查詢
    - `GET /dashboard/replay/{query_id}` - 攻擊鏈回放
  - CI 迴歸新增 `scripts/ci/event-query-smoke.sh` (6 個測試用例：路由篩選、風險分數篩選、攻擊鏈回放、參數驗證、API Key 驗證)


第 2 週（提升欺敵深度與可運營性）

1. 欺敵登入狀態機（P1）
- 目標：未授權/可疑用戶不直接拒絕，改導入擬真登入流程。
- 落點：`api/banking.py`、`core/mirage.py`。
- 完成條件：可維持多步互動一致性，延長攻擊停留時間。

2. AI 掃描器對抗策略（P1）
- 目標：加入回應擾動、Tarpitting、語義噪音注入。
- 落點：`core/api_mirage.py`、`model/llama.py`。
- 完成條件：高頻自動化探測命中率下降且 token 消耗上升。

3. 部署與回歸安全閘門（P1）
- 目標：部署後自動跑健康檢查 + 風險路由 smoke test。
- 落點：`.github/workflows/deploy.yml`。
- 完成條件：任何回歸都在 CI 階段失敗並附帶可讀 logs。

4. 事件回放與運維手冊（P1）
- 目標：新增故障與攻擊回放 Runbook。
- 落點：`docs/README.md` 或新增 `docs/RUNBOOK.md`。
- 完成條件：新成員可依文件完成部署、排障、攻擊回放。

### 文件入口 (Documentation Index)

- 需求規格：[`docs/REQUIREMENTS.md`](docs/REQUIREMENTS.md)
- 開發規範：[`docs/DEVELOPMENT_GUIDELINES.md`](docs/DEVELOPMENT_GUIDELINES.md)
- SecLists 維護：[`docs/SECLISTS_UPDATE_GUIDE.md`](docs/SECLISTS_UPDATE_GUIDE.md)
- 運維與回放：[`docs/RUNBOOK.md`](docs/RUNBOOK.md)

---

## 系統架構亮點 (Architecture Highlights)

* **無縫流量轉發與欺敵 (Seamless Traffic Routing)：** 當「哨兵閘道」偵測到惡意攻擊或異常探測時，系統**不會斷開連線**，而是即時將該流量無縫導向至 Docker 沙盒環境中，觸發 Mirage 引擎進行深度的欺敵工程。
* **Harness Engineering 與沙盒邊界：** 運用 Docker 容器化技術，將欺敵環境嚴格限縮在隔離網路內，禁用特權模式，防止容器逃逸與橫向移動。
* **資料庫實體解耦 (Database Decoupling)：**
  * 鑑識追蹤日誌 (`traffic_logs.db`) 與欺敵狀態記憶 (`mirage_memory.db`) 進行實體分離。
  * 阻斷反鑑識操作，並消除時間側信道 (Timing Side-Channel) 指紋。
* **毫秒級精度 (Millisecond Precision)：** 全系統強制 NTP 時鐘同步與毫秒級日誌記錄，確保攻擊鏈重構的絕對正確性。
* **SOC 資安戰情室：** 整合宏觀的趨勢統計與微觀的即時攻擊指令串流（透過 WebSocket），提供上帝視角的威脅視覺化介面。

---

## 工具棧 (Tech Stack)

本專案採用以下技術架構來平衡高效能攔截與高複雜度 AI 分析：

* **程式語言：** Python
* **哨兵閘道 (Sentinel Gateway)：** FastAPI + NGINX (負責流量代理與無縫導向)
* **意圖分析 (Sentinel)：** XGBoost (負責極速特徵辨識與意圖判定)
* **假資料生成 (Mirage)：** Llama 3.1 8B
* **資料庫：** PostgreSQL (測試與開發階段使用 SQLite 以加速迭代)
* **沙盒環境：** Docker (負責環境隔離與誘餌部署)
* **底層作業系統：** Canonical Ubuntu 24.04
* **雲端平台：** Oracle Cloud Infrastructure (OCI)
* **開發工具：** VS Code, GitHub, GitHub Copilot

---

## 雲端部署架構 (Cloud Deployment Architecture)

本專案支援部署於 Oracle Cloud Infrastructure (OCI) 或同等級公有雲環境，採用嚴格的 **VCN 分層隔離架構**，確保防禦核心的絕對安全。

* **公用子網 (Public Subnet) - 誘餌交戰區：**
  * **公開 API 服務 (Honeypot)：** 部署高度受限的 Docker 誘餌容器，偽裝為對外開放的金融服務 API。
  * **負載平衡器 (Load Balancer)：** 接收外部流量並齊一化回應時間，協助隱藏後端真實拓撲並消除時間側信道指紋。
* **專用子網 (Private Subnet) - 戰略指揮區：**
  * **SOC 後端與 AI 引擎：** 接收誘餌單向傳送的流量複本，進行 AI 意圖判定。完全阻斷來自網際網路的直接存取。
  * **解耦資料庫集群：** `traffic_logs.db` 與 `mirage_memory.db` 獨立運行，落實最小權限原則。
  * **SOC 戰情室前端：** 管理員視覺化介面。嚴禁對外暴露，僅限透過 API Gateway 或 Bastion Host (跳板機) 建立安全隧道進行存取。


## 專案目錄結構 (Project Structure)

```
Mirage-Sentinel/
├── api/
│   ├── __init__.py
│   ├── banking.py
│   ├── dashboard.py
│   └── db/
│       ├── __init__.py
│       ├── models.py
│       ├── operations.py
│       └── session.py
├── core/
│   ├── __init__.py
│   ├── analytics_engine.py
│   ├── api_mirage.py
│   ├── banking_db.py
│   ├── deception_db.py
│   ├── deception_engine.py
│   ├── mirage.py
│   ├── sandbox.py
│   ├── sentinel.py
│   ├── traffic_db.py
│   └── web_attack_dection.py
├── data/
│   ├── attack_signatures.json
│   ├── attack_signatures.txt
│   ├── traffic_logs_sample.sql
│   ├── _sanity_tmp/
│   └── backups/
│       └── seclists_invalid_20260328_192013/
│           ├── common.txt
│           ├── LFI-Jhaddix.txt
│           └── login_bypass.txt
├── datasets/
│   └── SecLists/
│       ├── CONTRIBUTING.md
│       ├── CONTRIBUTORS.md
│       ├── LICENSE
│       ├── README.md
│       ├── Ai/
│       ├── Discovery/
│       ├── Fuzzing/
│       ├── Miscellaneous/
│       ├── Passwords/
│       ├── Pattern-Matching/
│       ├── Payloads/
│       ├── Usernames/
│       └── Web-Shells/
├── docs/
│   ├── README.md
│   ├── REQUIREMENTS.md
│   └── SECLISTS_UPDATE_GUIDE.md
├── frontend/
│   ├── Dockerfile
│   ├── package.json
│   ├── README.md
│   ├── server.js
│   └── public/
│       ├── index.html
│       ├── main.js
│       └── style.css
├── model/
│   └── ai_sentinel.py
├── scripts/
│   ├── generate_sample_traffic_logs.py
│   ├── generate_signatures.py
│   ├── sanity_checks.py
│   ├── update_seclists.py
│   └── data/
│       ├── attack_signatures.json
│       ├── attack_signatures.txt
│       └── payloads/
├── services/
│   ├── __init__.py
│   └── dashboard_service.py
├── DATABASE_SETUP.md
├── docker-compose.oracle.dual-demo.yml
├── docker-compose.oracle.yml
├── docker-compose.yml
├── Dockerfile
├── main.py
├── README.md
├── requirements.txt
└── sandbox_service.py
```

---

## 執行與開啟方式 (Quick Start)

以下為根目錄 `README.md` 的執行與開啟方式摘要，方便在本文件直接查閱。

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
```

開啟位置：

- 後端 API 文件：http://127.0.0.1:8000/docs
- 前端儀表板：http://127.0.0.1:3000

OCI 線上環境：

- 服務網址：http://161.33.154.211

### Docker 部署（本地）

```bash
docker compose up --build
```

若要啟用真實 PostgreSQL（可選）：

```bash
cp .env.db.example .env
docker compose --profile db up --build
```

服務清單：

- API Gateway：http://127.0.0.1:8000
- Frontend Dashboard：http://127.0.0.1:3000
- Sandbox Service：http://127.0.0.1:8001
- PostgreSQL（可選）：localhost:5432

### 一鍵驗收流程 (Smoke Test)

本機一行版（自動啟動、檢查、清理）：

```powershell
# Windows PowerShell
./scripts/ci/run-local-smoke.ps1
```

```bash
# Bash
bash scripts/ci/run-local-smoke.sh
```

部署或啟動後，請依序執行以下檢查：

```bash
# 1) 服務健康檢查
curl -i http://127.0.0.1:8000/healthz
curl -i http://127.0.0.1:8002/healthz

# 2) OpenAPI 文件可用性
curl -i http://127.0.0.1:8000/openapi.json

# 3) Banking 端點基本驗證（示例）
curl -i -H "X-User-Id: 000000001" http://127.0.0.1:8000/banking/accounts
```

驗收判準：

1. `/healthz`（8000/8002）回應 200。
2. `/openapi.json` 回應 200 且為有效 JSON。
3. `/banking/accounts` 回應符合當前模式（真實路徑或欺敵路徑），且事件可被記錄。

若任一步驟失敗，請直接參照 [`docs/RUNBOOK.md`](docs/RUNBOOK.md) 的「503 排障 SOP」與「DB 建置、補種與遷移」。

CI 自動化：

1. 合併前由 [`PR Compose Smoke Test`](.github/workflows/pr-smoke.yml) 執行本地 compose 驗收，包括：
   - 健康檢查與 OpenAPI 可用性
   - 權限回歸測試（`scripts/ci/authz-smoke.sh`）：role gate / object-level authorization
   - 交易風險規則測試（`scripts/ci/transaction-risk-smoke.sh`）：重放檢測、高頻檢測、異常金額檢測
   - 鑑識事件查詢測試（`scripts/ci/event-query-smoke.sh`）：路由篩選、風險分數篩選、攻擊鏈回放
2. 部署成功後由 [`Post-Deploy Smoke Test`](.github/workflows/post-deploy-smoke.yml) 進行線上同等驗收，包括以上所有項目。

### Dashboard 事件查詢與回放 API

P0 鑑識事件欄位標準化提供三個新的查詢端點，支援按路由、風險分數篩選與完整攻擊鏈回放：

```bash
# 設定 API Key（預設為 dev-local-api-key-change-me）
API_KEY="dev-local-api-key-change-me"

# 1) 查詢欺敵路由事件（deception）
curl -H "X-API-Key: $API_KEY" \
  "http://127.0.0.1:8000/dashboard/events/by_route/deception?limit=10"

# 2) 查詢真實路由事件（real）
curl -H "X-API-Key: $API_KEY" \
  "http://127.0.0.1:8000/dashboard/events/by_route/real?limit=10"

# 3) 查詢特定風險分數範圍的事件（0-100）
curl -H "X-API-Key: $API_KEY" \
  "http://127.0.0.1:8000/dashboard/events/by_risk_score?min_score=60&max_score=100&limit=20"

# 4) 回放完整攻擊鏈（包含時間軸、每步決策理由、風險評分）
curl -H "X-API-Key: $API_KEY" \
  "http://127.0.0.1:8000/dashboard/replay/CIF000001001"
```

**回應欄位說明：**
- `route` - 分流路由（`real` 或 `deception`）
- `risk_score` - 風險評分（0-100 整數）
- `deception_reason` - 欺敵觸發原因（如 `invalid_user_id_format,suspicious_user_agent`）
- `attack_vector` - 攻擊向量分類（如 `sqli`, `lfi`, `paths`）
- `chain_length` - 攻擊鏈完整步驟數（回放端點時）
- `deception_events` - 鏈中欺敵事件計數（回放端點時）

這些端點已集成到 CI 迴歸測試，確保新增欄位在 PR 與線上部署時保持可用。
