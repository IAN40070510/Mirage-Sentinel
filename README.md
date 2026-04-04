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

---

## 系統架構亮點 (Architecture Highlights)

* **無縫流量轉發與欺敵 (Seamless Traffic Routing)：** 當「哨兵閘道」偵測到惡意攻擊或異常探測時，系統**不會斷開連線**，而是即時將該流量無縫導向至 Docker 沙盒環境中，觸發 Mirage 引擎進行深度的欺敵工程。
* **Harness Engineering 與沙盒邊界：** 運用 Docker 容器化技術，將欺敵環境嚴格限縮在隔離網路內，禁用特權模式，防止容器逃逸與橫向移動。
* **資料庫實體解耦 (Database Decoupling)：** * 鑑識追蹤日誌 (`traffic_logs.db`) 與欺敵狀態記憶 (`mirage_memory.db`) 進行實體分離。
  * 阻斷反鑑識操作，並消除時間側信道 (Timing Side-Channel) 指紋。
* **毫秒級精度 (Millisecond Precision)：** 全系統強制 NTP 時鐘同步與毫秒級日誌記錄，確保攻擊鏈重構的絕對正確性。
* **SOC 資安戰情室：** 整合宏觀的趨勢統計與微觀的即時攻擊指令串流（透過 WebSocket），提供上帝視角的威脅視覺化介面。

---

## 工具棧 (Tech Stack)

本專案採用以下技術架構來平衡高效能攔截與高複雜度 AI 分析：

* **程式語言：** Python
* **哨兵閘道 (Sentinel Gateway)：** FastAPI + NGINX (負責流量代理與無縫導向)
* **意圖分析 (Sentinel)：** XGBoost (負責極速特徵辨識與意圖判定)
* **假資料生成 (Mirage)：** Llama 3.1 8B (測試階段使用 API 串接，負責動態生成高逼真度回應)
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
├── render.yaml
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
