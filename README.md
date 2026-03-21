Markdown
# Mirage-Sentinel (幻影哨兵)

> **基於 AI Agent 之自主偽裝與隔離防禦系統**
> *(Autonomous Camouflage and Isolation Defense System Based on AI Agent)*
>
> **專案負責人**：林柏璋 (112AB0055) 暨開發團隊

---

## 專案簡介

在現代軟體安全與逆向工程的攻防對弈中，傳統防火牆與 WAF 往往受限於被動的「阻擋」邏輯，難以掌握攻擊者的真實意圖。**Mirage-Sentinel** 突破此框架，建構於 API 閘道器（API Gateway）之上，將防禦理念昇華為**「主動欺敵與資源消耗」**。

當系統偵測到惡意探測（如 SQL Injection、XSS、LFI）時，AI Agent 將不會直接切斷連線，而是將攻擊者無縫引導至「幻象引擎（Mirage Engine）」。系統會即時生成具備高度真實性的誘餌資料（Honeypot Data），在消耗駭客攻擊成本與時間的同時，同步側錄其攻擊特徵與行為模式，實現「誘捕、隔離、溯源」三位一體的次世代防禦體系。

---

## 核心模組與架構 (MVP 階段)

本系統底層採用 **CQRS (命令查詢職責分離)** 架構設計，以確保高併發流量下的極致效能，目前具備四大核心模組：

1. **核心 API 閘道 (FastAPI Gateway)**
   - 基於 `FastAPI` 打造的高效能異步路由，作為系統的最前線，負責攔截所有外部請求，並精準分流正常用戶與惡意攻擊者。

2. **哨兵攔截引擎 (Sentinel Agent)**
   - 結合 **Aho-Corasick 多字串比對演算法** 與 **Bloom Filter 布隆過濾器**，並串接 OWASP SecLists 惡意字典檔。
   - 具備微秒級（Microsecond）的攻擊意圖分析能力，動態賦予流量風險評估值 (`risk_level`)。

3. **幻象資料模擬器 (Mirage Agent)**
   - 具備**情境感知（Context-aware）**能力的動態誘餌生成器。
   - 整合 `Faker` 動態生成符合台灣繁體中文情境的假個資、假薪資結構或擬真系統報錯訊息，根據駭客的探測手法「量身打造」回傳內容。

4. **物理雙核記憶體 (Dual-DB Architecture)**
   - **`mirage_memory.db` (內部狀態庫)**：確保「欺敵一致性」。當同一 IP 重複發動攻擊時，系統會極速查閱此庫並回傳相同的誘餌資料，防止駭客識破偽裝。
   - **`traffic_logs.db` (戰情倉儲)**：背景異步寫入完整的攻防紀錄（IP、特徵、風險分數），作為後續威脅情報分析的資料基石。

---

## 專案目錄結構

```text
Mirage-Sentinel/
│
├── main.py                  # 【後端入口】FastAPI 主程式 (API Gateway, 路由分發)
│
├── frontend/                # 【前端戰情室】完全交給隊友發揮的專屬開發區
│   ├── dashboard.py         # 主程式入口 (不限制框架，讓他們自己決定結構)
│   └── requirements.txt     # (可選) 前端專屬的套件清單
│
├── core/                    # 【核心大腦】AI Agent 防禦系統的底層邏輯
│   ├── __init__.py
│   ├── sentinel.py          # 哨兵 Agent：載入機器學習模型，執行極速意圖判定
│   ├── mirage.py            # 幻象 Agent：串接 LLM，動態生成誘餌與假資料
│   └── database.py          # 資料庫操作：負責讀寫日誌與記憶庫
│
├── data/                    # 【資料與狀態】(建議 .gitignore 忽略敏感資料)
│   ├── traffic_logs.db      # 戰鬥日誌 (留給前端撈取畫圖的唯一來源)
│   ├── mirage_memory.db     # Agent 的欺敵狀態記憶庫
│   └── datasets/            # 存放用來訓練 AI 的原始 CSV 資料
│
├── models/                  # 【AI 模型庫】存放訓練好的靜態模型檔
│   ├── sentinel_model.pkl   # XGBoost 或 Random Forest 模型大腦
│   └── vectorizer.pkl       # 特徵轉換器
│
├── scripts/                 # 【自動化工具】開發與測試必備腳本
│   ├── train_model.py       # 讀取 datasets 並產出 .pkl 檔的訓練腳本
│   └── attack_simulation.py # 紅隊攻擊模擬器 (負責生數據給隊友畫圖)
│
├── Dockerfile               # 【部署】定義後端與 AI Agent 的容器環境
├── docker-compose.yml       # 【部署】一鍵啟動後端與前端的多容器編排檔
│
├── .env                     # 環境變數 (存放 API Key，絕對不可上傳)
├── .env.example             # 環境變數範例檔
├── requirements.txt         # 後端專案依賴套件清單
└── README.md                # 專案說明與啟動文件
本機端安裝與測試指南
1. 環境安裝
請確保您的開發環境已安裝 Python 3.10 以上版本，並執行以下指令初始化專案：

Bash
git clone [https://github.com/IAN40070510/Mirage-Sentinel.git](https://github.com/IAN40070510/Mirage-Sentinel.git)
cd Mirage-Sentinel
pip install -r requirements.txt
2. 啟動防禦伺服器
Bash
uvicorn main:app --reload --port 8000
3. API 攻防演習 (透過 Swagger UI)
伺服器啟動後，請開啟瀏覽器前往 API 互動測試面板：http://127.0.0.1:8000/docs 進行攻防演練：

良民測試 (正常流量)

Payload: (留白) 或輸入常規業務字串。

結果: 哨兵系統放行，正確回傳真實後端用戶資料。

駭客測試 (惡意流量攔截與欺敵)

Payload: 填入 DROP TABLE、UNION SELECT 或 <script> 等惡意指令。

結果: 哨兵 Agent 瞬間觸發警報，自動將連線切換至幻象模式。攻擊者將收到逼真的假資料（Honeypot），同時其攻擊情報與風險分數已默默寫入底層戰情倉儲。

未來展望與開發藍圖 (Next Steps)
[ ] CTI 戰情室儀表板：開發 Streamlit 前端視覺化介面，以唯讀模式介接 traffic_logs.db，將全球威脅熱點、攻擊手法與駭客滯留時間進行深度可視化。

[ ] Docker 容器化部署：配合實務上的 Linux 伺服器維運標準，撰寫 Dockerfile 與 docker-compose.yml，實現前後端雙引擎與資料庫掛載的標準化一鍵部署。

[ ] AI 幻象模型升級：導入 LLM (大型語言模型) 徹底取代靜態 Faker，賦予 Mirage Agent 處理複雜對話與極致擬真系統狀態的動態欺敵能力。

[ ] 主動式隔離與自動封鎖：整合外部防火牆 API (如 Cloudflare WAF 或 Linux iptables)，當特定 IP 累積達絕對風險閾值時，自動執行網路層級的硬性隔離與封鎖。