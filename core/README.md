🛡️ Mirage-Sentinel (幻影哨兵)
次世代動態欺敵與隔離防禦系統 (Dynamic Deception and Isolation Defense System)

「不只防禦，還要讓駭客在虛假的情報中自我消耗。」

📖 專案目錄
專案簡介

核心技術架構

系統功能模組

快速開始 (本地開發)

API 測試指南

戰情室儀表板

開發團隊與進度

📝 專案簡介
Mirage-Sentinel 是一款主動式資安防禦系統。它在 API 閘道端點進行即時流量分析，當偵測到 SQL Injection、XSS 等惡意意圖時，系統會自動切換至「幻象模式」，利用 AI 與動態生成技術回傳虛假的「誘餌資料」，藉此保護真實資料庫並記錄駭客行為。

🏗️ 核心技術架構
本專案採用微服務與異步處理架構：

Backend: FastAPI (Asynchronous Python Framework)

Security: Aho-Corasick Algorithm & Bloom Filter

AI/Mock: OpenAI GPT-4o (Dynamic Deception) & Faker

Visualization: Streamlit & Plotly

Database: SQLite (Local Cache) & Redis (Cloud Persistence)

🛠️ 系統功能模組
1. 哨兵攔截引擎 (Sentinel Engine)
精準偵測：整合 SecLists 惡意字典檔，實現微秒級過濾。

風險評分：動態計算 risk_level，區分誤報與真實攻擊。

2. 幻象模擬器 (Mirage Simulator)
情境感知：根據 user_id（如 admin, staff）自動配發不同層級的誘餌。

一致性防護：透過狀態記憶庫，確保同一駭客看到的假資料始終如一。

3. 戰情儀表板 (War Room Dashboard)
即時監控：視覺化呈現攻擊來源、趨勢與高風險標靶。

情報分析：自動彙整攻擊者特徵與頻率。

🚀 快速開始 (本地開發)
1. 複製專案
Bash
git clone https://github.com/IAN40070510/Mirage-Sentinel.git
cd Mirage-Sentinel
2. 環境設定
Bash
python -m venv venv
source venv/bin/activate  # Windows 使用 .\venv\Scripts\activate
pip install -r requirements.txt
3. 配置金鑰
建立 .env 檔案並填入：

Plaintext
OPENAI_API_KEY=your_api_key_here
REDIS_URL=your_redis_url_here
🧪 API 測試指南
啟動後訪問 http://127.0.0.1:8000/docs：

正常查詢：user_id=1001 (無 payload) -> 回傳真實資料。

模擬攻擊：user_id=admin, payload=DROP TABLE -> 回傳幻象資料。

📊 戰情室儀表板
啟動視覺化介面：

Bash
streamlit run dashboard.py
功能一：攻擊次數即時趨勢圖。

功能二：惡意 IP 風險排行榜。

📅 開發團隊與進度
負責人：林柏璋 (112AB0055)

進度表：

[x] Week 1: 核心 API 閘道、哨兵攔截引擎、SQLite 記憶庫。

[ ] Week 2: Streamlit 戰情室建置、OpenAI 動態誘餌升級、Redis 雲端同步。

[ ] Week 3: 系統壓力測試、Demo 簡報撰寫。