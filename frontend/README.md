# Mirage-Sentinel | 視覺化監控儀表板 (Frontend)

這是 **Mirage-Sentinel** 網路安全監控系統的視覺化前端模組。本模組負責將後端「全時哨兵」偵測到的惡意流量與欺敵紀錄，轉化為直觀的分析圖表與攻擊時間軸。

## 資料夾結構說明

```text
Mirage-Sentinel/
├── api/                   # [API 路由層] 定義對外接口
│   └── dashboard.py       # 前端專用 API (例如: /api/v1/dashboard/analysis)
│
├── services/              # [業務邏輯層] 數據處理與分析
│   └── web_service.py     # 核心分析邏輯 (例如: 計算停留時間、行為分析)
│
├── core/                  # [數據存取層] 底層資料庫操作
│   └── nexus_db.py        # 資料庫連線管理 (DAL) 與 Table Schema 定義
│
├── data/                  # [數據存儲層] 實體資料檔案
│   └── traffic_logs.db    # 存儲攻擊事件的 SQLite 資料庫檔案
│
├── frontend/              # [前端展示層] 視覺化介面
│   ├── public/            # 靜態資源存放處
│   │   ├── index.html     # 儀表板主入口
│   │   ├── main.js        # 調用 API (fetch) 與渲染數據
│   │   └── style.css      # 介面視覺樣式
│   ├── package.json       # 前端環境設定
│   └── server.js          # 前端託管伺服器
│
└── main.py                # [系統總入口] 啟動後端並掛載所有 API 路由
```

---

## 後端 API 串接規格

前端透過非同步請求與 **FastAPI (Port 8000)** 進行串接。目前已實現的介面如下：

| 功能項目         | API 路徑 (GET)                    | 數據來源          | 說明                                 |
| :--------------- | :-------------------------------- | :---------------- | :----------------------------------- |
| **停留時間分析** | `/api/v1/dashboard/analysis/{ip}` | `traffic_logs.db` | 獲取特定攻擊者的活動時長、總擊中筆數 |
| **行為時間軸**   | `/api/v1/dashboard/timeline/{ip}` | `traffic_logs.db` | 獲取該 IP 歷史攻擊的具體時間點與行為 |
| **風險判定**     | 整合於 `analysis` 接口            | `traffic_logs.db` | 顯示 AI 判定之風險分數與攻擊類別     |

---

## 核心視覺化功能

1. **實時威脅熱圖**: 顯示當前系統受攻擊的頻率與風險等級。
2. *欺敵互動深度 (Interaction Depth)**: 追蹤駭客在幻影環境中探索的層數。
3. **攻擊歸因分析**: 自動分類 SQL Injection, XSS 或 Command Injection。
4. **自動刷新**: 每 30 秒自動向後端同步最新哨兵日誌。

---
