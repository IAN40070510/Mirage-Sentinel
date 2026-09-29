# Mirage 電商欺敵服務

現行入口為 services/commerce/mirage.py，由 docker-compose.commerce.yml 的 mirage 服務啟動。Gateway 將可疑訪客送往獨立 Medusa 沙盒，在適用的錯誤回應路徑呼叫 Mirage。

輸入包含 visitor、path、rules 與 HTTP status；輸出是電商 JSON 錯誤格式。輸入是不可信資料，不得作為工具或系統指令執行。模型不可用時回傳固定 JSON 錯誤模板。

Mirage 僅可讀寫 /memory/mirage.db，不能讀取鑑識庫或正式 PostgreSQL。Gateway 非同步提交事件給 Collector。容器維持 non-root、read-only、cap_drop。

若需要 Ollama，使用 Compose 的 llm profile 並依部署環境準備模型。模型不存在或服務不可用時，不能將模板回應描述為模型推論。

設定以 .env.commerce 的 OLLAMA_MODEL 與 Compose 的 OLLAMA_URL 為準。model/Mirage 保留作歷史研究，不是現行入口。
