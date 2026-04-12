# AI Agent 設置指南

## 概述

Mirage-Sentinel 的 AI Agent 運行在隔離的沙盒環境中，使用 LLaMA 模型與攻擊者進行高互動欺敵。

## 功能特點

- **高互動欺敵**：根據攻擊類型生成不同的假資料回應
- **沙盒隔離**：AI Agent 只能修改環境內資源，無法訪問外部
- **多攻擊類型支援**：
  - SQL 注入：生成假資料庫記錄
  - XSS：過濾並生成安全回應
  - LFI：提供假檔案內容
  - RCE：模擬命令執行結果
  - 路徑遍歷：生成假目錄列表

## 設置步驟

### 1. 安裝 Ollama

在宿主機上安裝 Ollama：

```bash
# macOS
brew install ollama

# Linux
curl -fsSL https://ollama.ai/install.sh | sh

# Windows
# 從 https://ollama.ai/download 下載安裝
```

### 2. 下載 LLaMA 模型

```bash
# 下載 LLaMA 3.1 8B 模型
ollama pull llama3.1:8b

# 驗證安裝
ollama list
```

### 3. 啟動服務

```bash
# 啟動 Ollama 服務（在背景運行）
ollama serve

# 啟動 Mirage-Sentinel
docker-compose up -d
```

### 4. 測試 AI Agent

```bash
# 運行測試腳本
python test_ai_agent.py
```

## 安全設計

### 隔離機制

- **網路隔離**：AI Agent 只能通過 `host.docker.internal` 訪問 Ollama
- **檔案系統隔離**：只讀根目錄，只能寫入 `mirage_memory.db`
- **權限隔離**：以非 root 用戶運行，所有權限被移除

### 資料庫解耦

- **可寫**：`mirage_memory.db` - 存儲欺敵狀態
- **不可訪問**：`traffic_logs.db` - 只允許主應用寫入

## API 使用

### AI Agent 端點

```http
POST /ai_agent_execute
Authorization: Bearer mirage_sentinel_sandbox_token_2024

{
  "client_ip": "192.168.1.100",
  "query_id": "user123",
  "raw_payload": "SELECT * FROM users",
  "attack_vector": "sqli",
  "risk_level": 8
}
```

### 回應格式

```json
{
  "status": "ai_processed",
  "ai_decision": {
    "action": "generate_fake_database_records",
    "confidence": 0.85,
    "risk_level": 8
  },
  "fake_data": {
    "file_content": "假的資料庫記錄..."
  },
  "ai_log": {
    "timestamp": "2024-01-01T12:00:00.000000",
    "client_ip": "192.168.1.100",
    "ai_action": "generate_fake_database_records",
    "ai_confidence": 0.85,
    "ai_risk_level": 8,
    "sandbox_isolation": "enforced"
  }
}
```

## 故障排除

### Ollama 連接失敗

```bash
# 檢查 Ollama 是否運行
curl http://localhost:11434/api/tags

# 重新啟動 Ollama
ollama serve
```

### 沙盒無法訪問 Ollama

確保 Docker 配置正確：
- `extra_hosts` 包含 `host.docker.internal:host-gateway`
- 環境變數 `OLLAMA_URL` 正確設置

### AI 生成失敗

系統會自動回退到備用邏輯，生成靜態假資料。

## 效能考慮

- **超時設置**：15秒，避免阻斷攻擊者
- **資源限制**：CPU 和記憶體受限
- **並發處理**：每個請求獨立處理

## 日誌監控

AI Agent 活動記錄在：
- 沙盒日誌：`/app/logs/sandbox.log`
- 欺敵狀態：`data/mirage_memory.db`