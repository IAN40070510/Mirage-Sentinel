# Mirage-Sentinel 真實資料庫設置指南

## 概述

銀行 API 支援兩種模式自動切換：
- **Mock 模式**（預設）：使用記憶體中的示例資料
- **真實 DB 模式**：連接 PostgreSQL 資料庫，使用真實資料

系統會根據 `DATABASE_URL` 環境變數自動選擇模式。

## Mock 模式（無 DB）

如果未設置 `DATABASE_URL`，系統會自動進入 Mock 模式：

```bash
# 無需 DATABASE_URL 的情況下啟動
$env:ENABLE_DASHBOARD='false'
$env:ENABLE_BANKING_API='true'
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

**回應示例：**
```json
{
  "user_id": "CIF000001001",
  "accounts": [...],
  "notice": "(Demo 資料)"
}
```

---

## 真實 DB 模式（PostgreSQL）

### 1. 安裝 PostgreSQL

**Windows 版本：**
```bash
# 使用 Chocolatey
choco install postgresql

# 或從官方下載：https://www.postgresql.org/download/windows/
```

**macOS 版本：**
```bash
brew install postgresql@15
brew services start postgresql@15
```

**Linux 版本：**
```bash
sudo apt install postgresql postgresql-contrib
sudo systemctl start postgresql
```

### 2. 建立資料庫和使用者

```sql
-- 設定超級用戶密碼
ALTER USER postgres PASSWORD 'strong-password-here';

-- 建立應用使用者
CREATE USER mirage_user WITH PASSWORD 'user-password-here';

-- 建立資料庫
CREATE DATABASE mirage_sentinel;

-- 授予權限
GRANT ALL PRIVILEGES ON DATABASE mirage_sentinel TO mirage_user;
GRANT USAGE ON SCHEMA public TO mirage_user;
GRANT CREATE ON SCHEMA public TO mirage_user;
```

### 3. 設置連接字串

**方法 1：環境變數（推薦）**

```bash
# .env 檔案 或 PowerShell：
$env:DATABASE_URL = "postgresql://mirage_user:user-password-here@localhost:5432/mirage_sentinel"
```

**方法 2：直接設定**

```bash
# 在 main.py 同目錄創建 .env 檔案
DATABASE_URL=postgresql://mirage_user:user-password-here@localhost:5432/mirage_sentinel
```

### 4. 啟動應用（自動初始化表）

```bash
cd c:/Users/Ian/Desktop/Mirage-Sentinel

$env:DATABASE_URL="postgresql://mirage_user:password@localhost:5432/mirage_sentinel"
$env:ENABLE_BANKING_API='true'
$env:ENABLE_DASHBOARD='false'

python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

**日誌輸出：**
```
[DB] Connected to PostgreSQL database
[DB] Created all tables
[DB] PostgreSQL database initialized successfully.
```

### 5. 初始化測試資料（可選）

連接到資料庫並插入測試使用者和帳戶：

```sql
-- 連接到 mirage_sentinel 資料庫
psql -U mirage_user -d mirage_sentinel -h localhost

-- 插入使用者
INSERT INTO users (user_id, name, email) VALUES 
('CIF000001001', '王小明', 'wang@example.com'),
('CIF000001002', '李大安', 'li@example.com');

-- 插入帳戶
INSERT INTO accounts (account_id, user_id, account_type, currency, balance, status, open_date) VALUES
('ACCOD48PUCAEHKH', 'CIF000001001', 'Checking', 'USD', 500000.00, 'ACTIVE', '2021-03-27'),
('ACCZ1234567890AB', 'CIF000001002', 'Savings', 'USD', 1000000.00, 'ACTIVE', '2020-01-15');

-- 插入受款人
INSERT INTO beneficiaries (user_id, nickname, bank_code, account_id, beneficiary_name) VALUES
('CIF000001001', 'Primary Account', '812', 'ACCZ1234567890AB', '李大安');

-- 驗證資料
SELECT * FROM users;
SELECT * FROM accounts;
SELECT * FROM beneficiaries;
```

---

## API 查詢示例

### 查詢帳戶清單（Mock 模式）

```bash
$response = Invoke-WebRequest `
  -Uri 'http://127.0.0.1:8000/api/v1/banking/accounts' `
  -Headers @{'X-User-Id'='CIF000001001'} `
  -UseBasicParsing

$response.Content | ConvertFrom-Json | ConvertTo-Json -Depth 4
```

**回應（Mock）：**
```json
{
  "user_id": "CIF000001001",
  "accounts": [
    {
      "account_id": "ACCOD48PUCAEHKH",
      "customer_name": "王小明",
      "account_display": "ACCOD48PUCAEHKH(真實帳戶)",
      "currency": "USD",
      "balance": 182700.46,
      "status": "ACTIVE",
      "created_at": "2021-03-27"
    }
  ],
  "notice": "(Demo 資料)"
}
```

### 查詢帳戶清單（真實 DB 模式）

設置 `DATABASE_URL` 後，相同的 API 調用會返回：

```json
{
  "user_id": "CIF000001001",
  "accounts": [
    {
      "account_id": "ACCOD48PUCAEHKH",
      "customer_name": "王小明",
      "account_display": "ACCOD48PUCAEHKH(真實帳戶)",
      "currency": "USD",
      "balance": 500000.00,
      "status": "ACTIVE",
      "created_at": "2021-03-27"
    }
  ],
  "notice": "(真實資料庫查詢)"
}
```

---

## Notice 欄位說明

| Notice | 含義 | 資料來源 |
|--------|------|--------|
| `(Demo 資料)` | Mock 模式 | 記憶體 demo 常數 |
| `(真實資料庫查詢)` | 真實 DB 模式 | PostgreSQL 資料庫 |

---

## 多租戶支援

每個查詢 API 都支援透過 `X-User-Id` header 切換不同使用者的帳戶：

```bash
# 查詢使用者 CIF000001001 的帳戶
Invoke-WebRequest `
  -Uri 'http://127.0.0.1:8000/api/v1/banking/accounts' `
  -Headers @{'X-User-Id'='CIF000001001'}

# 查詢使用者 CIF000001002 的帳戶
Invoke-WebRequest `
  -Uri 'http://127.0.0.1:8000/api/v1/banking/accounts' `
  -Headers @{'X-User-Id'='CIF000001002'}
```

- **Mock 模式**：所有 X-User-Id 都映射到 `CIF000001001`（單一 demo 帳戶）
- **真實 DB 模式**：每個 X-User-Id 存取各自的帳戶和交易資料

---

## 故障排除

### 錯誤：`DATABASE_URL is invalid`

確保連接字串格式正確：
```
postgresql://username:password@host:port/database
```

### 錯誤：`Connection refused`

確認 PostgreSQL 伺服器正在運行：

```bash
# Windows
Get-Process | Where-Object {$_.ProcessName -like "*postgres*"}

# Linux / macOS
ps aux | grep postgres
```

啟動服務：
```bash
# Windows (如使用 PGADMIN)
net start postgresql-x64-15

# macOS
brew services start postgresql

# Linux
sudo systemctl start postgresql
```

### 日誌顯示 `using mock data mode`

檢查 `DATABASE_URL` 環境變數是否正確設置：

```bash
# 驗證環境變數
Write-Host $env:DATABASE_URL

# 如果為空，重新設置
$env:DATABASE_URL = "postgresql://user:pass@localhost:5432/db"
```

---

## 建議

1. **開發環境**：使用 Mock 模式快速迭代
2. **測試環境**：連接測試 PostgreSQL 資料庫驗證多租戶邏輯
3. **生產環境**：使用受保護的生產資料庫，設置強密碼和 SSL 連接

