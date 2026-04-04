# Mirage-Sentinel RUNBOOK

本手冊用於日常運維、503 排障、資料庫遷移與攻擊事件回放。

## 1) 部署前檢查 (Preflight)

1. 確認環境變數已設定：
- `DATABASE_URL` 指向容器網路內的 `postgres` 主機（不要使用 `localhost`）。
- `HOST`、`PORT` 已符合部署平台需求。
- `DB_INIT_RETRIES`、`DB_INIT_RETRY_INTERVAL` 已設定合理值（避免 DB 啟動競態）。

2. 確認 compose 配置：
- `postgres` 服務存在且包含 healthcheck。
- 後端服務 `depends_on` 包含 `postgres`（含 health 條件）。
- 誘餌容器維持最小權限（非 root、非 privileged、盡可能 read-only）。

3. 確認 CI/CD 健康閘門：
- 部署後需驗證 `8000` 與 `8002` 的 `/healthz`。
- 失敗時必須自動輸出 compose logs。

## 2) 快速啟動 (Local)

```bash
# backend
uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# frontend
npm --prefix frontend start
```

Docker:

```bash
docker compose up --build
```

啟用 PostgreSQL profile（若專案使用該設定）：

```bash
docker compose --profile db up --build
```

## 3) 503 排障 SOP

1. 先看健康端點

```bash
curl -i http://127.0.0.1:8000/healthz
curl -i http://127.0.0.1:8002/healthz
```

2. 若健康失敗，查看容器日誌

```bash
docker compose ps
docker compose logs --tail=200 backend
```

3. 若健康成功但 Banking API 回 503，優先檢查：
- 是否啟用真實 DB 模式。
- `DATABASE_URL` 是否連到 `postgres`。
- DB schema/seed 是否完成。

4. 驗證 OpenAPI 是否可用（避免文件端失效誤判）

```bash
curl -i http://127.0.0.1:8000/openapi.json
```

## 4) DB 建置、補種與遷移

### 4.1 初始種子資料

```bash
python scripts/seed_banking_users.py --start-cif 000000001 --end-cif 000001000
```

### 4.2 以 archive 模板補種（若腳本支援）

```bash
python scripts/seed_banking_users.py --start-cif 000000001 --end-cif 000010000 --archive scripts/data/archive.zip
```

### 4.3 刷新舊資料名稱/帳戶預設值

```bash
python scripts/seed_banking_users.py --start-cif 000000001 --end-cif 000010000 --refresh-existing-names --refresh-existing-accounts
```

### 4.4 金額欄位遷移為整數

```bash
psql "$DATABASE_URL" -f scripts/postgres/migrate_money_to_integer.sql
```

遷移後檢查：
- `accounts.balance`、`transactions.amount`、`transactions.fee` 型別已為整數型別。
- 舊 `USD` 預設值已按規則正規化。

## 5) 安全不變量檢查清單

1. `traffic_logs` 為 append-only 寫入路徑，不允許 honeypot 讀改刪。
2. 時間戳記需保留毫秒或微秒精度（ISO 8601 with fractional seconds 或 ms epoch）。
3. 鑑識寫入不可阻塞 API 回應（採非同步 I/O 或訊息佇列）。
4. 誘餌容器遵守最小權限與隔離策略。

## 6) 事件回放 SOP (SOC)

1. 依時間窗查詢事件：
- 條件至少包含 `route`, `risk_score`, `deception_reason`, `timestamp`。

2. 重建攻擊鏈：
- 按 `timestamp` 排序。
- 對齊 request-id / session-id。
- 標記從 real path 轉入 deception path 的節點。

3. 產出可行動結論：
- 攻擊模式分類（身份、交易、資料層、協議、AI 代理、基礎設施）。
- 對應防禦建議與回歸測試案例。

## 7) 變更回歸最低標準

1. `/healthz`（8000/8002）均為 200。
2. `/openapi.json` 可回應且結構有效。
3. Banking 真實路徑可查詢且資料正確。
4. 可疑請求可導入 deception path 且事件有完整欄位。
5. CI 失敗時可直接從 log 定位問題。
