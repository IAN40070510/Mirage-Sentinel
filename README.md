# Mirage-Sentinel 電商主動防禦系統

保護 Medusa DTC Starter 購物網站及電商 API。Gateway 評估請求，正常訪客進入正式商店，可疑訪客進入獨立沙盒商店。Mirage 提供電商 JSON 欺敵回應，Collector 保存正常及可疑互動供戰情室查詢。

## 現行入口

| 功能 | 程式 |
| --- | --- |
| 商店與 API | commerce/apps/storefront、commerce/apps/backend |
| 流量判斷與分流 | services/commerce/gateway.py、detection.py |
| 訪客持久狀態 | services/commerce/state.py |
| 欺敵回應 | services/commerce/mirage.py |
| 非同步鑑識提交 | services/commerce/audit.py |
| 鑑識儲存與戰情室 | services/commerce/collector.py、soc.html |
| Docker 編排 | docker-compose.commerce.yml |

正式與沙盒使用不同 PostgreSQL、JWT/Cookie secrets 與隔離網路。誘餌不掛載鑑識卷；Collector 寫入端與 SOC 讀取端分別驗證權限，事件禁止 UPDATE/DELETE。訪客及 Mirage 記憶使用 30 天期限；不代表所有資料庫都自動刪除 30 天前的資料。

## 本機啟動

需要 Docker Compose（plugin 或 docker-compose 執行檔）、Python 3.11+。首次設定：

```bash
python scripts/prepare_commerce.py
python scripts/deploy_commerce.py --build --initialize
python scripts/wait_commerce.py
python scripts/smoke_commerce.py
```

prepare_commerce.py 不覆寫既存 .env.commerce。購物網站預設 http://localhost:8080；SOC 為 3000 埠且要求登入；管理 API 僅綁定本機 9100 埠。帳密在私有 .env.commerce，不要提交或貼入聊天。

明確指定 Compose 與環境檔：

```bash
docker compose --env-file .env.commerce -f docker-compose.commerce.yml ps
```

舊預設 docker-compose.yml 與銀行入口已移除。更新只應操作 mirage-commerce 專案，不要對正式資料執行 down -v 或 volume prune。

## OCI 與 GitHub Actions

main 更新由 deploy.yml 先執行 commerce-ci.yml 的 ARM 測試與 Docker 購物/隔離驗證，再以 SSH 部署指定 commit。post-deploy-smoke.yml 檢查公開首頁與 /store/regions。

部署只管理電商服務及前一個電商 release 的應用程式復原，不再啟停銀行容器。使用前需確認 80/3000 埠未被其他服務占用。銀行資料卷及 OCI 的 db-backups 不由本專案清理。

## 模型與資料集

目前 model/commerce 沒有訓練好的 xgb.json，Gateway 使用規則判斷。XGBoost 契約仍為二分類、12 特徵；五類資料集不等於完成五分類訓練。

datasets/commerce 及生成、驗證、品質檢查程式保留。model/Sentinel、model/Mirage 是歷史研究成果，不參與電商映像；不可把舊 pickle 前處理器接回 Gateway。歷史依賴在 model/legacy-requirements.txt，請使用獨立研究環境。

## 驗證

```bash
python -m pip install -r requirements.txt -r deploy/commerce/requirements-test.txt
python -m pytest tests -q
```

文件索引見 docs/README.md，操作見 docs/RUNBOOK.md，資料庫見 DATABASE_SETUP.md。歷史報告描述當時狀態，不是目前啟動指令。
