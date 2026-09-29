# 電商資料儲存

| 服務 | 資料卷 | 內容 |
| --- | --- | --- |
| real-db | real_data | 正式 Medusa PostgreSQL |
| sandbox-db | sandbox_data | 沙盒 Medusa PostgreSQL |
| gateway | visitor_state | /state/visitors.db：訪客與隔離狀態 |
| collector | forensics | /forensics/events.db：append-only 鑑識事件 |
| mirage | mirage_memory | /memory/mirage.db：欺敵記憶 |

Compose project name 為 mirage-commerce，資料卷加此前綴。現有服務與卷名稱維持相容；改名可能建立新的空資料卷。

首次使用 scripts/prepare_commerce.py 產生私有憑證，再執行 scripts/deploy_commerce.py --build --initialize。正式與沙盒使用不同資料庫及憑證。

誘餌不可讀取鑑識庫；Gateway 使用非同步提交，SOC 使用唯讀查詢。事件保留毫秒精度。不要把舊鑑識庫掛回誘餌容器。

PostgreSQL 使用 pg_dump/pg_dumpall；運作中的 SQLite 使用 backup API，不單獨複製可能依賴 WAL 的 .db。應另行測試還原；應用程式回退不會自動回退 schema。

原始碼清理不刪除 OCI 銀行資料庫、Redis、上傳檔案、資料卷或 /home/ubuntu/db-backups。這些資料由管理者另行管理。
