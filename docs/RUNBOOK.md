# 電商操作指南

在專案根目錄執行，Compose 使用 docker-compose.commerce.yml、環境檔使用私有 .env.commerce。主機僅安裝 docker-compose 時替換下列 docker compose。

```bash
docker compose --env-file .env.commerce -f docker-compose.commerce.yml ps
docker compose --env-file .env.commerce -f docker-compose.commerce.yml logs --tail 100 gateway collector mirage
```

不要公開完整日誌中的請求、Cookie 或 token。Gateway、Collector、Mirage 為不同服務，不使用已移除的 main.py、sandbox_service.py 或銀行路由。

本機首次啟動順序：prepare_commerce.py → deploy_commerce.py --build --initialize → wait_commerce.py → smoke_commerce.py。smoke 會產生購物及攻擊測試，應用於隔離驗證環境。公開站台唯讀檢查由 post-deploy-smoke.yml 執行。

OCI main 部署通過 ARM CI 後在 release 目錄執行。保留共享 .env.commerce、commerce-current-release 與資料卷。SOC 為 3000 埠，管理端僅綁定 127.0.0.1:9100。銀行容器不再由部署腳本啟停；有其他服務占用埠時須先辨识，不可直接刪除容器資料。

更新失敗且存在前一個電商 release 時，腳本恢復應用映像；不能保證新 schema 可被舊程式使用。資料庫遷移前應備份並確認相容性。preview 與正式更新共用電商資料卷，不是資料庫副本。

不要以 down -v 或 volume prune 作一般更新。銀行原始碼清理與雲端資料退役分開處理，刪除資料前須驗證備份還原。
