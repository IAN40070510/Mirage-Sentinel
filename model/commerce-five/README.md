# 五分類模型服務接線

使用下載模型 run-20261028T081548514385Z，75 輪，8,014 個特徵，門檻 0.585。
來源：C:/Users/USER/Downloads/run-20261028T081548514385Z.zip。
模型保持原始檔案與雜湊，位於 model/commerce-five/run-20261028T081548514385Z/。

服務端以相同 runtime 產生 TF-IDF 與數值特徵；輸出 predicted_label、class_probabilities、model_contract、model_threshold。attack_score = 1 - P(normal)，達到模型門檻或命中現有規則即分流至 sandbox。原 features/feature_version 欄位仍是舊的 12 項監控數值，不是五分類模型輸入。

保留非同步推論、忙碌與逾時規則回退、唯讀模型掛載。未變更鑑識資料庫權限。原 model/commerce 保留；此模型仍未獨立驗證真實部署效果，不修改 bundle 中 validated_for_deployment=false。

套件已按模型版本固定。請在專案根目錄、Docker 引擎可用時執行：

```powershell
docker compose --env-file .env.commerce -f docker-compose.commerce.yml up -d --build --no-deps gateway
docker compose --env-file .env.commerce -f docker-compose.commerce.yml logs --tail 100 gateway
```

啟用前應確保既有依賴服務已運行。Gateway 受保護的 /_control/status 回應 model 欄位應為 ready_five_class；unavailable_or_incompatible 代表模型未載入、目前使用規則回退。

回復：從 artifacts/model-migration-backup-20261028T085620649653Z 還原 detection.py、requirements.txt、docker-compose.commerce.yml 並重建 gateway。原二分類目錄沒有已訓練模型，因此回復後為原規則判斷流程。

本機 Docker 引擎未啟動；本次沒有重建或重啟執行中的容器。
