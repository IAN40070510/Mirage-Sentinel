# 正常購物資料修正進度

原始 1,000,000 筆池有 600,000 筆 normal，但只有 8,136 筆 POST；17 項必要正常流程缺少 11 項。
目前 560,000 筆版本的訓練集有 275,000 筆 normal，POST 只剩 2 筆；17 項必要正常流程缺少 14 項。
因此既有高分不能代表正常購物適用性，舊資料集不應再被標示為部署就緒。

已修正：
- scripts/collect_commerce_normal.py：只允許隔離 loopback，實際完成購物流程後才保存正常請求。只保存模型所需欄位，移除認證 Header，密碼／Token 替換成獨立隨機替代值。
- 每個完整流程預先指定 train/validation/test；不以個別請求隨機切分。
- scripts/audit_normal_coverage.py：檢查首頁、資源與 15 類 API 步驟。覆蓋率不是多樣性或準確率保證。
- scripts/prepare_normal_capture.py：檢查收集完成、來源雜湊、session 歸屬；完全相同的請求只保留一次；不為整數筆數複製資料。
- commerce_ml.train 新增 --allow-shared-normal-templates 明確選項。只有 normal 對 normal 的近似結構可以在報告中標示重疊；完全相同請求、session 重疊、涉及攻擊類別的近似重疊仍阻擋。預設仍嚴格阻擋。

原始完整流程另作重播驗收。常見首頁／靜態資源可能在每個流程完全相同；去重後的獨立請求測試集不一定涵蓋所有頁面，不能把流程重播視為全新請求泛化。

收集先用 30 個流程驗證可用性。這不是新 560,000 筆正式資料集；沒有宣稱資料量足夠、沒有重新訓練或開啟自動模型分流。
收集完成後先檢查來源、筆數、路徑覆蓋與重複程度，再決定擴大實際流程案例及產生新的五分類資料版本。

命令（從專案根目錄）：
```
python scripts/prepare_normal_capture.py --capture artifacts/normal-shopping-capture --output datasets/commerce/application-normal-candidates-v1
python scripts/audit_normal_coverage.py --data datasets/commerce/application-normal-candidates-v1/train --output artifacts/normal-training-coverage.json --require-complete
```

GitHub 收集產物名稱 normal-shopping-capture；下載後檢查 manifest.json 的 complete 必須為 true。
