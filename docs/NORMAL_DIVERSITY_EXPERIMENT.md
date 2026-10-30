# 正常情境多樣性、重新平衡與封存驗收

日期：2026-10-30。這是一個新候選模型實驗，不代表正式服務已切換。

## 固定的收集方案

- development：200 個完整流程，前 160 個 train、後 40 個 validation。
- acceptance：另一個收集命令與 60 個新流程，姓名、城市、街道、搜尋詞池與 development 不重疊。
- 變化包含商品、規格、1–4 件數量、姓名／Unicode、地址行缺省或空字串、帳單地址相同或不同、分頁、搜尋、未登入和空表單錯誤。
- 這些是實際呼叫隔離應用的腳本情境，不是真實使用者流量；不同值與新 session 不等於新的 API 類型。
- 只有預先指定的正常錯誤情境可接受 4xx。其餘流程必須成功完成訂單，5xx 不作正常樣本。

## 固定的重新平衡方案

舊 normal 中不存在的 /store/custom 不再保留；商品查詢每來源上限 train 250、validation/test 50。保留原攻擊樣本與分割，新正常流程僅進入預先指定的 train/validation。
訓練用 --balance-normal-routes：五類總權重相同，normal 各 method/路徑組總權重相同。動態購物車／訂單 ID 不會成為不同權重組。這是樣本權重，不是複製資料。
驗證的 early stopping 也使用平衡權重。固定 8,000 TF-IDF 特徵、最多 600 輪、early stopping 30 輪、以 mlogloss 選停止輪數；種子 42。
門檻只由驗證集選定，要求整體及每個有 normal 支持的路徑組 FPR <= 1%，在符合條件的門檻中選攻擊召回率最高者。

## 驗收封存

在候選模型完成後，記錄 bundle.json、protocol JSON、仍未開啟的 acceptance ZIP 的 SHA-256，形成 freeze.json。只有核對上述雜湊後，驗收工具才解壓 acceptance 並評分。
驗收不 fit、不選門檻、不根據其結果再調參。標準見 normal-acceptance-protocol-v1.json；失敗必須如實保留，服務維持 shadow。
同時報告全部流程請求，以及扣除 development 已見請求後的 unique 請求結果；相同首頁／資源重播不冒充全新請求。
舊攻擊測試集仍是診斷，不能宣稱新的未知攻擊泛化。新的正常驗收也不證明攻擊召回率。
