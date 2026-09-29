# Commerce curated-100k-v1

## 使用哪一份

**requests.jsonl 是整合完成的 100,000 筆，不要再把它與舊批次或 new-records.jsonl 串接。**

| 檔案 | 內容 |
|---|---|
| requests.jsonl | 完整十萬筆整合版，已打散 |
| new-records.jsonl | 整合版中的 98,807 筆新資料子集合，不是額外資料 |
| schema.json | 四欄位格式規範 |
| validation.json | 舊檔雜湊、保留／排除數量、類別／家族／位置分布、獨立檢查 |

normal、sqli、xss、cmdi、path_traversal **各 20,000 筆**。每筆只有 sample_id、template_family、request、label；沒有 source、session_id、annotation、scenario_id、outcome。

## 舊資料如何處理

原有 review-v1、synthetic-10k-v1、synthetic-10k-v2 共 20,015 筆。這次以更嚴格的結構規則分組，只保留 1,193 個代表，其餘 18,822 筆未納入新整合版。原始三份資料完全保留，SHA-256 已重新確認。

上述 18,822 是「啟發式結構等價」的變形，不表示它們是逐字重複，或具有完全相同的執行效果。舊批次的完全重複檢查並沒有檢查所有名稱替換；本次補強了這個缺口。

保留的舊樣本：normal 217、sqli 227、xss 221、cmdi 217、path_traversal 311。新增：normal 19,783、sqli 19,773、xss 19,779、cmdi 19,783、path_traversal 19,689。

## 排重規則

1. 完整 canonical HTTP 請求排重，sample_id 等管理欄位不參與比較。
2. 對新資料與舊資料另做先前的傳輸／大小寫／數字正規化比較。
3. 新增結構指紋：解析 query 和 JSON；最多還原三層百分比編碼；忽略 User-Agent 等客戶端背景 header；保留輸入用 Referer／x-search；匿名化資源 ID；遮掉一般詞彙、名稱及數字；保留 JSON 鍵、陣列結構、語法符號及有限的 SQL／HTML／Shell 文法詞彙。
4. 在同一結構組內只保留一筆；結構相同但標籤不同的舊組應全部隔離，本次舊資料沒有這類衝突。

獨立重新檢查十萬筆通過：完整重複 0、上述結構重複 0、重複 ID 0；98,807 筆新資料與所有舊資料的完整／正規化／結構重複均為 0。JSON body、禁止欄位、Header 換行、可重用認證 header 也已檢查。更換名稱、數字、資源 ID、query 編碼及 User-Agent 的正規化回歸案例通過。

**此指紋不是形式化語意分析。** 它可能把不同情境合併，也可能漏掉其他形式的近似。零指紋重複不等於十萬個獨立、真實或同等重要的攻擊情境。

## 多樣性來源

本批在 16 類操作位置組合內容：商品／商品集合／分類搜尋、會員姓名／metadata／建立會員、會員地址、收件／帳單、優惠碼、購物車巢狀內容、新增／更新商品項目、配送方式資料、建立購物車。

請求結構包含 query 選填欄位、多層 JSON、陣列、不同輸入欄位，以及 gift_wrap、delivery_note、gift_message、packaging、contact_preferences、personalization、gift_recipients、preferences 的組合。選填欄位最多形成 256 種配置，這是擴充數量的重要來源，並非全部來自新增攻擊機制。

內容包含正常多語言與合法技術文字，以及 Boolean／Union／子查詢／條件 SQL、不同 HTML／JS 上下文、Shell 分隔／群組／替換、POSIX／Windows／混合與編碼路徑。既有機制沿用相同 template_family；沒有用每筆唯一家族名稱掩蓋近似關係。

## 不應如何解讀這批資料

- 這是由程式模板與欄位組合產生的候選資料，不是十萬次獨立 LLM 推理或人工審核。
- 新增的選填 metadata 可能完全不被 Medusa 商業邏輯使用。欄位差異可使結構不同，但不一定增加同等的學習價值；應做含／不含此類選填欄位的消融比較。
- 正常欄位有自由文字與完整句子，有些未必像真實姓名或實際會員輸入。資料仍需要真人操作補充與抽樣品質審核。
- API 形狀來自既有專案流程，但未逐筆對實際 Medusa schema、認證或業務狀態驗證；部分選填參數或 metadata 可能被拒絕／忽略。placeholder ID、虛構帳號與配送方式都不是可直接使用的真實資源。
- 沒有發送請求、完成下單、讀取正式資料庫或執行攻擊字串。攻擊標籤代表預設情境中的嘗試，不聲稱利用成功。
- 每類 20% 為人工平衡配置，不代表實際攻擊比例。不得把此資料上的 precision 直接視為正式部署 precision。
- 不依據 User-Agent 或任意 metadata 假設資料沒有來源偏差；本批保留分布供後續檢查，沒有宣稱完全消除捷徑。
- 未保留工作階段 ID／時間序列，不能從行序製造頻率、回訪、交易狀態或工作階段指標。

## 訓練之前

先把 template_family 與近似關聯分組再切分，不可直接隨機按行切分。還應對大量共用選填配置與同一生成配方進行更保守的隔離測試。保留完全獨立的實際操作測試集；不要把本批規模當作泛化證據。

label 是 y；sample_id、template_family 不得放入 X。現有 commerce 二分類／12 特徵程式不會自動因為此資料變成五分類。本次沒有訓練模型、產生混淆矩陣或準確率，也沒有推送／部署。

## 重現

生成器：專案根目錄下 scripts/build_commerce_100k.py。使用 pathlib，預設輸出依程式位置解析，支援 --output-dir／--seed，拒絕覆寫既有資料夾。

種子：2026092301。重現需使用 validation.json 列出的三份舊資料快照，不要讓整合版也被自動掃描成舊資料。紀錄了執行時與格式整理後的生成程式 SHA-256；兩者只差集合 literal 格式。亦需使用相同版本的 expand_commerce_dataset.py、generate_commerce_dataset.py 和 validate_commerce_dataset.py。

輸出檔 UTF-8；資料檔不包含訓練電腦路徑。所有時間紀錄含毫秒。
