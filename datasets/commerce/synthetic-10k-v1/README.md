# Commerce synthetic-10k-v1

本批為 **10,000 筆離線、確定性模板生成的候選資料**。未對本機、OCI 或第三方網站發送請求，未訓練模型。不是 10,000 次獨立人工審核，也不是實際購物流量。

| label | 筆數 |
|---|---:|
| normal | 2,000 |
| sqli | 2,000 |
| xss | 2,000 |
| cmdi | 2,000 |
| path_traversal | 2,000 |

資料只有 sample_id、template_family、request、label。沒有 source、session_id、scenario_id、annotation 或 outcome。request 的 body 為字串或 null。編號不包含類別，資料已打散。SSTI、SSRF 不包含在本批中。

## 檔案

- requests.jsonl：UTF-8 資料集，10,000 行。
- schema.json：欄位規格。
- validation.json：筆數、類別／家族統計、SHA-256、生成種子、生成程式雜湊及檢查結果。
- ../../../../scripts/generate_commerce_dataset.py：可重現的生成程式。

## 生成與檢查

種子為 20260922。從專案根目錄執行：

```text
python scripts/generate_commerce_dataset.py --output-dir datasets/commerce/reproduced-10k
python scripts/validate_commerce_dataset.py datasets/commerce/synthetic-10k-v1/requests.jsonl
```

不指定輸出位置時，生成程式依自己的檔案位置找專案根目錄，不依賴啟動目錄或 Windows 絕對路徑。已有 requests.jsonl 的位置會拒絕覆寫。

已檢查 10,000 筆欄位格式、唯一 sample_id、完全重複請求、忽略客戶端 header 並還原傳輸編碼後的重複請求，以及跨標籤相同請求衝突。生成可重現，所有類別的 method、path 和 User-Agent 分布一致。沒有 Cookie／Authorization 或 header 中的原始 CR/LF。格式以專案 Python validator 檢查，未使用第三方 JSON Schema 引擎。

相同模板的近似變形仍然存在，使用相同 template_family 標記；零完全重複不代表樣本彼此獨立，或已消除全部近似樣本。

## 使用範圍與限制

1. 標籤由生成模板指定，尚未獨立逐筆審核；不是已驗證的攻擊成功紀錄。分類依生成情境，不能將所有含可疑文字的真實輸入直接視為惡意。
2. 正常資料集中於文字搜尋、個人欄位與 metadata；包含中文、單引號、URL、合法路徑和技術詞彙，但不是完整註冊、購物車、支付、訂單流程。無結果、缺貨等結果未經執行確認。
3. 五種共用輸入位置為商品搜尋 query、會員 first_name、購物車 metadata.note、額外 filename query、x-search header。後兩者為探測載體，沒有證據顯示 Medusa 會讀取該檔案或消費該 header；未聲稱存在相應漏洞。member API 需要認證，此處不附 token；reg_PLACEHOLDER 不是有效地區 ID。
4. CMDi 僅使用輸出文字的命令字串；XSS 使用頁面標記／提示，不含資料外傳；Traversal 指向虛構 fixtures 路徑。所有內容都是字串，生成器不執行命令。
5. 每類 20% 是合成平衡配置，不代表公開網站實際攻擊比例。不得將其 precision 直接解釋為正式部署 precision。
6. 不把 sample_id、template_family 或 label 拼進模型輸入；label 是 y。分割時先按非空 template_family 和近似關聯分組，不能直接隨機按行切分。這些粗粒度家族數量有限，切分後須報告各類覆蓋，不能只換數字得到看似獨立的測試集。
7. 未保存 session_id，不能以此批資料計算真實工作階段特徵、操作序列或工作階段誤隔離率；不能從 JSONL 行序捏造時間與頻率。
8. 建議後續補實際正常操作、人工確認案例及獨立未知模板測試。只有模板合成資料無法證明實際泛化效果。
9. 現行電商推論仍為二分類／12 特徵；此五類資料不會自動改變推論程式。未新增多分類模型、混淆矩陣或準確率成績。

本批放在獨立目錄，保留 review-v1 原有 15 筆資料不變。
