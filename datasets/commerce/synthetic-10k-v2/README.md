# Commerce synthetic-10k-v2

新增 10,000 筆離線合成候選資料，normal、sqli、xss、cmdi、path_traversal 各 2,000 筆。先前 synthetic-10k-v1 的 10,000 筆與 review-v1 的 15 筆保留不變；合計 20,015 筆。未發送任何請求、未訓練或部署。

每筆只包含 sample_id、template_family、request、label。所有類別已打散；不含 source、session_id、annotation、scenario_id、outcome。請求中的路徑是 HTTP 路徑，沒有綁定訓練電腦目錄。

## 相對第一批的新增面向

| 面向 | 本批內容 |
|---|---|
| 商品查詢 | 搜尋搭配 fields、排序及分頁；排序欄位注入嘗試 |
| 結帳資料 | 收件 company、帳單 address_2、會員地址等巢狀欄位 |
| 優惠碼 | promo_codes 陣列中的合法代碼與注入內容；不聲稱真有此優惠 |
| 商品項目 | variant、quantity、刻字 metadata 與 gift_wrap 的組合 |
| 巢狀內容 | 會員 preferences、購物車 gift.messages 陣列 |
| Header | Referer 中的 query；不代表應用程式會把它用於 SQL 或渲染 |
| 正常文字 | 中文、日文、韓文、阿拉伯文、法文、德文、葡萄牙文、emoji、商店名稱、送貨／包裝需求及合法技術詞彙 |
| SQLi | LIKE、IN、NULL、COALESCE、NULLIF、CAST、CONCAT、CTE、VALUES、字串串接等唯讀探測形式 |
| XSS | textarea／style／title 等上下文跳脫、script 字串跳脫、attribute 跳脫、media／click／pointer 事件 |
| CMDi | 命令群組、子 shell、process substitution、IFS、換行延續、Windows 命令群組；只輸出標記文字 |
| Traversal | 嵌套目錄超界、混合分隔、編碼層次、點路徑與部分解析器相依探測；只指向虛構 fixtures |

每類覆蓋相同 10 種請求位置，每個位置 200 筆。method、path、User-Agent、Accept-Language 的聯合分布也一致，降低這些背景因素造成的類別捷徑。這不保證消除所有合成資料偏差。

## 不重複的定義與證據

生成前載入專案 datasets 下所有既有 requests.jsonl。validation.json 記錄本次比較的兩份先前檔案及 SHA-256。排除：

1. 相同 canonical request（不看 sample_id、label 等管理欄位）。
2. 忽略 User-Agent 等客戶端身分 header、解析 query／JSON、還原最多三層百分比編碼、忽略大小寫、抹除數字值與數字字串後相同的請求。Referer 和 x-search 等輸入載體仍保留。
3. 本批內同樣的重複與跨批 sample_id 衝突。

獨立重算檢查通過：本批內及與先前 10,015 筆之間，完全重複與上述正規化重複皆為 0；舊檔案雜湊未改變。

**這不是完整的語意等價判定，也不是 10,000 種不同攻擊機制。** 模板變形仍然存在；新增上下文、不同字詞或不同語法也可能非常近似。共用 v1 家族名稱以保留跨批分組，不會因為換了欄位就聲稱是獨立測試家族。只有新增機制才使用新家族名稱。

## 使用限制

- 標籤來自生成模板，尚未獨立逐筆審核。SQLi／XSS／CMDi 等標籤只表示探測意圖，不表示 Medusa 存在相應漏洞。
- reg_PLACEHOLDER、cart_PLACEHOLDER、variant_PLACEHOLDER 都是佔位值；會員與購物车操作未提供實際登入憑證。正常資料包含購物流程相關請求形狀，但不是已完成結帳的真實軌跡。
- 任意 metadata／Referer 不一定被網站用於執行或顯示；解析器相依的 Traversal 未經環境驗證。不可把這些內容直接當成成功利用樣本。
- 加號／百分比編碼、HTML／JS 片段是字串；生成程式不執行系統命令、不讀正式資料庫，也不連線送出攻擊。
- 欄位值仍存在模板化與詞彙重複。平衡的每類 20% 不代表上線流量比例；合併訓練後仍需要獨立實際操作資料評估。
- 先合併相同 template_family 和近似關係再切分訓練／驗證／測試，不把第二批直接當作全新獨立測試集。sample_id、template_family、label 不可當成輸入特徵；label 是答案 y。
- 未收集 session_id 或真實時間序列，不能從行序生成請求頻率、回訪或工作階段統計。

## 檔案與重跑

- requests.jsonl：新增 10,000 筆。
- schema.json：欄位規格。
- validation.json：雜湊、類別／家族／位置統計、舊檔比較資訊與檢查結果。
- scripts/expand_commerce_dataset.py（相對專案根目錄）：本批生成程式。

檢查：`python scripts/validate_commerce_dataset.py datasets/commerce/synthetic-10k-v2/requests.jsonl`

生成器預設目錄依程式位置解析，支援 --output-dir 與 --seed。拒絕覆寫已存在資料。輸出由種子、程式版本及當時既有資料共同決定；再跑新目錄時會把本批也列入排重，所以不能只憑同一種子期待重建完全相同檔案。需要重現時使用 validation.json 指定的先前資料快照。
