# Commerce curated-300k-v1

## 使用方式與內容

**requests.jsonl 是完整 300,000 筆整合版；不要再與十萬筆或 new-records.jsonl 串接。**

| 類別 | 保留十萬筆中的資料 | 本次新增 | 整合後 |
|---|---:|---:|---:|
| normal | 20,000 | 40,000 | 60,000 |
| sqli | 20,000 | 40,000 | 60,000 |
| xss | 20,000 | 40,000 | 60,000 |
| cmdi | 20,000 | 40,000 | 60,000 |
| path_traversal | 20,000 | 40,000 | 60,000 |
| 合計 | 100,000 | 200,000 | 300,000 |

只有 sample_id、template_family、request、label 四個欄位。沒有 source、session_id、annotation、scenario_id、outcome。request 內仍包含 method、path、query、headers、body。沒有 SSTI 或 SSRF 類別。

- requests.jsonl：已打散的完整整合版。
- new-records.jsonl：本次 200,000 筆新增資料的子集合，方便追查，不是額外資料。
- schema.json：欄位格式規範。
- validation.json：生成資訊、來源快照、雜湊、分布及獨立驗證結果。

十萬筆中的每筆 sample_id、template_family、request、label 原樣保留，僅整合排列順序改變。review-v1 與前兩批一萬筆已經是十萬筆整合時的來源，**其檔案筆數不能再累加**。全部舊檔原樣保留。

## 本次擴充

沿用 16 種操作情境，新增 24 種，共 40 種：

- 會員地址的姓名、街道、第二地址與城市；既有地址更新。
- 收件與帳單地址各欄位，以及建立購物車時的收件／帳單資料。
- 建立購物車時附帶初始商品項目和商品 metadata。
- 商品客製化陣列、會員多層偏好設定、多收件人禮物訊息。
- 配送方式 data 中的收件指示、修改商品項目時的個人化資料。
- 原有商品搜尋、集合與分類查詢、會員資料、優惠碼、購物車及商品項目操作。

攻擊內容包含不同 SQL 表達式、HTML／JavaScript 注入上下文、Shell 群組／替換，以及 POSIX／Windows／混合路徑。新增語法仍沿用適當的機制家族名稱，不能因換欄位或批次就當成獨立家族。

**規模的重要來源仍是語法、欄位位置與合法選填 metadata 配置的組合。** 這不是三十萬種獨立攻擊機制，也不是三十萬筆人工審核的實測流量。

## 排重與驗證

scripts/verify_commerce_300k.py 以串流方式重新讀取輸出檔案，檢查：

1. 完整請求、正規化請求、啟發式結構指紋及 sample_id 重複。
2. 新增資料與十萬筆及更早快照間的相同檢查。
3. 十萬筆中每一筆是否在新整合版完整保留，並逐筆比較內容。
4. new-records.jsonl 是否恰好對應整合版新增的二十萬筆，包含內容一致性。
5. 五類筆數、四欄位契約、JSON body、Header 換行與認證 header。
6. 舊資料快照、生成檔案與程式 SHA-256。
7. 更換名稱／數字／資源 ID／query 編碼／User-Agent 不會成為新結構的回歸案例。

結構規則沿用十萬筆版本：遮罩一般名稱與數字、匿名化常見資源 ID、解析 query／JSON、最多三層百分比解碼，保留資料鍵、巢狀形狀、語法符號及有限文法詞彙。忽略客戶端身分 header，但保留 Referer／x-search 輸入載體。

這不是完整語意等價判定，可能漏掉其他近似或把不同情境合併。**零指紋重複不能解釋為零相關性。**

## 選填欄位移除診斷

validation.json 的 metadata_ablation_diagnostic 額外移除八種頂層 metadata／data 欄位：gift_wrap、delivery_note、gift_message、packaging、contact_preferences、personalization、gift_recipients、preferences，再計算核心結構數及同結構最高重複量。

本次結果：整合版為 33,483 種核心結構，同一核心最多對應 209 筆；新增部分為 17,749 種核心結構。這項檢查揭露「移除背景選填欄位後，有多少樣本仍相似」，不是模型準確率，也不是完整攻擊機制計數。應結合 template_family 和近似關聯做更保守的切分／消融實驗，不能只根據三十萬筆總量宣稱泛化能力。

## 重要限制

- 本批純離線合成，執行請求數為 0；沒有完成真實下單、攻擊或驗證漏洞。
- 標籤由生成情境指定，未獨立逐筆審核。正常文字有些放在姓名等字串欄位中，雖不含攻擊意圖，也未必符合真實買家的輸入分布。
- 任意 metadata 或 provider data 不一定被應用程式使用；實際 API 可能忽略或拒絕某些欄位／組合。未逐筆做 Medusa schema、認證、資源存在與交易狀態驗證。
- ID、email、地址及優惠碼都是測試值／佔位值。沒有實際 Cookie／Authorization。攻擊字串僅是資料，不會被生成程式執行。
- 保持分類筆數平衡不代表真實流量中每類占 20%；正常誤報率與部署 precision 須另外用實際分布評估。
- 資料沒有工作階段與真實時間序列，不能從打散後的行序計算頻率、回訪或下單操作順序。
- 同一 template_family 與近似變形不得任意散到訓練／驗證／測試。大量背景欄位組合應納入更保守的分組；測試集另外保留真實操作與未見機制。
- label 是訓練答案 y，sample_id／template_family 不能當成模型特徵。現有二分類推論介面不會因資料增多而自動變成五分類。

本次沒有訓練模型、產生混淆矩陣、推送 GitHub 或部署 OCI。

## 重現與可攜性

生成器：scripts/build_commerce_300k.py；驗證器：scripts/verify_commerce_300k.py。種子 2026092302。使用明確的四份歷史快照路徑，避免把整合資料重複當作不同來源。完整依賴程式與快照雜湊記錄於 validation.json。

從專案根目錄執行驗證：

```text
python scripts/verify_commerce_300k.py
```

生成器支援 --output-dir／--seed，拒絕覆寫已存在的輸出目錄。預設路徑依程式檔案位置解析，不依賴執行目錄或 Windows 絕對路徑。資料檔 UTF-8，紀錄時間包含毫秒。不使用 pickle，也不連線存取正式／沙盒／鑑識資料庫。

## 便於搬移的壓縮檔

commerce-300k-v1.zip 只含 requests.jsonl、schema.json、validation.json、README.md。未放入 new-records.jsonl，以免解壓後誤將子集合再次合併。
