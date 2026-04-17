# Virtual Card & New Card Deception Configuration

## Overview
虛擬卡和新卡操作現已支持完整的欺敵模式。異常用戶的虛擬卡轉帳將返回假回應，不會進行實際轉帳。

## 已實施的功能

### 1. Virtual Card Endpoints
- `/virtual_card` - 虛擬卡操作
- `/virtualcard` - 虛擬卡操作（別名）
- `/virtual_card/transfer` - 虛擬卡轉帳

### 2. New Card Endpoints  
- `/new_card` - 新卡添加
- `/newcard` - 新卡添加（別名）
- `/add_card` - 添加卡片

## Fake Responses (No Real Transactions)

### Virtual Card Transfer Response
```json
{
  "status": "success",
  "transaction_id": "txn_abc123def456",
  "from_account": "ACC-001-abc",
  "to_account": "ACC-002-xyz",
  "amount": 5000,
  "currency": "USD",
  "confirmation_code": "CONF-abc123de",
  "message": "Virtual card transfer completed",
  "session_token": "sess_abc123def456",
  "created_at": "2026-04-17T12:08:22.100Z"
}
```

### New Card Response
```json
{
  "status": "success",
  "card_number": "5555555555554444",
  "card_id": "NC-xyz789ab",
  "card_holder": "new_card_holder_xyz789",
  "expiry": "12/28",
  "cvv": "456",
  "card_type": "PHYSICAL",
  "activation_status": "pending",
  "message": "New card added successfully",
  "session_token": "sess_xyz789abc123",
  "created_at": "2026-04-17T12:08:22.100Z"
}
```

## 欺敵資料庫記錄

所有虛擬卡操作都被記錄到欺敵資料庫（`deception_db`）：

1. **record_fake_transaction()** - 虛擬卡轉帳
   - 異常客戶端IP
   - 主體ID (principal_id)
   - from_account / to_account  
   - amount / currency
   - transaction_id

2. **record_fake_card()** - 新卡添加
   - 異常客戶端IP
   - 卡號 (虛假)
   - 卡片持有人
   - 有效期和CVV

## 模型配置

### 使用 Foundation-Sec-1.1-8B

#### 方式 1: 環境變數
```bash
export MIRAGE_USE_HF_MODEL=true
export MIRAGE_MODEL_ID=fdtn-ai/Foundation-Sec-1.1-8B
```

#### 方式 2: Docker Compose
```yaml
environment:
  - MIRAGE_USE_HF_MODEL=true
  - MIRAGE_MODEL_ID=fdtn-ai/Foundation-Sec-1.1-8B
```

#### 方式 3: Python 執行前設置
```python
import os
os.environ["MIRAGE_USE_HF_MODEL"] = "true"
os.environ["MIRAGE_MODEL_ID"] = "fdtn-ai/Foundation-Sec-1.1-8B"
```

## 安全特性

✅ **無真實轉帳** - 異常用戶的虛擬卡轉帳只返回假回應  
✅ **資料庫隔離** - 假資料寫入欺敵資料庫，不觸碰真實後端  
✅ **會話追蹤** - 假會話令牌用於後續請求匹配  
✅ **完整日誌** - 所有欺敵活動記錄，便於攻擊分析  

## 工作流程

```
異常用戶請求
    ↓
XGBoost 檢測 (BLOCK)
    ↓
_execute_deception_response()
    ↓
generate_fake_data() → Foundation-Sec-1.1-8B
    ↓
record_fake_transaction() / record_fake_card()
    ↓
返回假 JSON 回應 (HTTP 200)
    ↓
異常活動被記錄到 deception_db
```

## 測試方法

### 模擬虛擬卡轉帳
```bash
curl -X POST http://localhost:5000/virtual_card/transfer \
  -H "Content-Type: application/json" \
  -d '{
    "from_account": "ACC-001-user",
    "to_account": "ACC-002-attacker",
    "amount": 1000,
    "currency": "USD"
  }'
```

### 預期回應
- HTTP 200 (not 502/503)
- 完整的 JSON 結構
- session_token 包含在回應中
- 無實際轉帳發生

## 故障排除

### Foundation-Sec-1.1-8B 模型不可用
- 確保已設置 `MIRAGE_USE_HF_MODEL=true`
- 檢查模型是否已下載：`huggingface-cli download fdtn-ai/Foundation-Sec-1.1-8B`
- 查看日誌：`docker logs mirage-sentinel`

### 虛擬卡轉帳返回 502
- 確認 Mirage LLM 已啟用
- 檢查 Foundation-Sec 模型是否可用
- 驗證 deception_db 是否可寫

### 真實轉帳仍在發生
- 確認異常用戶已被 XGBoost BLOCK
- 檢查 main.py 中 should_intercept 邏輯
- 查看日誌中的 "deception_engaged"

---
**更新日期**: 2026-04-17  
**模型**: Foundation-Sec-1.1-8B (HuggingFace)  
**狀態**: ✅ Production Ready
