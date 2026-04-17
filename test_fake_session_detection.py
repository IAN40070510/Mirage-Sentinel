#!/usr/bin/env python3
"""
假會話檢測測試
演示攻擊者登入被 BLOCK 後，後續請求如何被假會話檢測攔截
"""

import json
import hashlib
import sys
sys.path.insert(0, ".")

from core.deception_db import (
    setup_deception_db,
    save_deception_state,
    create_fake_session_token,
    record_fake_login,
    record_fake_transaction,
    record_fake_card,
    get_fake_session,
    get_fake_account_for_attacker,
    get_fake_transactions_for_attacker,
    get_fake_cards_for_attacker,
)
from core.mirage import generate_fake_data


def test_login_attack_flow():
    """模擬登入攻擊的完整流程"""
    print("\n" + "="*60)
    print("【測試 1】登入攻擊流程")
    print("="*60)
    
    client_ip = "192.168.1.100"
    principal_id = "attacker_001"
    attack_vector = "sqli"
    risk_level = 95
    
    # 1. 初始化資料庫
    setup_deception_db()
    print(f"✓ 資料庫初始化完成")
    
    # 2. Sentinel 判斷 BLOCK
    print(f"\n【Sentinel 判斷】")
    print(f"  IP: {client_ip}")
    print(f"  Principal: {principal_id}")
    print(f"  Attack Vector: {attack_vector}")
    print(f"  Decision: BLOCK (攻擊等級 {risk_level}/100)")
    
    # 3. Mirage 生成虛假回應
    print(f"\n【Mirage 生成虛假回應】")
    fake_response = generate_fake_data(principal_id, endpoint="/login", attack_vector=attack_vector)
    print(f"  回應內容: {json.dumps(fake_response, ensure_ascii=False, indent=2)}")
    
    # 4. 創建假會話令牌
    print(f"\n【創建假會話令牌】")
    fake_session_token = create_fake_session_token(client_ip, principal_id)
    print(f"  會話令牌: {fake_session_token}")
    
    # 5. 記錄虛假登入
    print(f"\n【記錄虛假登入信息】")
    fake_username = fake_response.get("user_id", f"attacker_{principal_id}")
    fake_password = fake_response.get("password", "honeypot_password123")
    fake_account_id = f"ACC-001-{hashlib.sha256(client_ip.encode()).hexdigest()[:8]}"
    
    record_fake_login(client_ip, principal_id, fake_username, fake_password, fake_account_id)
    print(f"  ✓ 記錄用戶名: {fake_username}")
    print(f"  ✓ 記錄密碼: {fake_password}")
    print(f"  ✓ 記錄帳號ID: {fake_account_id}")
    
    # 6. 保存欺敵狀態
    save_deception_state(client_ip, principal_id, attack_vector, risk_level, fake_response)
    print(f"  ✓ 保存欺敵狀態")
    
    # 7. 返回虛假登入回應給攻擊者
    login_response = {
        "status": "success",
        "message": "Login successful",
        "session_token": fake_session_token,
        "user_id": fake_username,
        "account_id": fake_account_id,
    }
    print(f"\n【返回給攻擊者的登入回應】")
    print(f"  {json.dumps(login_response, ensure_ascii=False, indent=2)}")


def test_subsequent_request_detection():
    """測試後續請求的假會話檢測"""
    print("\n" + "="*60)
    print("【測試 2】後續請求的假會話檢測")
    print("="*60)
    
    client_ip = "192.168.1.100"
    principal_id = "attacker_001"
    
    # 1. 攻擊者使用 session_token 進行後續請求
    print(f"\n【攻擊者發送後續請求】")
    fake_session = get_fake_session(client_ip, principal_id)
    if fake_session:
        fake_session_token = fake_session.get("fake_session_token")
        print(f"  HTTP Header: X-Mirage-Session: {fake_session_token}")
        print(f"  Engagement Level: {fake_session.get('engagement_level')}")
        
        # 2. 系統檢測到假會話
        print(f"\n【系統檢測到假會話】")
        print(f"  ✓ 找到匹配的會話令牌")
        print(f"  ✓ 檢查客戶端 IP: {client_ip}")
        print(f"  ✓ 檢查主要標識: {principal_id}")
        
        # 3. 檢索快取的虛假數據
        print(f"\n【檢索虛假數據】")
        fake_account = get_fake_account_for_attacker(client_ip, principal_id)
        if fake_account:
            print(f"  ✓ 找到虛假帳戶:")
            print(f"    - Username: {fake_account.get('username')}")
            print(f"    - Account ID: {fake_account.get('account_id')}")
        
        # 4. 返回快取的虛假響應
        cached_response = {
            "status": "success",
            "response_origin": "deception_cache",
            "message": "Retrieved from deception cache",
            "account_id": fake_account.get('account_id'),
            "balance": 50000.0,
        }
        print(f"\n【返回快取的虛假回應】")
        print(f"  {json.dumps(cached_response, ensure_ascii=False, indent=2)}")


def test_fake_transaction_recording():
    """測試虛假轉帳記錄"""
    print("\n" + "="*60)
    print("【測試 3】虛假轉帳記錄")
    print("="*60)
    
    client_ip = "192.168.1.100"
    principal_id = "attacker_001"
    
    print(f"\n【攻擊者發送轉帳請求】")
    print(f"  POST /transfer")
    print(f"  from_account: ACC-001-12345")
    print(f"  to_account: ACC-999-ATTACKER")
    print(f"  amount: 10000")
    
    # 記錄虛假轉帳
    transaction_id = f"TXN-{hashlib.sha256(client_ip.encode()).hexdigest()[:12]}"
    record_fake_transaction(
        client_ip=client_ip,
        principal_id=principal_id,
        from_account="ACC-001-12345",
        to_account="ACC-999-ATTACKER",
        amount=10000.0,
        currency="USD",
        transaction_id=transaction_id,
        status="completed"
    )
    print(f"\n【系統記錄虛假轉帳】")
    print(f"  ✓ Transaction ID: {transaction_id}")
    print(f"  ✓ Status: completed")
    
    # 檢索轉帳歷史
    print(f"\n【攻擊者查詢交易歷史】")
    txns = get_fake_transactions_for_attacker(client_ip, principal_id)
    for txn in txns:
        print(f"  - {txn['transaction_id']}: {txn['from_account']} → {txn['to_account']} ({txn['amount']} {txn['currency']})")


def test_fake_card_recording():
    """測試虛假卡片記錄"""
    print("\n" + "="*60)
    print("【測試 4】虛假卡片記錄")
    print("="*60)
    
    client_ip = "192.168.1.100"
    principal_id = "attacker_001"
    
    print(f"\n【攻擊者添加虛假卡片】")
    
    record_fake_card(
        client_ip=client_ip,
        principal_id=principal_id,
        card_number="4111111111111111",
        card_holder="Attacker Name",
        expiry="12/28",
        cvv="123",
        card_type="VISA"
    )
    print(f"  ✓ 記錄卡片: 4111111111111111")
    
    # 檢索卡片列表
    print(f"\n【系統返回卡片列表】")
    cards = get_fake_cards_for_attacker(client_ip, principal_id)
    for card in cards:
        print(f"  - {card['card_number']}: {card['card_holder']} ({card['expiry']})")


if __name__ == "__main__":
    print("\n" + "█"*60)
    print("█  假會話檢測系統測試")
    print("█"*60)
    
    try:
        test_login_attack_flow()
        test_subsequent_request_detection()
        test_fake_transaction_recording()
        test_fake_card_recording()
        
        print("\n" + "█"*60)
        print("█  所有測試完成！✓")
        print("█"*60 + "\n")
    except Exception as e:
        print(f"\n❌ 測試失敗: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
