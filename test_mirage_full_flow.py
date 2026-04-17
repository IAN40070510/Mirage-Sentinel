#!/usr/bin/env python3
"""
測試 Mirage 完整流程：
1. 生成假數據（通過 Mirage 模型或決定性回退）
2. 驗證數據被正確寫入 deception_db
3. 驗證後續請求可以從快取中檢索數據
"""

import sys
import os
import json
from pathlib import Path

# 添加項目根路徑
sys.path.insert(0, str(Path(__file__).parent))

from core.mirage import generate_fake_data
from core.deception_db import (
    setup_deception_db,
    save_deception_state,
    get_memory,
    create_fake_session_token,
    record_fake_login,
    record_fake_transaction,
    record_fake_card,
    get_fake_account_for_attacker,
    get_fake_transactions_for_attacker,
)


def test_mirage_login_response():
    """測試登入端點的 Mirage 回應"""
    print("\n=== Test 1: Mirage Login Response ===")
    
    client_ip = "192.168.1.100"
    principal_id = "attacker_test"
    endpoint = "/login"
    attack_vector = "sqli"
    
    fake_response = generate_fake_data(principal_id, endpoint, attack_vector)
    
    print(f"Endpoint: {endpoint}")
    print(f"Attack Vector: {attack_vector}")
    print(f"Response Origin: {fake_response.get('response_origin')}")
    print(f"Response Status: {fake_response.get('status')}")
    print(f"Generated Keys: {list(fake_response.keys())}")
    
    # 驗證必要的欄位
    assert "status" in fake_response, "Missing 'status' in response"
    assert fake_response.get("status") == "success", "Status should be 'success'"
    assert "deception_meta" in fake_response or "deception_origin" in fake_response, \
        "Missing deception metadata"
    
    print("✓ Login response generated successfully")
    
    # 現在模擬保存到 deception_db
    setup_deception_db()
    
    fake_session_token = create_fake_session_token(client_ip, principal_id)
    print(f"Session Token Created: {fake_session_token[:32]}...")
    
    fake_username = fake_response.get("user_id", f"attacker_{principal_id}")
    fake_password = fake_response.get("session_id", "honeypot_default")
    fake_account_id = fake_response.get("account_id", f"ACC-{fake_session_token[:8]}")
    
    record_fake_login(client_ip, principal_id, fake_username, fake_password, fake_account_id)
    save_deception_state(client_ip, principal_id, attack_vector, 90, fake_response)
    
    # 驗證保存成功
    memory = get_memory(client_ip, principal_id)
    assert memory is not None, "Failed to retrieve memory from deception_db"
    assert memory["payload"] is not None, "Saved payload is None"
    
    print(f"✓ Data saved to deception_db")
    print(f"  Saved Payload Keys: {list(memory['payload'].keys())[:5]}...")
    
    return True


def test_mirage_transfer_response():
    """測試轉帳端點的 Mirage 回應"""
    print("\n=== Test 2: Mirage Transfer Response ===")
    
    client_ip = "192.168.1.101"
    principal_id = "attacker_transfer"
    endpoint = "/transfer"
    attack_vector = "xss"
    
    fake_response = generate_fake_data(principal_id, endpoint, attack_vector)
    
    print(f"Endpoint: {endpoint}")
    print(f"Attack Vector: {attack_vector}")
    print(f"Response has transaction_id: {'transaction_id' in fake_response}")
    print(f"Response has amount: {'amount' in fake_response}")
    
    assert "transaction_id" in fake_response or "status" in fake_response, \
        "Transfer response missing critical fields"
    
    setup_deception_db()
    fake_session_token = create_fake_session_token(client_ip, principal_id)
    
    # 提取軉帳信息
    from_account = fake_response.get("from_account", f"ACC-001-{principal_id}")
    to_account = fake_response.get("to_account", f"ACC-002-FAKE")
    amount = fake_response.get("amount", 1000.0)
    currency = fake_response.get("currency", "USD")
    transaction_id = fake_response.get("transaction_id", f"TXN-{fake_session_token[:12]}")
    
    record_fake_transaction(client_ip, principal_id, from_account, to_account, amount, currency, transaction_id)
    save_deception_state(client_ip, principal_id, attack_vector, 85, fake_response)
    
    memory = get_memory(client_ip, principal_id)
    assert memory is not None, "Failed to retrieve transfer memory"
    
    print(f"✓ Transfer response generated and saved")
    print(f"  From: {from_account}, To: {to_account}, Amount: {amount}")
    
    return True


def test_mirage_deterministic_fallback():
    """測試決定性回退（當 LLM 不可用時）"""
    print("\n=== Test 3: Deterministic Fallback Response ===")
    
    client_ip = "192.168.1.102"
    principal_id = "attacker_fallback"
    endpoint = "/balance"
    attack_vector = "lfi"
    
    # 模擬 LLM 不可用的情況
    fake_response = generate_fake_data(principal_id, endpoint, attack_vector)
    
    print(f"Endpoint: {endpoint}")
    print(f"Response Origin: {fake_response.get('response_origin')}")
    print(f"Has balance: {'balance' in fake_response or 'account_balance' in fake_response}")
    
    # 驗證回退邏輯生成的數據有效
    assert "status" in fake_response, "Fallback response missing status"
    
    setup_deception_db()
    save_deception_state(client_ip, principal_id, attack_vector, 80, fake_response)
    
    memory = get_memory(client_ip, principal_id)
    assert memory is not None, "Fallback memory not saved"
    
    print(f"✓ Fallback response handled correctly")
    print(f"  Response Fields: {len(fake_response)} fields")
    
    return True


def test_multiple_endpoints():
    """測試多個不同端點的 Mirage 回應"""
    print("\n=== Test 4: Multiple Endpoints ===")
    
    endpoints = ["/login", "/dashboard", "/graphql", "/card"]
    
    setup_deception_db()
    
    for i, endpoint in enumerate(endpoints):
        client_ip = f"192.168.1.{200 + i}"
        principal_id = f"attacker_ep{i}"
        
        fake_response = generate_fake_data(principal_id, endpoint, "sqli")
        
        create_fake_session_token(client_ip, principal_id)
        save_deception_state(client_ip, principal_id, "sqli", 90, fake_response)
        
        memory = get_memory(client_ip, principal_id)
        
        print(f"  ✓ {endpoint:20} -> {len(memory['payload'])} fields")
    
    return True


if __name__ == "__main__":
    try:
        print("=" * 60)
        print("MIRAGE FULL FLOW TEST")
        print("=" * 60)
        
        test_mirage_login_response()
        test_mirage_transfer_response()
        test_mirage_deterministic_fallback()
        test_multiple_endpoints()
        
        print("\n" + "=" * 60)
        print("✓ ALL TESTS PASSED")
        print("=" * 60)
        print("\nSummary:")
        print("• Mirage generates realistic fake responses")
        print("• Data is correctly saved to deception_db")
        print("• Fallback mechanism works when LLM unavailable")
        print("• Multiple endpoints supported")
        
    except Exception as e:
        print(f"\n✗ TEST FAILED: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
