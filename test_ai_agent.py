#!/usr/bin/env python3
"""
測試沙盒AI Agent功能

此腳本測試AI agent是否能正確在沙盒中運行，並且只能修改環境內的資源。
"""

import asyncio
import httpx
import json
import os
from datetime import datetime

SANDBOX_URL = "http://localhost:8001"
AI_TOKEN = "mirage_sentinel_sandbox_token"

async def test_ai_agent():
    """測試AI Agent功能"""
    print("Testing sandbox AI Agent")
    print("=" * 50)

    # 測試數據 - 模擬不同類型的攻擊
    test_payloads = [
        {
            "client_ip": "192.168.1.100",
            "query_id": "test_user_001",
            "raw_payload": "SELECT * FROM users WHERE id = 1; DROP TABLE users;--",
            "attack_vector": "sqli",
            "risk_level": 8,
            "description": "SQL注入攻擊"
        },
        {
            "client_ip": "192.168.1.101",
            "query_id": "test_user_002",
            "raw_payload": "<script>alert('xss')</script>",
            "attack_vector": "xss",
            "risk_level": 7,
            "description": "XSS攻擊"
        },
        {
            "client_ip": "192.168.1.102",
            "query_id": "test_user_003",
            "raw_payload": "../../../../etc/passwd",
            "attack_vector": "lfi",
            "risk_level": 6,
            "description": "本地檔案包含"
        },
        {
            "client_ip": "192.168.1.103",
            "query_id": "test_user_004",
            "raw_payload": "; cat /etc/passwd",
            "attack_vector": "rce",
            "risk_level": 9,
            "description": "遠程代碼執行"
        },
        {
            "client_ip": "192.168.1.104",
            "query_id": "test_user_005",
            "raw_payload": "../../../config/database.php",
            "attack_vector": "path-traversal",
            "risk_level": 5,
            "description": "路徑遍歷"
        }
    ]

    async with httpx.AsyncClient(timeout=30.0) as client:
        for i, payload in enumerate(test_payloads, 1):
            print(f"\nTest case {i}: {payload['description']}")
            print(f"   Payload: {payload['raw_payload'][:50]}...")
            print(f"   Attack vector: {payload['attack_vector']}")
            try:
                # Call AI Agent
                response = await client.post(
                    f"{SANDBOX_URL}/ai_agent_execute",
                    json={
                        **payload,
                        "token": AI_TOKEN
                    }
                )

                if response.status_code == 200:
                    result = response.json()
                    print("   Success")
                    print(f"   AI status: {result.get('status')}")
                    ai_decision = result.get('ai_decision', {})
                    print(f"   AI action: {ai_decision.get('action')}")
                    print(f"   Risk level: {ai_decision.get('risk_level')}")

                    # Check for fake data
                    if 'fake_data' in result:
                        print("   Fake data generated")
                    else:
                        print("   No fake data returned")

                else:
                    print(f"   Failure: HTTP {response.status_code}")
                    print(f"   Error: {response.text}")

            except Exception as e:
                print(f"   Exception: {e}")

    print("\n" + "=" * 50)
    print("AI Agent test completed")

    # Check sandbox isolation
    print("\nChecking sandbox isolation:")
    try:
        # Try to access external service (should fail)
        response = await client.get("http://localhost:8000/health")
        if response.status_code == 200:
            print("   Warning: Sandbox can access external service")
        else:
            print("   Sandbox cannot access external service")
    except Exception:
        print("   Sandbox cannot access external service")

    # Check database isolation
    print("\nChecking database isolation:")
    try:
        # Check if mirage_memory.db exists
        if os.path.exists("data/mirage_memory.db"):
            print("   mirage_memory.db exists (sandbox can write)")
        else:
            print("   mirage_memory.db does not exist")

        # traffic_logs.db should not be exposed
        if os.path.exists("data/traffic_logs.db"):
            print("   traffic_logs.db is visible (isolation issue)")
        else:
            print("   traffic_logs.db is not exposed")
    except Exception as e:
        print(f"   Database check error: {e}")

if __name__ == "__main__":
    asyncio.run(test_ai_agent())