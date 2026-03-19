from faker import Faker
import random

# 初始化台灣繁體中文的假資料生成器
fake = Faker('zh_TW')

def generate_fake_data(query_id: str) -> dict:
    """
    核心幻象引擎：將欄位完全對齊真實模式 (Real Mode)
    讓駭客的爬蟲程式無法察覺欄位異動
    """
    
    # 🌟 規格對齊重點：
    # 真實模式回傳：user_id, name, email, balance, status
    
    # 情境 1：高權限標靶 (666) -> 給他超級大肥羊資料，誘使他繼續深入
    if query_id == "666":
        return {
            "user_id": "666",
            "name": f"{fake.name()} (Admin)", # Demo 用，上線可拿掉 (Admin)
            "email": fake.company_email(),
            "balance": float(fake.pyint(min_value=100000, max_value=999999)), # 高資產
            "status": "Privileged" 
        }
        
    # 情境 2：後台標靶 (admin) -> 給他看起來像管理員的個資
    elif query_id.lower() == "admin":
        return {
            "user_id": "ADMIN_001",
            "name": "系統管理員",
            "email": "root@company.corp",
            "balance": 0.0,
            "status": "Root"
        }
        
    # 情境 3：一般查詢 (預設) -> 完美模擬王小明的格式
    else:
        return {
            "user_id": query_id,
            "name": fake.name(),
            "email": fake.email(),
            "balance": float(fake.pyint(min_value=1000, max_value=8000)), # 正常薪水
            "status": "Normal"
        }

if __name__ == "__main__":
    # 測試是否對齊規格
    print("測試 [一般查詢]:", generate_fake_data("1001"))