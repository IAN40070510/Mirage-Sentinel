from faker import Faker
import random

# 初始化台灣繁體中文的假資料生成器
fake = Faker('zh_TW')

def generate_fake_data(query_id: str) -> dict:
    """
    核心幻象引擎：根據查詢標靶 (query_id) 動態生成對應的假資料
    完全對齊期末簡報上的三種 Payload 範例！
    """
    
    # 情境 1：駭客想打 Admin 後台 
    # 給他假的錯誤訊息，讓他以為再試幾次就能登入成功
    if query_id.lower() == "admin":
        return {
            "error": False, 
            "msg": "Login failed",
            "try_left": random.randint(1, 3)  # 隨機產生 1~3 次剩餘機會
        }
        
    # 情境 2：駭客想打高權限代碼 
    elif query_id == "666":
        return {
            "name": fake.name(),
            "role": "admin",
            "bal": f"${fake.pyint(min_value=10000, max_value=99999):,}"
        }
        
    # 情境 3：預設的一般員工查詢 
    else:
        departments = ["HR", "IT", "Finance", "Sales", "R&D"]
        return {
            "id": query_id, # 駭客查什麼，就還給他什麼，降低戒心
            "dept": random.choice(departments),
            "salary": f"${fake.pyint(min_value=3000, max_value=9000):,}"
        }

if __name__ == "__main__":
    print("測試 [一般查詢 1001]:", generate_fake_data("1001"))
    print("測試 [高權限 666]:", generate_fake_data("666"))
    print("測試 [後台 admin]:", generate_fake_data("admin"))