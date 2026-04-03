# -*- coding: utf-8 -*-

from tensorflow.keras.models import load_model
from sentence_transformers import SentenceTransformer
from huggingface_hub import hf_hub_download

# --- 1. 載入分類器 (.h5 檔案) ---
def load_classifier():
    print("[系統] 正在從 Hugging Face 下載 Keras 模型權重...")
    # 這裡使用 noobpk 的版本，因為他整理好了 .h5 檔案
    local_model_path = hf_hub_download(
        repo_id="noobpk/web-attack-detection", 
        filename="model.h5"
    )
    print(f"[系統] 模型已下載至: {local_model_path}")
    return load_model(local_model_path)

# --- 2. 載入向量生成器 (Sentence-Transformers) ---
def load_encoder():
    print("[系統] 正在載入文字編碼器 (all-MiniLM-L6-v2)...")
    return SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")

# 初始化
model = load_classifier()
encoder = load_encoder()

def check_payload(payload: str):
    # 將文字轉換為 384 維向量
    embeddings = encoder.encode([payload]) # 注意這裡傳入 list
    
    # 進行預測
    prediction = model.predict(embeddings, verbose=0)
    
    # 取得機率 (該模型通常輸出 0~1 之間的值)
    # 假設 > 0.5 代表是攻擊
    score = float(prediction[0][0])
    is_attack = score > 0.5
    
    return {
        "payload": payload,
        "is_attack": is_attack,
        "confidence": round(score * 100, 2), # 轉成百分比
        "label": "ATTACK" if is_attack else "SAFE"
    }

if __name__ == "__main__":
    while True:
        user_input = input("\n請輸入要分析的文字 (輸入 q 離開): ")
        if user_input.lower() == 'q':
            break
            
        res = check_payload(user_input)
        print("-" * 30)
        print(f"分析目標: {res['payload']}")
        print(f"檢測結果: {res['label']}")
        print(f"威脅機率: {res['confidence']}%")
        print("-" * 30)