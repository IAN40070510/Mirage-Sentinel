import torch
import os
import pandas as pd
import numpy as np
from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification

current_file_path = os.path.abspath(__file__)
project_root = os.path.dirname(os.path.dirname(current_file_path))
MODEL_PATH = os.path.join(project_root, "model", "distilbert")

ATTACK_LABELS = {
    0: "normal", 1: "sqli", 2: "xss", 3: "lfi",
    4: "ssti",   5: "cmdi", 6: "path-traversal", 7: "anomaly"
}

class BertSentinelModule:
    def __init__(self, model_path=MODEL_PATH, labels=ATTACK_LABELS):
        self.labels = labels
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        
        try:
            self.tokenizer = DistilBertTokenizerFast.from_pretrained(model_path)
            self.model = DistilBertForSequenceClassification.from_pretrained(model_path)
            self.model.to(self.device)
            self.model.eval()
            print(f"[BERT-Sentinel] 權重載入成功: {model_path} (Device: {self.device})")
        except Exception as e:
            print(f"[BERT-Sentinel] 載入失敗: {e}")
            raise

    @torch.no_grad()
    def predict(self, df_input) -> pd.DataFrame:
        """
        輸入: DataFrame (需含 payload 欄位) 或 Series/List
        輸出: 包含 attack_score, decision, top_attack_type 的 DataFrame
        """
        # 轉換輸入格式
        if isinstance(df_input, (list, pd.Series)):
            df_input = pd.DataFrame({"payload": df_input})
        
        payloads = df_input["payload"].astype(str).tolist()
        
        if not payloads:
            return pd.DataFrame()

        # 1. Tokenization & Inference
        inputs = self.tokenizer(
            payloads, 
            return_tensors="pt", 
            truncation=True, 
            padding=True, 
            max_length=128
        ).to(self.device)

        outputs = self.model(**inputs)
        logits = outputs.logits
        
        # 2. 計算機率 (Softmax)
        probs = torch.softmax(logits, dim=-1).cpu().numpy()
        
        # 3. 計算攻擊信心值 (1.0 - 正常類別的機率)
        # 假設標籤 0 是 normal
        normal_idx = 0 
        attack_score = 1.0 - probs[:, normal_idx]
        
        # 4. 取得排除 normal 後最強的攻擊類型
        atk_probs = probs.copy()
        atk_probs[:, normal_idx] = 0 # 屏蔽正常類別
        top_idx = atk_probs.argmax(axis=1)
        top_type = [self.labels.get(i, f"unknown({i})") for i in top_idx]
        top_prob = atk_probs.max(axis=1)

        # 5. 根據信心值做決策
        decision = np.where(
            attack_score > 0.7, 
            " BLOCK", 
            " PASS"
        )

        return pd.DataFrame({
            "attack_score": np.round(attack_score, 4),
            "decision": decision,
            "top_attack_type": top_type,
            "top_attack_prob": np.round(top_prob, 4),
            "preview": df_input["payload"].astype(str).str[:60].values,
        })

# ─── 2. 載入函數 (對齊 XGBoost 的 load_sentinel_model) ──────────────
def load_bert_sentinel():
    try:
        instance = BertSentinelModule(MODEL_PATH)
        return instance
    except Exception as e:
        print(f"[DistilBERT 載入失敗] 發生錯誤:{e}")
        return None
