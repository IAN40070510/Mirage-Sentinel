import os
import pandas as pd
import numpy as np
import scipy.sparse as sp
import joblib
import re
from math import log2
from collections import Counter

"""AI Sentinel 推論模組。

資料流：
1) 外部傳入 DataFrame（至少包含 combined_text, method）
2) 建立特徵（TF-IDF + 安全統計特徵 + HTTP method one-hot）
3) XGBoost 輸出多分類機率
4) 依門檻轉成 BLOCK / CALL BERT / PASS 決策
"""

# 機器學習與 FastAPI 核心套件
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import MaxAbsScaler
from xgboost import XGBClassifier

current_file_path = os.path.abspath(__file__)
project_root = os.path.dirname(os.path.dirname(current_file_path))
MODEL_PATH = os.path.join(project_root, 'model', 'sentinel_v14_perfected.pkl')

# ─── 1. 系統常數設定 ──────────────────────────────────────────────
ATTACK_LABELS = {
    0: "normal", 1: "sqli",  2: "xss",   3: "lfi",
    4: "ssti",   5: "rce",   6: "path-traversal",
    7: "cmdi",   8: "anomaly"
}
# 主門檻：整體攻擊分數高於此值就直接阻擋
BLOCK_THRESHOLD = 0.7
# 次門檻：若某特定攻擊類別機率非常高，也可直接阻擋
SPECIFIC_BLOCK_THRESHOLD = 0.65
# 灰區門檻：介於 review 與 block 之間，交由二階模型/人工覆核
REVIEW_THRESHOLD = 0.3
METHOD_MAP = {"GET": 0, "POST": 1, "PUT": 2, "DELETE": 3, "PATCH": 4, "HEAD": 5, "OPTIONS": 6}

# ─── 2. 核心 Class 定義 (載入模型必備) ───────────────────────────
class SecurityExtractor(BaseEstimator, TransformerMixin):
    """將請求文本轉成安全統計特徵。

    這裡的特徵偏向「行為型訊號」，可補足純字詞模型的盲點：
    - 熵值、路徑深度、特殊符號密度、URL 編碼密度、混淆特徵等。
    """

    _RE_SQL  = re.compile(r"[;'\"\-#]")
    _RE_XSS  = re.compile(r"[<>{}]")
    _RE_CMD  = re.compile(r"[|&`\\]")
    _RE_PATH = re.compile(r"\.\./|\.\.\\|/\.\./")
    _RE_URLENCODE = re.compile(r"%[0-9a-fA-F]{2}")
    _RE_TEMPLATE = re.compile(r"\{\{|\}\}|\$\{")
    _RE_RCE = re.compile(r"(?:system|exec|shell_exec|passthru|eval|assert|create_function|preg_replace)\s*\(", re.IGNORECASE)
    _RE_OBFUSCATION = re.compile(r"%00|::|data:|javascript:|\\u[0-9a-fA-F]{4}", re.IGNORECASE)
    _RE_ALNUM = re.compile(r"[a-zA-Z0-9]")

    @staticmethod
    def _entropy(text: str) -> float:
        """計算字元熵，越高通常代表 payload 越雜訊或混淆。"""
        if not text: return 0.0
        counts = Counter(text)
        L = len(text)
        return -sum((c / L) * log2(c / L) for c in counts.values())

    def fit(self, X, y=None): return self

    def transform(self, X):
        """輸出稀疏矩陣，供後續和 TF-IDF 特徵拼接。"""
        if not isinstance(X, pd.Series): X = pd.Series(X)
        X_str = X.fillna('').astype(str)
        # +1 避免密度特徵遇到空字串時除以 0
        L_series = X_str.str.len() + 1 
        len_log = np.log1p(X_str.str.len())
        entropy_arr = X_str.apply(self._entropy)
        path_depth = X_str.str.count('/')
        path_trav = X_str.str.count(self._RE_PATH)
        sql_den = X_str.str.count(self._RE_SQL) / L_series
        xss_den = X_str.str.count(self._RE_XSS) / L_series
        cmd_den = X_str.str.count(self._RE_CMD) / L_series
        url_enc_den = X_str.str.count(self._RE_URLENCODE) / L_series
        has_ssti = X_str.str.contains(self._RE_TEMPLATE, regex=True).astype(int)
        has_rce = X_str.str.contains(self._RE_RCE, regex=True).astype(int)
        has_obfuscation = X_str.str.contains(self._RE_OBFUSCATION, regex=True).astype(int)
        non_alnum_den = (X_str.str.len() - X_str.str.count(self._RE_ALNUM)) / L_series
        q_count = X_str.str.count(r'\?')
        eq_count = X_str.str.count('=')

        features_df = pd.concat([
            len_log, entropy_arr, path_depth, path_trav,
            sql_den, xss_den, cmd_den, url_enc_den,
            has_ssti, has_rce, has_obfuscation,
            non_alnum_den, q_count, eq_count
        ], axis=1)
        return sp.csr_matrix(features_df.values.astype(np.float32))

class SentinelModuleV14:
    """推論封裝：
    - tfidf: 字元 n-gram 特徵
    - extractor: 手工安全特徵
    - scaler: 將手工特徵做 MaxAbs 正規化
    - model: XGBoost 多分類器
    """

    def __init__(self, labels=ATTACK_LABELS):
        self.labels = labels
        self.tfidf = TfidfVectorizer(analyzer='char', ngram_range=(2, 4), max_features=8000, lowercase=False)
        self.extractor = SecurityExtractor()
        self.scaler = MaxAbsScaler()
        self.model = XGBClassifier()
        self._is_fitted = True

    def _encode_method(self, methods: pd.Series) -> sp.csr_matrix:
        """將 HTTP method 轉為 one-hot，作為上下文輔助訊號。"""
        n, m = len(methods), len(METHOD_MAP)
        mat = np.zeros((n, m), dtype=np.float32)
        for i, v in enumerate(methods):
            idx = METHOD_MAP.get(str(v).upper(), -1)
            if idx >= 0: mat[i, idx] = 1.0
        return sp.csr_matrix(mat)

    def _build_features(self, X: pd.Series, methods: pd.Series) -> sp.csr_matrix:
        """組合最終特徵矩陣：TF-IDF + 安全特徵 + method 特徵。"""
        x_t = self.tfidf.transform(X)
        x_s = self.scaler.transform(self.extractor.transform(X))
        x_m = self._encode_method(methods)
        return sp.hstack([x_t, x_s, x_m], format='csr')

    def predict(self, df_input: pd.DataFrame) -> pd.DataFrame:
        """回傳可直接給策略層使用的預測結果。

        attack_score: 非 normal 的總風險（1 - P(normal)）
        top_attack_type/top_attack_prob: 最可能攻擊類別
        decision: 最終動作建議
        """
        X_final = self._build_features(df_input['combined_text'], df_input['method'])
        probs = self.model.predict_proba(X_final)
        normal_idx = list(self.model.classes_).index(0)
        attack_score = 1.0 - probs[:, normal_idx]
        atk_p = probs.copy()
        atk_p[:, normal_idx] = 0
        top_idx = atk_p.argmax(axis=1)
        top_prob = atk_p.max(axis=1)

        # 決策規則：
        # 1) 高風險 -> BLOCK
        # 2) 中風險 -> CALL BERT（或二階審查）
        # 3) 低風險 -> PASS
        decision = np.where(
            (attack_score > BLOCK_THRESHOLD) | (top_prob > SPECIFIC_BLOCK_THRESHOLD), "🚫 BLOCK",
            np.where(attack_score >= REVIEW_THRESHOLD, "🔍 CALL BERT", "✅ PASS")
        )
        return pd.DataFrame({
            "attack_score": np.round(attack_score, 4),
            "decision": decision,
            "top_attack_type": [self.labels[self.model.classes_[i]] for i in top_idx],
            "top_attack_prob": np.round(top_prob, 4),
            "method": df_input['method'].values,
            "preview": df_input['combined_text'].str[:50].values
        })

    @staticmethod
    def load(path=MODEL_PATH):
        """反序列化已訓練完成的 Sentinel 模型物件。"""
        return joblib.load(path)

def load_sentinel_model():
    """提供給外部(main.py)呼叫的載入函數"""
    try:
        # 使用剛才定義好的 MODEL_PATH
        instance = SentinelModuleV14.load(MODEL_PATH)
        print(f"[AI-Sentinel] 權重載入成功: {MODEL_PATH}")
        return instance
    except Exception as e:
        print(f"[AI-Sentinel] 載入失敗: {e}")
        return None