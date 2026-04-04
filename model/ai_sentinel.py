import os
import pandas as pd
import numpy as np
import scipy.sparse as sp
import joblib
import re
from math import log2
from collections import Counter

"""AI Sentinel 推論模組 (對齊新版 Sentinel_v2 訓練邏輯)

資料流：
1) 外部傳入 DataFrame(只需包含 payload)
2) 建立特徵(TF-IDF + 安全統計特徵）
3) XGBoost 輸出多分類機率
4) 依門檻轉成 BLOCK / CALL BERT / PASS 決策
"""

from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import MaxAbsScaler
from xgboost import XGBClassifier
import warnings

warnings.filterwarnings("ignore")

current_file_path = os.path.abspath(__file__)
project_root = os.path.dirname(os.path.dirname(current_file_path))
#  更新為你最新存檔的檔名
MODEL_PATH = os.path.join(project_root, "model", "sentinel_v2.pkl")

# ─── 1. 系統常數設定 ──────────────────────────────────────────────
ATTACK_LABELS = {
    0: "normal",
    1: "sqli",
    2: "xss",
    3: "lfi",
    4: "ssti",
    5: "rce",
    6: "path-traversal",
    7: "cmdi",
    8: "anomaly",
}
BLOCK_THRESHOLD = 0.7
REVIEW_THRESHOLD = 0.3


# ─── 2. 核心 Class 定義 (載入模型必備，與訓練檔完全一致) ────────────
class SecurityExtractor(BaseEstimator, TransformerMixin):
    _RE_SQL = re.compile(r"[;'\"\-#]")
    _RE_XSS = re.compile(r"[<>{}]")
    _RE_CMD = re.compile(r"[|&`\\]")
    _RE_PATH = re.compile(r"\.\./|\.\.\\|/\.\./")
    _RE_URLENCODE = re.compile(r"%[0-9a-fA-F]{2}")
    _RE_TEMPLATE = re.compile(r"\{\{|\}\}|\$\{")
    _RE_RCE = re.compile(
        r"(?:system|exec|shell_exec|passthru|eval|assert|"
        r"create_function|preg_replace)\s*\(",
        re.IGNORECASE,
    )
    _RE_OBFUSCATION = re.compile(
        r"%00|::|data:|javascript:|\\u[0-9a-fA-F]{4}", re.IGNORECASE
    )
    _RE_ALNUM = re.compile(r"[a-zA-Z0-9]")

    @staticmethod
    def _entropy(text: str) -> float:
        if not text:
            return 0.0
        counts = Counter(text)
        L = len(text)
        return -sum((c / L) * log2(c / L) for c in counts.values())

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        if not isinstance(X, pd.Series):
            X = pd.Series(X)

        X_str = X.fillna("").astype(str)
        # 加入防呆機制
        L_series = np.maximum(X_str.str.len().values, 1)

        features_df = pd.DataFrame(
            {
                "len_log": np.log1p(X_str.str.len()),
                "entropy": X_str.apply(self._entropy),
                "path_depth": X_str.str.count("/"),
                "path_trav": X_str.str.count(self._RE_PATH),
                "sql_dens": X_str.str.count(self._RE_SQL) / L_series,
                "xss_dens": X_str.str.count(self._RE_XSS) / L_series,
                "cmd_dens": X_str.str.count(self._RE_CMD) / L_series,
                "url_dens": X_str.str.count(self._RE_URLENCODE) / L_series,
                "ssti_flag": X_str.str.contains(self._RE_TEMPLATE, regex=True).astype(
                    int
                ),
                "rce_flag": X_str.str.contains(self._RE_RCE, regex=True).astype(int),
                "obf_flag": X_str.str.contains(self._RE_OBFUSCATION, regex=True).astype(
                    int
                ),
                "non_alnum": (X_str.str.len() - X_str.str.count(self._RE_ALNUM))
                / L_series,
                "q_mark": X_str.str.count(r"\?"),
                "eq_mark": X_str.str.count("="),
            }
        )

        # 終極淨化：消滅 NaN 和 Inf
        features_df = features_df.replace([np.inf, -np.inf], 0).fillna(0)
        return sp.csr_matrix(features_df.values.astype(np.float32))


class SentinelModule:
    """注意：這裡的 Class 名稱要與訓練檔保持一致 (SentinelModule)"""

    def __init__(self, labels=ATTACK_LABELS):
        self.labels = labels
        self._is_fitted = False
        self.tfidf = TfidfVectorizer(
            analyzer="char", ngram_range=(2, 4), max_features=8000, lowercase=False
        )
        self.extractor = SecurityExtractor()
        self.scaler = MaxAbsScaler()
        self.model = None

    def _build_features(self, X: pd.Series, is_training=False) -> sp.csr_matrix:
        """移除原本傳入的 method 參數，只靠文本特徵"""
        if not is_training and not self._is_fitted:
            raise RuntimeError("請先呼叫 fit()")
        if is_training:
            x_t = self.tfidf.fit_transform(X)
            x_s = self.scaler.fit_transform(self.extractor.transform(X))
        else:
            x_t = self.tfidf.transform(X)
            x_s = self.scaler.transform(self.extractor.transform(X))
        return sp.hstack([x_t, x_s], format="csr")

    def predict(self, df_input) -> pd.DataFrame:
        """
        輸入:DataFrame(需含 payload 欄）
        """
        if isinstance(df_input, (list, pd.Series)):
            df_input = pd.DataFrame({"payload": df_input})

        X = self._build_features(df_input["payload"])
        probs = self.model.predict_proba(X)
        cl = list(self.model.classes_)
        nidx = cl.index(0)

        attack_score = 1.0 - probs[:, nidx]
        atk_p = probs.copy()
        atk_p[:, nidx] = 0
        top_idx = atk_p.argmax(axis=1)
        top_type = [self.labels.get(cl[i], f"unknown({cl[i]})") for i in top_idx]
        top_prob = atk_p.max(axis=1)

        decision = np.where(
            attack_score > BLOCK_THRESHOLD,
            " BLOCK",
            np.where(attack_score >= REVIEW_THRESHOLD, " CALL BERT", " PASS"),
        )

        return pd.DataFrame(
            {
                "attack_score": np.round(attack_score, 4),
                "decision": decision,
                "top_attack_type": top_type,
                "top_attack_prob": np.round(top_prob, 4),
                "preview": df_input["payload"].astype(str).str[:60].values,
            }
        )

    @staticmethod
    def load(path=MODEL_PATH):
        return joblib.load(path)


def load_sentinel_model():
    """提供給外部(main.py)呼叫的載入函數"""
    try:
        instance = SentinelModule.load(MODEL_PATH)
        print(f"[AI-Sentinel] 權重載入成功: {MODEL_PATH}")
        return instance
    except Exception as e:
        print(f"[AI-Sentinel] 載入失敗: {e}")
        return None
