# XGBoost 模型載入與推論介面
import xgboost as xgb
import pandas as pd
import os

MODEL_PATH = os.path.join(os.path.dirname(__file__), "xgboost_model.json")


class XGBoostSentinel:
    def __init__(self):
        self.model = xgb.Booster()
        self.model.load_model(MODEL_PATH)

    def predict(self, df: pd.DataFrame):
        dmatrix = xgb.DMatrix(df)
        preds = self.model.predict(dmatrix)
        return preds
