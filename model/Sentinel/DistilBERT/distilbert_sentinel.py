# DistilBERT 模型載入與推論介面
from transformers import DistilBertTokenizer, DistilBertForSequenceClassification
import torch
import os

MODEL_DIR = os.path.dirname(__file__)


class DistilBERTSentinel:
    def __init__(self):
        self.tokenizer = DistilBertTokenizer.from_pretrained(MODEL_DIR)
        self.model = DistilBertForSequenceClassification.from_pretrained(MODEL_DIR)
        self.model.eval()

    def predict(self, text: str):
        inputs = self.tokenizer(
            text, return_tensors="pt", truncation=True, padding=True
        )
        with torch.no_grad():
            outputs = self.model(**inputs)
            logits = outputs.logits
            probs = torch.softmax(logits, dim=1)
        return probs
