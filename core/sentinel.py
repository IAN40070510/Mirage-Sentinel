import os
import urllib.parse
import ahocorasick
from rbloom import Bloom

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# --- 核心偵測引擎 ---
class HoneypotDetector:
    def __init__(self, seclists_root: str):
        self.seclists_root = seclists_root
        self.automaton = ahocorasick.Automaton()
        # 預期 100,000 筆資料，誤報率萬分之一
        self.bloom = Bloom(expected_items=100000, false_positive_rate=0.0001)
        
        self.configs = {
            "lfi": {"path": "LFI-Jhaddix.txt", "weight": 0.50},
            "paths": {"path": "common.txt", "weight": 0.20}
        }
        self._initialize_engine()

    def _initialize_engine(self):
        """預載入字典數據到記憶體"""
        for category, config in self.configs.items():
            full_path = os.path.join(self.seclists_root, config["path"])
            if not os.path.exists(full_path):
                continue

            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    p = line.strip().lower()
                    if p and not p.startswith("#"):
                        self.bloom.add(p)
                        if p not in self.automaton:
                            self.automaton.add_word(p, (p, category))
        
        self.automaton.make_automaton()
        print("[*] Sentinel Engine Initialized.")

    def _recursive_url_decode(self, text: str, depth=0) -> str:
        """處理 URL 遞迴解碼"""
        if depth > 3 or not text:
            return text
        decoded = urllib.parse.unquote(text)
        if decoded != text:
            return self._recursive_url_decode(decoded, depth + 1)
        return decoded.lower().strip()

    def analyze(self, raw_input: str):
        """
        核心判定邏輯：回傳 (是否為攻擊, 信心分數, 攻擊類別)
        """
        if not raw_input: 
            return False, 0.0, "None"
        
        clean_text = self._recursive_url_decode(raw_input)
        
        # 1. 第一層：Bloom Filter 快速路徑檢查
        if clean_text in self.bloom:
            # 新增：命中 Bloom Filter 代表 100% 吻合字典完整惡意字串
            return True, 1.0, "exact_match"

        # 2. 第二層：Aho-Corasick 多模式掃描
        matches = list(self.automaton.iter(clean_text))
        if not matches:
            # 新增：安全流量回傳 "None" 類別
            return False, 0.0, "None"

        # 3. 第三層：權重計算與情報收集
        total_score = 0.0
        seen_patterns = set()
        matched_categories = set() # 新增：用來收集他中了哪些攻擊類別

        for _, (pattern, category) in matches:
            if pattern not in seen_patterns:
                total_score += self.configs[category]["weight"]
                seen_patterns.add(pattern)
                matched_categories.add(category) # 記錄命中類別 (例如 'lfi', 'paths')

        confidence = min(round(total_score, 2), 1.0)
        
        # 將 Set 轉換為字串，如果駭客用了組合拳，會變成 "lfi, paths"
        attack_vector = ", ".join(matched_categories)
        
        return (confidence >= 0.4), confidence, attack_vector

# --- 初始化偵測器實例 ---
# 確保 SecLists 資料夾放在正確的路徑
_detector = HoneypotDetector("./SecLists")

# --- 給 main.py 呼叫的介面 ---
def analyze_intent(text: str):
    """
    對接 main.py 的介面：is_attack, confidence, attack_vector = analyze_intent(query_string)
    """
    return _detector.analyze(text)