import os
import urllib.parse
import ahocorasick
from rbloom import Bloom

# 雲端路徑定位
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__)) 
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)               
SECLISTS_PATH = os.path.join(PROJECT_ROOT, "data", "datasets", "SecLists")

class HoneypotDetector:
    def __init__(self, seclists_root: str):
        self.seclists_root = seclists_root
        self.automaton = ahocorasick.Automaton()
        self.bloom = Bloom(expected_items=100000, false_positive_rate=0.0001)
        
        # 權重分配：admin (paths) 分數極低，只有真正帶攻擊特徵的才會飆高
        self.configs = {
            "lfi": {"path": "LFI-Jhaddix.txt", "weight": 0.70},
            "paths": {"path": "common.txt", "weight": 0.10},
            "sqli": {"path": "Generic-SQLi.txt", "weight": 0.85}
        }
        self._initialize_engine()

    def _initialize_engine(self):
        loaded_count = 0
        for category, config in self.configs.items():
            full_path = os.path.join(self.seclists_root, config["path"])
            if not os.path.exists(full_path): continue
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    p = line.strip().lower()
                    if not p or p.startswith("#"): continue
                    
                    # --- [關鍵修正邏輯] ---
                    # 1. 如果是 paths (common.txt)，維持長度檢查，保護 1001 不被抓
                    # 2. 如果是 sqli 或 lfi，長度 >= 1 就要載入，因為符號才是關鍵！
                    should_load = False
                    if category == "paths" and len(p) > 4:
                        should_load = True
                    elif category in ["sqli", "lfi"] and len(p) >= 1:
                        should_load = True
                    
                    if should_load:
                        self.bloom.add(p)
                        if p not in self.automaton:
                            self.automaton.add_word(p, (p, category))
                            loaded_count += 1
        
        self.automaton.make_automaton()
        print(f"[*] Sentinel 核心已武裝！載入筆數: {loaded_count}")

    def _recursive_url_decode(self, text: str, depth=0) -> str:
        if depth > 3 or not text: return text
        decoded = urllib.parse.unquote(text)
        return self._recursive_url_decode(decoded, depth + 1) if decoded != text else decoded.lower().strip()

    def analyze(self, raw_input: str):
        if not raw_input: return False, 0.0, "None"
        clean_text = self._recursive_url_decode(raw_input)
        
        matches = list(self.automaton.iter(clean_text))
        if not matches:
            return False, 0.0, "None"

        total_score = 0.0
        matched_categories = set()
        seen_patterns = set()

        for _, (pattern, category) in matches:
            if pattern not in seen_patterns:
                total_score += self.configs.get(category, {"weight": 0})["weight"]
                seen_patterns.add(pattern)
                matched_categories.add(category)

        confidence = min(round(total_score, 2), 1.0)
        attack_vector = ", ".join(matched_categories)
        
        # 這裡的 True 僅代表「有命中」，最終生死由 main.py 決定
        return (confidence > 0), confidence, attack_vector

_detector = HoneypotDetector(SECLISTS_PATH)
def analyze_intent(text: str):
    return _detector.analyze(text)