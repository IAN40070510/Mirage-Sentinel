import os
import urllib.parse
import ahocorasick
from rbloom import Bloom

# 雲端路徑自動定位
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__)) 
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)               
SECLISTS_PATH = os.path.join(PROJECT_ROOT, "data", "datasets", "SecLists")

class HoneypotDetector:
    def __init__(self, seclists_root: str):
        self.seclists_root = seclists_root
        self.automaton = ahocorasick.Automaton()
        self.bloom = Bloom(expected_items=100000, false_positive_rate=0.0001)
        
        # --- [隊長修正：精細權重設定] ---
        # 降低路徑（paths）的權重，調高注入（lfi/sqli）的權重
        self.configs = {
            "lfi": {"path": "LFI-Jhaddix.txt", "weight": 0.80},   # 檔案包含攻擊：極危險
            "paths": {"path": "common.txt", "weight": 0.15},    # 常見路徑：中低風險（admin 就在這）
            "sqli": {"path": "Generic-SQLi.txt", "weight": 0.90} # 建議之後加入 SQLi 字典
        }
        self._initialize_engine()

    def _initialize_engine(self):
        loaded_count = 0
        print(f"[DEBUG] Sentinel 掃描路徑: {os.path.abspath(self.seclists_root)}")

        for category, config in self.configs.items():
            full_path = os.path.join(self.seclists_root, config["path"])
            if not os.path.exists(full_path):
                continue

            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    p = line.strip().lower()
                    if p and not p.startswith("#"):
                        # 將單字加入 Bloom 與 AC 自動機
                        self.bloom.add(p)
                        if p not in self.automaton:
                            self.automaton.add_word(p, (p, category))
                            loaded_count += 1
        
        if loaded_count == 0:
            self.automaton.add_word("mirage_init", ("none", "none"))
            
        self.automaton.make_automaton()
        print(f"[*] Sentinel 引擎初始化完成。載入筆數: {loaded_count}")

    def _recursive_url_decode(self, text: str, depth=0) -> str:
        if depth > 3 or not text: return text
        decoded = urllib.parse.unquote(text)
        if decoded != text:
            return self._recursive_url_decode(decoded, depth + 1)
        return decoded.lower().strip()

    def analyze(self, raw_input: str):
        if not raw_input: 
            return False, 0.0, "None"
        
        clean_text = self._recursive_url_decode(raw_input)
        
        # --- [關鍵修正：取消 exact_match 的 1.0 霸王條款] ---
        # 即使完全匹配，我們也要根據它所屬的類別來給分
        # 例如命中 admin (paths)，分數只會給 0.15，不會達到 main.py 的 0.75 門檻
        
        matches = list(self.automaton.iter(clean_text))
        if not matches:
            return False, 0.0, "None"

        total_score = 0.0
        seen_patterns = set()
        matched_categories = set()

        for _, (pattern, category) in matches:
            if pattern not in seen_patterns and category != "none":
                # 累加該類別的權重
                weight = self.configs.get(category, {"weight": 0})["weight"]
                total_score += weight
                seen_patterns.add(pattern)
                matched_categories.add(category)

        # 計算最終信心度 (上限 1.0)
        confidence = min(round(total_score, 2), 1.0)
        attack_vector = ", ".join(matched_categories) if matched_categories else "None"
        
        # 這裡只回傳「哨兵的判斷」，最後要不要攔截，交給 main.py 的信心門檻
        # 只要有一點點分數，is_attack 就給 True，但 confidence 會告訴你它多危險
        return (confidence > 0), confidence, attack_vector

_detector = HoneypotDetector(SECLISTS_PATH)

def analyze_intent(text: str):
    return _detector.analyze(text)