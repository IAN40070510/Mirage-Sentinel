import os
import urllib.parse
import ahocorasick
from rbloom import Bloom

# 雲端路徑校準：自動定位根目錄 ---
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__)) # 指向 core/
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)               # 指向 Mirage-Sentinel/

# 修正：精準指向新的 data/datasets/SecLists 路徑
SECLISTS_PATH = os.path.join(PROJECT_ROOT, "data", "datasets", "SecLists")

# --- 核心偵測引擎 ---
class HoneypotDetector:
    def __init__(self, seclists_root: str):
        self.seclists_root = seclists_root
        self.automaton = ahocorasick.Automaton()
        self.bloom = Bloom(expected_items=100000, false_positive_rate=0.0001)
        
        # 修正：根據你的檔案分佈調整路徑 (如果 LFI-Jhaddix.txt 在 SecLists 根目錄下)
        self.configs = {
            "lfi": {"path": "LFI-Jhaddix.txt", "weight": 0.50},
            "paths": {"path": "common.txt", "weight": 0.20}
        }
        self._initialize_engine()

    def _initialize_engine(self):
        """預載入字典數據到記憶體"""
        loaded_count = 0
        # 啟動時顯示絕對路徑，方便除錯
        print(f"[DEBUG] Sentinel 掃描路徑: {os.path.abspath(self.seclists_root)}")

        for category, config in self.configs.items():
            full_path = os.path.join(self.seclists_root, config["path"])
            
            if not os.path.exists(full_path):
                print(f"[WARNING] 找不到字典檔: {full_path}")
                continue

            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    p = line.strip().lower()
                    if p and not p.startswith("#"):
                        self.bloom.add(p)
                        if p not in self.automaton:
                            self.automaton.add_word(p, (p, category))
                            loaded_count += 1
        
        # 關鍵防禦：若 loaded_count 為 0，也要塞一個空字串避免 automaton 崩潰
        if loaded_count == 0:
            print("[CRITICAL] 完全沒載入任何字典！請檢查 data/datasets/SecLists/ 是否存在對應檔案。")
            self.automaton.add_word("mirage_sentinel_init_safe_node", ("none", "none"))
            
        self.automaton.make_automaton()
        print(f"[*] Sentinel Engine Initialized. 載入筆數: {loaded_count}")

    def _recursive_url_decode(self, text: str, depth=0) -> str:
        if depth > 3 or not text:
            return text
        decoded = urllib.parse.unquote(text)
        if decoded != text:
            return self._recursive_url_decode(decoded, depth + 1)
        return decoded.lower().strip()

    def analyze(self, raw_input: str):
        if not raw_input: 
            return False, 0.0, "None"
        
        clean_text = self._recursive_url_decode(raw_input)
        
        # 快速過濾
        if clean_text in self.bloom:
            return True, 1.0, "exact_match"

        # 多模式匹配
        matches = list(self.automaton.iter(clean_text))
        if not matches:
            return False, 0.0, "None"

        total_score = 0.0
        seen_patterns = set()
        matched_categories = set()

        for _, (pattern, category) in matches:
            if pattern not in seen_patterns and category != "none":
                total_score += self.configs.get(category, {"weight": 0})["weight"]
                seen_patterns.add(pattern)
                matched_categories.add(category)

        confidence = min(round(total_score, 2), 1.0)
        attack_vector = ", ".join(matched_categories) if matched_categories else "None"
        
        # 信心門檻設定為 0.4
        return (confidence >= 0.4), confidence, attack_vector

# --- 初始化偵測器實例 ---
_detector = HoneypotDetector(SECLISTS_PATH)

def analyze_intent(text: str):
    return _detector.analyze(text)