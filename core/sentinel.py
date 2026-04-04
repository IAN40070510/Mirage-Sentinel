import os
import logging
import urllib.parse
import ahocorasick
from rbloom import Bloom

logger = logging.getLogger(__name__)

# 雲端路徑定位
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
SECLISTS_PATH = os.path.join(PROJECT_ROOT, "data", "datasets", "SecLists")

# 雲端最小可用簽名字典：當 SecLists 未部署時，仍可維持基本檢測能力。
DEFAULT_SIGNATURES = {
    "lfi": [
        "../../",
        "..\\..\\",
        "/etc/passwd",
        "/etc/shadow",
        "win.ini",
        "boot.ini",
        "php://filter",
    ],
    "paths": [
        "/admin",
        "/administrator",
        "/wp-admin",
        "/api/admin",
        "/api/internal",
        "/api/salary",
    ],
    "sqli": [
        "' or '1'='1",
        '" or "1"="1',
        "union select",
        "drop table",
        "information_schema",
        "sleep(",
    ],
}


class SentinelEngine:
    def __init__(self, seclists_root: str):
        self.seclists_root = seclists_root
        self.automaton = ahocorasick.Automaton()
        self.automaton_ready = False
        self.bloom = Bloom(expected_items=100000, false_positive_rate=0.0001)

        # 權重分配：admin (paths) 分數極低，只有真正帶攻擊特徵的才會飆高
        self.configs = {
            "lfi": {"path": "LFI-Jhaddix.txt", "weight": 0.70},
            "paths": {"path": "common.txt", "weight": 0.10},
            "sqli": {"path": "login_bypass.txt", "weight": 0.85},
        }
        self._initialize_engine()

    def _resolve_signature_path(self, filename: str) -> str | None:
        direct_path = os.path.join(self.seclists_root, filename)
        if os.path.exists(direct_path):
            return direct_path

        # 支援完整 SecLists 目錄結構：遞迴尋找目標檔名
        for root, _, files in os.walk(self.seclists_root):
            for current_name in files:
                if current_name.lower() == filename.lower():
                    return os.path.join(root, current_name)

        return None

    def _initialize_engine(self):
        loaded_count = 0
        for category, config in self.configs.items():
            full_path = self._resolve_signature_path(config["path"])
            if not full_path:
                logger.warning(
                    "Sentinel 找不到簽名字典: %s，改用內建 fallback 字典。",
                    config["path"],
                )
                candidate_patterns = DEFAULT_SIGNATURES.get(category, [])
            else:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    candidate_patterns = [line.strip().lower() for line in f]

            category_count = 0
            for p in candidate_patterns:
                p = p.strip().lower()
                if not p or p.startswith("#"):
                    continue

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
                        category_count += 1
                        loaded_count += 1

            logger.debug(f"[Sentinel] {category}: 成功載入 {category_count} 個簽名")

        if loaded_count > 0:
            self.automaton.make_automaton()
            self.automaton_ready = True
            logger.info(f"✅ Sentinel 核心已武裝！總計載入 {loaded_count} 筆簽名")
        else:
            self.automaton_ready = False
            logger.error(
                "❌ Sentinel 未載入到任何簽名字典，將以安全降級模式運行（所有請求視為非攻擊）。"
            )

    def _recursive_url_decode(self, text: str, depth=0) -> str:
        if depth > 3 or not text:
            return text
        decoded = urllib.parse.unquote(text)
        return (
            self._recursive_url_decode(decoded, depth + 1)
            if decoded != text
            else decoded.lower().strip()
        )

    def analyze(self, raw_input: str):
        if not raw_input:
            return False, 0.0, "None"
        if not self.automaton_ready:
            return False, 0.0, "None"
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


_detector = SentinelEngine(SECLISTS_PATH)


def analyze_intent(text: str):
    return _detector.analyze(text)
