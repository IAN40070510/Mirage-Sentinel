"""Generate offline, inert HTTP training candidates; never execute requests."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote, urlencode

from validate_commerce_dataset import validate

ROOT = Path(__file__).resolve().parents[1]
LABELS = ("normal", "sqli", "xss", "cmdi", "path_traversal")
WORDS = (
    "cotton",
    "linen",
    "wool",
    "silk",
    "denim",
    "canvas",
    "leather",
    "knit",
    "shirt",
    "jacket",
    "trousers",
    "shorts",
    "socks",
    "scarf",
    "cap",
    "bag",
    "blue",
    "green",
    "black",
    "white",
    "red",
    "navy",
    "olive",
    "cream",
    "summer",
    "winter",
    "spring",
    "classic",
    "casual",
    "formal",
    "sport",
    "daily",
)
AGENTS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
    "python-httpx/0.27.0",
    "curl/8.7.1",
)


def payload(label: str, index: int, rng: random.Random) -> tuple[str, str]:
    """Family groups reflect mechanisms, not each spelling/encoding variation."""
    a, b, c = rng.sample(WORDS, 3)
    term = f"{a} {b} {c}"
    token = f"{a}_{b}_{c}"
    n = rng.randint(2, 9000)
    if label == "normal":
        examples = [
            ("shopping-text", term),
            ("shopping-text", f"{term} size {rng.choice(['XS', 'S', 'M', 'L', 'XL'])}"),
            ("quoted-text", f"O'Reilly {term}"),
            ("punctuation-text", f"{term} & accessories; gift wrap please"),
            ("punctuation-text", f"{term} C++ collection | limited edition"),
            ("unicode-text", f"棉質商品 {term}，請不要附價格標籤"),
            ("unicode-text", f"café édition {term} größe M"),
            ("path-text", f"catalog/{a}/{b}/{c}.jpg"),
            ("path-text", f"images/{a}_{b}_{c}.png"),
            ("url-text", f"https://example.invalid/catalog/{a}/{b}/{c}"),
            ("technical-text", f"SQL SELECT reference book - {term}"),
            ("technical-text", f"HTML &lt;script&gt; reference print - {term}"),
            ("technical-text", f"bash command guide: {term}"),
            ("shopping-text", f"{term} model {n}"),
            ("shopping-text", f"Please exchange {term}; order reference {n}"),
            ("shopping-text", f"Looking for {term} without matching stock"),
        ]
    elif label == "sqli":
        examples = [
            ("boolean", f"{term}' OR {n}={n}-- "),
            ("boolean", f"{term}' OR '{token}'='{token}'-- "),
            ("boolean", f"{term}' AND {n}={n}-- "),
            ("boolean", f"{term}') OR ({n}={n})-- "),
            ("boolean", f"{term}' OR/**/{n}={n}-- "),
            ("union", f"{term}' UNION SELECT {n},NULL-- "),
            ("union", f"{term}' UNION ALL SELECT NULL,{n},NULL-- "),
            ("union", f"{term}' UNION/**/SELECT {n}-- "),
            ("stacked-select", f"{term}'; SELECT {n};-- "),
            ("conditional", f"{term}' AND (CASE WHEN {n}={n} THEN 1 ELSE 0 END)=1-- "),
            ("subquery", f"{term}' OR EXISTS(SELECT {n})-- "),
            ("boolean", f"{term}' OR NOT ({n}<{n})-- "),
        ]
    elif label == "xss":
        # Marker-only effects: no network requests, credential access or persistence.
        action = f"document.title='{token}'"
        examples = [
            ("script-element", f"<script>{action}</script>"),
            ("script-element", f'"><script>{action}</script>'),
            ("image-event", f'<img src="invalid-{token}" onerror="{action}">'),
            ("svg-event", f'<svg onload="{action}"></svg>'),
            ("focus-event", f'<input autofocus onfocus="{action}">'),
            (
                "toggle-event",
                f'<details open ontoggle="{action}"><summary>{term}</summary></details>',
            ),
            ("javascript-url", f'<a href="javascript:{action}">{term}</a>'),
            (
                "iframe-srcdoc",
                f'<iframe srcdoc="&lt;script&gt;{action}&lt;/script&gt;"></iframe>',
            ),
            ("mouse-event", f'<span onmouseover="{action}">{term}</span>'),
            ("image-event", f'"><img src="invalid-{token}" onerror="{action}">'),
            ("svg-event", f"<svg/onload=alert('{token}')>"),
            ("script-element", f"<ScRiPt>alert('{token}')</ScRiPt>"),
        ]
    elif label == "cmdi":
        examples = [
            ("shell-separator", f"{token}.txt; printf '{token}'"),
            ("shell-separator", f"{token}.txt && printf '{token}'"),
            ("shell-separator", f"{token}.txt || printf '{token}'"),
            ("shell-pipe", f"{token}.txt | printf '{token}'"),
            ("shell-newline", f"{token}.txt\nprintf '{token}'"),
            ("shell-substitution", f"{token}$(printf '{token}').txt"),
            ("shell-substitution", f"{token}`printf '{token}'`.txt"),
            ("shell-quote-break", f"{token}'; printf '{token}'; #"),
            ("shell-quote-break", f"{token}\"; printf '{token}'; #"),
            ("shell-separator", f"{token}.txt;\tprintf\t'{token}'"),
            ("windows-separator", f"{token}.txt & echo {token}"),
            ("windows-separator", f"{token}.txt && echo {token}"),
        ]
    else:
        # Fixture paths only. No actual file reads or sensitive target files.
        depth = rng.randint(2, 7)
        examples = [
            ("posix-parent", "../" * depth + f"fixtures/{token}.txt"),
            ("windows-parent", "..\\" * depth + f"fixtures\\{token}.txt"),
            ("mixed-parent", "../..\\" * depth + f"fixtures/{token}.txt"),
            ("posix-parent", f"images/{a}/" + "../" * depth + f"fixtures/{token}.txt"),
            (
                "windows-parent",
                f"images\\{a}\\" + "..\\" * depth + f"fixtures\\{token}.txt",
            ),
            ("posix-parent", "./" + "../" * depth + f"fixtures/{token}.txt"),
        ]
    family, value = examples[index % len(examples)]
    return f"{label}-{family}", value


def make_request(value: str, index: int) -> dict[str, Any]:
    """Identical channel/header schedule for every class; labels never enter HTTP."""
    surface = index % 5
    headers = {"accept": "application/json", "user-agent": AGENTS[(index // 5) % 5]}
    headers["accept-language"] = ("en-US,en;q=0.9", "zh-TW,zh;q=0.9", "de-DE,de;q=0.9")[
        (index // 25) % 3
    ]
    encoder = quote if (index // 75) % 2 else None

    # Alternate the two legitimate query-space encodings, across all labels.
    def query(data: dict[str, str]) -> str:
        return urlencode(data, quote_via=encoder) if encoder else urlencode(data)

    request: dict[str, Any] = {
        "method": "GET",
        "path": "/store/products",
        "query": "",
        "headers": headers,
        "body": None,
    }
    if surface == 0:
        request["query"] = query({"q": value, "limit": str((12, 20, 24)[index % 3])})
    elif surface == 1:
        request["method"] = "POST"
        request["path"] = "/store/customers/me"
        headers["content-type"] = "application/json"
        request["body"] = json.dumps(
            {"first_name": value, "last_name": "Example"}, ensure_ascii=index % 2 == 0
        )
    elif surface == 2:
        request["method"] = "POST"
        request["path"] = "/store/carts"
        headers["content-type"] = "application/json"
        request["body"] = json.dumps(
            {"region_id": "reg_PLACEHOLDER", "metadata": {"note": value}},
            ensure_ascii=index % 2 == 0,
        )
    elif surface == 3:
        request["query"] = query({"filename": value})
    else:
        # A syntactically valid custom header; percent encoding protects CR/LF.
        headers["x-search"] = quote(value, safe="")
        request["query"] = "limit=12"
    return request


def semantic_key(request: dict[str, Any]) -> str:
    """Ignore client headers and equivalent transport encodings for deduplication."""
    body = json.loads(request["body"]) if request["body"] is not None else None
    content = {
        "method": request["method"],
        "path": request["path"],
        "query": unquote(request["query"].replace("+", " ")),
        "body": body,
        "x-search": unquote(request["headers"].get("x-search", "")),
    }
    return json.dumps(content, ensure_ascii=False, sort_keys=True)


def generate(seed: int) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for label in LABELS:
        rng = random.Random(f"{seed}:{label}")
        for index in range(2000):
            for _ in range(1000):
                family, value = payload(label, index, rng)
                request = make_request(value, index)
                key = semantic_key(request)
                if key not in seen:
                    seen.add(key)
                    break
            else:
                raise ValueError("Unable to generate a distinct candidate")
            records.append(
                {"template_family": family, "request": request, "label": label}
            )
    random.Random(seed).shuffle(records)
    return [
        {"sample_id": f"commerce-10k-v1-{i:05d}", **r} for i, r in enumerate(records, 1)
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=20260922)
    parser.add_argument(
        "--output-dir", type=Path, default=ROOT / "datasets/commerce/synthetic-10k-v1"
    )
    args = parser.parse_args()
    out = args.output_dir
    out.mkdir(parents=True, exist_ok=True)
    path = out / "requests.jsonl"
    if path.exists():
        raise FileExistsError(f"Refusing to overwrite {path}")
    records = generate(args.seed)
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        for record in records:
            stream.write(
                json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
            )
    report = validate(path)
    report["path"] = "requests.jsonl"
    report["created_at"] = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    report["seed"] = args.seed
    report["generator_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    report["template_families"] = dict(
        sorted(Counter(r["template_family"] for r in records).items())
    )
    report["semantic_duplicates_ignoring_client_headers"] = len(records) - len(
        {semantic_key(r["request"]) for r in records}
    )
    report["classes"] = {}
    for label in LABELS:
        subset = [r for r in records if r["label"] == label]
        report["classes"][label] = {
            "methods": dict(Counter(r["request"]["method"] for r in subset)),
            "paths": dict(Counter(r["request"]["path"] for r in subset)),
            "user_agents": dict(
                Counter(r["request"]["headers"]["user-agent"] for r in subset)
            ),
        }
    report["executed_requests"] = 0
    report["label_review"] = (
        "Template-assigned candidates; not independently reviewed ground truth"
    )
    (out / "validation.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                k: report[k]
                for k in (
                    "records",
                    "labels",
                    "sha256",
                    "semantic_duplicates_ignoring_client_headers",
                )
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
