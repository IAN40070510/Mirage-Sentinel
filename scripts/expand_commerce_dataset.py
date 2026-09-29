"""Offline expansion with new contexts and cross-batch duplicate exclusion."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, quote, unquote, urlencode

from generate_commerce_dataset import AGENTS, LABELS, ROOT
from validate_commerce_dataset import validate

WORDS = (
    "apron",
    "blazer",
    "cardigan",
    "dress",
    "earring",
    "glove",
    "hoodie",
    "jewelry",
    "kimono",
    "loafer",
    "mittens",
    "necklace",
    "overcoat",
    "pajamas",
    "quilt",
    "raincoat",
    "sandals",
    "towel",
    "umbrella",
    "vest",
    "wallet",
    "yoga",
    "zipper",
    "backpack",
    "amber",
    "bronze",
    "coral",
    "emerald",
    "floral",
    "gingham",
    "ivory",
    "jade",
    "khaki",
    "lavender",
    "maroon",
    "ochre",
    "pearl",
    "rust",
    "striped",
    "teal",
)
SURFACES = (
    "product-search-with-filters",
    "cart-shipping-address",
    "cart-billing-address",
    "customer-address",
    "cart-promotions-array",
    "line-item-metadata",
    "customer-metadata",
    "cart-nested-metadata",
    "referer-query",
    "product-order-query",
)


def decode(value: str) -> str:
    for _ in range(3):
        decoded = unquote(value)
        if decoded == value:
            break
        value = decoded
    return value


def normalize(value: Any) -> Any:
    """Collapse numeric-only variants too, retaining non-numeric semantics."""
    if isinstance(value, str):
        return re.sub(r"\d+", "<number>", decode(value)).casefold()
    if isinstance(value, dict):
        return {k: normalize(v) for k, v in sorted(value.items())}
    if isinstance(value, (list, tuple)):
        return [normalize(v) for v in value]
    if isinstance(value, (int, float)):
        return "<number>"
    return value


def fingerprint(request: dict[str, Any], *, relaxed: bool) -> str:
    if not relaxed:
        value = request
    else:
        body = request["body"]
        if body is not None:
            try:
                body = json.loads(body)
            except ValueError:
                if "application/x-www-form-urlencoded" in request["headers"].get(
                    "content-type", ""
                ):
                    body = sorted(parse_qsl(body, keep_blank_values=True))
        value = {
            "method": request["method"],
            "path": request["path"],
            "query": sorted(parse_qsl(request["query"], keep_blank_values=True)),
            "body": body,
            # Ignore client identity headers, keep headers carrying actual input.
            "input_headers": {
                k.lower(): v
                for k, v in request["headers"].items()
                if k.lower() in {"referer", "x-search"}
            },
        }
        value = normalize(value)
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, ensure_ascii=False).encode()
    ).hexdigest()


def make_payload(label: str, variant: int, rng: random.Random) -> tuple[str, str]:
    a, b, c = rng.sample(WORDS, 3)
    token = f"{a}_{b}_{c}"
    term = f"{a} {b} {c}"
    if label == "normal":
        choices = [
            (
                "shopping-text",
                f"Please wrap the {term} separately; no printed receipt.",
            ),
            ("shopping-text", f"交換 {term}，希望改成寬鬆版，保留原包裝。"),
            ("unicode-text", f"{term} を探しています。ギフト用です。"),
            ("unicode-text", f"{term} 선물 포장을 부탁합니다."),
            ("unicode-text", f"أبحث عن {term} كهدية"),
            ("unicode-text", f"Veuillez livrer {term} à l'accueil, s'il vous plaît."),
            ("quoted-text", f"D'Angelo & Sons — {term}"),
            ("punctuation-text", f"{term}: please keep A+B together / do not fold"),
            ("technical-text", f"{term} gift card text: SQL UNION joins results"),
            ("technical-text", f"{term} printed text: &lt;svg&gt; is an image format"),
            ("path-text", f"receipts/{a}/archive/{b}-{c}.pdf"),
            ("url-text", f"https://example.invalid/lookbook/{a}?style={b}&fabric={c}"),
            (
                "shopping-text",
                f"{term} not suitable; please suggest a softer alternative",
            ),
            ("shopping-text", f"Bitte {term} ohne Plastik verpacken. Danke!"),
            ("shopping-text", f"{term} — sem preço na embalagem, por favor"),
            ("shopping-text", f"{term} 🛍️🎁 — deliver to reception"),
        ]
    elif label == "sqli":
        choices = [
            ("boolean", f"{term}' OR '{token}' LIKE '%{a}%'-- "),
            ("boolean", f"{term}' OR '{token}' IN ('{token}')-- "),
            ("conditional", f"{term}' AND COALESCE(NULL,'{token}')='{token}'-- "),
            ("boolean", f"{term}' OR LOWER('{token.upper()}')='{token}'-- "),
            ("boolean", f"{term}' OR '{token}' IS NOT NULL-- "),
            ("conditional", f"{term}' AND NULLIF('{token}','{token}') IS NULL-- "),
            ("subquery", f"{term}' OR EXISTS(VALUES ('{token}'))-- "),
            ("union", f"{term}' UNION SELECT CAST('{token}' AS TEXT)-- "),
            ("union", f"{term}' UNION SELECT CONCAT('{a}','{b}','{c}')-- "),
            (
                "stacked-select",
                f"{term}'; WITH sample(value) AS (VALUES ('{token}')) SELECT value FROM sample;-- ",
            ),
            ("boolean", f"{term}' OR '{token}' IS NOT DISTINCT FROM '{token}'-- "),
            ("union", f"{term}' UNION SELECT $probe${token}$probe$-- "),
            ("subquery", f"{term}' AND (SELECT '{token}')='{token}'-- "),
            (
                "conditional",
                f"{term}' AND CASE WHEN '{a}'='{a}' THEN '{token}' ELSE NULL END IS NOT NULL-- ",
            ),
            ("union", f"{term}' UNION SELECT '{a}'||'{b}'||'{c}'-- "),
            ("boolean", f"{term}' OR REVERSE(REVERSE('{token}'))='{token}'-- "),
        ]
    elif label == "xss":
        action = f"document.title='{token}'"
        choices = [
            ("script-element", f"</textarea><script>{action}</script>"),
            ("script-element", f"</style><script>{action}</script>"),
            ("svg-event", f'</title><svg onload="{action}"></svg>'),
            ("image-event", f'--><img src="invalid-{token}" onerror="{action}">'),
            ("script-string-break", f"';{action};//"),
            ("script-string-break", f"\";document.title='{token}';//"),
            (
                "media-event",
                f'<video src="invalid-{token}" onerror="{action}"></video>',
            ),
            (
                "media-event",
                f'<audio src="invalid-{token}" onerror="{action}"></audio>',
            ),
            ("click-event", f'<button onclick="{action}">{term}</button>'),
            (
                "focus-event",
                f'<select autofocus onfocus="{action}"><option>{term}</option></select>',
            ),
            (
                "javascript-url",
                f'<form action="javascript:{action}"><button>{term}</button></form>',
            ),
            (
                "iframe-srcdoc",
                f'<iframe srcdoc="&lt;svg onload=&quot;{action}&quot;&gt;&lt;/svg&gt;"></iframe>',
            ),
            ("mouse-event", f'<div onpointerenter="{action}">{term}</div>'),
            ("attribute-break", f'" autofocus onfocus="{action}" data-note="'),
            (
                "svg-event",
                f'<svg><set onbegin="{action}" attributeName="x" to="1" /></svg>',
            ),
            ("script-element", f"</noscript><script>{action}</script>"),
        ]
    elif label == "cmdi":
        choices = [
            ("shell-separator", f"{token}.pdf; (printf '%s' '{token}')"),
            ("shell-separator", f"{token}.pdf && {{ printf '%s' '{token}'; }}"),
            ("shell-pipe", f"{token}.pdf | (printf '%s' '{token}')"),
            ("shell-substitution", f"{token}$(printf '%s' '{a}' '{b}' '{c}').pdf"),
            ("shell-substitution", f"{token}${{IFS}}$(printf '{token}').pdf"),
            ("shell-newline", f"{token}.pdf\r\nprintf '%s' '{token}'"),
            ("shell-quote-break", f"{token}' && printf '%s' '{token}' #"),
            ("shell-quote-break", f"{token}\" | printf '%s' '{token}' #"),
            ("shell-separator", f"{token}.pdf; echo${{IFS}}{token}"),
            ("windows-separator", f"{token}.pdf & (echo {token})"),
            ("windows-separator", f"{token}.pdf | (echo {token})"),
            ("windows-separator", f'{token}" & echo {token} & rem "'),
            ("shell-process-substitution", f"{token}.pdf <(printf '%s' '{token}')"),
            ("shell-substitution", f"{token}$(echo '{a}' '{b}' '{c}').pdf"),
            ("shell-separator", f"{token}.pdf; printf\\\n '%s' '{token}'"),
            ("shell-separator", f"{token}.pdf; 'printf' '%s' '{token}'"),
        ]
    else:
        # All parent chains exceed their prepended directory depth.
        # Parser-dependent variants remain attempts, not claims of successful access.
        choices = [
            ("posix-parent", f"downloads/./{a}/../../../fixtures/{b}/{c}.pdf"),
            ("posix-parent", f"assets/{a}/../{b}/../../../fixtures/{c}.svg"),
            ("posix-parent", f"documents//{a}//../../../fixtures/{b}-{c}.pdf"),
            ("windows-parent", f"reports\\{a}\\..\\..\\..\\fixtures\\{b}\\{c}.csv"),
            ("mixed-parent", f"assets/{a}\\../..\\../fixtures/{b}/{c}.json"),
            ("posix-parent", f"%2e%2e/%2e%2e/fixtures/{a}/{b}/{c}.pdf"),
            ("posix-parent", f"%252e%252e%252f%252e%252e%252ffixtures/{a}/{b}/{c}.pdf"),
            ("windows-parent", f"%2e%2e%5c%2e%2e%5cfixtures%5c{a}%5c{b}-{c}.csv"),
            ("posix-parent", f"..%2f..%2ffixtures/{a}/{b}/{c}.json"),
            ("posix-parent", f".%2e/.%2e/fixtures/{a}/{b}/{c}.json"),
            ("parser-dependent-parent", f"..;/..;/fixtures/{a}/{b}/{c}.pdf"),
            ("parser-dependent-parent", f"....//....//fixtures/{a}/{b}/{c}.pdf"),
            ("posix-parent", f"media/{a}/{b}/../../../../fixtures/{c}.csv"),
            ("windows-parent", f"media\\{a}\\{b}\\..\\..\\..\\..\\fixtures\\{c}.json"),
            ("posix-parent", f"././../../fixtures/{a}/{b}/{c}.svg"),
            ("mixed-parent", f"..\\../..\\fixtures/{a}/{b}/{c}.pdf"),
        ]
    family, value = choices[variant % len(choices)]
    # Reuse v1 names for shared mechanisms: new contexts are not independent families.
    return f"{label}-{family}", value


def request_for(value: str, index: int, normal: bool) -> dict[str, Any]:
    channel = index % len(SURFACES)
    headers = {
        "accept": "application/json",
        "user-agent": AGENTS[(index // 10) % len(AGENTS)],
        "accept-language": (
            "en-GB,en;q=0.9",
            "zh-TW,zh;q=0.9",
            "ja-JP,ja;q=0.9",
            "fr-FR,fr;q=0.9",
        )[(index // 50) % 4],
    }
    request: dict[str, Any] = {
        "method": "POST",
        "path": "/store/carts/cart_PLACEHOLDER",
        "query": "",
        "headers": headers,
        "body": None,
    }
    body: dict[str, Any] = {}
    if channel == 0:
        request.update(method="GET", path="/store/products")
        params = [
            ("q", value),
            ("limit", "12"),
            ("order", "title"),
            ("fields", "id,title,handle"),
        ]
        request["query"] = urlencode(
            params if index % 2 else params[::-1], quote_via=quote
        )
    elif channel in (1, 2, 3):
        address = {
            "first_name": "Alex",
            "last_name": "Example",
            "address_1": "Example Street",
            "city": "Copenhagen",
            "country_code": "dk",
            "postal_code": "1000",
            "company": value,
        }
        if channel == 1:
            body = {"shipping_address": address}
        elif channel == 2:
            address["address_2"] = value
            address["company"] = "Example shop"
            body = {"billing_address": address}
        else:
            request["path"] = "/store/customers/me/addresses"
            body = address
    elif channel == 4:
        # Plain uppercase code with no amount/privilege tampering for normal requests.
        code = (
            "-".join(re.findall(r"[A-Za-z]+", value)[:6]).upper() if normal else value
        )
        body = {"promo_codes": [code]}
    elif channel == 5:
        request["path"] = "/store/carts/cart_PLACEHOLDER/line-items"
        body = {
            "variant_id": "variant_PLACEHOLDER",
            "quantity": 1,
            "metadata": {"engraving": value, "gift_wrap": True},
        }
    elif channel == 6:
        request["path"] = "/store/customers/me"
        body = {"metadata": {"preferences": {"delivery_note": value, "gift": False}}}
    elif channel == 7:
        body = {"metadata": {"gift": {"messages": [value], "wrap": "paper"}}}
    elif channel == 8:
        request.update(
            method="GET", path="/store/products", query="limit=12&fields=id,title"
        )
        headers["referer"] = "https://example.invalid/dk/store?" + urlencode(
            {"q": value}
        )
    else:
        request.update(method="GET", path="/store/products")
        # Normal values use the documented field ordering shape, plus a real search.
        request["query"] = urlencode(
            {
                "q": value if normal else "gift",
                "order": ("title" if index % 2 else "-created_at") if normal else value,
                "limit": "12",
            }
        )
    if request["method"] == "POST":
        headers["content-type"] = "application/json; charset=utf-8"
        request["body"] = json.dumps(
            body, ensure_ascii=(index // 10) % 2 == 0, separators=(",", ":")
        )
    return request


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=20260923)
    parser.add_argument(
        "--output-dir", type=Path, default=ROOT / "datasets/commerce/synthetic-10k-v2"
    )
    args = parser.parse_args()
    output = args.output_dir.resolve()
    if (output / "requests.jsonl").exists():
        raise FileExistsError(
            "Choose a new output directory; previous datasets are preserved"
        )
    previous_files = sorted((ROOT / "datasets").rglob("requests.jsonl"))
    exact: set[str] = set()
    relaxed: set[str] = set()
    previous_ids: set[str] = set()
    previous_families: set[str] = set()
    prior_report: list[dict[str, Any]] = []
    for path in previous_files:
        records = [
            json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
        ]
        prior_report.append(
            {
                "path": path.relative_to(ROOT).as_posix(),
                "records": len(records),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
        for record in records:
            exact.add(fingerprint(record["request"], relaxed=False))
            relaxed.add(fingerprint(record["request"], relaxed=True))
            previous_ids.add(record["sample_id"])
            previous_families.add(record.get("template_family", ""))
    rows: list[dict[str, Any]] = []
    exclusions = 0
    coverage: dict[str, Any] = {}
    for label in LABELS:
        rng = random.Random(f"{args.seed}:{label}:new-contexts")
        for index in range(2000):
            for _ in range(2000):
                family, value = make_payload(label, index // 10, rng)
                request = request_for(value, index, label == "normal")
                one, two = (
                    fingerprint(request, relaxed=False),
                    fingerprint(request, relaxed=True),
                )
                if one not in exact and two not in relaxed:
                    exact.add(one)
                    relaxed.add(two)
                    break
                exclusions += 1
            else:
                raise RuntimeError("Candidate space exhausted")
            rows.append({"template_family": family, "request": request, "label": label})
        coverage[label] = {surface: 200 for surface in SURFACES}
    random.Random(args.seed).shuffle(rows)
    rows = [
        {"sample_id": f"commerce-10k-v2-{i:05d}", **row}
        for i, row in enumerate(rows, 1)
    ]
    assert not previous_ids.intersection(r["sample_id"] for r in rows)
    output.mkdir(parents=True, exist_ok=True)
    path = output / "requests.jsonl"
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        for row in rows:
            stream.write(
                json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n"
            )
    report = validate(path)
    report.update(
        {
            "path": "requests.jsonl",
            "seed": args.seed,
            "created_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "prior_datasets": prior_report,
            "generator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "cross_batch_exact_duplicates": 0,
            "cross_batch_normalized_numeric_variant_duplicates": 0,
            "within_batch_normalized_numeric_variant_duplicates": 0,
            "rejected_duplicate_candidates": exclusions,
            "normalization": "Ignore client identity headers; parse query/JSON; recursively decode percent escapes up to three times; case-fold; replace numeric values/runs. Input-carrying Referer/x-search retained. Not full semantic equivalence.",
            "template_families": dict(
                sorted(Counter(r["template_family"] for r in rows).items())
            ),
            "new_family_names": sorted(
                {r["template_family"] for r in rows} - previous_families
            ),
            "request_surfaces_per_class": coverage,
            "executed_requests": 0,
            "label_validation": "Template-assigned; no independent ground-truth review or Medusa execution",
        }
    )
    (output / "validation.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    schema = ROOT / "datasets/commerce/review-v1/schema.json"
    (output / "schema.json").write_bytes(schema.read_bytes())
    print(
        json.dumps(
            {
                k: report[k]
                for k in (
                    "records",
                    "labels",
                    "prior_datasets",
                    "new_family_names",
                    "rejected_duplicate_candidates",
                )
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
