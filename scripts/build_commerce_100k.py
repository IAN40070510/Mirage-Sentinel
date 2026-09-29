"""Curate prior batches and build 100k offline structural-unique candidates."""

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
from urllib.parse import parse_qsl, quote, urlencode

from expand_commerce_dataset import decode, make_payload
from generate_commerce_dataset import AGENTS, LABELS, ROOT, payload
from validate_commerce_dataset import validate_record

# Preserve execution grammar, not shop names, fixture names or generated markers.
GRAMMAR = {
    "a",
    "action",
    "alert",
    "all",
    "and",
    "annotation",
    "as",
    "asc",
    "attribute",
    "audio",
    "autofocus",
    "bash",
    "between",
    "body",
    "button",
    "by",
    "case",
    "cast",
    "char",
    "cmd",
    "coalesce",
    "concat",
    "data",
    "desc",
    "details",
    "distinct",
    "div",
    "document",
    "download",
    "echo",
    "else",
    "end",
    "exists",
    "false",
    "file",
    "form",
    "from",
    "having",
    "href",
    "html",
    "http",
    "https",
    "iframe",
    "ifs",
    "img",
    "in",
    "input",
    "is",
    "javascript",
    "length",
    "like",
    "lower",
    "math",
    "name",
    "noscript",
    "not",
    "null",
    "nullif",
    "onbegin",
    "onclick",
    "onerror",
    "onfocus",
    "onload",
    "onmouseover",
    "onpointerenter",
    "ontoggle",
    "open",
    "option",
    "or",
    "order",
    "powershell",
    "printf",
    "rem",
    "reverse",
    "script",
    "select",
    "set",
    "sh",
    "span",
    "src",
    "srcdoc",
    "style",
    "substr",
    "summary",
    "svg",
    "text",
    "textarea",
    "then",
    "title",
    "to",
    "true",
    "union",
    "utf",
    "values",
    "video",
    "when",
    "where",
    "with",
    "xlink",
    "xml",
    "xmlns",
}


def text_shape(text: str) -> str:
    text = decode(text).casefold()
    text = re.sub(r"\b\d+\b", "~num~", text)
    text = re.sub(
        r"[^\W\d]+[\w-]*",
        lambda m: m[0] if m[0] in GRAMMAR else "~word~",
        text,
        flags=re.UNICODE,
    )
    text = re.sub(r"(?:~word~[\s_\-]*)+", "~word~", text)
    return re.sub(r"\s+", " ", text).strip()


def shape(value: Any) -> Any:
    if isinstance(value, str):
        return text_shape(value)
    if isinstance(value, dict):
        return {k: shape(v) for k, v in sorted(value.items())}
    if isinstance(value, (tuple, list)):
        return [shape(v) for v in value]
    if isinstance(value, bool) or value is None:
        return value
    return "~number~"


def structure(request: dict[str, Any]) -> str:
    body = request["body"]
    if body is not None:
        try:
            body = json.loads(body)
        except ValueError:
            pass
    # Endpoint names remain, object IDs become placeholders.
    path = re.sub(
        r"\b(cart|order|variant|addr|cus|pay_col|prod|item)_[^/]+",
        r"\1_ID",
        decode(request["path"]),
    )
    value = {
        "method": request["method"],
        "path": path,
        "query": [
            (k, shape(v))
            for k, v in sorted(parse_qsl(request["query"], keep_blank_values=True))
        ],
        "body": shape(body),
        "input_headers": {
            k.lower(): shape(v)
            for k, v in request["headers"].items()
            if k.lower() in {"x-search", "referer"}
        },
    }
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, ensure_ascii=False).encode()
    ).hexdigest()


def metadata(mask: int) -> dict[str, Any]:
    options = {
        "gift_wrap": True,
        "delivery_note": "Leave with reception during opening hours",
        "gift_message": "Thank you for your help",
        "packaging": {"material": "paper", "include_receipt": False},
        "contact_preferences": {"email": True, "sms": False},
        "personalization": {"font": "serif", "alignment": "center"},
        "gift_recipients": [{"name": "Example A"}, {"name": "Example B"}],
        "preferences": {"substitutions": False, "colors": ["navy", "cream"]},
    }
    return {k: v for i, (k, v) in enumerate(options.items()) if mask & (1 << i)}


CONTEXTS = (
    "product-search",
    "collection-search",
    "category-search",
    "customer-first-name",
    "customer-last-name",
    "customer-metadata",
    "new-customer",
    "customer-address",
    "cart-shipping",
    "cart-billing",
    "cart-promotion",
    "cart-metadata",
    "add-line-item",
    "update-line-item",
    "shipping-method-data",
    "create-cart",
)


def compose(
    value: str, index: int, mask: int, normal: bool, rng: random.Random
) -> dict[str, Any]:
    context = index % len(CONTEXTS)
    headers = {"accept": "application/json", "user-agent": rng.choice(AGENTS)}
    r: dict[str, Any] = {
        "method": "POST",
        "path": "/store/carts/cart_PLACEHOLDER",
        "query": "",
        "headers": headers,
        "body": None,
    }
    meta = metadata(mask)
    if context < 3:
        r["method"] = "GET"
        r["path"] = (
            "/store/products",
            "/store/collections",
            "/store/product-categories",
        )[context]
        params = {"q": value}
        # Fields select different response projections; never create imaginary API fields.
        options = [
            ("limit", "12"),
            ("offset", "0"),
            ("fields", "id,name" if context == 2 else "id,title"),
            ("order", "name" if context == 2 else "title"),
        ]
        if context == 0:
            options += [
                ("region_id", "reg_PLACEHOLDER"),
                ("currency_code", "eur"),
                ("collection_id[]", "pcol_PLACEHOLDER"),
                ("tags[]", "ptag_PLACEHOLDER"),
            ]
        else:
            options += [
                ("id[]", "pcat_PLACEHOLDER" if context == 2 else "pcol_PLACEHOLDER")
            ]
        params.update({k: v for i, (k, v) in enumerate(options) if mask & (1 << i)})
        r["query"] = urlencode(params, quote_via=quote)
        return r
    body: dict[str, Any] = {"metadata": meta}
    address = {
        "first_name": "Alex",
        "last_name": "Example",
        "address_1": "Example Street",
        "city": "Copenhagen",
        "country_code": "dk",
        "postal_code": "1000",
    }
    if context in (3, 4, 5):
        r["path"] = "/store/customers/me"
        if context == 3:
            body["first_name"] = value
        elif context == 4:
            body["last_name"] = value
        else:
            meta["shopping_note"] = value
    elif context == 6:
        r["path"] = "/store/customers"
        body.update(email="buyer@example.invalid", first_name=value)
    elif context == 7:
        r["path"] = "/store/customers/me/addresses"
        address["company"] = value
        body.update(address)
    elif context in (8, 9):
        address["company"] = value
        body["shipping_address" if context == 8 else "billing_address"] = address
    elif context == 10:
        # One coupon string; the field does not imply an active promotion.
        body["promo_codes"] = ["WELCOME-GIFT" if normal else value]
        if normal:
            meta["shopping_note"] = value
    elif context == 11:
        meta["delivery_instructions"] = {"message": value, "recipient": "reception"}
    elif context == 12:
        r["path"] = "/store/carts/cart_PLACEHOLDER/line-items"
        body.update(variant_id="variant_PLACEHOLDER", quantity=1)
        meta["engraving"] = value
    elif context == 13:
        r["path"] = "/store/carts/cart_PLACEHOLDER/line-items/item_PLACEHOLDER"
        body["quantity"] = 1
        meta["engraving"] = value
    elif context == 14:
        r["path"] = "/store/carts/cart_PLACEHOLDER/shipping-methods"
        # Provider-defined data, not arbitrary top-level schema properties.
        body = {
            "option_id": "so_PLACEHOLDER",
            "data": {**meta, "delivery_instructions": value},
        }
    else:
        r["path"] = "/store/carts"
        body.update(region_id="reg_PLACEHOLDER", email="buyer@example.invalid")
        meta["gift_note"] = value
    headers["content-type"] = "application/json"
    r["body"] = json.dumps(
        body, ensure_ascii=rng.choice((True, False)), separators=(",", ":")
    )
    return r


def candidate(label: str, recipe: int, rng: random.Random) -> tuple[str, str]:
    # Mechanism names stay shared with previous batches for honest grouped evaluation.
    if recipe < 16:
        return make_payload(label, recipe, rng)
    if recipe < 32:
        return payload(label, recipe - 16, rng)
    if label == "normal":
        texts = [
            "Please use recyclable packaging and omit the printed invoice.",
            "訂單備註：收件人不在時，請交管理室；請勿放在門外。",
            "Please keep the gift message blank; the recipient will write it.",
            "The name should read “Anne-Marie O’Connor” — accents matter.",
            "Size M/L, length ¾, cotton & linen; delivery Mon–Fri.",
            "交換原因：尺寸不合，希望保留優惠；未穿過且吊牌完整。",
            "新しい住所への配送をお願いします。表札は別の名前です。",
            "Bitte nicht beim Nachbarn abgeben. Abholung bevorzugt.",
            "A+B / C++ / R&D — these are the requested printed initials.",
            "Please print &lt;button&gt; as plain text, not a graphic.",
            "The instructions mention SQL SELECT and UNION as textbook terms.",
            "Looking for a gift under €50; no fragrance or leather please.",
            "هل يمكن تغليف الطلب كهدية؟ شكراً.",
            "선물용입니다. 영수증은 포장 안에 넣지 말아 주세요.",
            "Unavailable color is acceptable; please contact me before changing size.",
            "catalog/summer/lookbook.pdf is the reference filename.",
        ]
        return "normal-shopping-text", texts[(recipe - 32) % len(texts)]
    # New syntax combinations remain grouped by their mechanisms, not random IDs.
    family, text = make_payload(label, (recipe - 32) % 16, rng)
    if label == "sqli":
        text = (
            text.replace(" OR ", " OR (").replace("-- ", ")-- ")
            if " OR " in text
            else text.replace("SELECT ", "SELECT DISTINCT ")
        )
    elif label == "xss":
        # Distinct surrounding HTML context, not numerical/string-marker variations.
        if text.startswith("<"):
            text = "<section><p>" + text + "</p></section>"
        else:
            family, text = make_payload(label, 0, rng)
    elif label == "cmdi":
        family, text = make_payload(label, (recipe - 32) % 16, rng)
        text = text.replace("printf '%s'", "printf '%s\\n'")
    else:
        text = "uploads/previews/" + text
        # Ensure parents still escape the prepended directories.
        text = text.replace("fixtures/", "../../fixtures/").replace(
            "fixtures\\", "..\\..\\fixtures\\"
        )
    return family, text


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir", type=Path, default=ROOT / "datasets/commerce/curated-100k-v1"
    )
    parser.add_argument("--seed", type=int, default=2026092301)
    args = parser.parse_args()
    out = args.output_dir.resolve()
    if out.exists():
        raise FileExistsError("Choose a fresh directory; previous files are preserved")
    paths = sorted((ROOT / "datasets").rglob("requests.jsonl"))
    groups: dict[str, list[dict[str, Any]]] = {}
    priors = []
    for path in paths:
        data = path.read_bytes()
        rows = [json.loads(line) for line in data.decode("utf-8").splitlines()]
        priors.append(
            {
                "path": path.relative_to(ROOT).as_posix(),
                "rows": len(rows),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
        for row in rows:
            groups.setdefault(structure(row["request"]), []).append(row)
    conflicts = {k for k, v in groups.items() if len({r["label"] for r in v}) > 1}
    retained = [v[0] for k, v in groups.items() if k not in conflicts]
    seen = set(groups)  # Reject all previous shapes, including ambiguous ones.
    old_counts = Counter(r["label"] for r in retained)
    new_rows = []
    rejected = Counter()
    coverage = {}
    recipes = {}
    for label in LABELS:
        needed = 20000 - old_counts[label]
        if needed < 0:
            raise ValueError("Prior curated label count exceeds target")
        rng = random.Random(f"{args.seed}:{label}")
        # Finite, shuffled cross-product: content grammar x real context x optional metadata.
        configurations = [
            (recipe, context, mask)
            for recipe in range(48)
            for context in range(16)
            for mask in range(256)
        ]
        rng.shuffle(configurations)
        accepted = 0
        count = Counter()
        used = Counter()
        for recipe, context, mask in configurations:
            family, value = candidate(label, recipe, rng)
            request = compose(value, context, mask, label == "normal", rng)
            key = structure(request)
            if key in seen:
                rejected[label] += 1
                continue
            seen.add(key)
            row = {
                "sample_id": f"commerce-100k-new-{len(new_rows) + 1:06d}",
                "template_family": family,
                "request": request,
                "label": label,
            }
            new_rows.append(row)
            count[CONTEXTS[context]] += 1
            used[str(recipe)] += 1
            accepted += 1
            if accepted % 5000 == 0:
                print(f"{label}: {accepted}/{needed}", flush=True)
            if accepted == needed:
                break
        if accepted != needed:
            raise RuntimeError(
                f"Insufficient structural diversity for {label}: {accepted}/{needed}; no dataset written"
            )
        coverage[label] = dict(count)
        recipes[label] = dict(used)
    all_rows = retained + new_rows
    random.Random(args.seed).shuffle(all_rows)
    assert len(all_rows) == 100000
    assert len({r["sample_id"] for r in all_rows}) == 100000
    out.mkdir(parents=True)
    for name, rows in [("requests.jsonl", all_rows), ("new-records.jsonl", new_rows)]:
        with (out / name).open("w", encoding="utf-8", newline="\n") as f:
            for i, row in enumerate(rows, 1):
                validate_record(row, i)
                f.write(
                    json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n"
                )
    report = {
        "created_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "seed": args.seed,
        "records": len(all_rows),
        "labels": dict(Counter(r["label"] for r in all_rows)),
        "prior_datasets": priors,
        "prior_records": sum(p["rows"] for p in priors),
        "retained_prior_records": len(retained),
        "retained_prior_labels": dict(old_counts),
        "excluded_prior_records": sum(p["rows"] for p in priors) - len(retained),
        "prior_conflicting_structure_groups": len(conflicts),
        "new_records": len(new_rows),
        "new_labels": dict(Counter(r["label"] for r in new_rows)),
        "rejected_candidate_structures": dict(rejected),
        "new_contexts": coverage,
        "new_recipes": recipes,
        "families": dict(Counter(r["template_family"] for r in all_rows)),
        "generator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "requests_sha256": hashlib.sha256(
            (out / "requests.jsonl").read_bytes()
        ).hexdigest(),
        "new_records_sha256": hashlib.sha256(
            (out / "new-records.jsonl").read_bytes()
        ).hexdigest(),
        "executed_requests": 0,
        "limits": "Structural uniqueness is heuristic; optional metadata combinations and shared attack mechanisms remain correlated. Not independently reviewed ground truth.",
    }
    (out / "validation.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (out / "schema.json").write_bytes(
        (ROOT / "datasets/commerce/review-v1/schema.json").read_bytes()
    )
    print(
        json.dumps(
            {
                k: report[k]
                for k in [
                    "records",
                    "labels",
                    "retained_prior_records",
                    "excluded_prior_records",
                    "new_records",
                    "prior_conflicting_structure_groups",
                ]
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
