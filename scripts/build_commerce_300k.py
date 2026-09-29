"""Extend a fixed 100k snapshot to 300k without sending any HTTP requests."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from build_commerce_100k import CONTEXTS, candidate, compose, metadata, structure
from generate_commerce_dataset import AGENTS, LABELS, ROOT
from validate_commerce_dataset import validate_record

NEW_CONTEXTS = (
    "customer-address-first-name",
    "customer-address-last-name",
    "customer-address-line-one",
    "customer-address-line-two",
    "customer-address-city",
    "update-customer-address-company",
    "update-customer-address-line-one",
    "update-customer-address-line-two",
    "cart-shipping-first-name",
    "cart-shipping-last-name",
    "cart-shipping-line-one",
    "cart-shipping-line-two",
    "cart-billing-first-name",
    "cart-billing-last-name",
    "cart-billing-line-one",
    "cart-billing-line-two",
    "create-cart-initial-items",
    "create-cart-shipping",
    "create-cart-billing",
    "line-item-customizations-array",
    "customer-nested-preferences",
    "cart-multiple-gift-messages",
    "shipping-method-recipient",
    "update-line-item-personalization",
)
ALL_CONTEXTS = CONTEXTS + NEW_CONTEXTS


def more_payload(label: str, recipe: int, rng: random.Random) -> tuple[str, str]:
    if recipe < 48:
        return candidate(label, recipe, rng)
    # Constant harmless markers: additional uniqueness must come from structure.
    examples = {
        "normal": [
            ("shopping-text", "Gift message: “Thank you!”\nPlease omit the price tag."),
            (
                "shopping-text",
                "Accessibility request: ring the bell, then allow extra time.",
            ),
            ("shopping-text", "請把禮物分開包裝：外套一包、圍巾一包，謝謝。"),
            (
                "technical-text",
                'Print the literal text &lt;input type="text"&gt; on the card.',
            ),
            (
                "shopping-text",
                "Delivery instructions (office): use the side entrance, not the loading bay.",
            ),
            (
                "shopping-text",
                "If unavailable, cancel this item; do not replace the size automatically.",
            ),
            (
                "punctuation-text",
                "Mon–Fri / AM–PM; A&B studio — attention: front desk.",
            ),
            ("unicode-text", "التغليف بدون بلاستيك، مع بطاقة تهنئة. 🎁"),
        ],
        "sqli": [
            (
                "conditional",
                "gift' AND (CASE WHEN 'a' IN ('a','b') THEN TRUE ELSE FALSE END)-- ",
            ),
            (
                "union",
                "gift' UNION SELECT value FROM (VALUES ('probe')) AS sample(value)-- ",
            ),
            ("subquery", "gift' OR EXISTS(SELECT 'probe' WHERE 'a'='a')-- "),
            ("boolean", "gift' AND LENGTH(COALESCE('probe',''))>0-- "),
            (
                "union",
                "gift' UNION SELECT CASE WHEN TRUE THEN 'probe' ELSE NULL END-- ",
            ),
            ("subquery", "gift' AND (SELECT COALESCE(NULL,'probe'))='probe'-- "),
            ("boolean", "gift' OR NOT ('probe' IS DISTINCT FROM 'probe')-- "),
            ("conditional", "gift' AND CAST('true' AS BOOLEAN)-- "),
        ],
        "xss": [
            (
                "svg-event",
                "</option></select><svg onload=\"document.title='probe'\"></svg>",
            ),
            ("script-element", '</template><script>document.title="probe"</script>'),
            ("click-event", "<label onclick=\"document.title='probe'\">gift</label>"),
            (
                "focus-event",
                "<textarea autofocus onfocus=\"document.title='probe'\"></textarea>",
            ),
            (
                "mouse-event",
                "<button onpointerenter=\"document.title='probe'\">gift</button>",
            ),
            ("script-element", '</xmp><script>document.title="probe"</script>'),
            (
                "attribute-break",
                "' autofocus onfocus='document.title=\"probe\"' data-note='",
            ),
            ("script-string-break", "';document.title=String('probe');//"),
        ],
        "cmdi": [
            ("shell-separator", "gift; { printf '%s' 'probe'; printf '\\n'; }"),
            ("shell-pipe", "gift | { printf '%s' 'probe'; }"),
            ("shell-substitution", "gift$(printf '%s' 'pro' 'be').txt"),
            ("shell-newline", "gift\n{ printf '%s' 'probe'; }"),
            ("shell-quote-break", "gift' || { printf '%s' 'probe'; } #"),
            ("shell-separator", "gift && (echo 'probe'; printf '\\n')"),
            ("windows-separator", "gift & (echo probe & echo done)"),
            ("shell-process-substitution", "gift <(echo 'probe'; printf '\\n')"),
        ],
        "path_traversal": [
            ("posix-parent", "assets/cache/../../../fixtures/report.txt"),
            ("posix-parent", "assets/../cache/../../fixtures/report.txt"),
            ("windows-parent", "assets\\cache\\..\\..\\..\\fixtures\\report.txt"),
            ("mixed-parent", "assets\\cache/..\\../../fixtures/report.txt"),
            ("posix-parent", "assets/%2e%2e/%2e%2e/fixtures/report.txt"),
            ("posix-parent", "cache/.hidden/../../../fixtures/report.txt"),
            ("windows-parent", "cache\\.hidden\\..\\..\\..\\fixtures\\report.txt"),
            ("posix-parent", "previews/./cache/../../../fixtures/report.txt"),
        ],
    }
    family, text = examples[label][(recipe - 48) % 8]
    return f"{label}-{family}", text


def extended_request(
    value: str, context: int, mask: int, normal: bool, rng: random.Random
) -> dict[str, Any]:
    if context < len(CONTEXTS):
        return compose(value, context, mask, normal, rng)
    index = context - len(CONTEXTS)
    meta = metadata(mask)
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "user-agent": rng.choice(AGENTS),
    }
    address = {
        "first_name": "Alex",
        "last_name": "Example",
        "address_1": "Example Street",
        "city": "Copenhagen",
        "country_code": "dk",
        "postal_code": "1000",
    }
    path = "/store/carts/cart_PLACEHOLDER"
    body: dict[str, Any] = {"metadata": meta}
    if index <= 4:
        field = ("first_name", "last_name", "address_1", "address_2", "city")[index]
        path = "/store/customers/me/addresses"
        address[field] = value
        body.update(address)
    elif index <= 7:
        path = "/store/customers/me/addresses/addr_PLACEHOLDER"
        field = ("company", "address_1", "address_2")[index - 5]
        body[field] = value
    elif index <= 15:
        field = ("first_name", "last_name", "address_1", "address_2")[(index - 8) % 4]
        address[field] = value
        body["shipping_address" if index < 12 else "billing_address"] = address
    elif index == 16:
        path = "/store/carts"
        body.update(
            region_id="reg_PLACEHOLDER",
            items=[
                {
                    "variant_id": "variant_PLACEHOLDER",
                    "quantity": 1,
                    "metadata": {"engraving": value},
                }
            ],
        )
    elif index in (17, 18):
        path = "/store/carts"
        address["company"] = value
        body.update(region_id="reg_PLACEHOLDER")
        body["shipping_address" if index == 17 else "billing_address"] = address
    elif index == 19:
        path = "/store/carts/cart_PLACEHOLDER/line-items"
        body.update(variant_id="variant_PLACEHOLDER", quantity=1)
        meta["customizations"] = [
            {"side": "front", "text": value},
            {"side": "back", "text": "Gift"},
        ]
    elif index == 20:
        path = "/store/customers/me"
        meta["shopping_preferences"] = {
            "delivery": {"instructions": [value], "leave_unattended": False}
        }
    elif index == 21:
        meta["gift_messages"] = [
            {"recipient": "Example A", "text": value},
            {"recipient": "Example B", "text": "Thank you"},
        ]
    elif index == 22:
        path = "/store/carts/cart_PLACEHOLDER/shipping-methods"
        body = {
            "option_id": "so_PLACEHOLDER",
            "data": {
                **meta,
                "recipient": {"instructions": value, "handoff": "reception"},
            },
        }
    else:
        path = "/store/carts/cart_PLACEHOLDER/line-items/item_PLACEHOLDER"
        body["quantity"] = 1
        meta["customizations"] = {"embroidery": {"text": value, "style": "plain"}}
    return {
        "method": "POST",
        "path": path,
        "query": "",
        "headers": headers,
        "body": json.dumps(
            body, ensure_ascii=rng.choice((True, False)), separators=(",", ":")
        ),
    }


def file_hash(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read_rows(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as stream:
        return [json.loads(line) for line in stream]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir", type=Path, default=ROOT / "datasets/commerce/curated-300k-v1"
    )
    parser.add_argument("--seed", type=int, default=2026092302)
    args = parser.parse_args()
    out = args.output_dir.resolve()
    if out.exists():
        raise FileExistsError(
            "Choose a fresh directory; existing datasets are preserved"
        )
    base = ROOT / "datasets/commerce/curated-100k-v1/requests.jsonl"
    old = read_rows(base)
    if len(old) != 100000 or Counter(r["label"] for r in old) != Counter(
        {label: 20000 for label in LABELS}
    ):
        raise ValueError("Expected the verified balanced 100k snapshot")
    # Explicit snapshots avoid accidentally reading copies of a merged master twice.
    paths = [
        ROOT / "datasets/commerce" / name / "requests.jsonl"
        for name in (
            "review-v1",
            "synthetic-10k-v1",
            "synthetic-10k-v2",
            "curated-100k-v1",
        )
    ]
    seen: set[str] = set()
    prior_ids: set[str] = set()
    priors = []
    for path in paths:
        rows = old if path == base else read_rows(path)
        priors.append(
            {
                "path": path.relative_to(ROOT).as_posix(),
                "records": len(rows),
                "sha256": file_hash(path),
            }
        )
        for row in rows:
            seen.add(structure(row["request"]))
            prior_ids.add(row["sample_id"])
    new = []
    rejected = Counter()
    contexts = {}
    recipes = {}
    for label in LABELS:
        rng = random.Random(f"{args.seed}:{label}")
        choices = [
            (recipe, context, mask)
            for recipe in range(56)
            for context in range(len(ALL_CONTEXTS))
            for mask in range(256)
        ]
        rng.shuffle(choices)
        accepted = 0
        count: Counter[str] = Counter()
        recipe_count: Counter[str] = Counter()
        for recipe, context, mask in choices:
            family, value = more_payload(label, recipe, rng)
            request = extended_request(value, context, mask, label == "normal", rng)
            key = structure(request)
            if key in seen:
                rejected[label] += 1
                continue
            seen.add(key)
            record = {
                "sample_id": f"commerce-300k-new-{len(new) + 1:06d}",
                "template_family": family,
                "request": request,
                "label": label,
            }
            if record["sample_id"] in prior_ids:
                raise ValueError("Sample ID conflicts with a prior batch")
            new.append(record)
            count[ALL_CONTEXTS[context]] += 1
            recipe_count[str(recipe)] += 1
            accepted += 1
            if accepted % 10000 == 0:
                print(f"{label}: {accepted}/40000", flush=True)
            if accepted == 40000:
                break
        if accepted != 40000:
            raise RuntimeError(
                f"Insufficient structural diversity for {label}; no dataset written"
            )
        contexts[label] = dict(count)
        recipes[label] = dict(recipe_count)
    merged = old + new
    random.Random(args.seed).shuffle(merged)
    if len(merged) != 300000:
        raise ValueError("Unexpected master size")
    out.mkdir(parents=True)
    for name, rows in [("requests.jsonl", merged), ("new-records.jsonl", new)]:
        with (out / name).open("w", encoding="utf-8", newline="\n") as stream:
            for i, row in enumerate(rows, 1):
                validate_record(row, i)
                stream.write(
                    json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n"
                )
    report = {
        "created_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "seed": args.seed,
        "records": len(merged),
        "labels": dict(Counter(r["label"] for r in merged)),
        "retained_100k_records": len(old),
        "new_records": len(new),
        "new_labels": dict(Counter(r["label"] for r in new)),
        "prior_datasets": priors,
        "prior_snapshot_note": "Prior snapshots overlap; their record counts are NOT additive.",
        "rejected_structural_candidates": dict(rejected),
        "new_contexts": contexts,
        "new_recipes": recipes,
        "families": dict(Counter(r["template_family"] for r in merged)),
        "dependency_sha256": {
            name: file_hash(ROOT / "scripts" / name)
            for name in (
                "build_commerce_300k.py",
                "build_commerce_100k.py",
                "expand_commerce_dataset.py",
                "generate_commerce_dataset.py",
                "validate_commerce_dataset.py",
            )
        },
        "requests_sha256": file_hash(out / "requests.jsonl"),
        "new_records_sha256": file_hash(out / "new-records.jsonl"),
        "executed_requests": 0,
        "limits": "Offline compositional candidates, not 300k independent attacks. Structure deduplication is heuristic; optional metadata configurations remain correlated. No independent label review or live API execution.",
    }
    (out / "validation.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (out / "schema.json").write_bytes((base.parent / "schema.json").read_bytes())
    print(
        json.dumps(
            {
                k: report[k]
                for k in ("records", "labels", "retained_100k_records", "new_records")
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
