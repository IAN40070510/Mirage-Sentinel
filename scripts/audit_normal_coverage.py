"""Check normal request coverage without reading responses or forensic databases."""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re
from typing import Any

# Matches the implemented storefront and smoke-test API contract, not arbitrary URLs.
REQUIRED = {
    'regions': ('GET', r'/store/regions'),
    'products': ('GET', r'/store/products'),
    'storefront': ('GET', r'/[a-z]{2}'),
    'assets': ('GET', r'/_next/static/.+'),
    'register': ('POST', r'/auth/customer/emailpass/register'),
    'login': ('POST', r'/auth/customer/emailpass'),
    'create_customer': ('POST', r'/store/customers'),
    'current_customer': ('GET', r'/store/customers/me'),
    'create_cart': ('POST', r'/store/carts'),
    'cart_items': ('POST', r'/store/carts/[^/]+/line-items'),
    'cart_address': ('POST', r'/store/carts/[^/]+'),
    'shipping_options': ('GET', r'/store/shipping-options'),
    'shipping_method': ('POST', r'/store/carts/[^/]+/shipping-methods'),
    'payment_collection': ('POST', r'/store/payment-collections'),
    'payment_session': ('POST', r'/store/payment-collections/[^/]+/payment-sessions'),
    'complete_cart': ('POST', r'/store/carts/[^/]+/complete'),
    'read_order': ('GET', r'/store/orders/[^/]+'),
}


def audit(folder: Path) -> dict[str, Any]:
    methods: Counter[str] = Counter()
    coverage: Counter[str] = Counter()
    sessions: set[str] = set()
    total = 0
    for path in sorted(folder.glob('*.jsonl')):
        for line in path.open(encoding='utf-8'):
            row = json.loads(line)
            if row['label'] != 'normal':
                continue
            total += 1
            request = row['request']
            methods[request['method']] += 1
            if row.get('session_id'):
                sessions.add(row['session_id'])
            for name, (method, pattern) in REQUIRED.items():
                if request['method'] == method and re.fullmatch(pattern, request['path']):
                    coverage[name] += 1
    missing = sorted(set(REQUIRED) - set(coverage))
    return {'normal_rows': total, 'methods': dict(methods), 'sessions': len(sessions),
            'route_coverage': {name: coverage[name] for name in REQUIRED},
            'missing': missing, 'minimum_route_coverage_passed': not missing,
            'warning': 'Route presence alone does not establish realistic diversity, label quality or generalization'}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--require-complete', action='store_true')
    args = parser.parse_args()
    report = audit(args.data)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(report, ensure_ascii=False), flush=True)
    if args.require_complete and report['missing']:
        raise SystemExit('Normal route coverage is incomplete; do not release this as a repaired dataset')


if __name__ == '__main__':
    main()
