"""Collect successful scripted shopping requests from an isolated loopback stack.

This is application-exercised synthetic traffic, never production customer data.
Only a completed normal journey is admitted; no attack requests are collected.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import secrets
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit

import httpx

from smoke_commerce import ScriptAssets, exercise
from normal_scenarios import profile


def sanitized_request(request: httpx.Request) -> dict[str, Any]:
    """Keep only model fields; replace credentials with independent surrogates."""
    private = re.compile(r'password|token|secret|authorization|cookie|api.?key', re.I)

    def scrub(value: Any, key: str = '') -> Any:
        if private.search(key):
            # Preserve a credential-like shape, not an actual credential or hash of it.
            return secrets.token_urlsafe(24)
        if isinstance(value, dict):
            return {k: scrub(v, k) for k, v in value.items()}
        if isinstance(value, list):
            return [scrub(v) for v in value]
        return value

    body = request.content.decode('utf-8') if request.content else ''
    content_type = request.headers.get('content-type', '')
    if body:
        if 'application/json' not in content_type:
            raise ValueError('Collector only admits known JSON request bodies')
        body = json.dumps(scrub(json.loads(body)), ensure_ascii=False, separators=(',', ':'))
    query = urlencode([(k, scrub(v, k)) for k, v in parse_qsl(request.url.query.decode(), keep_blank_values=True)])
    return {'method': request.method, 'path': request.url.path, 'query': query,
            'headers': {'content-type': content_type} if content_type else {}, 'body': body}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', default='http://localhost:8080')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--sessions', type=int, default=30)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--suite', choices=('pilot', 'development', 'acceptance'), default='pilot')
    args = parser.parse_args()
    if urlsplit(args.url).hostname not in {'localhost', '127.0.0.1', '::1'}:
        parser.error('Only isolated loopback endpoints are allowed')
    if args.sessions < 10:
        parser.error('At least 10 independent sessions are required')
    args.output.mkdir(parents=True, exist_ok=False)
    report: dict[str, Any] = {'created_at': datetime.now(timezone.utc).isoformat(timespec='milliseconds'),
        'source': 'isolated scripted application requests, not production traffic',
        'revision': args.revision, 'suite': args.suite, 'sessions': [], 'complete': False,
        'limits': ['Scripted success is not independent human label review',
                   'Credentials replaced before persistence; responses and auth headers excluded',
                   'Repeated normal route templates are expected; never split a journey across sets']}
    searches = ['cotton shirt', 'blue backpack', "OBrien mug", '中文商品', 'size 10 shoes',
                'linen pillow', 'red scarf', 'wooden desk', 'bamboo box', 'coffee cup']
    try:
        for index in range(args.sessions):
            session = secrets.token_hex(16)
            split = 'train' if index < args.sessions * .7 else ('validation' if index < args.sessions * .85 else 'test')
            if args.suite == 'development':
                split = 'train' if index < args.sessions * .8 else 'validation'
            elif args.suite == 'acceptance':
                split = 'acceptance'
            scenario = profile(split if split != 'test' else 'validation', index)
            captured: list[dict[str, Any]] = []
            admitted_errors: set[int] = set()

            def receive(response: httpx.Response) -> None:
                if 200 <= response.status_code < 300 or response.status_code in admitted_errors:
                    captured.append({'request': sanitized_request(response.request), 'status': response.status_code})

            with httpx.Client(base_url=args.url, timeout=60, follow_redirects=True,
                              event_hooks={'response': [receive]}) as client:
                region_response = client.get('/store/regions')
                region_response.raise_for_status()
                region = region_response.json()['regions'][0]
                home = client.get('/' + region['countries'][0]['iso_2'])
                home.raise_for_status()
                assets = ScriptAssets()
                assets.feed(home.text)
                if not assets.urls:
                    raise ValueError('Missing storefront assets')
                for source in assets.urls:
                    client.get(source).raise_for_status()
                if args.suite == 'pilot':
                    client.get('/store/products', params={'q': searches[index % len(searches)], 'limit': 5 + index}).raise_for_status()
                else:
                    client.get('/store/products', params={k: scenario[k] for k in ('limit', 'offset')} | {'q': scenario['query']}).raise_for_status()
                    # Explicit benign guest/validation errors, not arbitrary response errors.
                    admitted_errors = {401, 403}
                    guest = client.get('/store/customers/me')
                    if guest.status_code not in admitted_errors:
                        raise ValueError('Unexpected guest-access response')
                    admitted_errors = {400, 422}
                    invalid = client.post('/auth/customer/emailpass/register', json={})
                    if invalid.status_code not in admitted_errors:
                        raise ValueError('Unexpected empty-registration response')
                    admitted_errors = set()
                # This function completes registration, cart, shipping, payment and an order.
                exercise(client, scenario if args.suite != 'pilot' else None)
            path = args.output / (split + '-' + session + '.jsonl')
            with path.open('x', encoding='utf-8') as stream:
                for rownum, item in enumerate(captured, 1):
                    row = {'sample_id': f'app-normal-{session}-{rownum}', 'session_id': session,
                           'source': 'external', 'label': 'normal', 'template_family': None,
                           'request': item['request'],
                           'annotation': {'review_status': 'source_labeled_unverified', 'reviewer': None,
                                          'reason': 'Known benign scripted journey completed against isolated application; not hand reviewed'},
                           'provenance': {'dataset': 'Mirage-Sentinel/isolated-shopping-capture',
                                          'revision': args.revision, 'file': path.name, 'row': rownum,
                                          'assigned_split': split, 'response_status': item['status'],
                                          'suite': args.suite, 'scenario_index': index,
                                          'profile': scenario if args.suite != 'pilot' else None,
                                          'credential_policy': 'random surrogates; no authentication headers'}}
                    stream.write(json.dumps(row, ensure_ascii=False) + '\n')
            report['sessions'].append({'session_id': session, 'split': split, 'file': path.name,
                'rows': len(captured), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                'profile': scenario if args.suite != 'pilot' else None,
                'routes': dict(Counter(item['request']['method'] + ' ' + item['request']['path'] for item in captured))})
            print(f'Completed isolated normal session {index + 1}/{args.sessions}: {len(captured)} requests', flush=True)
        report['complete'] = True
    finally:
        (args.output / 'manifest.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print('Normal capture completed; this is source material, not an audited training release.', flush=True)


if __name__ == '__main__':
    main()
