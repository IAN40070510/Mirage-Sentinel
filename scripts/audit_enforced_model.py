"""Offline diagnostic probes of the deployed adapter; no fitting or network traffic."""
from __future__ import annotations

import argparse
import asyncio
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import time
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from services.commerce.detection import Detector


def probes() -> list[dict]:
    rows = []
    def add(name: str, expected: str, *, method: str = 'GET', path: str = '/store/products',
            query: str = 'limit=20', body: str = '', headers: dict | None = None) -> None:
        rows.append({'name': name, 'expected': expected, 'request': {
            'method': method, 'path': path, 'query': query, 'body': body, 'headers': headers or {}}})
    for query in ('cotton shirt', '紅色上衣', "O\'Reilly", 'AT&T', '100% cotton',
                  'size < 10', 'price >= 100', 'shirt; blue', 'C++', '日本製',
                  '優惠 🎉', 'a' * 1000, 'javascript: the definitive guide',
                  'UNION SELECT SQL textbook', '../../ print pattern'):
        add('benign product search: ' + query[:60], 'normal', query=urlencode({'q': query}))
    for method,path in [('GET','/dk'),('GET','/store/orders/order_01JABCDEFGHIJK'),
                        ('GET','/store/customers/me'),('OPTIONS','/store/products'),
                        ('HEAD','/store/products'),('GET','/favicon.ico'),('GET','/robots.txt'),
                        ('GET','/store/products/nonexistent-product')]:
        add('benign route: '+method+' '+path, 'normal', method=method,path=path,query='')
    for body in ({'first_name':"O'Reilly",'city':'台北','address_1':'信義路100號'},
                 {'first_name':'Anne-Marie','city':'Montréal','address_1':'12 Rue Saint-Paul'},
                 {'metadata':{'note':'Please deliver after 18:00; ring twice.'}}):
        add('benign cart address: '+str(body), 'normal',method='POST',
            path='/store/carts/cart_01JABCDEFGHIJK',query='',body=json.dumps(body,ensure_ascii=False),
            headers={'content-type':'application/json'})
    payloads = {'sqli':["' OR 1=1--", "' UNION SELECT 1--", "'/**/OR/**/1=1--"],
                'xss':['<script>alert(1)</script>', '<svg/onload=alert(1)>', '<img src=x onerror=alert(1)>'],
                'cmdi':['; whoami', '$(id)', '| id', '`id`'],
                'path_traversal':['../../etc/passwd', '..%2f..%2fetc%2fpasswd', '..\\..\\windows\\win.ini']}
    for label,values in payloads.items():
        for payload in values:
            add('attack query: '+payload, label, query=urlencode({'q':payload}))
            add('attack body: '+payload, label, method='POST',path='/store/carts/cart_01JABCDEFGHIJK',
                query='',body=json.dumps({'metadata':{'note':payload}}),headers={'content-type':'application/json'})
            add('attack header: '+payload, label, headers={'x-probe':payload})
    return rows


async def inspect(bundle: Path, capture: Path | None) -> dict:
    detector = Detector(str(bundle))
    assert detector.model_status == 'ready_five_class' and detector.model_mode == 'enforce'
    results = []
    for index,row in enumerate(probes()):
        request = row['request']
        start = time.perf_counter()
        result = await detector.assess(str(index),request['method'],request['path'],request['query'],
                                       request['headers'],request['body'].encode())
        results.append({**row,'latency_ms':(time.perf_counter()-start)*1000,'result':result})
        # A timed-out worker must finish before the next sequential probe.
        while detector.busy:
            await asyncio.sleep(.001)
    captured = []
    if capture:
        manifest = json.loads((capture/'manifest.json').read_text(encoding='utf-8'))
        for session in manifest['sessions']:
            path = (capture/session['file']).resolve()
            assert path.parent == capture.resolve()
            assert hashlib.sha256(path.read_bytes()).hexdigest() == session['sha256']
            for line in path.read_text(encoding='utf-8').splitlines():
                row=json.loads(line)
                assert row['label']=='normal'
                r=row['request']
                result=await detector.assess(row['session_id'],r['method'],r['path'],r['query'],
                                             r['headers'],(r.get('body') or '').encode())
                captured.append({'sample_id':row['sample_id'],'session_id':row['session_id'],
                                 'path':r['path'],'attack':result['attack'],
                                 'model_attack':result['model_attack'],'fallback':result['fallback']})
                while detector.busy:
                    await asyncio.sleep(.001)
    # A separate concurrency diagnostic, not a throughput benchmark.
    concurrent = await asyncio.gather(*[
        detector.assess(f'concurrent-{i}','GET','/store/products','q=cotton',{},b'') for i in range(16)])
    while detector.busy:
        await asyncio.sleep(.001)
    return {'created_at':datetime.now(timezone.utc).isoformat(timespec='milliseconds'),
            'bundle_sha256':hashlib.sha256((bundle/'bundle.json').read_bytes()).hexdigest(),
            'mode':detector.model_mode,'threshold':detector.threshold,'fit_or_tuning':False,
            'scope':'Synthetic diagnostic strings; intended attack labels do not prove exploitability. Replayed acceptance is regression only, not a new blind evaluation.',
            'probe_rows':len(results),'probes':results,
            'false_positives':[r for r in results if r['expected']=='normal' and r['result']['attack']],
            'missed_attack_strings':[r for r in results if r['expected']!='normal' and not r['result']['attack']],
            'capture_rows':len(captured),
            'capture_flagged':sum(r['attack'] for r in captured),
            'capture_flagged_sessions':len({r['session_id'] for r in captured if r['attack']}),
            'capture_fallbacks':dict(Counter(r['fallback'] or 'none' for r in captured)),
            'capture_problems':[r for r in captured if r['attack'] or r['fallback']],
            'concurrent_16_fallbacks':dict(Counter(r['fallback'] or 'none' for r in concurrent))}


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle',type=Path,default=ROOT/'model/commerce-five/diversity-v2')
    parser.add_argument('--capture',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    report=asyncio.run(inspect(args.bundle,args.capture))
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('x',encoding='utf-8') as stream:
        json.dump(report,stream,ensure_ascii=False,indent=2)
    print(json.dumps({k:v for k,v in report.items() if k not in
                     ('probes','false_positives','missed_attack_strings','capture_problems')},ensure_ascii=False))
    print('False positives:',len(report['false_positives']),'; missed attack strings:',len(report['missed_attack_strings']))


if __name__=='__main__':
    main()
