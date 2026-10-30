"""Rebalance legacy normal traffic and add development-only application journeys."""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from commerce_ml.data import audit_splits, load
from commerce_ml.normal_balance import normal_route_group
from commerce_ml.runtime import request_text, sha


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--development', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    original = json.loads((args.base / 'manifest.json').read_text(encoding='utf-8'))
    capture = json.loads((args.development / 'manifest.json').read_text(encoding='utf-8'))
    if not capture['complete'] or capture['suite'] != 'development':
        raise ValueError('Only complete development capture may enter training/validation')
    if any(s['split'] not in {'train', 'validation'} for s in capture['sessions']):
        raise ValueError('Reserved acceptance/test sessions are forbidden here')
    args.output.mkdir(parents=True, exist_ok=False)
    report = {'created_at': datetime.now(timezone.utc).isoformat(timespec='milliseconds'),
              'status': 'development_rebalanced_not_deployment_validated',
              'capture_manifest_sha256': sha(args.development / 'manifest.json'),
              'capture_revision': capture['revision'], 'splits': {}, 'acceptance_used': False,
              'normal_weight_policy': 'equal total weight per method/canonical route within the normal class',
              'normal_selection_policy': 'legacy product queries capped at 250/source train, 50/source holdouts; unsupported /store/custom removed; genuine development journeys exact-deduplicated only'}
    exact_owners = {}
    sessions_seen = set()
    pending = {}
    for split in ('train', 'validation', 'test'):
        pending[split] = {}
        for source, info in original['splits'][split]['sources'].items():
            path = args.base / split / (source + '.jsonl')
            if sha(path) != info['sha256']:
                raise ValueError('Baseline hash mismatch')
            keep, products = [], []
            for line in path.open(encoding='utf-8'):
                row = json.loads(line)
                if row['label'] != 'normal':
                    keep.append(row)
                elif row['request']['path'] == '/store/products':
                    products.append(row)
                elif row['request']['method'] == 'POST' and row['request']['path'].startswith('/store/carts'):
                    keep.append(row)
            products.sort(key=lambda r: hashlib.sha256(('diverse-v1:' + r['sample_id']).encode()).digest())
            keep.extend(products[:250 if split == 'train' else 50])
            if keep:
                pending[split][source] = keep
                for row in keep:
                    key = hashlib.sha256(request_text(row['request']).encode()).hexdigest()
                    if key in exact_owners:
                        raise ValueError('Existing exact duplicate')
                    exact_owners[key] = split
    removed = Counter()
    for session in capture['sessions']:
        split = session['split']
        identifier = session['session_id']
        if identifier in sessions_seen:
            raise ValueError('Duplicate session')
        sessions_seen.add(identifier)
        path = args.development / session['file']
        if path.parent.resolve() != args.development.resolve() or sha(path) != session['sha256']:
            raise ValueError('Capture path/hash mismatch')
        for line in path.open(encoding='utf-8'):
            row = json.loads(line)
            if row['label'] != 'normal' or row['session_id'] != identifier or row['provenance']['assigned_split'] != split:
                raise ValueError('Invalid capture assignment')
            key = hashlib.sha256(request_text(row['request']).encode()).hexdigest()
            if key in exact_owners:
                removed[split] += 1
                continue
            exact_owners[key] = split
            pending[split].setdefault('application_normal', []).append(row)
    loaded = {}
    for split, sources in pending.items():
        directory = args.output / split
        directory.mkdir()
        info = {'sources': {}, 'labels': {}, 'normal_routes': {}, 'removed_capture_exact_duplicates': removed[split]}
        labels, routes = Counter(), Counter()
        for source, rows in sources.items():
            path = directory / (source + '.jsonl')
            with path.open('x', encoding='utf-8') as stream:
                for row in rows:
                    stream.write(json.dumps(row, ensure_ascii=False) + '\n')
                    labels[row['label']] += 1
                    if row['label'] == 'normal':
                        routes[normal_route_group(request_text(row['request']))] += 1
            info['sources'][source] = {'rows': len(rows), 'labels': dict(Counter(r['label'] for r in rows)), 'sha256': sha(path)}
        info.update(rows=sum(labels.values()), labels=dict(labels), normal_routes=dict(routes))
        report['splits'][split] = info
        loaded[split], _ = load(directory)
    report['audit'] = audit_splits(loaded, allow_shared_families=True, allow_shared_normal_templates=True)
    if report['audit']['cross_split_conflicts']:
        raise ValueError('Combined split audit failed')
    report['limitations'] = ['Legacy attack test is diagnostic, not a new independent attack benchmark',
        'Normal scenarios are scripted and source-labelled, not production traffic or human-reviewed ground truth',
        'Common normal templates may overlap; exact rows and journey IDs remain isolated',
        'The independent acceptance collection is intentionally absent from all three model input splits']
    (args.output / 'manifest.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({k: v['labels'] for k, v in report['splits'].items()}, indent=2), flush=True)


if __name__ == '__main__':
    main()
