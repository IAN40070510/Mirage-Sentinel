"""One-shot reserved normal journey evaluation of a frozen model; no fitting."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import json
import zipfile
from pathlib import Path

from .data import digest
from .normal_balance import normal_route_group
from .runtime import Predictor, request_text, sha


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--baseline-bundle', type=Path)
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--development', type=Path, required=True)
    parser.add_argument('--dataset', type=Path, required=True)
    parser.add_argument('--protocol', type=Path, required=True)
    parser.add_argument('--freeze', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    frozen = json.loads(args.freeze.read_text(encoding='utf-8'))
    if frozen['bundle_sha256'] != sha(args.bundle / 'bundle.json') or frozen['protocol_sha256'] != sha(args.protocol):
        raise ValueError('Model/protocol changed after freeze')
    if sha(args.archive) != frozen['acceptance_zip_sha256']:
        raise ValueError('Acceptance archive differs from frozen commitment')
    args.capture.mkdir(parents=True, exist_ok=False)
    with zipfile.ZipFile(args.archive) as archive:
        for name in archive.namelist():
            if not (args.capture / name).resolve().is_relative_to(args.capture.resolve()):
                raise ValueError('Unsafe archive path')
        archive.extractall(args.capture)
    protocol = json.loads(args.protocol.read_text(encoding='utf-8'))
    predictor = Predictor(args.bundle)
    manifest = json.loads((args.capture / 'manifest.json').read_text(encoding='utf-8'))
    development = json.loads((args.development / 'manifest.json').read_text(encoding='utf-8'))
    if manifest.get('suite') != 'acceptance' or not manifest['complete']:
        raise ValueError('A complete reserved acceptance collection is required')
    old_sessions = {s['session_id'] for s in development['sessions']}
    # Read only feature hashes, not performance, from development inputs.
    old_exact = set()
    for split in ('train', 'validation'):
        for file in (args.dataset / split).glob('*.jsonl'):
            for line in file.open(encoding='utf-8'):
                old_exact.add(digest(request_text(json.loads(line)['request'])))
    args.output.mkdir(parents=True, exist_ok=False)
    records = []
    for session in manifest['sessions']:
        if session['split'] != 'acceptance' or session['session_id'] in old_sessions:
            raise ValueError('Acceptance session overlaps development')
        file = args.capture / session['file']
        if file.parent.resolve() != args.capture.resolve() or sha(file) != session['sha256']:
            raise ValueError('Capture integrity check failed')
        for line in file.open(encoding='utf-8'):
            row = json.loads(line)
            if row['label'] != 'normal' or row['session_id'] != session['session_id']:
                raise ValueError('Unexpected acceptance label/session')
            records.append(row)
    route_counts = defaultdict(Counter)
    flagged_sessions = set()
    predictions = []
    for start in range(0, len(records), 256):
        batch = records[start:start + 256]
        for row, result in zip(batch, predictor.predict([r['request'] for r in batch])):
            text = request_text(row['request'])
            route = normal_route_group(text)
            seen = digest(text) in old_exact
            route_counts[route]['rows'] += 1
            route_counts[route]['false_positives'] += int(result['model_attack'])
            if result['combined_attack']:
                flagged_sessions.add(row['session_id'])
            predictions.append({'sample_id': row['sample_id'], 'session_id': row['session_id'],
                                'seen_request_in_development': seen, **result})
    unique = {}
    for row, result in zip(records, predictions):
        key = digest(request_text(row['request']))
        if key not in old_exact:
            unique.setdefault(key, result)
    count = len(predictions)
    fpr = sum(p['model_attack'] for p in predictions) / count
    novel_fpr = sum(p['model_attack'] for p in unique.values()) / len(unique) if unique else None
    session_rate = len(flagged_sessions) / len(manifest['sessions'])
    route_report = {k: {**v, 'fpr': v['false_positives'] / v['rows']} for k, v in route_counts.items()}
    passed = (len(manifest['sessions']) >= protocol['minimum_sessions']
              and fpr <= protocol['maximum_request_fpr']
              and novel_fpr is not None and novel_fpr <= protocol['maximum_request_fpr']
              and session_rate <= protocol['maximum_flagged_session_rate']
              and all(v['fpr'] <= protocol['maximum_route_fpr'] for v in route_report.values()))
    report = {'created_at': datetime.now(timezone.utc).isoformat(timespec='milliseconds'),
              'model_bundle_sha256': sha(args.bundle / 'bundle.json'), 'threshold': predictor.threshold,
              'capture_manifest_sha256': sha(args.capture / 'manifest.json'),
              'sessions': len(manifest['sessions']), 'rows': count,
              'threshold_false_positives': sum(p['model_attack'] for p in predictions),
              'threshold_fpr': fpr, 'novel_unique_rows': len(unique), 'novel_unique_fpr': novel_fpr,
              'flagged_sessions_rules_or_model': len(flagged_sessions), 'flagged_session_rate': session_rate,
              'routes': route_report, 'protocol': protocol, 'normal_acceptance_passed': passed,
              'fit_performed': False, 'threshold_tuning_performed': False, 'deploy_authorized': False,
              'limitations': ['Offline replay of successful scripted application journeys; not production traffic',
                             'Common request templates may overlap; both all-request and novel-unique results reported',
                             'This normal-only acceptance does not establish attack detection performance',
                             'Do not tune on this acceptance result and report it again as blind evaluation']}
    if args.baseline_bundle:
        if sha(args.baseline_bundle / 'bundle.json') != frozen['baseline_bundle_sha256']:
            raise ValueError('Baseline differs from the frozen comparison')
        baseline = Predictor(args.baseline_bundle)
        baseline_fp = 0
        baseline_flagged = set()
        for start in range(0, len(records), 256):
            batch = records[start:start + 256]
            for row, item in zip(batch, baseline.predict([r['request'] for r in batch])):
                baseline_fp += int(item['model_attack'])
                if item['combined_attack']:
                    baseline_flagged.add(row['session_id'])
        report['baseline_comparison'] = {
            'bundle_sha256': sha(args.baseline_bundle / 'bundle.json'),
            'threshold': baseline.threshold, 'false_positives': baseline_fp,
            'normal_fpr': baseline_fp / count,
            'flagged_sessions': len(baseline_flagged), 'fit_or_tuning_performed': False,
        }
    (args.output / 'acceptance.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    with (args.output / 'predictions.jsonl').open('x', encoding='utf-8') as stream:
        for result in predictions:
            stream.write(json.dumps(result, ensure_ascii=False) + '\n')
    print(json.dumps(report, ensure_ascii=False, indent=2), flush=True)


if __name__ == '__main__':
    main()
