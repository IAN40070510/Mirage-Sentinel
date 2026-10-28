"""Prepare captured normal candidates without collapsing all JSON route variants.

Preserves preassigned sessions. Removes exact duplicates, reports rather than
discards normal-only near-template overlap. Raw capture remains a workflow replay
suite; unique rows alone may not cover every route in every split.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from commerce_ml.data import audit_splits, load
from commerce_ml.runtime import request_text
from scripts.audit_normal_coverage import audit


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads((args.capture / 'manifest.json').read_text(encoding='utf-8'))
    if not manifest['complete']:
        raise ValueError('Incomplete capture cannot be released')
    args.output.mkdir(parents=True, exist_ok=False)
    seen: set[str] = set()
    session_owners: dict[str, str] = {}
    report = {'source_revision': manifest['revision'], 'model_trained': False,
              'status': 'normal_candidates_only_not_a_five_class_release', 'splits': {}}
    loaded = {}
    for split in ('train', 'validation', 'test'):
        folder = args.output / split
        folder.mkdir()
        stats: Counter[str] = Counter()
        with (folder / 'application_normal.jsonl').open('x', encoding='utf-8') as out:
            for session in manifest['sessions']:
                if session['split'] != split:
                    continue
                path = args.capture / session['file']
                if path.parent.resolve() != args.capture.resolve():
                    raise ValueError('Unsafe capture filename')
                if hashlib.sha256(path.read_bytes()).hexdigest() != session['sha256']:
                    raise ValueError('Capture checksum mismatch')
                if session_owners.setdefault(session['session_id'], split) != split:
                    raise ValueError('Session crosses split boundary')
                for line in path.open(encoding='utf-8'):
                    row = json.loads(line)
                    if row['label'] != 'normal' or row['session_id'] != session['session_id']:
                        raise ValueError('Invalid normal capture provenance')
                    stats['input_rows'] += 1
                    fingerprint = hashlib.sha256(request_text(row['request']).encode()).hexdigest()
                    if fingerprint in seen:
                        stats['exact_duplicate_rows_removed'] += 1
                        continue
                    seen.add(fingerprint)
                    out.write(json.dumps(row, ensure_ascii=False) + '\n')
                    stats['retained_rows'] += 1
        loaded[split], _ = load(folder)
        report['splits'][split] = {**stats, 'coverage': audit(folder)}
    report['audit'] = audit_splits(loaded, allow_shared_normal_templates=True)
    if report['audit']['cross_split_conflicts']:
        raise ValueError('Unexpected exact/session overlap')
    report['limitations'] = [
        'Normal JSON template overlap is explicit; this is not unseen-template evaluation',
        'Repeated pages/assets removed from unique holdout rows remain in the raw replay suite',
        'No artificial duplication or fabricated traffic used to meet a row quota',
        'Do not mix into old holdouts without a new combined leakage audit',
    ]
    (args.output / 'manifest.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps(report, ensure_ascii=False, indent=2), flush=True)


if __name__ == '__main__':
    main()
