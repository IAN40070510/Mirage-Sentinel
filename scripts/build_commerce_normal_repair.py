"""Build a traceable pilot release with captured normal application requests."""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from commerce_ml.data import audit_splits, load
from commerce_ml.runtime import sha
from scripts.audit_normal_coverage import audit


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--normal', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    original = json.loads((args.base / 'manifest.json').read_text(encoding='utf-8'))
    normal = json.loads((args.normal / 'manifest.json').read_text(encoding='utf-8'))
    args.output.mkdir(parents=True, exist_ok=False)
    report = {'created_at': datetime.now(timezone.utc).isoformat(timespec='milliseconds'),
              'status': 'pilot_normal_coverage_repair_not_deployment_validated',
              'base_manifest_sha256': sha(args.base / 'manifest.json'),
              'normal_manifest_sha256': sha(args.normal / 'manifest.json'),
              'splits': {}, 'model_trained': False}
    loaded = {}
    for split in ('train', 'validation', 'test'):
        target = args.output / split
        target.mkdir()
        source_info = {}
        for name, info in original['splits'][split]['sources'].items():
            source = args.base / split / (name + '.jsonl')
            if sha(source) != info['sha256']:
                raise ValueError('Baseline changed: ' + name)
            shutil.copy2(source, target / source.name)
            source_info[name] = info
        source = args.normal / split / 'application_normal.jsonl'
        normal_rows, _ = load(source)
        if len(normal_rows) != normal['splits'][split]['retained_rows'] or any(r.label != 0 for r in normal_rows):
            raise ValueError('Invalid normal supplement')
        shutil.copy2(source, target / source.name)
        source_info['application_normal'] = {'rows': len(normal_rows), 'labels': {'normal': len(normal_rows)}, 'sha256': sha(source)}
        labels: Counter[str] = Counter()
        for info in source_info.values():
            labels.update(info['labels'])
        report['splits'][split] = {'rows': sum(labels.values()), 'labels': dict(labels), 'sources': source_info,
                                   'normal_route_coverage': audit(target)}
        loaded[split], _ = load(target)
    checked = audit_splits(loaded, allow_shared_families=True, allow_shared_normal_templates=True)
    if checked['cross_split_conflicts'] or any(info['exact_duplicates'] for info in checked['splits'].values()):
        raise ValueError('Combined dataset failed duplicate/session audit')
    if report['splits']['train']['normal_route_coverage']['missing']:
        raise ValueError('Training normal route coverage is incomplete')
    report['audit'] = checked
    report['limitations'] = ['Only 30 scripted sessions; this is a coverage pilot, not representative production traffic',
        'Common normal templates explicitly shared; exact duplicate requests removed and sessions isolated',
        'Original synthetic attack families and synthetic XSS diagnostic limitations remain',
        'Normal test candidate results have been inspected; acquire a fresh acceptance batch before deployment',
        'No old examples removed or duplicated to force round counts; previous test results cannot establish generalization']
    provenance = args.output / 'provenance'
    provenance.mkdir()
    shutil.copytree(args.base / 'provenance', provenance / 'previous-sources')
    shutil.copy2(args.base / 'manifest.json', provenance / 'base-manifest.json')
    shutil.copy2(args.normal / 'manifest.json', provenance / 'normal-manifest.json')
    (args.output / 'manifest.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({s: report['splits'][s]['labels'] for s in loaded}, indent=2), flush=True)


if __name__ == '__main__':
    main()
