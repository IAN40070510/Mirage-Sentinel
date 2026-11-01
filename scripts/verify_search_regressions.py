"""Replay disclosed search failures and legacy model predictions through current rules."""
from __future__ import annotations
import argparse
import asyncio
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts.evaluate_search_repair import evaluate
from services.commerce.detection import Detector
from commerce_ml.runtime import sha

async def main(args: argparse.Namespace) -> None:
    results,groups=await evaluate(args.run/'bundle',json.loads(args.previous_pool.read_text(encoding='utf-8')))
    predictions={r['sample_id']:r for line in (args.run/'test-predictions.jsonl').open(encoding='utf-8') if (r:=json.loads(line))}
    detector=Detector()
    matrix=[[0,0],[0,0]];problems=[];counts=Counter()
    for path in (args.dataset/'test').glob('*.jsonl'):
        for line in path.open(encoding='utf-8'):
            row=json.loads(line); req=row['request']; pred=predictions.pop(row['sample_id'])
            assert pred['true_label']==row['label']
            rules=await detector.assess(row['sample_id'],req['method'],req['path'],req.get('query') or '',req.get('headers') or {},(req.get('body') or '').encode())
            actual=int(pred['model_attack'] or bool(rules['rules']));truth=int(row['label']!='normal')
            matrix[truth][actual]+=1;counts[row['label']]+=1
            if actual!=truth:problems.append({'sample_id':row['sample_id'],'request':req,'label':row['label'],'model_score':pred['attack_score'],'rules':rules['rules']})
    assert not predictions
    report={'created_at':datetime.now(timezone.utc).isoformat(timespec='milliseconds'),
            'scope':'Previously disclosed development regressions; not blind evaluation',
            'bundle_sha256':sha(args.run/'bundle/bundle.json'),'detector_sha256':sha(ROOT/'services/commerce/detection.py'),
            'previous_pool_rows':len(results),'previous_pool_flagged':sum(r['attack'] for r in results),
            'previous_pool_fallbacks':sum(r['fallback'] is not None for r in results),'groups':groups,
            'previous_pool_problems':[r for r in results if r['attack'] or r['fallback']],
            'legacy_counts':dict(counts),'legacy_current_service_confusion':matrix,'legacy_problems':problems}
    args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k not in ('previous_pool_problems','legacy_problems')},ensure_ascii=False))
    if report['previous_pool_flagged'] or report['previous_pool_fallbacks'] or matrix[0][1] or matrix[1][0]/sum(matrix[1])>.001:
        raise SystemExit('Development regression gate failed')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('run','previous-pool','dataset','output'):p.add_argument('--'+name,type=Path,required=True)
    asyncio.run(main(p.parse_args()))
