"""One-shot reserved normal-search replay after freezing model, rules and criteria."""
from __future__ import annotations
import argparse
import asyncio
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from services.commerce.detection import Detector
from services.commerce.five_runtime import request_text


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


async def evaluate(bundle: Path, requests: list[dict]) -> tuple[list[dict], dict]:
    detector=Detector(str(bundle))
    assert detector.model_status=='ready_five_class' and detector.model_mode=='enforce'
    results=[];groups=defaultdict(Counter);seen=set()
    shapes=['q_only','pagination_first','pagination_last','sort_first','percent_spaces','json_note']
    for index,req in enumerate(requests):
        key=json.dumps(req,sort_keys=True,ensure_ascii=False)
        if key in seen:continue
        seen.add(key)
        prediction=await detector.assess(str(index),req['method'],req['path'],req['query'],
                                         req['headers'],req['body'].encode())
        while detector.busy:await asyncio.sleep(.001)
        group=shapes[index % len(shapes)]
        groups[group]['rows']+=1
        groups[group]['flagged']+=int(prediction['attack'])
        groups[group]['fallback']+=int(prediction['fallback'] is not None)
        results.append({'request':req,'shape':group,**prediction})
    return results,{k:dict(v) for k,v in groups.items()}


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle',type=Path,required=True)
    parser.add_argument('--freeze',type=Path,required=True)
    parser.add_argument('--reserved',type=Path,required=True)
    parser.add_argument('--protocol',type=Path,required=True)
    parser.add_argument('--dataset',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    frozen=json.loads(args.freeze.read_text(encoding='utf-8'))
    assert frozen['evaluation_source_sha256']==sha(Path(__file__)), 'Evaluator changed after freeze'
    for key,path in [('bundle_sha256',args.bundle/'bundle.json'),('reserved_sha256',args.reserved),
                     ('protocol_sha256',args.protocol),('detector_sha256',ROOT/'services/commerce/detection.py'),
                     ('dataset_manifest_sha256',args.dataset/'manifest.json')]:
        assert frozen[key]==sha(path),f'Changed after freeze: {key}'
    args.output.mkdir(exist_ok=False)
    protocol=json.loads(args.protocol.read_text(encoding='utf-8'))
    requests=json.loads(args.reserved.read_text(encoding='utf-8'))
    development=set()
    for split in ('train','validation'):
        for path in (args.dataset/split).glob('*.jsonl'):
            for line in path.open(encoding='utf-8'):
                development.add(hashlib.sha256(request_text(json.loads(line)['request']).encode()).hexdigest())
    overlaps=len({hashlib.sha256(request_text(r).encode()).hexdigest() for r in requests} & development)
    results,groups=asyncio.run(evaluate(args.bundle,requests))
    count=len(results);flagged=sum(r['attack'] for r in results)
    fallbacks=Counter(r['fallback'] or 'none' for r in results)
    report={'created_at':datetime.now(timezone.utc).isoformat(timespec='milliseconds'),
            'freeze':frozen,'raw_rows':len(requests),'rows':count,'exact_duplicates_excluded':len(requests)-count,
            'flagged':flagged,'fpr':flagged/count,'groups':groups,
            'development_exact_overlaps':overlaps,
            'fallbacks':dict(fallbacks),'passed':not overlaps and flagged/count<=protocol['max_reserved_normal_fpr']
            and all(g['flagged']/g['rows']<=protocol['max_each_request_shape_fpr'] and not g['fallback'] for g in groups.values()),
            'fit_or_tuning':False,'scope':'Reserved synthetic lexical pool; same application and generator, not real-user or unseen-attack generalization.',
            'problems':[r for r in results if r['attack'] or r['fallback']]}
    (args.output/'result.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k not in ('freeze','problems')},ensure_ascii=False))


if __name__=='__main__':main()
