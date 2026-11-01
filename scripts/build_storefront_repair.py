"""Extend development with literal descriptions and paired executable syntax."""
from __future__ import annotations
from collections import Counter
from datetime import datetime, timezone
import hashlib
import itertools
import json
from pathlib import Path
import shutil
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from scripts.storefront_requests import requests, catalog, SOURCE_FILES
from urllib.parse import urlencode
from commerce_ml.data import load, audit_splits, near_key
from commerce_ml.runtime import request_text, sha




def main() -> None:
    base=ROOT/'datasets/commerce/search-repair-v6';out=ROOT/'datasets/commerce/search-repair-v7'
    out.mkdir(exist_ok=False)
    owners={};near_owners={};attack_owners={}
    for split in ('train','validation','test'):
        shutil.copytree(base/split,out/split)
        for file in (out/split).glob('*.jsonl'):
            for line in file.open(encoding='utf-8'):
                row=json.loads(line);text=request_text(row['request']);key=sha_text(text);near=near_key(text)
                owners[key]=split;near_owners.setdefault(near,set()).add(split)
                if row['label']!='normal':attack_owners.setdefault(near,set()).add(split)
    report={'created_at':datetime.now(timezone.utc).isoformat(timespec='milliseconds'),
            'base_manifest_sha256':sha(base/'manifest.json'),
            'prior_reserved_policy':'v3 and v6 disclosed pools are regression-only; v7 reserved pool is not used for fitting',
            'fit_uses_reserved_v7':False, 'test_policy':'Legacy test inspected for diagnosis; no longer an untouched estimate. No test row copied into fitting.','splits':{}}
    for split in ('train','validation'):
        rows=[];skipped=Counter()
        def add(items: list[dict],label: str) -> None:
            for req in items:
                text=request_text(req);key=sha_text(text);near=near_key(text)
                if key in owners:skipped['exact']+=1;continue
                if (label!='normal' and near_owners.get(near,set())-{split}) or (label=='normal' and attack_owners.get(near,set())-{split}):
                    skipped['cross_split_near']+=1;continue
                owners[key]=split;near_owners.setdefault(near,set()).add(split)
                if label!='normal':attack_owners.setdefault(near,set()).add(split)
                rows.append({'sample_id':'storefront-v7-'+key,'source':'ai','label':label,'template_family':None,
                    'request':req,'annotation':{'review_status':'generated_unverified','reviewer':None,
                    'reason':'Source-derived storefront request or paired attack syntax; synthetic IDs, not observed customer traffic'},
                    'provenance':{'dataset':'Mirage-Sentinel/source-derived-storefront-v7','assigned_split':split,
                                  'generator_sha256':sha(Path(__file__))}})
        for index in range(100 if split=='train' else 25):
            add(requests(split,index),'normal')
            if index%2==0:
                # Same valid routing/field context paired with actual syntax.
                for path,fields in catalog(split,index):
                    for label,value in [('sqli',f"' UNION SELECT {index+7}-- {split}"),
                                        ('xss',f'<svg onload=alert({index})> {split}'),
                                        ('cmdi',f'; whoami # {split}'),
                                        ('path_traversal',f'../../fixtures/{split}-{index}.txt')]:
                        add([{'method':'GET','path':path,'query':urlencode({**fields,'q':value}),
                              'headers':{'content-type':'application/json'},'body':''}],label)
        file=out/split/'storefront_context.jsonl'
        with file.open('x',encoding='utf-8') as stream:
            for row in rows:stream.write(json.dumps(row,ensure_ascii=False)+'\n')
        report['splits'][split]={'added':dict(Counter(r['label'] for r in rows)),'skipped':dict(skipped),'sha256':sha(file)}
    report['request_catalog_sha256']=sha(ROOT/'scripts/storefront_requests.py')
    report['application_sources']={name:sha(ROOT/'commerce/apps/storefront/src/lib/data'/name) for name in SOURCE_FILES}
    report['audit']=audit_splits({s:load(out/s)[0] for s in ('train','validation','test')},allow_shared_families=True,allow_shared_normal_templates=True)
    (out/'manifest.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report['splits'],indent=2))
    if report['audit']['cross_split_conflicts']:raise ValueError(report['audit']['cross_split_conflicts'])


def sha_text(value: str) -> str:return hashlib.sha256(value.encode()).hexdigest()


if __name__=='__main__':main()
