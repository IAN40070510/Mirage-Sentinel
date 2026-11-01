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
from scripts.build_search_repair import variants
from commerce_ml.data import load, audit_splits, near_key
from commerce_ml.runtime import request_text, sha


def literals(split: str) -> list[str]:
    # General product comparisons and parenthesized catalog descriptors. Distinct
    # vocabulary and numeric ranges per development fold; no test row copied.
    if split == 'train':
        words = 'price sale size width height length weight capacity discount rating'.split()
        numbers = ['0','1','5','10','20','50','100','250','500','1000']
        names = 'cotton linen silk wool bamboo denim nylon leather ceramic steel'.split()
        details = 'blue red large small organic recycled premium summer winter classic'.split()
    else:
        words = 'cost amount diameter volume thickness'.split()
        numbers = ['3','12','75','180','360']
        names = 'polyester canvas velvet copper glass'.split()
        details = 'green medium lightweight durable natural'.split()
    values = [f'{w} {op} {n}' for w,op,n in itertools.product(words,['<','>','<=','>=','=','!='],numbers)]
    values += [f'{a} ({b})' for a,b in itertools.product(names,details)]
    values += [f'{a} ({b} edition)' for a,b in itertools.product(names,details)]
    return sorted(set(values))


def main() -> None:
    base=ROOT/'datasets/commerce/search-repair-v4';out=ROOT/'datasets/commerce/search-repair-v5'
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
            'prior_reserved_policy':'v3b disclosed cases now development regressions; never claimed as new blind results',
            'fit_uses_reserved_v4':False, 'test_policy':'Legacy test inspected for diagnosis; no longer an untouched estimate. No test row copied into fitting.','splits':{}}
    for split in ('train','validation'):
        rows=[];skipped=Counter()
        def add(value: str,label: str) -> None:
            for req in variants(value):
                text=request_text(req);key=sha_text(text);near=near_key(text)
                if key in owners:skipped['exact']+=1;continue
                if (label!='normal' and near_owners.get(near,set())-{split}) or (label=='normal' and attack_owners.get(near,set())-{split}):
                    skipped['cross_split_near']+=1;continue
                owners[key]=split;near_owners.setdefault(near,set()).add(split)
                if label!='normal':attack_owners.setdefault(near,set()).add(split)
                rows.append({'sample_id':'comparison-v5-'+key,'source':'ai','label':label,'template_family':None,
                    'request':req,'annotation':{'review_status':'generated_unverified','reviewer':None,
                    'reason':'Synthetic literal description or paired executable syntax; not a real attack success label'},
                    'provenance':{'dataset':'Mirage-Sentinel/comparison-context-v5','assigned_split':split,
                                  'generator_sha256':sha(Path(__file__))}})
        for value in literals(split):add(value,'normal')
        # Pair explanatory words with actual syntax to avoid learning a book-word whitelist.
        for index in range(80 if split=='train' else 20):
            word=('price' if split=='train' else 'cost')+str(index)
            for label,value in [('sqli',f"' UNION SELECT {index+7}-- {word}"),
                                ('xss',f'javascript:alert({index}); // {word}'),
                                ('xss',f'<svg onload=alert({index})> {word}'),
                                ('cmdi',f'; whoami # {word}'),
                                ('path_traversal',f'../../fixtures/{word}.txt')]:add(value,label)
        file=out/split/'comparison_context.jsonl'
        with file.open('x',encoding='utf-8') as stream:
            for row in rows:stream.write(json.dumps(row,ensure_ascii=False)+'\n')
        report['splits'][split]={'added':dict(Counter(r['label'] for r in rows)),'skipped':dict(skipped),'sha256':sha(file)}
    report['audit']=audit_splits({s:load(out/s)[0] for s in ('train','validation','test')},allow_shared_families=True,allow_shared_normal_templates=True)
    (out/'manifest.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report['splits'],indent=2))
    if report['audit']['cross_split_conflicts']:raise ValueError(report['audit']['cross_split_conflicts'])


def sha_text(value: str) -> str:return hashlib.sha256(value.encode()).hexdigest()


if __name__=='__main__':main()
