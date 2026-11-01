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
    pools={
        'train': ('browser web advanced practical beginner complete interactive modern classic portable'.split(),
                  'guide reference manual course workbook handbook textbook companion notes overview'.split(),
                  'print fabric textile cotton geometric floral sewing shirt'.split(),
                  'pattern illustration design stencil diagram drawing example sample'.split()),
        'validation': ('concise visual daily essential applied'.split(),
                       'tutorial primer encyclopedia syllabus study'.split(),
                       'silk wool striped denim'.split(),'sketch motif chart layout'.split()),
        'reserved': ('accessible professional illustrated compact apprentice'.split(),
                     'readings essentials lessons exercises introduction'.split(),
                     'linen bamboo embroidered modal'.split(),'weave draft artwork schematic'.split())}
    adjectives,books,materials,patterns=pools[split]
    values=[]
    for a,b in itertools.product(adjectives,books):
        values.extend([f'javascript: {a} {b}',f'UNION SELECT {a} SQL {b}',f'C++ {a} {b}',
                       f'`id` command {a} {b}',f'pipe | id command {a} {b}'])
    for a,b in itertools.product(materials,patterns):
        values.extend([f'../../ {a} {b}',f'../../../ {a} {b}',f'{a} {b} 100% cotton'])
    if split=='train':values+=['../../ textile illustration','javascript: browser reference']
    return sorted(set(values))


def main() -> None:
    base=ROOT/'datasets/commerce/search-repair-v3b';out=ROOT/'datasets/commerce/search-repair-v4'
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
            'fit_uses_reserved_v4':False,'splits':{}}
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
                rows.append({'sample_id':'literal-v4-'+key,'source':'ai','label':label,'template_family':None,
                    'request':req,'annotation':{'review_status':'generated_unverified','reviewer':None,
                    'reason':'Synthetic literal description or paired executable syntax; not a real attack success label'},
                    'provenance':{'dataset':'Mirage-Sentinel/literal-context-v4','assigned_split':split,
                                  'generator_sha256':sha(Path(__file__))}})
        for value in literals(split):add(value,'normal')
        # Pair explanatory words with actual syntax to avoid learning a book-word whitelist.
        for index in range(80 if split=='train' else 20):
            word=('manual' if split=='train' else 'primer')+str(index)
            for label,value in [('sqli',f"' UNION SELECT {index+7}-- {word}"),
                                ('xss',f'javascript:alert({index}); // {word}'),
                                ('xss',f'<svg onload=alert({index})> {word}'),
                                ('cmdi',f'; whoami # {word}'),
                                ('path_traversal',f'../../fixtures/{word}.txt')]:add(value,label)
        file=out/split/'literal_context.jsonl'
        with file.open('x',encoding='utf-8') as stream:
            for row in rows:stream.write(json.dumps(row,ensure_ascii=False)+'\n')
        report['splits'][split]={'added':dict(Counter(r['label'] for r in rows)),'skipped':dict(skipped),'sha256':sha(file)}
    reserved=ROOT/'artifacts/fp-repair/reserved-literal-v4.json'
    reserved.write_text(json.dumps([r for value in literals('reserved') for r in variants(value)],ensure_ascii=False),encoding='utf-8')
    report['reserved_sha256']=sha(reserved)
    report['audit']=audit_splits({s:load(out/s)[0] for s in ('train','validation','test')},allow_shared_families=True,allow_shared_normal_templates=True)
    (out/'manifest.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report['splits'],indent=2))
    if report['audit']['cross_split_conflicts']:raise ValueError(report['audit']['cross_split_conflicts'])


def sha_text(value: str) -> str:return hashlib.sha256(value.encode()).hexdigest()


if __name__=='__main__':main()
