"""Counterfactual request-shape augmentation; provenance and held-out pools explicit."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import itertools
import json
from pathlib import Path
import shutil
import sys
from urllib.parse import parse_qsl, urlencode, quote

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from commerce_ml.data import load, audit_splits, near_key
from commerce_ml.runtime import request_text, sha


def normal_values(split: str) -> list[str]:
    pools = {
        'train': ('紅色 藍色 黑色 白色 純棉 夏季 輕量 防水'.split(),
                  '上衣 褲子 外套 襪子 背包 帽子 手套 圍巾 水杯 筆記本'.split(),
                  ['cotton shirt','日本製','C++','AT&T','100% cotton','size < 10','price >= 100',
                   '優惠 🎉',"O'Reilly",'javascript: the definitive guide','UNION SELECT SQL textbook',
                   '../../ print pattern','shirt & trousers','SQL programming textbook','café','日本製 シャツ']),
        'validation': ('綠色 灰色 紫色 橙色 羊毛 冬季 厚款 可洗'.split(),
                       '大衣 毛巾 雨衣 長裙 行李袋 鞋帶 腰帶 皮夾'.split(),
                       ['C# guide','85% linen','budget <= 750','兒童禮物 🎁','日本製 靴',
                        'javascript: language handbook','UNION SELECT query tutorial','../../ fabric design']),
        'reserved': ('深藍 米色 粉紅 銀色 有機 秋季 透氣 防風'.split(),
                     '針織衫 短靴 登山杖 手提箱 睡衣 枕頭 床單 髮帶'.split(),
                     ['A&B accessories','C++ templates book','72% viscose','幅 < 28','sale >= 250',
                      '新年快樂 🧧','日本製 傘','javascript: browser reference','UNION SELECT database workbook',
                      '../../ textile illustration'])}
    colors,items,extras=pools[split]
    values=list(extras)
    for color,item,style in itertools.product(colors,items,range(5)):
        values.append([f'{color}{item}',f'{color} {item} 100% cotton',f'{item} size < 20',
                       f'{color} {item} A+B',f'{item} 特惠 🎉 {color}'][style])
    english = {'train':['cotton','linen','denim','leather','silk'],
               'validation':['wool','nylon','hemp'], 'reserved':['viscose','bamboo','modal']}[split]
    for material,item,style in itertools.product(english,items,range(4)):
        values.append([f'{material} {item}',f'95% {material} {item}',f'{material} {item} price >= 50',
                       f'{material} {item} & accessories'][style])
    return sorted(set(values))


def variants(value: str) -> list[dict]:
    shapes = [[('q',value)], [('limit','20'),('offset','0'),('q',value)],
              [('q',value),('limit','20'),('offset','0')],
              [('order','-created_at'),('q',value),('limit','12')]]
    rows=[dict(method='GET',path='/store/products',query=urlencode(s),headers={},body='') for s in shapes]
    rows.append(dict(method='GET',path='/store/products',query=urlencode(shapes[0],quote_via=quote),headers={},body=''))
    rows.append(dict(method='POST',path='/store/carts/cart_SEARCHFIX',query='',
                     headers={'content-type':'application/json'},body=json.dumps({'metadata':{'note':value}},ensure_ascii=False)))
    return rows


def main() -> None:
    base=ROOT/'datasets/commerce/diverse-rebalanced-v2'
    out=ROOT/'datasets/commerce/search-repair-v3b'
    out.mkdir(exist_ok=False)
    owners: dict[str,str]={}
    near_owners: dict[str,set[str]]={}
    attack_owners: dict[str,set[str]]={}
    for split in ('train','validation','test'):
        shutil.copytree(base/split,out/split)
        for f in (base/split).glob('*.jsonl'):
            for line in f.open(encoding='utf-8'):
                row=json.loads(line);text=request_text(row['request'])
                owners[hashlib.sha256(text.encode()).hexdigest()]=split
                near_owners.setdefault(near_key(text),set()).add(split)
                if row['label']!='normal':attack_owners.setdefault(near_key(text),set()).add(split)
    report={'created_at':datetime.now(timezone.utc).isoformat(timespec='milliseconds'),
            'base_manifest_sha256':sha(base/'manifest.json'),'source':'script-generated counterfactual augmentation',
            'fit_uses_reserved':False,'splits':{}}
    for split in ('train','validation'):
        generated=[]; skipped=Counter()
        def add(value: str,label: str,parent: str) -> None:
            for request in variants(value):
                text=request_text(request);key=hashlib.sha256(text.encode()).hexdigest();near=near_key(text)
                if key in owners:
                    skipped['exact']+=1;continue
                if (label!='normal' and near_owners.get(near,set())-{split}) or (label=='normal' and attack_owners.get(near,set())-{split}):
                    skipped['attack_near_other_split']+=1;continue
                owners[key]=split;near_owners.setdefault(near,set()).add(split)
                if label!='normal':attack_owners.setdefault(near,set()).add(split)
                generated.append({'sample_id':'search-v3-'+key,'source':'ai','label':label,
                    'template_family':None,'request':request,
                    'annotation':{'review_status':'generated_unverified','reviewer':None,
                                  'reason':'Known benign shopping text or source-labelled attack payload; synthetic context variants, not independent real requests'},
                    'provenance':{'dataset':'Mirage-Sentinel/search-shape-counterfactual-v3',
                                  'assigned_split':split,'parent':parent,'generator_sha256':sha(Path(__file__))}})
        for value in normal_values(split): add(value,'normal','synthetic-normal-lexical-pool:'+split)
        # Only same-split payloads enter augmentation; all request shapes occur for both labels.
        taken=Counter();seen_payload=set()
        for file in sorted((base/split).glob('*.jsonl')):
            for line in file.open(encoding='utf-8'):
                row=json.loads(line);label=row['label']
                if label=='normal' or taken[label]>=(700 if split=='train' else 150):continue
                query=dict(parse_qsl(row['request']['query'],keep_blank_values=True))
                value=next((query[k] for k in ('q','file','path','search','id') if query.get(k)),None)
                if value is None or len(value)>3000 or (label,value) in seen_payload:continue
                seen_payload.add((label,value));taken[label]+=1
                add(value,label,row['sample_id'])
        file=out/split/'search_counterfactual.jsonl'
        with file.open('x',encoding='utf-8') as stream:
            for row in generated:stream.write(json.dumps(row,ensure_ascii=False)+'\n')
        report['splits'][split]={'added':dict(Counter(r['label'] for r in generated)),
                                'skipped':dict(skipped),'sha256':sha(file)}
    # Keep separate from all model inputs. Do not evaluate until the model is frozen.
    reserved=ROOT/'artifacts/fp-repair/reserved-search-v3b.json'
    reserved.write_text(json.dumps([r for value in normal_values('reserved') for r in variants(value)],ensure_ascii=False),encoding='utf-8')
    report['reserved_sha256']=sha(reserved)
    splits={s:load(out/s)[0] for s in ('train','validation','test')}
    report['audit']=audit_splits(splits,allow_shared_families=True,allow_shared_normal_templates=True)
    (out/'manifest.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report['splits'],indent=2))
    if report['audit']['cross_split_conflicts']:raise ValueError(report['audit']['cross_split_conflicts'])


if __name__=='__main__':main()
