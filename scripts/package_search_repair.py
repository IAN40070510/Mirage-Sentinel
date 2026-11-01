"""Package the exact repaired dataset and training code with a matching Colab notebook."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

ROOT=Path(__file__).resolve().parents[1]

def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version',required=True)
    parser.add_argument('--dataset-version')
    parser.add_argument('--notebook-template',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();v=args.version
    dataset=ROOT/f'datasets/commerce/search-repair-{args.dataset_version or v}'
    model=ROOT/f'model/commerce-five/search-repair-{v}'
    docs=ROOT/f'docs/experiments/search-repair-{v}'
    assert json.loads((docs/'reserved-result.json').read_text(encoding='utf-8'))['passed']
    args.output.mkdir(exist_ok=False)
    files={f'data/{p.relative_to(dataset).as_posix()}':p.read_bytes() for p in dataset.rglob('*') if p.is_file()}
    # Preserve upstream provenance/license material from the previous released data package.
    prior=ROOT/'datasets/commerce/diverse-rebalanced-v2/provenance'
    for p in prior.rglob('*'):
        if p.is_file():files[f'data/provenance/{p.relative_to(prior).as_posix()}']=p.read_bytes()
    for stage in ('v3b','v4','v5','v6'):
        path=ROOT/f'datasets/commerce/search-repair-{stage}/manifest.json'
        files[f'data/provenance/repair-{stage}-manifest.json']=path.read_bytes()
    for name in ('LICENSE','README.md','source.json'):
        path=ROOT/'artifacts/hf-evaluation-sources-v1/Morzeux--HttpParamsDataset'/name
        files[f'data/provenance/httpparams/{name}']=path.read_bytes()
    for name in ('__init__.py','runtime.py','data.py','train.py','normal_balance.py','requirements.txt'):
        files['commerce_ml/'+name]=(ROOT/'commerce_ml'/name).read_bytes()
    for name in ('build_search_repair.py','build_literal_repair.py','build_comparison_repair.py',
                 'build_multilingual_repair.py','build_storefront_repair.py','storefront_requests.py'):
        files['scripts/'+name]=(ROOT/'scripts'/name).read_bytes()
    files['README.md']=(docs/'REPORT.md').read_bytes()
    files['data/source-counts.json']=(docs/'source-counts.json').read_bytes()
    files['package-checksums.json']=json.dumps({k:sha(b) for k,b in files.items()},indent=2).encode()
    archive=args.output/f'mirage-search-repair-{v}.zip'
    with zipfile.ZipFile(archive,'x',zipfile.ZIP_DEFLATED) as z:
        for name,data in files.items():z.writestr(name,data)
    model_archive=args.output/f'mirage-search-model-{v}.zip'
    with zipfile.ZipFile(model_archive,'x',zipfile.ZIP_DEFLATED) as z:
        for p in model.iterdir():
            if p.is_file():z.write(p,'bundle/'+p.name)
    audit=json.loads((dataset/'manifest.json').read_text(encoding='utf-8'))['audit']['splits']
    counts={s:audit[s]['rows'] for s in ('train','validation','test')}
    notebook=json.loads(args.notebook_template.read_text(encoding='utf-8'))
    old_hash='d2e2d3b0c07d0bc4e7c9dc41f3619be04bc0754b078282e5b66a3a81fc5ec484'
    replacements={'v3':v,old_hash:sha(archive.read_bytes()),'146,260':f"{counts['train']:,}",
        '30,115':f"{counts['validation']:,}",'201,477':f"{sum(counts.values()):,}",
        '146260':str(counts['train']),'30115':str(counts['validation']),
        "'--max-fpr', '0.01'":"'--max-fpr', '0.001'"}
    for index,cell in enumerate(notebook['cells']):
        source=''.join(cell['source'])
        for old,new in replacements.items():source=source.replace(old,new)
        if cell['cell_type']=='code':
            compile(source,f'cell-{index}','exec')
            cell['outputs']=[];cell['execution_count']=None
        cell['source']=source.splitlines(keepends=True)
    (args.output/f'Mirage_Sentinel_Search_Repair_{v}.ipynb').write_text(json.dumps(notebook,ensure_ascii=False,indent=2),encoding='utf-8')
    for archive_path in (archive,model_archive):
        with zipfile.ZipFile(archive_path) as z:assert z.testzip() is None
    with zipfile.ZipFile(archive) as z:
        expected=json.loads(z.read('package-checksums.json'))
        assert all(sha(z.read(name))==digest for name,digest in expected.items())
        assert not any('reserved' in name for name in z.namelist())
    report={'training_zip_sha256':sha(archive.read_bytes()),'model_zip_sha256':sha(model_archive.read_bytes()),
            'crc_and_file_hashes':'passed','notebook_code_cells':'compiled','reserved_data_in_training_package':False,
            'colab_execution':'not run; local training verified, Colab Python version may affect results', 'counts':counts}
    (args.output/'package-verification.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report))

if __name__=='__main__':main()
