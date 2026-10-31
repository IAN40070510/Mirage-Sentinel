"""Package the completed diversity experiment without opening or retuning models."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import zipfile


def archive_files(destination: Path, files: list[tuple[Path, str]]) -> str:
    checks = {}
    with zipfile.ZipFile(destination, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for source, name in files:
            checks[name] = hashlib.sha256(source.read_bytes()).hexdigest()
            archive.write(source, name)
        archive.writestr('package-checksums.json', json.dumps(checks, indent=2))
    with zipfile.ZipFile(destination) as archive:
        assert archive.testzip() is None
        for name, expected in checks.items():
            assert hashlib.sha256(archive.read(name)).hexdigest() == expected
    return hashlib.sha256(destination.read_bytes()).hexdigest()


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    work = root / 'artifacts/diversity-repair'
    data = root / 'datasets/commerce/diverse-rebalanced-v2'
    out = root.parent / 'normal-diversity-v2'
    out.mkdir(exist_ok=True)
    manifest = json.loads((data / 'manifest.json').read_text(encoding='utf-8'))
    model = work / 'candidate-v2'
    run = json.loads((model / 'run.json').read_text(encoding='utf-8'))
    result = json.loads((work / 'acceptance-v2/acceptance.json').read_text(encoding='utf-8'))
    meta = json.loads((model / 'bundle/bundle.json').read_text(encoding='utf-8'))
    legacy = json.loads((model / 'test-metrics.json').read_text(encoding='utf-8'))
    for name in ('freeze-v2.json',):
        shutil.copy2(work / name, out / name)
    shutil.copy2(work / 'acceptance-v2/acceptance.json', out / 'acceptance.json')
    shutil.copy2(root / 'docs/normal-acceptance-protocol-v1.json', out / 'acceptance-protocol.json')
    provenance = data / 'provenance'
    provenance.mkdir(exist_ok=True)
    baseline = root / 'datasets/commerce/mixed-context-augmented-560k-v1'
    shutil.copytree(baseline / 'provenance', provenance / 'previous-sources', dirs_exist_ok=True)
    shutil.copy2(baseline / 'manifest.json', provenance / 'baseline-manifest.json')
    shutil.copy2(work / 'development/manifest.json', provenance / 'development-capture-manifest.json')
    lines = ['# 正常情境擴充、重新平衡與獨立流程驗收', '',
        '本次重新訓練了候選模型。資料來自隔離應用中的腳本流程，不是真實使用者流量。',
        '200 個開發流程（160 訓練／40 驗證）和另外 60 個封存驗收流程；姓名、城市、街道與搜尋詞池分開。',
        '開發批次實際收集 7,200 筆請求。完全去重後新增訓練 1,953、驗證 492 筆，保留完整流程歸屬。', '',
        '| 類別 | 訓練 | 驗證 | 舊來源診斷測試 |', '|---|---:|---:|---:|']
    for label in ('normal', 'sqli', 'xss', 'cmdi', 'path_traversal'):
        lines.append('| ' + label + ' | ' + ' | '.join(f"{manifest['splits'][s]['labels'][label]:,}" for s in ('train', 'validation', 'test')) + ' |')
    lines += ['| 合計 | 127,455 | 25,592 | 25,102 |', '',
        '| 來源 | 訓練 | 驗證 | 舊來源診斷測試 |', '|---|---:|---:|---:|']
    for source in manifest['splits']['train']['sources']:
        lines.append('| ' + source + ' | ' + ' | '.join(str(manifest['splits'][s]['sources'].get(source, {}).get('rows', 0)) for s in ('train', 'validation', 'test')) + ' |')
    lines += ['', '## 重新平衡', '',
        '舊正常商品查詢每來源保留訓練 250／驗證測試各 50；不再保留不存在的 /store/custom 正常樣本。攻擊樣本原分割不變。',
        '正常類別共有 17 個路徑組，每組總訓練權重相同；商品查詢有 513 筆，占正常筆數 20.9%，但只占正常總權重 1/17。五個類別總權重各占 20%，不是實際流量比例或校準機率。',
        '正常近似模板重疊明確記錄；完全相同請求和 session 仍不跨開發集合。重播常見資源另算，不冒充未知請求。', '',
        '## 模型與封存驗收', '',
        f"模型保存 {run['rounds_saved']} 輪，門檻 {meta['threshold']:.3f}；停止輪數和門檻只使用驗證集決定。",
        '在解開驗收 ZIP 前先記錄模型、驗收標準與 ZIP 雜湊，見 freeze-v2.json；沒有使用驗收資料 fit 或調參。',
        f"驗收：{result['sessions']} 個完整流程，{result['rows']:,} 筆正常請求；門檻誤報 {result['threshold_false_positives']} 筆（{result['threshold_fpr']:.3%}）。",
        f"扣除開發已見請求後，共 {result['novel_unique_rows']:,} 筆獨特請求，誤報率 {result['novel_unique_fpr']:.3%}。",
        f"依規則或模型會被分流的正常流程：{result['flagged_sessions_rules_or_model']}/{result['sessions']}（{result['flagged_session_rate']:.3%}）。",
        f"同一驗收批次的舊模型：誤報 {result['baseline_comparison']['false_positives']:,}/{result['rows']:,}（{result['baseline_comparison']['normal_fpr']:.3%}）；{result['baseline_comparison']['flagged_sessions']}/{result['sessions']} 個流程至少有一次被標記。舊模型門檻保持原值，沒有調參。",
        f"是否通過事前設定的正常驗收門檻：{result['normal_acceptance_passed']}。",
        f"舊來源診斷測試之門檻攻擊漏報率：{legacy['binary_comparison']['model_threshold']['attack_false_negative_rate']:.3%}；這不是新的未知攻擊驗收。", '',
        '即使本次正常驗收通過，也不能保證零誤報或真實流量泛化。只有腳本正常流程的新值／新 session，並非全新網站或攻擊家族。服務自動分流設定沒有因此開啟。',
        '本次驗收結果已揭露；如根據它修改模型，下一次必須重新收集新的驗收批次，不可重用後宣稱盲測。', '',
        '## 檔案用途', '',
        '- mirage-diverse-training-v2.zip：重新平衡的資料與訓練／推論程式，沒有包含封存驗收資料。',
        '- mirage-diverse-model-v2.zip：本次已訓練候選模型、訓練紀錄、診斷測試指標與混淆矩陣。',
        '- acceptance.json：獨立正常驗收之逐路徑結果。',
        '- Mirage_Sentinel_Diverse_v2.ipynb：如需在 Colab 重現訓練；不會把本次驗收資料自動混入。', '',
        '上傳資料 ZIP 到 Google Drive/MyDrive/MirageSentinel/，再將新版 ipynb 上傳 Colab，依序執行。若重新訓練形成不同模型，不能沿用本次模型的驗收結論。']
    report = '\n'.join(lines) + '\n'
    (out / 'EXPERIMENT_REPORT.md').write_text(report, encoding='utf-8')
    (data / 'README.md').write_text(report, encoding='utf-8')
    files = [(p, 'data/' + p.relative_to(data).as_posix()) for p in sorted(data.rglob('*')) if p.is_file()]
    for name in ('__init__.py', 'runtime.py', 'data.py', 'train.py', 'normal_balance.py', 'evaluate_context.py', 'evaluate_external.py', 'requirements.txt'):
        files.append((root / 'commerce_ml' / name, 'commerce_ml/' + name))
    data_zip = out / 'mirage-diverse-training-v2.zip'
    data_sha = archive_files(data_zip, files)
    model_sha = archive_files(out / 'mirage-diverse-model-v2.zip', [(p, 'candidate-v2/' + p.relative_to(model).as_posix()) for p in sorted(model.rglob('*')) if p.is_file()])
    notebook = json.loads((root.parent / 'normal-coverage-pilot-v1/Mirage_Sentinel_Normal_Coverage_Pilot.ipynb').read_text(encoding='utf-8'))
    for cell in notebook['cells']:
        source = ''.join(cell['source'])
        source = source.replace('mirage-normal-coverage-pilot-v1.zip', data_zip.name)
        import re
        source = re.sub(r"assert actual == '[0-9a-f]{64}'", "assert actual == '" + data_sha + "'", source)
        source = source.replace("'train': 400293, 'validation': 80065, 'test': 80052", "'train': 127455, 'validation': 25592, 'test': 25102")
        source = source.replace("'--allow-shared-normal-templates'", "'--allow-shared-normal-templates', '--balance-normal-routes', '--early-stopping-metric', 'mlogloss'")
        source = source.replace('560,410', '178,149')
        source = source.replace('/content/mirage-context-560k-', '/content/mirage-diverse-v2-')
        if cell['cell_type'] == 'code':
            compile(source, 'notebook-cell', 'exec')
            cell['outputs'] = []
            cell['execution_count'] = None
        cell['source'] = source.splitlines(keepends=True)
    notebook['cells'][0]['source'] = ['# 正常情境擴充與重新平衡訓練\n',
        '訓練 127,455／驗證 25,592／舊來源診斷測試 25,102。使用 mirage-diverse-training-v2.zip。\n',
        '開發正常流程與封存驗收流程分開；此筆記本不含獨立驗收資料，不能用合併高分宣稱部署驗收通過。\n',
        '8,000 是 TF-IDF 特徵上限，使用 CPU。重現新模型後需另行驗收；不要直接開啟自動分流。\n']
    (out / 'Mirage_Sentinel_Diverse_v2.ipynb').write_text(json.dumps(notebook, ensure_ascii=False, indent=2), encoding='utf-8')
    (out / 'verification.json').write_text(json.dumps({'training_zip_sha256': data_sha, 'model_zip_sha256': model_sha,
        'archive_crc_and_file_hashes': 'passed', 'notebook_code_cells': 'compiled', 'acceptance_used_for_fit': False}, indent=2), encoding='utf-8')
    print(out, flush=True)


if __name__ == '__main__':
    main()
