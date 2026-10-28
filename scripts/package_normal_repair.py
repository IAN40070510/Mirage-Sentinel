"""Package the pilot normal-coverage dataset and matching Colab notebook."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import zipfile


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    data = root / 'datasets/commerce/normal-coverage-pilot-v1'
    out = root.parent / 'normal-coverage-pilot-v1'
    out.mkdir(exist_ok=True)
    manifest = json.loads((data / 'manifest.json').read_text(encoding='utf-8'))
    audit = json.loads((root / 'artifacts/normal-coverage-repair/combined-training-audit/data-audit.json').read_text(encoding='utf-8'))
    assert not audit['cross_split_conflicts']
    rows = ['# 正常購物覆蓋修正：試訓版', '',
        '此版補上實際呼叫隔離電商系統所得的正常請求，不是正式使用者流量，也尚未重訓或驗證部署效果。',
        '30 個完整流程共 1,020 筆，完全去重後保留 410 筆；資料來源為專案 4a7bca6 的隔離 CI 執行。',
        '新增 normal：train 293（21 個流程）、validation 65（5 個流程）、test 52（4 個流程）。',
        '全部 17 項必要路徑在新增訓練資料中出現；舊訓練集缺少 14 項。這只代表基本覆蓋，尚不足以涵蓋所有正常變化。', '',
        '| 類別 | 訓練 | 驗證 | 測試 |', '|---|---:|---:|---:|']
    for label in ('normal', 'sqli', 'xss', 'cmdi', 'path_traversal'):
        rows.append('| ' + label + ' | ' + ' | '.join(f"{manifest['splits'][s]['labels'][label]:,}" for s in ('train', 'validation', 'test')) + ' |')
    rows += ['| 合計 | 400,293 | 80,065 | 80,052 |', '',
             '| 來源 | 訓練 | 驗證 | 測試 |', '|---|---:|---:|---:|']
    for source in manifest['splits']['train']['sources']:
        rows.append('| ' + source + ' | ' + ' | '.join(f"{manifest['splits'][s]['sources'][source]['rows']:,}" for s in ('train', 'validation', 'test')) + ' |')
    rows += ['', '## 使用與解讀', '',
        '總數 560,410，保留上一版所有攻擊與正常樣本，沒有複製資料湊整數。XSS 仍包含既有合成上下文，其原有實驗限制沒有消失。',
        '正常 JSON 只因欄位形狀相似不再被合併刪除。明確啟用 --allow-shared-normal-templates，並記錄重疊；完全相同請求、跨集合 session、涉及攻擊類別的近似重疊仍阻擋。',
        '首頁和靜態資源會在多個正常流程重複，去重後驗證／測試不再保留相同請求；原始流程重播另行保存，不能把重播稱為未知模板測試。',
        '新增來源只有 normal，因此分來源評估重點為正常召回率與誤報率，不是完整五類 Macro-F1。',
        '舊模型在新增測試候選 52 筆中，依 0.585 門檻誤報 8 筆；該批結果已被用於診斷，不可再宣稱是完全未見過的盲測。',
        '這是修復覆蓋缺口的第一批試訓資料；新增訓練資料只有 293 筆，仍需擴充獨立正常情境。不要直接開啟 enforce 或宣稱誤報已修復。', '',
        '1. 將 mirage-normal-coverage-pilot-v1.zip 放到 Google Drive/MyDrive/MirageSentinel/，不需解壓。',
        '2. 將 Mirage_Sentinel_Normal_Coverage_Pilot.ipynb 上傳 Colab。',
        '3. 依序執行安裝、設定、稽核、訓練及分來源評估。8,000 仍是特徵上限。',
        '4. 特別檢查 application_normal 的 normal recall；1 − normal recall 為這批正常資料的分類誤報率。門檻分流另看 metrics 的 model_threshold 指標。',
        '5. 模型維持觀察模式；必須另取新流程批次驗收後，才評估自動分流。', '',
        '程式與資料已在本機完成合併稽核；此版尚未在 Colab 重訓。本包的資料、報告與來源版本均保留 SHA-256。']
    report = '\n'.join(rows) + '\n'
    (out / 'DATASET_REPORT.md').write_text(report, encoding='utf-8')
    (data / 'README.md').write_text(report, encoding='utf-8')
    checks = {}
    archive = out / 'mirage-normal-coverage-pilot-v1.zip'
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for file in sorted(data.rglob('*')):
            if file.is_file():
                name = 'data/' + file.relative_to(data).as_posix()
                checks[name] = hashlib.sha256(file.read_bytes()).hexdigest()
                z.write(file, name)
        for file in sorted((root / 'commerce_ml').glob('*')):
            if file.is_file():
                name = 'commerce_ml/' + file.name
                checks[name] = hashlib.sha256(file.read_bytes()).hexdigest()
                z.write(file, name)
        for name in ('capture-coverage.json', 'baseline-train.json', 'original-pool.json', 'old-model-normal-diagnostic.json'):
            file = root / 'artifacts/normal-coverage-repair' / name
            checks['evidence/' + name] = hashlib.sha256(file.read_bytes()).hexdigest()
            z.write(file, 'evidence/' + name)
        z.writestr('package-checksums.json', json.dumps(checks, indent=2))
    with zipfile.ZipFile(archive) as z:
        assert z.testzip() is None
        for name, expected in checks.items():
            assert hashlib.sha256(z.read(name)).hexdigest() == expected
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    old = root.parent / 'context-augmented-560k-v1/Mirage_Sentinel_560k_Colab.ipynb'
    notebook = json.loads(old.read_text(encoding='utf-8'))
    for cell in notebook['cells']:
        source = ''.join(cell['source'])
        source = source.replace('mirage-context-augmented-560k-data.zip', archive.name)
        source = source.replace('5eb25f549984c8921a72a5646a82a15591e4cc5ef94b4852a33d656589c47fd9', digest)
        source = source.replace("'train': 400000, 'validation': 80000, 'test': 80000", "'train': 400293, 'validation': 80065, 'test': 80052")
        source = source.replace("'--allow-unreviewed', '--allow-shared-families'", "'--allow-unreviewed', '--allow-shared-families', '--allow-shared-normal-templates'")
        source = source.replace("'per_class_report': metrics['per_class_report']}", "'per_class_report': metrics['per_class_report'], 'confusion_matrix': metrics['confusion_matrix'], 'binary_comparison': metrics['binary_comparison']}")
        source = source.replace('560,000', '560,410').replace('400,000／80,000／80,000', '400,293／80,065／80,052')
        if cell['cell_type'] == 'code':
            compile(source, 'notebook-cell', 'exec')
            cell['execution_count'] = None
            cell['outputs'] = []
        cell['source'] = source.splitlines(keepends=True)
    notebook['cells'][0]['source'] = ("# 正常購物覆蓋修正：試訓版\n\n" + '\n'.join(rows[2:6]) +
        '\n\n訓練／驗證／測試共 400,293／80,065／80,052。總數 560,410。\n'
        '使用新的 mirage-normal-coverage-pilot-v1.zip；依序執行。CPU、Python 3.11～3.13；12.7 GiB RAM 不保證足夠。\n'
        '不要把本次結果直接拿來啟用自動分流。分開檢查 application_normal、公開來源、合成來源的表現。\n').splitlines(keepends=True)
    notebook['cells'][13]['source'] = ['## 7. 部署限制\n',
        '服務端已接上五分類觀察模式。這份試訓包仍需新的正常購物流程驗收；不要直接覆蓋已部署模型或開啟自動分流。\n']
    (out / 'Mirage_Sentinel_Normal_Coverage_Pilot.ipynb').write_text(json.dumps(notebook, ensure_ascii=False, indent=2), encoding='utf-8')
    (out / 'verification.json').write_text(json.dumps({'zip_sha256': digest, 'all_file_hashes': 'passed',
        'notebook_code_cells': 'compile_passed', 'model_trained': False}, indent=2), encoding='utf-8')
    print(out, digest, flush=True)


if __name__ == '__main__':
    main()
