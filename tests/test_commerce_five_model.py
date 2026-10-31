"""Exercise the downloaded model through the actual asynchronous service adapter."""
from pathlib import Path
import shutil

import pytest

from services.commerce.detection import Detector
from services.commerce.five_runtime import Predictor, LABELS

BUNDLE = Path(__file__).resolve().parents[1] / 'model/commerce-five/run-20261028T081548514385Z'


@pytest.mark.parametrize('bundle', [BUNDLE, BUNDLE.parent / 'diversity-v2'])
@pytest.mark.asyncio
async def test_five_class_service_matches_training_runtime(bundle: Path):
    detector = Detector(str(bundle), timeout=5, model_mode='enforce')
    assert detector.model_status == 'ready_five_class'
    reference = Predictor(bundle)
    for query in ('q=cotton', 'q=%3Cscript%3Evoid(0)%3C/script%3E', 'q=%27+OR+1%3D1--'):
        request = dict(method='GET', path='/store/products', query=query, headers={}, body='')
        expected = reference.predict([request])[0]
        actual = await detector.assess('test', 'GET', '/store/products', query, {}, b'')
        assert actual['fallback'] is None
        assert actual['predicted_label'] == expected['predicted_label']
        assert actual['class_probabilities'] == pytest.approx(expected['probabilities'])
        assert set(actual['class_probabilities']) == set(LABELS)
        assert actual['model_probability'] == pytest.approx(expected['attack_score'])
        assert actual['model_threshold'] == reference.threshold
        assert actual['attack'] == (bool(actual['rules']) or expected['model_attack'])


def test_corrupt_five_class_model_falls_back(tmp_path):
    shutil.copytree(BUNDLE, tmp_path / 'bundle')
    (tmp_path / 'bundle/xgb.json').write_text('{}')
    detector = Detector(str(tmp_path / 'bundle'))
    assert detector.model is None
    assert detector.model_status == 'unavailable_or_incompatible'


@pytest.mark.asyncio
async def test_shadow_keeps_normal_browsing_real_but_rules_still_quarantine():
    detector = Detector(str(BUNDLE), timeout=5)
    # Real downloaded model reproduces the production smoke-test false positive.
    normal = await detector.assess('visitor', 'GET', '/dk', '', {}, b'')
    assert normal['model_attack'] is True
    assert normal['model_mode'] == 'shadow'
    assert normal['attack'] is False
    assert normal['decision_source'] == 'rule_with_shadow_model'
    attack = await detector.assess('visitor', 'GET', '/store/products', 'q=UNION%20SELECT%201', {}, b'')
    assert attack['attack'] is True
    assert 'sqli' in attack['rules']
    assert attack['class_probabilities'] is not None


def test_unknown_model_mode_is_rejected():
    with pytest.raises(ValueError):
        Detector(model_mode='silent')
