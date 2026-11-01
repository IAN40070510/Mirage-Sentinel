from __future__ import annotations
import asyncio
import time
import pytest
from services.commerce.detection import Detector, has_atomic_command


@pytest.mark.asyncio
async def test_sixteen_requests_are_serialized_without_skipping_model() -> None:
    detector=Detector(timeout=.2,queue_timeout=1)
    detector.model=object()
    active=0;peak=0
    def predict(values: list[float]) -> float:
        nonlocal active,peak
        active+=1;peak=max(peak,active)
        time.sleep(.002)
        active-=1
        return .01
    detector._predict=predict
    results=await asyncio.gather(*[detector.assess(str(i),'GET','/store/products','q=cotton',{},b'') for i in range(16)])
    assert peak==1
    assert all(r['fallback'] is None and not r['retry_required'] for r in results)
    assert detector.stats['predicted']==16
    assert detector.waiting==0


@pytest.mark.asyncio
async def test_queue_overload_is_not_classified_as_attack_or_silently_allowed() -> None:
    detector=Detector(timeout=.2,queue_timeout=.2,queue_limit=1)
    detector.model=object()
    detector._predict=lambda _:time.sleep(.03) or .01
    results=await asyncio.gather(*[detector.assess(str(i),'GET','/store/products','q=cotton',{},b'') for i in range(8)])
    overloaded=[r for r in results if r['fallback']=='model_queue_full']
    assert len(overloaded)==7
    assert all(r['retry_required'] and not r['attack'] for r in overloaded)


@pytest.mark.parametrize('value', ['| id','`id`','| whoami','`whoami`'])
def test_atomic_commands_are_detected_in_header_and_body(value: str) -> None:
    import json
    assert has_atomic_command('',json.dumps({'metadata':{'note':value}}),{})
    assert has_atomic_command('', '', {'x-probe':value})
    assert not has_atomic_command('',json.dumps({'note':value+' command reference'}),{})


@pytest.mark.asyncio
@pytest.mark.parametrize('value,label', [("'/**/OR/**/1=1--",'sqli'),('<svg/onload=alert(1)>','xss')])
async def test_header_variants_hit_rules(value: str,label: str) -> None:
    detector=Detector(rules_enforce=True)
    result=await detector.assess('test','GET','/store/products','limit=20',{'x-probe':value},b'')
    assert label in result['rules'] and result['attack']


@pytest.mark.asyncio
async def test_json_escaped_values_are_inspected_after_parsing() -> None:
    import json
    detector = Detector(rules_enforce=True)
    for note, expected in [(r"..\..\windows\win.ini", True),
                            ("../../ textile illustration", False),
                            ("javascript: browser reference", False)]:
        body = json.dumps({'metadata': {'note': note}}, ensure_ascii=True).encode()
        result = await detector.assess('json', 'POST', '/store/carts/cart_fixture', '',
                                       {'content-type': 'application/json'}, body)
        assert result['attack'] is expected
