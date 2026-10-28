from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys

import httpx


def test_capture_removes_actual_credentials_and_keeps_json_structure():
    scripts = Path(__file__).resolve().parents[1] / 'scripts'
    sys.path.insert(0, str(scripts))
    try:
        spec = importlib.util.spec_from_file_location('capture_test', scripts / 'collect_commerce_normal.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        request = httpx.Request('POST', 'http://localhost/auth/customer/emailpass?token=private-query',
            headers={'authorization': 'Bearer private-header', 'cookie': 'private-cookie'},
            json={'email': 'test@example.invalid', 'password': 'private-password',
                  'nested': {'access_token': 'private-nested'}, 'quantity': 2})
        result = module.sanitized_request(request)
        serialized = json.dumps(result)
        for secret in ('private-query', 'private-header', 'private-cookie', 'private-password', 'private-nested'):
            assert secret not in serialized
        assert set(result['headers']) == {'content-type'}
        assert json.loads(result['body'])['quantity'] == 2
        assert result['path'] == '/auth/customer/emailpass'
    finally:
        sys.path.remove(str(scripts))
