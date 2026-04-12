from __future__ import annotations

import importlib
import sys
import types
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

fake_ai_sentinel = types.ModuleType("model.ai_sentinel")
fake_ai_sentinel.load_sentinel_model = lambda: None
sys.modules["model.ai_sentinel"] = fake_ai_sentinel

main = importlib.import_module("main")


class _GraphMetricsStub:
    user_device_ratio = 0.0
    device_user_ratio = 0.0
    req_rate_5m = 0.0
    source = "test"


class _NoUpstreamAsyncClient:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def request(self, *args, **kwargs):
        raise AssertionError(
            "upstream request should not be attempted for intercepted traffic"
        )


class _FakeUpstreamResponse:
    def __init__(self):
        self.status_code = 200
        self.content = b'{"status":"upstream_ok"}'
        self.headers = {"content-type": "application/json"}


class _UpstreamAsyncClient:
    called = False
    requested_url = ""

    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def request(self, *args, **kwargs):
        _UpstreamAsyncClient.called = True
        _UpstreamAsyncClient.requested_url = kwargs.get("url", "")
        return _FakeUpstreamResponse()


async def _fake_sandbox_ai_agent(**kwargs):
    return {
        "status": "ai_processed",
        "ai_decision": {"action": "sandbox_route", "confidence": 0.99},
        "fake_data": {"status": "deceived", "response_origin": "sandbox_ai"},
    }


class PreUpstreamInterceptionTests(unittest.TestCase):
    def _base_patches(self) -> list[patch]:
        return [
            patch.object(main, "_compute_timing_features", return_value=(0.0, 0.0)),
            patch.object(main, "_compute_amount_deviation", return_value=0.0),
            patch.object(main, "_parse_mouse_entropy", return_value=(0.0, "missing")),
            patch.object(main.feature_store, "record_observation", return_value=None),
            patch.object(
                main.feature_store,
                "get_metrics",
                return_value=_GraphMetricsStub(),
            ),
        ]

    def test_intercepted_request_skips_upstream_and_returns_deception(self):
        captured_events: list[dict[str, object]] = []
        patches = self._base_patches() + [
            patch.object(main, "analyze_intent", return_value=(True, 0.95, "sqli")),
            patch.object(main, "detect_replication_risk", return_value=(False, "")),
            patch.object(main, "detect_rate_limiting_risk", return_value=(False, "")),
            patch.object(
                main, "detect_anomalous_amount_risk", return_value=(False, "")
            ),
            patch.object(main.httpx, "AsyncClient", _NoUpstreamAsyncClient),
            patch(
                "core.ai_agent_orchestrator.execute_sandbox_ai_agent",
                _fake_sandbox_ai_agent,
            ),
            patch.object(main, "log_traffic_event", side_effect=captured_events.append),
        ]

        for started_patch in patches:
            started_patch.start()
        self.addCleanup(lambda: [p.stop() for p in reversed(patches)])

        with TestClient(main.app) as client:
            response = client.get("/api/transactions?account=1%20UNION%20SELECT")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["response_origin"], "sandbox_ai")
        self.assertEqual(len(captured_events), 1)
        self.assertEqual(captured_events[0]["upstream_attempted"], 0)
        self.assertEqual(captured_events[0]["real_backend_touched"], 0)
        self.assertEqual(captured_events[0]["response_origin"], "sandbox_ai")

    def test_benign_request_still_proxies_to_upstream(self):
        captured_events: list[dict[str, object]] = []
        _UpstreamAsyncClient.called = False
        _UpstreamAsyncClient.requested_url = ""
        patches = self._base_patches() + [
            patch.object(main, "analyze_intent", return_value=(False, 0.0, "None")),
            patch.object(main, "detect_replication_risk", return_value=(False, "")),
            patch.object(main, "detect_rate_limiting_risk", return_value=(False, "")),
            patch.object(
                main, "detect_anomalous_amount_risk", return_value=(False, "")
            ),
            patch.object(main.httpx, "AsyncClient", _UpstreamAsyncClient),
            patch.object(main, "log_traffic_event", side_effect=captured_events.append),
        ]

        for started_patch in patches:
            started_patch.start()
        self.addCleanup(lambda: [p.stop() for p in reversed(patches)])

        with TestClient(main.app) as client:
            response = client.get("/api/transactions")

        self.assertEqual(response.status_code, 200)
        self.assertTrue(_UpstreamAsyncClient.called)
        self.assertIn("/api/transactions", _UpstreamAsyncClient.requested_url)
        self.assertEqual(response.json()["status"], "upstream_ok")
        self.assertEqual(len(captured_events), 1)
        self.assertEqual(captured_events[0]["upstream_attempted"], 1)
        self.assertEqual(captured_events[0]["real_backend_touched"], 1)
        self.assertEqual(captured_events[0]["response_origin"], "vuln_bank_main")


if __name__ == "__main__":
    unittest.main()
