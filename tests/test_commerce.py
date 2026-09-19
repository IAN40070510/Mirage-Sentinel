from __future__ import annotations

import asyncio
import json
import sqlite3
import time
import uuid

import httpx
import pytest
from fastapi.testclient import TestClient

from services.commerce.audit import AuditQueue
from services.commerce.collector import Forensics
from services.commerce.collector import create_app as collector_app
from services.commerce.detection import FEATURES, Detector
from services.commerce.gateway import create_app
from services.commerce.state import TTL, VisitorStore


class MemoryAudit(AuditQueue):
    def __init__(self) -> None:
        super().__init__("http://unused", "test")
        self.events: list[dict] = []

    def emit(self, event: dict) -> None:
        self.events.append(event)

    async def run(self) -> None:
        await asyncio.Future()


@pytest.fixture
def system(tmp_path, monkeypatch):
    for name in [
        "EDGE_TOKEN",
        "VISITOR_SIGNING_KEY",
        "REAL_STOREFRONT_TOKEN",
        "SANDBOX_STOREFRONT_TOKEN",
        "CONTROL_TOKEN",
        "AUDIT_WRITE_TOKEN",
        "SOC_PASSWORD",
    ]:
        monkeypatch.setenv(name, name * 4)
    store = VisitorStore(str(tmp_path / "state.db"), "signing" * 8)
    audit = MemoryAudit()
    requests: list[httpx.Request] = []

    def upstream(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.host == "mirage":
            return httpx.Response(
                200, json={"type": "invalid_data", "message": "Validation failed"}
            )
        if request.url.path == "/unavailable":
            raise httpx.ConnectError("offline")
        return httpx.Response(
            200,
            json={"host": request.url.host, "path": request.url.path},
            headers=[
                ("set-cookie", "_medusa_cart_id=cart123; Path=/; HttpOnly"),
                ("set-cookie", "_medusa_jwt=token123; Path=/; HttpOnly"),
            ],
        )

    with TestClient(
        create_app(store, Detector(), audit, httpx.MockTransport(upstream))
    ) as client:
        client.headers["x-edge-token"] = "EDGE_TOKEN" * 4
        yield client, store, audit, requests
    store.close()


def test_sticky_sandbox_includes_pages_assets_login_and_api(system):
    client, _store, audit, calls = system
    assert client.get("/dk").json()["host"] == "real-storefront"
    assert client.get("/store/products?q=' OR 1=1--").json()["host"] == "sandbox-medusa"
    first = len(calls)
    for path in [
        "/dk",
        "/_next/static/a.js",
        "/dk/account",
        "/auth/customer/emailpass",
        "/store/carts",
    ]:
        client.get(path, headers={"x-forwarded-for": "203.0.113.17"})
    assert all(r.url.host.startswith("sandbox-") for r in calls[first:])
    assert all(e["route"] == "sandbox" for e in audit.events[1:])


def test_cookie_signed_and_persistent(system):
    client, store, _, _ = system
    response = client.get("/dk")
    assert "Max-Age=2592000" in response.headers.get("set-cookie", "")
    assert store.verify(client.cookies["visitor_id"])
    assert store.verify(client.cookies["visitor_id"] + "tampered") is None


def test_sliding_expiry_and_manual_release(tmp_path):
    store = VisitorStore(str(tmp_path / "state.db"), "key")
    first = store.touch("", True, 100)
    second = store.touch(first["token"], False, TTL)
    assert second["sandbox"]
    assert store.touch(first["token"], False, TTL * 2 - 1)["sandbox"]
    expired = store.touch(first["token"], False, TTL * 3)
    assert not expired["sandbox"] and expired["epoch"] != first["epoch"]
    store.touch(first["token"], True, TTL * 3 + 1)
    assert store.release(first["id"])
    assert not store.touch(first["token"], False, TTL * 3 + 2)["sandbox"]
    store.close()


def test_persistence_restart_and_other_visitor(tmp_path):
    path = str(tmp_path / "state.db")
    store = VisitorStore(path, "key")
    first = store.touch("", True)
    store.close()
    store = VisitorStore(path, "key")
    assert store.touch(first["token"], False)["sandbox"]
    assert not store.touch("", False)["sandbox"]
    store.close()


def test_backend_failure_never_falls_back_to_real(system):
    client, _, _, calls = system
    client.get("/store/products?q=../../etc/passwd")
    assert client.get("/unavailable").status_code == 502
    assert calls[-1].url.host == "sandbox-storefront"


def test_post_body_and_custom_header_detection(system):
    client, _, audit, _calls = system
    response = client.post("/store/carts", json={"q": "<script>alert(1)</script>"})
    assert response.json()["host"] == "sandbox-medusa"
    client.cookies.clear()
    response = client.get(
        "/store/products", headers={"x-search": "UNION SELECT password FROM users"}
    )
    assert response.json()["host"] == "sandbox-medusa"
    assert audit.events[-1]["model_probability"] is None
    assert audit.events[-1]["features"]["header_count"] > 0


def test_internal_requests_require_key_context_and_epoch(system):
    client, store, _audit, calls = system
    assert client.get("/_api/store/products").status_code == 404
    client.get("/dk")
    state = store.touch(client.cookies["visitor_id"], False)
    headers = {
        "x-storefront-token": "REAL_STOREFRONT_TOKEN" * 4,
        "x-routing-epoch": state["epoch"],
    }
    assert (
        client.get("/_api/store/products", headers=headers).json()["host"]
        == "real-medusa"
    )
    client.get("/store/products?q=UNION SELECT 1")
    before = len(calls)
    assert client.get("/_api/store/products", headers=headers).status_code == 409
    assert len(calls) == before


def test_sandbox_ssr_key_cannot_reach_real(system):
    client, store, _, calls = system
    client.get("/dk")
    state = store.touch(client.cookies["visitor_id"], False)
    before = len(calls)
    response = client.get(
        "/_api/store/products",
        headers={
            "x-storefront-token": "SANDBOX_STOREFRONT_TOKEN" * 4,
            "x-routing-epoch": state["epoch"],
        },
    )
    assert response.status_code == 409
    assert len(calls) == before


def test_gateway_is_not_a_sandbox_to_real_bridge(system):
    client, _, _, calls = system
    client.headers.pop("x-edge-token")
    assert client.get("/store/products").status_code == 404
    assert not calls


def test_cookies_do_not_cross_realms_and_multiple_set_cookie_preserved(system):
    client, _, _, calls = system
    response = client.get("/dk")
    assert len(response.headers.get_list("set-cookie")) == 3
    client.get("/dk")
    assert "_medusa_cart_id=cart123" in calls[-1].headers["cookie"]
    client.get("/dk?q=UNION SELECT 1")
    assert "_medusa_cart_id=" not in calls[-1].headers["cookie"]
    assert "_medusa_jwt=" not in calls[-1].headers["cookie"]
    assert "shop_" not in calls[-1].headers["cookie"]
    assert "cart123" not in calls[-1].headers["cookie"]


def test_next_route_group_asset_path(system):
    client, _, _, calls = system
    client.get("/_next/static/chunks/app/%5BcountryCode%5D/(main)/layout.js")
    assert "/(main)/" in str(calls[-1].url)
    assert "%28main%29" not in str(calls[-1].url)


def test_controls_and_redaction(system):
    client, store, audit, _ = system
    client.post(
        "/auth/customer/emailpass",
        json={"password": "sensitive", "email": "test@example.invalid"},
    )
    assert audit.events[-1]["request_body"]["password"] == "[redacted]"
    visitor = store.verify(client.cookies["visitor_id"])
    assert client.post("/_control/release/" + visitor).status_code == 404
    assert (
        client.post(
            "/_control/release/" + visitor,
            headers={"x-control-token": "CONTROL_TOKEN" * 4},
        ).status_code
        == 200
    )
    assert audit.events[-1]["kind"] == "manual_release"
    assert client.get("/admin/users").status_code == 404
    assert client.get("/auth/user/emailpass").status_code == 404


def test_encoded_traversal_cannot_reach_admin(system):
    client, _, _, calls = system
    for path in [
        "/store/%2e%2e/admin/users",
        "/store/%252e%252e/admin/users",
        "/store/%5c..%5cadmin/users",
    ]:
        before = len(calls)
        assert client.get(path).status_code == 404
        assert len(calls) == before


@pytest.mark.asyncio
async def test_model_timeout_uses_rules_and_does_not_spawn_unlimited_work():
    detector = Detector(timeout=0.001)
    detector.model = object()
    detector._predict = lambda values: time.sleep(0.1) or 0.1
    result = await detector.assess("a", "GET", "/", "q=UNION SELECT 1", {}, b"")
    assert result["attack"] and result["fallback"] == "model_error_or_timeout"
    second = await detector.assess("a", "GET", "/", "", {}, b"")
    assert second["fallback"] == "model_busy"
    await asyncio.sleep(0.15)


@pytest.mark.asyncio
async def test_native_xgboost_json_contract(tmp_path):
    import numpy as np
    import xgboost as xgb

    # Tiny model validates serialization/inference wiring, not detection accuracy.
    data = xgb.DMatrix(
        np.zeros((4, len(FEATURES)), dtype=np.float32),
        label=[0, 1, 0, 1],
        feature_names=FEATURES,
    )
    booster = xgb.train(
        {"objective": "binary:logistic", "nthread": 1}, data, num_boost_round=1
    )
    booster.save_model(tmp_path / "xgb.json")
    (tmp_path / "features.json").write_text(
        json.dumps({"version": 1, "features": FEATURES, "objective": "binary:logistic"})
    )
    detector = Detector(str(tmp_path), timeout=5)
    result = await detector.assess("a", "GET", "/store/products", "", {}, b"")
    assert result["decision_source"] == "xgboost"
    assert 0 <= result["model_probability"] <= 1
    (tmp_path / "features.json").write_text("{}")
    assert Detector(str(tmp_path)).model is None


def test_append_only_and_idempotent_forensics(tmp_path):
    path = str(tmp_path / "audit.db")
    db = Forensics(path)
    event = {
        "event_id": str(uuid.uuid4()),
        "at": "2026-09-18T00:00:00.123+00:00",
        "visitor_id": "abc",
    }
    db.append(event)
    db.append(event)
    assert len(db.read(0, "abc", 10)) == 1
    with sqlite3.connect(path) as connection:
        for command in ["UPDATE events SET at='oops'", "DELETE FROM events"]:
            with pytest.raises(sqlite3.IntegrityError, match="append-only"):
                connection.execute(command)


def test_collector_write_token_cannot_read_soc(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDIT_WRITE_TOKEN", "write" * 8)
    monkeypatch.setenv("SOC_PASSWORD", "password" * 8)
    with TestClient(collector_app(Forensics(str(tmp_path / "audit.db")))) as client:
        assert (
            client.get(
                "/api/events", headers={"authorization": "Bearer " + "write" * 8}
            ).status_code
            == 401
        )
        assert (
            client.get("/api/events", auth=("analyst", "password" * 8)).status_code
            == 200
        )
        assert (
            client.post("/api/release/a", auth=("analyst", "password" * 8)).status_code
            == 403
        )


def test_audit_queue_does_not_block_when_full():
    queue = AuditQueue("http://unused", "token", capacity=1)
    queue.emit({"one": 1})
    queue.emit({"two": 2})
    assert queue.dropped == 1 and queue.queue.qsize() == 1


def test_deployment_network_isolation():
    from pathlib import Path

    import yaml

    config = yaml.safe_load(Path("docker-compose.commerce.yml").read_text())
    services = config["services"]
    for name in ["sandbox-medusa", "sandbox-storefront", "mirage"]:
        service = services[name]
        assert not service.get("ports")
        assert service["read_only"] and not service["privileged"]
        assert service["cap_drop"] == ["ALL"]
        assert "audit" not in service["networks"]
        assert "real_data" not in service["networks"]
    assert "forensics:/forensics" not in services["gateway"]["volumes"]
    assert all(
        p.startswith(("127.0.0.1:", "0.0.0.0:"))
        for p in services["collector"]["ports"]
    )
