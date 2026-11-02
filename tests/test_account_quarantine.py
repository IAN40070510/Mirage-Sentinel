"""Account identity must come from the authenticated customer API."""
import asyncio
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from services.commerce.audit import AuditQueue
from services.commerce.detection import Detector
from services.commerce.gateway import create_app
from services.commerce.state import TTL, VisitorStore


class Audit(AuditQueue):
    def __init__(self):
        super().__init__("http://unused", "unused")
        self.events = []

    def emit(self, event):
        self.events.append(event)

    async def run(self):
        await asyncio.Future()


@pytest.fixture
def system(tmp_path, monkeypatch):
    for key in ("EDGE_TOKEN", "CONTROL_TOKEN", "REAL_STOREFRONT_TOKEN", "SANDBOX_STOREFRONT_TOKEN"):
        monkeypatch.setenv(key, key * 4)
    store = VisitorStore(str(tmp_path / "visitors.db"), "test-key")
    audit = Audit()
    calls = []

    def backend(request):
        calls.append(request)
        realm = "sandbox" if request.url.host.startswith("sandbox") else "real"
        auth = request.headers.get("authorization", "")
        if request.url.path == "/store/customers/me":
            if auth == "Bearer outage":
                raise httpx.ConnectError("unavailable")
            if auth not in ("Bearer " + realm + "-alice", "Bearer " + realm + "-bob"):
                return httpx.Response(401, json={"message": "unauthorized"})
            return httpx.Response(200, json={"customer": {"id": "cus_" + auth.split("-")[-1]}})
        if request.url.path == "/auth/customer/emailpass":
            body = json.loads(request.content)
            if body.get("password") != "correct":
                return httpx.Response(401, json={"message": "unauthorized"})
            return httpx.Response(200, json={"token": realm + "-" + body["email"]})
        return httpx.Response(200, json={"realm": realm})

    with TestClient(create_app(store, Detector(rules_enforce=True), audit, httpx.MockTransport(backend))) as client:
        client.headers["x-edge-token"] = "EDGE_TOKEN" * 4
        yield client, store, audit, calls
    store.close()


def login(client, who="alice", password="correct"):
    return client.post("/auth/customer/emailpass", json={"email": who, "password": password})


def attack(client):
    return client.get("/store/products", params={"q": "' OR 1=1--"})


def test_deleted_cookie_same_account_stays_quarantined(system):
    client, store, audit, calls = system
    assert login(client).json()["token"] == "real-alice"
    attack(client)
    assert audit.events[-1]["route"] == "sandbox"
    client.cookies.clear()
    result = login(client)
    assert result.status_code == 409
    assert "token" not in result.json()
    assert audit.events[-1]["origin"] == "account_quarantine"
    assert client.get("/store/products").json()["realm"] == "sandbox"
    visitor = store.verify(client.cookies["visitor_id"])
    assert store.release(visitor)
    client.cookies.clear()
    assert login(client).json()["token"] == "real-alice"
    assert client.get("/store/products").json()["realm"] == "real"


def test_bearer_cannot_bypass_or_cross_realms(system):
    client, store, audit, calls = system
    login(client)
    attack(client)
    client.cookies.clear()
    start = len(calls)
    result = client.get("/store/orders/order_test", headers={"authorization": "Bearer real-alice"})
    assert result.json()["realm"] == "sandbox"
    protected = [r for r in calls[start:] if r.url.path != "/store/customers/me"]
    assert all(r.url.host == "sandbox-medusa" for r in protected)
    assert all("authorization" not in r.headers for r in protected)
    client.get("/store/products", headers={"authorization": "Bearer real-alice"})
    assert not any(r.url.host == "sandbox-medusa" and r.headers.get("authorization") == "Bearer real-alice" for r in calls)


def test_spoofed_identity_does_not_quarantine_victim(system):
    client, store, audit, calls = system
    assert login(client, password="wrong").status_code == 401
    client.post("/store/products", params={"q": "' OR 1=1--"}, json={"email": "alice", "customer_id": "cus_alice"}, headers={"authorization": "Bearer forged"})
    client.cookies.clear()
    assert login(client).status_code == 200
    assert audit.events[-1]["route"] == "real"


def test_unrelated_account_and_realm_are_separate(system):
    client, store, audit, calls = system
    login(client)
    attack(client)
    client.cookies.clear()
    assert login(client, "bob").status_code == 200
    assert audit.events[-1]["route"] == "real"
    assert store.account_key("real", "cus_alice") != store.account_key("sandbox", "cus_alice")


def test_verification_outage_prevents_operation(system):
    client, store, audit, calls = system
    result = client.post("/store/orders", headers={"authorization": "Bearer outage"}, json={})
    assert result.status_code == 503
    assert not any(r.url.path == "/store/orders" for r in calls)


def test_persistence_expiry_and_release_all_sessions(tmp_path):
    path = str(tmp_path / "visitors.db")
    store = VisitorStore(path, "key")
    account = store.account_key("real", "cus_alice")
    first = store.touch("", False, timestamp=100, account=account)
    second = store.touch("", False, timestamp=100, account=account)
    store.touch(first["token"], True, timestamp=101)
    store.close()
    store = VisitorStore(path, "key")
    assert store.touch(second["token"], False, timestamp=102)["sandbox"]
    assert store.touch("", False, timestamp=103, account=account)["sandbox"]
    assert store.release(first["id"])
    assert not store.touch(second["token"], False, timestamp=104)["sandbox"]
    store.touch(first["token"], True, timestamp=105)
    assert not store.touch("", False, timestamp=106 + TTL, account=account)["sandbox"]
    store.close()


def test_logout_detaches_identity(system):
    client, store, audit, calls = system
    login(client)
    assert client.delete("/auth/session").status_code == 200
    attack(client)
    client.cookies.clear()
    assert login(client).status_code == 200
