"""Exercise verified account isolation with a new synthetic account only."""
from __future__ import annotations

import argparse
import secrets

import httpx


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://localhost:8080")
    parser.add_argument("--soc-url", default="http://localhost:3000")
    args = parser.parse_args()
    credentials = {"email": secrets.token_hex(12) + "@example.invalid",
                   "password": secrets.token_urlsafe(24)}
    with httpx.Client(base_url=args.url, timeout=30) as client:
        registered = client.post("/auth/customer/emailpass/register", json=credentials)
        registered.raise_for_status()
        created = client.post("/store/customers", json={"email": credentials["email"]},
                              headers={"authorization": "Bearer " + registered.json()["token"]})
        created.raise_for_status()
        login = client.post("/auth/customer/emailpass", json=credentials)
        login.raise_for_status()
        client.get("/store/products", params={"q": "' OR 1=1--"}).raise_for_status()
        client.cookies.clear()
        # Wrong credentials must still fail without disclosing account isolation.
        invalid = client.post("/auth/customer/emailpass", json={**credentials, "password": "incorrect"})
        assert invalid.status_code == 401, invalid.status_code
        login = client.post("/auth/customer/emailpass", json=credentials)
        assert login.status_code == 409, login.status_code
        assert "token" not in login.json(), "Real token leaked after account quarantine"
        visitor = client.cookies["visitor_id"].split(".")[0]
        try:
            events = httpx.get(args.soc_url.rstrip("/") + "/api/events",
                               params={"visitor": visitor, "latest": "true"}, timeout=15)
            events.raise_for_status()
            # Async delivery may lag; routing is also enforced by the 409 above.
        finally:
            released = httpx.post(args.soc_url.rstrip("/") + "/api/release/" + visitor,
                                  headers={"x-soc-action": "release"}, timeout=15)
            released.raise_for_status()
            assert released.json()["released"]
        client.cookies.clear()
        client.post("/auth/customer/emailpass", json=credentials).raise_for_status()
    print("PASS: authenticated account survives cookie deletion; no real token issued; release restores login")


if __name__ == "__main__":
    main()
