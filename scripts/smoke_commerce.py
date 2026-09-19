"""Explicit opt-in acceptance test for an isolated test deployment; creates synthetic orders."""

from __future__ import annotations

import argparse
import secrets
from html.parser import HTMLParser

import httpx


class ScriptAssets(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.urls: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "script":
            source = dict(attrs).get("src")
            if source and source.startswith("/_next/"):
                self.urls.append(source)


def exercise(client: httpx.Client) -> str:
    def call(method: str, path: str, data: dict | None = None) -> dict:
        result = client.request(method, path, json=data)
        result.raise_for_status()
        return result.json()

    region = call("GET", "/store/regions")["regions"][0]
    products = call(
        "GET",
        f"/store/products?region_id={region['id']}&fields=*variants.calculated_price",
    )["products"]
    assert products, "Seed products missing"
    email = secrets.token_hex(6) + "@example.invalid"
    password = secrets.token_urlsafe(24)
    token = call(
        "POST",
        "/auth/customer/emailpass/register",
        {"email": email, "password": password},
    )["token"]
    client.headers["authorization"] = "Bearer " + token
    call(
        "POST",
        "/store/customers",
        {"email": email, "first_name": "Test", "last_name": "Visitor"},
    )
    token = call(
        "POST", "/auth/customer/emailpass", {"email": email, "password": password}
    )["token"]
    client.headers["authorization"] = "Bearer " + token
    assert call("GET", "/store/customers/me")["customer"]["email"] == email
    cart = call("POST", "/store/carts", {"region_id": region["id"], "email": email})[
        "cart"
    ]
    cart_id = cart["id"]
    call(
        "POST",
        f"/store/carts/{cart_id}/line-items",
        {"variant_id": products[0]["variants"][0]["id"], "quantity": 1},
    )
    address = {
        "first_name": "Test",
        "last_name": "Visitor",
        "address_1": "1 Test Street",
        "city": "Copenhagen",
        "postal_code": "1000",
        "country_code": region["countries"][0]["iso_2"],
    }
    call(
        "POST",
        f"/store/carts/{cart_id}",
        {"shipping_address": address, "billing_address": address},
    )
    shipping = call("GET", f"/store/shipping-options?cart_id={cart_id}")[
        "shipping_options"
    ]
    assert shipping, "Seed shipping options missing"
    call(
        "POST",
        f"/store/carts/{cart_id}/shipping-methods",
        {"option_id": shipping[0]["id"]},
    )
    collection = call("POST", "/store/payment-collections", {"cart_id": cart_id})[
        "payment_collection"
    ]
    call(
        "POST",
        f"/store/payment-collections/{collection['id']}/payment-sessions",
        {"provider_id": "pp_system_default"},
    )
    completed = call("POST", f"/store/carts/{cart_id}/complete", {})
    assert completed.get("type") == "order", completed
    order_id = completed["order"]["id"]
    assert call("GET", f"/store/orders/{order_id}")["order"]["id"] == order_id
    return order_id


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://localhost:8080")
    args = parser.parse_args()
    with httpx.Client(base_url=args.url, timeout=60, follow_redirects=True) as client:
        regions_response = client.get("/store/regions")
        regions_response.raise_for_status()
        region = regions_response.json()["regions"][0]
        country = region["countries"][0]["iso_2"]
        home = client.get(f"/{country}")
        assert home.status_code == 200
        assets = ScriptAssets()
        assets.feed(home.text)
        assert assets.urls, "Storefront JavaScript assets missing"
        for source in assets.urls:
            asset = client.get(source)
            assert asset.status_code == 200, f"Missing browser asset: {source}"
            assert "javascript" in asset.headers.get("content-type", "")
        normal_order = exercise(client)
        client.get("/store/products?q=UNION%20SELECT%201")
        client.headers.pop("authorization", None)
        sandbox_order = exercise(client)
        assert normal_order != sandbox_order
        # The real order must not be visible through the quarantined identity.
        assert client.get("/store/orders/" + normal_order).status_code in {
            401,
            403,
            404,
        }
        saved_cookies = dict(client.cookies)
        saved_auth = client.headers["authorization"]
    with httpx.Client(
        base_url=args.url,
        timeout=60,
        cookies=saved_cookies,
        headers={"authorization": saved_auth},
    ) as returning:
        assert returning.get("/store/orders/" + normal_order).status_code in {
            401,
            403,
            404,
        }
        response = returning.get("/store/orders/" + sandbox_order)
        response.raise_for_status()
        assert response.json()["order"]["id"] == sandbox_order
    print(
        "PASS: real + sandbox registration, cart, simulated checkout, orders and return isolation"
    )


if __name__ == "__main__":
    main()
