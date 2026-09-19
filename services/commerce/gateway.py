from __future__ import annotations

import asyncio
import hmac
import json
import os
import re
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from http.cookies import CookieError, SimpleCookie
from typing import Any
from urllib.parse import quote, unquote

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import Response

from .audit import AuditQueue
from .common import now_iso, secret
from .detection import Detector
from .state import COOKIE, TTL, VisitorStore

HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-length",
    "host",
    "accept-encoding",
}
SENSITIVE = {
    "authorization",
    "cookie",
    "set-cookie",
    "password",
    "token",
    "access_token",
    "refresh_token",
    "secret",
}


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            k: "[redacted]" if k.lower() in SENSITIVE else redact(v)
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


def capture(content: bytes, content_type: str) -> Any:
    text = content[:32768].decode("utf-8", "replace")
    if "json" in content_type:
        try:
            return redact(json.loads(text))
        except ValueError:
            pass
    # Logs stay inert text in the SOC. Never render attacker HTML as markup.
    return re.sub(
        r'(?i)(password|access_token|refresh_token)([="\s:]+)[^&\s"<]+',
        r"\1\2[redacted]",
        text,
    )


def create_app(
    state: VisitorStore | None = None,
    detector: Detector | None = None,
    audit: AuditQueue | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.store = state or VisitorStore(
            os.getenv("STATE_DB", "/state/visitors.db"), secret("VISITOR_SIGNING_KEY")
        )
        app.state.detector = detector or Detector(os.getenv("SENTINEL_MODEL_DIR", ""))
        app.state.audit = audit or AuditQueue(
            os.getenv("AUDIT_URL", "http://collector:8000"), secret("AUDIT_WRITE_TOKEN")
        )
        app.state.client = httpx.AsyncClient(
            transport=transport,
            timeout=60,
            follow_redirects=False,
            limits=httpx.Limits(max_connections=100),
        )
        app.state.audit.task = asyncio.create_task(app.state.audit.run())
        yield
        await app.state.audit.stop()
        await app.state.client.aclose()
        if state is None:
            app.state.store.close()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/healthz")
    async def health() -> dict:
        return {"status": "ok", "at": now_iso()}

    @app.get("/_control/status")
    async def status(request: Request) -> dict:
        check_control(request)
        return {
            "model": app.state.detector.model_status,
            "audit_queued": app.state.audit.queue.qsize(),
            "audit_dropped": app.state.audit.dropped,
            "audit_delivered": app.state.audit.delivered,
        }

    @app.post("/_control/release/{visitor}")
    async def release(visitor: str, request: Request) -> dict:
        check_control(request)
        if not re.fullmatch(r"[a-f0-9]{32}", visitor):
            raise HTTPException(400, "Invalid visitor")
        released = await asyncio.to_thread(app.state.store.release, visitor)
        app.state.audit.emit(
            {
                "event_id": str(uuid.uuid4()),
                "at": now_iso(),
                "visitor_id": visitor,
                "kind": "manual_release",
                "released": released,
            }
        )
        return {"released": released}

    def check_control(request: Request) -> None:
        if not hmac.compare_digest(
            request.headers.get("x-control-token", ""), secret("CONTROL_TOKEN")
        ):
            raise HTTPException(404, "Not found")

    @app.api_route(
        "/{path:path}",
        methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    )
    async def proxy(path: str, request: Request) -> Response:
        started, at = time.perf_counter(), now_iso()
        request_id = str(uuid.uuid4())
        internal = path.startswith("_api/")
        forced_sandbox = False
        if internal:
            provided = request.headers.get("x-storefront-token", "")
            sandbox_key, real_key = (
                secret("SANDBOX_STOREFRONT_TOKEN"),
                secret("REAL_STOREFRONT_TOKEN"),
            )
            forced_sandbox = hmac.compare_digest(provided, sandbox_key)
            if not forced_sandbox and not hmac.compare_digest(provided, real_key):
                raise HTTPException(404, "Not found")
            path = path[5:]
            if not app.state.store.verify(request.cookies.get(COOKIE, "")):
                raise HTTPException(400, "Missing visitor context")
        elif not hmac.compare_digest(
            request.headers.get("x-edge-token", ""), secret("EDGE_TOKEN")
        ):
            # A compromised sandbox may reach this listener, but cannot use it as
            # a bridge into the protected environment by posing as a new browser.
            raise HTTPException(404, "Not found")
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 1024 * 1024:
                raise HTTPException(413, "Request too large")
        token = request.cookies.get(COOKIE, "")
        provisional = await asyncio.to_thread(
            app.state.store.touch, token, forced_sandbox
        )
        forwarded = {
            k.lower(): v
            for k, v in request.headers.items()
            if k.lower()
            not in {
                "x-edge-token",
                "x-storefront-token",
                "x-control-token",
                "x-routing-epoch",
                "x-visitor-context",
            }
        }
        decision = await app.state.detector.assess(
            provisional["id"],
            request.method,
            "/" + path,
            request.url.query,
            forwarded,
            bytes(body),
        )
        visitor = await asyncio.to_thread(
            app.state.store.touch,
            provisional["token"],
            decision["attack"] or forced_sandbox,
        )
        realm = "sandbox" if visitor["sandbox"] else "real"
        is_api = (
            internal
            or path.startswith(("store/", "auth/"))
            or path in {"store", "auth"}
        )
        control_path = path.startswith(
            ("_control", "_api", "admin", "app", "docs", "openapi")
        )
        decoded_path = path
        for _ in range(5):
            decoded_path = unquote(decoded_path)
        if (
            any(part in {".", ".."} for part in decoded_path.split("/"))
            or "\\" in decoded_path
            or any(ord(c) < 32 for c in decoded_path)
        ):
            control_path = True
        if (
            path.startswith("auth/")
            and not path.startswith("auth/customer/")
            and path != "auth/token/refresh"
        ):
            control_path = True
        prefix = realm.upper()
        upstream = os.getenv(
            prefix + ("_API_URL" if is_api else "_WEB_URL"),
            f"http://{realm}-{'medusa' if is_api else 'storefront'}:{9000 if is_api else 8000}",
        )
        headers = {
            k: v
            for k, v in request.headers.items()
            if k.lower() not in HOP
            and not k.lower().startswith("x-")
            and k.lower() != "cookie"
        }
        # A server-side SDK request is fenced to the page's routing epoch.
        # A concurrent transition never allows it to fall through to the real backend.
        stale_context = (
            internal and request.headers.get("x-routing-epoch") != visitor["epoch"]
        )
        jar = SimpleCookie()
        try:
            jar.load(request.headers.get("cookie", ""))
        except CookieError:
            jar = SimpleCookie()
        allowed_cookies = {
            k: m.value
            for k, m in jar.items()
            if not k.startswith(("_medusa_", "shop_"))
        }
        allowed_cookies[COOKIE] = visitor["token"]
        # Prefix stateful storefront cookies by realm + epoch to prevent state transfer.
        cookie_prefix = f"shop_{visitor['epoch']}_"
        for k, m in jar.items():
            if k.startswith(cookie_prefix):
                allowed_cookies["_medusa_" + k[len(cookie_prefix) :]] = m.value
        headers["cookie"] = "; ".join(f"{k}={v}" for k, v in allowed_cookies.items())
        headers["x-routing-epoch"] = visitor["epoch"]
        headers["x-visitor-context"] = visitor["token"]
        headers["x-parent-request-id"] = request_id
        headers["x-client-ip"] = request.headers.get(
            "x-client-ip", request.client.host if request.client else "unknown"
        )
        headers["x-forwarded-host"] = request.headers.get("host", "localhost")
        headers["x-forwarded-proto"] = os.getenv("PUBLIC_SCHEME", "http")
        if is_api:
            headers.pop("cookie", None)
            # Never forward a real-environment auth token at a realm transition.
            if (not internal or stale_context) and (
                visitor["changed"] or provisional["changed"] or stale_context
            ):
                headers.pop("authorization", None)
            headers["x-publishable-api-key"] = os.getenv(
                prefix + "_PUBLISHABLE_KEY", ""
            )
            if request.headers.get("x-medusa-locale"):
                headers["x-medusa-locale"] = request.headers["x-medusa-locale"]
        status_code, content, response_headers = (
            502,
            b'{"type":"service_unavailable","message":"Please try again later."}',
            [("content-type", "application/json")],
        )
        origin = "unavailable"
        if control_path:
            status_code, content = 404, b'{"type":"not_found","message":"Not found"}'
        elif stale_context:
            status_code, content = (
                409,
                b'{"type":"invalid_state","message":"Please reload the page and try again."}',
            )
        else:
            try:
                # Next's static route matcher needs literal route-group parentheses.
                url = upstream.rstrip("/") + "/" + quote(path, safe="/-._~()")
                if request.url.query:
                    url += "?" + request.url.query
                response = await app.state.client.request(
                    request.method, url, headers=headers, content=bytes(body)
                )
                status_code, content = response.status_code, response.content
                response_headers = [
                    (k, v)
                    for k, v in response.headers.multi_items()
                    if k.lower()
                    not in HOP
                    | {"content-encoding", "set-cookie", "cache-control", "location"}
                ]
                for set_cookie in response.headers.get_list("set-cookie"):
                    if set_cookie.startswith("_medusa_"):
                        set_cookie = cookie_prefix + set_cookie[len("_medusa_") :]
                    # Do not let an upstream set the visitor identity or redirect routing.
                    if not set_cookie.startswith(COOKIE + "="):
                        response_headers.append(("set-cookie", set_cookie))
                if response.headers.get("location"):
                    location = response.headers["location"]
                    if location.startswith(upstream):
                        location = location[len(upstream) :] or "/"
                    response_headers.append(("location", location))
                origin = realm + ("_api" if is_api else "_web")
                # Mirage enriches failed suspicious API probes, never changes successful orders.
                if (
                    visitor["sandbox"]
                    and is_api
                    and decision["attack"]
                    and status_code >= 400
                ):
                    try:
                        generated = await app.state.client.post(
                            os.getenv("MIRAGE_URL", "http://mirage:8000") + "/respond",
                            json={
                                "visitor": visitor["id"],
                                "path": path[:1000],
                                "rules": decision["rules"],
                                "status": status_code,
                            },
                            timeout=3,
                        )
                        if generated.is_success:
                            content = json.dumps(generated.json()).encode()
                            response_headers = [("content-type", "application/json")]
                            origin = "mirage"
                    except httpx.HTTPError:
                        pass
            except httpx.HTTPError:
                pass
        event = {
            "event_id": request_id,
            "parent_request_id": request.headers.get("x-parent-request-id")
            if internal
            else None,
            "client_ip": headers["x-client-ip"],
            "at": at,
            "response_at": now_iso(),
            "visitor_id": visitor["id"],
            "sequence": visitor["seq"],
            "epoch": visitor["epoch"],
            "kind": "request",
            "method": request.method,
            "path": "/" + path,
            "query": request.url.query,
            "internal": internal,
            "route": realm,
            "origin": origin,
            "sticky": visitor["sandbox"] and not decision["attack"],
            "status": status_code,
            "duration_ms": round((time.perf_counter() - started) * 1000, 3),
            "request_headers": redact(forwarded),
            "request_body": capture(
                bytes(body), request.headers.get("content-type", "")
            ),
            "response": capture(
                content,
                next(
                    (v for k, v in response_headers if k.lower() == "content-type"), ""
                ),
            ),
            **decision,
        }
        app.state.audit.emit(event)
        result = Response(content, status_code=status_code)
        result.raw_headers = [
            (k.encode("latin-1"), v.encode("latin-1")) for k, v in response_headers
        ]
        result.headers["cache-control"] = "private, no-store"
        for name, morsel in jar.items():
            if name.startswith(cookie_prefix) and not any(
                k == "set-cookie" and v.startswith(name + "=")
                for k, v in response_headers
            ):
                result.set_cookie(
                    name,
                    morsel.value,
                    max_age=TTL,
                    httponly=True,
                    samesite="lax",
                    secure=os.getenv("PUBLIC_SCHEME", "http") == "https",
                )
        result.set_cookie(
            COOKIE,
            visitor["token"],
            max_age=TTL,
            httponly=True,
            samesite="lax",
            secure=os.getenv("PUBLIC_SCHEME", "http") == "https",
        )
        return result

    return app


app = create_app()
