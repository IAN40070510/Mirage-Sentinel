from __future__ import annotations

import asyncio
import hmac
import json
import os
import sqlite3
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from .common import now_iso, secret

security = HTTPBasic()


class Forensics:
    def __init__(self, path: str) -> None:
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(path) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE NOT NULL, at TEXT NOT NULL,
                    visitor_id TEXT NOT NULL, payload TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS events_visitor ON events(visitor_id,id);
                CREATE TRIGGER IF NOT EXISTS prevent_event_update BEFORE UPDATE ON events
                    BEGIN SELECT RAISE(ABORT, 'append-only'); END;
                CREATE TRIGGER IF NOT EXISTS prevent_event_delete BEFORE DELETE ON events
                    BEGIN SELECT RAISE(ABORT, 'append-only'); END;
            """)

    def append(self, event: dict) -> None:
        with sqlite3.connect(self.path, timeout=10) as db:
            db.execute(
                "INSERT OR IGNORE INTO events(event_id,at,visitor_id,payload) VALUES(?,?,?,?)",
                (
                    event["event_id"],
                    event["at"],
                    event.get("visitor_id", "system"),
                    json.dumps(event, ensure_ascii=False),
                ),
            )

    def read(self, after: int, visitor: str, limit: int) -> list[dict]:
        # Explicit read-only connection for SOC queries.
        uri = Path(self.path).resolve().as_uri() + "?mode=ro"
        with sqlite3.connect(uri, uri=True) as db:
            rows = db.execute(
                "SELECT id,payload FROM events WHERE id>? AND (?='' OR visitor_id=?) ORDER BY id LIMIT ?",
                (after, visitor, visitor, min(max(limit, 1), 500)),
            ).fetchall()
        return [{"cursor": row[0], **json.loads(row[1])} for row in rows]


def create_app(database: Forensics | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.db = database or Forensics(
            os.getenv("FORENSICS_DB", "/forensics/events.db")
        )
        # Fail startup if either access channel is unconfigured.
        secret("AUDIT_WRITE_TOKEN")
        secret("SOC_PASSWORD")
        yield

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

    def operator(
        credentials: Annotated[HTTPBasicCredentials, Depends(security)],
    ) -> None:
        if not (
            hmac.compare_digest(
                credentials.username.encode(), os.getenv("SOC_USER", "analyst").encode()
            )
            and hmac.compare_digest(
                credentials.password.encode(), secret("SOC_PASSWORD").encode()
            )
        ):
            raise HTTPException(
                401, "Authentication required", headers={"WWW-Authenticate": "Basic"}
            )

    @app.post("/events")
    async def ingest(request: Request) -> dict:
        if not hmac.compare_digest(
            request.headers.get("authorization", ""),
            "Bearer " + secret("AUDIT_WRITE_TOKEN"),
        ):
            raise HTTPException(403, "Forbidden")
        data = bytearray()
        async for chunk in request.stream():
            data.extend(chunk)
            if len(data) > 256 * 1024:
                raise HTTPException(413, "Event too large")
        try:
            event = json.loads(data)
            uuid.UUID(event["event_id"])
            if not isinstance(event["at"], str) or "." not in event["at"]:
                raise ValueError("millisecond timestamp required")
        except (ValueError, KeyError, TypeError):
            raise HTTPException(400, "Invalid event")
        await asyncio.to_thread(app.state.db.append, event)
        return {"accepted": True}

    @app.get("/", dependencies=[Depends(operator)])
    async def index() -> FileResponse:
        return FileResponse(
            Path(__file__).with_name("soc.html"),
            headers={
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
                "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
            },
        )

    @app.get("/api/events", dependencies=[Depends(operator)])
    async def events(after: int = 0, visitor: str = "", limit: int = 200) -> list[dict]:
        return await asyncio.to_thread(app.state.db.read, max(after, 0), visitor, limit)

    @app.get("/api/status", dependencies=[Depends(operator)])
    async def status() -> dict:
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.get(
                os.getenv("GATEWAY_URL", "http://gateway:8000") + "/_control/status",
                headers={"x-control-token": secret("CONTROL_TOKEN")},
            )
            response.raise_for_status()
            return response.json()

    @app.post("/api/release/{visitor}", dependencies=[Depends(operator)])
    async def release(visitor: str, request: Request) -> dict:
        # Same-origin JS-only header prevents CSRF with cached Basic credentials.
        if request.headers.get("x-soc-action") != "release":
            raise HTTPException(403, "Forbidden")
        await asyncio.to_thread(
            app.state.db.append,
            {
                "event_id": str(uuid.uuid4()),
                "at": now_iso(),
                "visitor_id": visitor,
                "kind": "release_requested",
                "operator": os.getenv("SOC_USER", "analyst"),
            },
        )
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.post(
                os.getenv("GATEWAY_URL", "http://gateway:8000")
                + "/_control/release/"
                + visitor,
                headers={"x-control-token": secret("CONTROL_TOKEN")},
            )
            if not response.is_success:
                raise HTTPException(502, "Release failed")
            return response.json()

    return app


app = create_app()
