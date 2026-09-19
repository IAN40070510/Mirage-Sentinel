from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
import threading
import time
from pathlib import Path

TTL = 30 * 24 * 60 * 60
COOKIE = "visitor_id"


class VisitorStore:
    """Disposable routing state. Never accesses the forensic database."""

    def __init__(self, path: str, signing_key: str) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.key = signing_key.encode()
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS visitors (id TEXT PRIMARY KEY, sandbox INTEGER NOT NULL, last_seen INTEGER NOT NULL, epoch TEXT NOT NULL, seq INTEGER NOT NULL DEFAULT 0)"
        )
        self.db.commit()

    def sign(self, visitor: str) -> str:
        return (
            visitor
            + "."
            + hmac.new(self.key, visitor.encode(), hashlib.sha256).hexdigest()
        )

    def verify(self, token: str) -> str | None:
        visitor, sep, _signature = token.partition(".")
        if (
            not sep
            or len(visitor) != 32
            or any(c not in "0123456789abcdef" for c in visitor)
        ):
            return None
        return visitor if hmac.compare_digest(self.sign(visitor), token) else None

    def touch(self, token: str, attack: bool, timestamp: float | None = None) -> dict:
        stamp = int((time.time() if timestamp is None else timestamp) * 1000)
        visitor = self.verify(token) or secrets.token_hex(16)
        with self.lock, self.db:
            row = self.db.execute(
                "SELECT sandbox, last_seen, epoch, seq FROM visitors WHERE id=?",
                (visitor,),
            ).fetchone()
            expired = row is None or stamp - row[1] >= TTL * 1000
            before = bool(row[0]) if row and not expired else False
            epoch = secrets.token_hex(8) if expired else row[2]
            after = before or attack
            if after != before:
                epoch = secrets.token_hex(8)
            seq = (row[3] if row else 0) + 1
            self.db.execute(
                "INSERT INTO visitors VALUES (?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET sandbox=excluded.sandbox,last_seen=excluded.last_seen,epoch=excluded.epoch,seq=excluded.seq",
                (visitor, int(after), stamp, epoch, seq),
            )
        return {
            "id": visitor,
            "sandbox": after,
            "epoch": epoch,
            "seq": seq,
            "changed": before != after or expired,
            "token": self.sign(visitor),
        }

    def release(self, visitor: str) -> bool:
        with self.lock, self.db:
            return (
                self.db.execute(
                    "UPDATE visitors SET sandbox=0, epoch=? WHERE id=?",
                    (secrets.token_hex(8), visitor),
                ).rowcount
                > 0
            )

    def close(self) -> None:
        self.db.close()
