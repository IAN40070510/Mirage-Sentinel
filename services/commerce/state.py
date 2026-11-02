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
        self.db.execute("CREATE TABLE IF NOT EXISTS visitor_accounts (visitor TEXT PRIMARY KEY, account TEXT NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS account_quarantine (account TEXT PRIMARY KEY, last_seen INTEGER NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS token_realms (digest TEXT PRIMARY KEY, realm TEXT NOT NULL, last_seen INTEGER NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS visitor_account_history (visitor TEXT NOT NULL, account TEXT NOT NULL, PRIMARY KEY(visitor, account))")
        self.db.execute("CREATE INDEX IF NOT EXISTS visitor_accounts_account ON visitor_accounts(account)")
        self.db.execute("CREATE INDEX IF NOT EXISTS token_realms_seen ON token_realms(last_seen)")
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

    def account_key(self, realm: str, customer_id: str) -> str:
        return hmac.new(self.key, ("account:" + realm + ":" + customer_id).encode(), hashlib.sha256).hexdigest()

    def token_realm(self, authorization: str, realm: str | None = None) -> str | None:
        digest = hmac.new(self.key, ("token:" + authorization).encode(), hashlib.sha256).hexdigest()
        stamp = int(time.time() * 1000)
        with self.lock, self.db:
            self.db.execute("DELETE FROM token_realms WHERE last_seen<?", (stamp - TTL * 1000,))
            if realm is not None:
                self.db.execute("INSERT INTO token_realms VALUES (?,?,?) ON CONFLICT(digest) DO UPDATE SET last_seen=excluded.last_seen", (digest, realm, stamp))
            row = self.db.execute("SELECT realm FROM token_realms WHERE digest=?", (digest,)).fetchone()
            return row[0] if row else None

    def detach_account(self, visitor: str) -> None:
        with self.lock, self.db:
            self.db.execute("DELETE FROM visitor_accounts WHERE visitor=?", (visitor,))

    def touch(self, token: str, attack: bool, timestamp: float | None = None,
              account: str | None = None) -> dict:
        stamp = int((time.time() if timestamp is None else timestamp) * 1000)
        visitor = self.verify(token) or secrets.token_hex(16)
        with self.lock, self.db:
            row = self.db.execute(
                "SELECT sandbox, last_seen, epoch, seq FROM visitors WHERE id=?",
                (visitor,),
            ).fetchone()
            expired = row is None or stamp - row[1] >= TTL * 1000
            if expired:
                self.db.execute("DELETE FROM visitor_accounts WHERE visitor=?", (visitor,))
                self.db.execute("DELETE FROM visitor_account_history WHERE visitor=?", (visitor,))
            if account is not None:
                self.db.execute("INSERT OR IGNORE INTO visitor_account_history VALUES (?,?)", (visitor, account))
                self.db.execute("INSERT INTO visitor_accounts VALUES (?,?) ON CONFLICT(visitor) DO UPDATE SET account=excluded.account", (visitor, account))
            binding = self.db.execute("SELECT account FROM visitor_accounts WHERE visitor=?", (visitor,)).fetchone()
            account = binding[0] if binding else None
            blocked = self.db.execute("SELECT last_seen FROM account_quarantine WHERE account=?", (account,)).fetchone() if account else None
            account_blocked = bool(blocked and stamp - blocked[0] < TTL * 1000)
            before = bool(row[0]) if row and not expired else False
            epoch = secrets.token_hex(8) if expired else row[2]
            after = before or attack or account_blocked
            if account and after:
                self.db.execute("INSERT INTO account_quarantine VALUES (?,?) ON CONFLICT(account) DO UPDATE SET last_seen=excluded.last_seen", (account, stamp))
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
            "account_linked": account is not None,
            "account_quarantined": account_blocked,
            "epoch": epoch,
            "seq": seq,
            "changed": before != after or expired,
            "token": self.sign(visitor),
        }

    def release(self, visitor: str) -> bool:
        with self.lock, self.db:
            bindings = self.db.execute("SELECT account FROM visitor_account_history WHERE visitor=? UNION SELECT account FROM visitor_accounts WHERE visitor=?", (visitor, visitor)).fetchall()
            for binding in bindings:
                self.db.execute("DELETE FROM account_quarantine WHERE account=?", (binding[0],))
                self.db.execute("UPDATE visitors SET sandbox=0, epoch=? WHERE id IN (SELECT visitor FROM visitor_accounts WHERE account=?)", (secrets.token_hex(8), binding[0]))
            return (
                self.db.execute(
                    "UPDATE visitors SET sandbox=0, epoch=? WHERE id=?",
                    (secrets.token_hex(8), visitor),
                ).rowcount
                > 0
            )

    def close(self) -> None:
        self.db.close()
