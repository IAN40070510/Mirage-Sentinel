from __future__ import annotations

from datetime import datetime
import hashlib


def generate_fake_data(query_id: str) -> dict[str, object]:
    """Generate deterministic but disposable deception data for intercepted flows."""
    normalized_query = str(query_id or "unknown")
    seed = hashlib.sha256(normalized_query.encode("utf-8")).hexdigest()
    balance_cents = int(seed[:8], 16) % 900000 + 10000
    pending_amount = int(seed[8:12], 16) % 50000 + 250
    timestamp = datetime.now().isoformat(timespec="milliseconds")

    return {
        "status": "success",
        "route": "mirage",
        "response_origin": "mirage",
        "user_id": normalized_query,
        "ledger": {
            "account_id": f"SIM-{seed[12:20].upper()}",
            "currency": "USD",
            "available_balance": round(balance_cents / 100, 2),
            "pending_review": round(pending_amount / 100, 2),
            "updated_at": timestamp,
        },
        "review_queue": {
            "ticket": f"MRG-{seed[20:32].upper()}",
            "status": "queued_review",
            "queued_at": timestamp,
        },
    }
