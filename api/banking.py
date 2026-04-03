import uuid
from datetime import datetime

from fastapi import APIRouter, Header, HTTPException, Query
from pydantic import BaseModel, Field

from core.banking_db import get_connection


router = APIRouter(prefix="/banking", tags=["Banking API"])


class BeneficiaryCreateRequest(BaseModel):
    nickname: str = Field(..., min_length=1, max_length=80)
    bank_code: str = Field(..., min_length=3, max_length=10)
    account_id: str = Field(..., min_length=6, max_length=40)


class TransferRequest(BaseModel):
    from_account: str = Field(..., min_length=6, max_length=40)
    to_account: str = Field(..., min_length=6, max_length=40)
    amount: float = Field(..., gt=0)
    note: str | None = Field(default=None, max_length=200)


def _require_user(x_user_id: str | None) -> str:
    if not x_user_id or not x_user_id.strip():
        raise HTTPException(status_code=401, detail="Missing X-User-Id header")
    return x_user_id.strip()


def _ensure_account_owner(cur, account_id: str, user_id: str):
    cur.execute(
        "SELECT account_id, user_id, currency, balance, status FROM accounts WHERE account_id = ?",
        (account_id,),
    )
    row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Account not found")
    if row["user_id"] != user_id:
        raise HTTPException(status_code=403, detail="Forbidden by object-level authorization")
    return row


@router.get("/accounts", summary="列出使用者可存取帳戶")
async def list_accounts(
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
):
    user_id = _require_user(x_user_id)
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT account_id, currency, balance, status, created_at FROM accounts WHERE user_id = ? ORDER BY account_id",
        (user_id,),
    )
    items = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {"user_id": user_id, "accounts": items}


@router.get("/accounts/{account_id}/balance", summary="查詢帳戶餘額（含 BOLA 檢查）")
async def get_balance(
    account_id: str,
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
):
    user_id = _require_user(x_user_id)
    conn = get_connection()
    cur = conn.cursor()
    row = _ensure_account_owner(cur, account_id, user_id)
    conn.close()
    return {
        "account_id": row["account_id"],
        "currency": row["currency"],
        "balance": round(float(row["balance"]), 2),
        "status": row["status"],
    }


@router.get("/accounts/{account_id}/transactions", summary="查詢帳戶交易明細")
async def get_transactions(
    account_id: str,
    limit: int = Query(20, ge=1, le=100),
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
):
    user_id = _require_user(x_user_id)
    conn = get_connection()
    cur = conn.cursor()
    _ensure_account_owner(cur, account_id, user_id)

    cur.execute(
        """
        SELECT tx_id, from_account, to_account, amount, currency, fee, status, created_at, note
        FROM transactions
        WHERE from_account = ? OR to_account = ?
        ORDER BY created_at DESC
        LIMIT ?
        """,
        (account_id, account_id, limit),
    )
    items = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {"account_id": account_id, "transactions": items}


@router.get("/beneficiaries", summary="查詢受款人")
async def list_beneficiaries(
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
):
    user_id = _require_user(x_user_id)
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, nickname, bank_code, account_id, created_at FROM beneficiaries WHERE user_id = ? ORDER BY id DESC",
        (user_id,),
    )
    items = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {"user_id": user_id, "beneficiaries": items}


@router.post("/beneficiaries", summary="新增受款人")
async def create_beneficiary(
    req: BeneficiaryCreateRequest,
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
):
    user_id = _require_user(x_user_id)
    conn = get_connection()
    cur = conn.cursor()
    now = datetime.utcnow().isoformat(timespec="seconds")
    cur.execute(
        "INSERT INTO beneficiaries(user_id, nickname, bank_code, account_id, created_at) VALUES (?, ?, ?, ?, ?)",
        (user_id, req.nickname, req.bank_code, req.account_id, now),
    )
    conn.commit()
    created_id = cur.lastrowid
    conn.close()
    return {"status": "created", "beneficiary_id": created_id}


@router.post("/transfers", summary="轉帳（含冪等鍵與 BOLA）")
async def transfer_money(
    req: TransferRequest,
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
):
    user_id = _require_user(x_user_id)
    if not idempotency_key or not idempotency_key.strip():
        raise HTTPException(status_code=400, detail="Missing Idempotency-Key header")

    conn = get_connection()
    cur = conn.cursor()

    # 冪等：同 user + key 若已存在，直接回傳既有交易
    cur.execute(
        "SELECT tx_id FROM transfer_idempotency WHERE user_id = ? AND idempotency_key = ?",
        (user_id, idempotency_key.strip()),
    )
    idem_row = cur.fetchone()
    if idem_row:
        cur.execute(
            "SELECT tx_id, from_account, to_account, amount, currency, fee, status, created_at, note FROM transactions WHERE tx_id = ?",
            (idem_row["tx_id"],),
        )
        tx = cur.fetchone()
        conn.close()
        return {"status": "already_processed", "transaction": dict(tx) if tx else {"tx_id": idem_row["tx_id"]}}

    from_account = _ensure_account_owner(cur, req.from_account, user_id)

    cur.execute(
        "SELECT account_id, status, currency FROM accounts WHERE account_id = ?",
        (req.to_account,),
    )
    to_account = cur.fetchone()
    if not to_account:
        conn.close()
        raise HTTPException(status_code=404, detail="Destination account not found")
    if to_account["status"] != "ACTIVE":
        conn.close()
        raise HTTPException(status_code=400, detail="Destination account is not active")

    if from_account["status"] != "ACTIVE":
        conn.close()
        raise HTTPException(status_code=400, detail="Source account is not active")

    if from_account["currency"] != to_account["currency"]:
        conn.close()
        raise HTTPException(status_code=400, detail="Currency mismatch")

    fee = 15.0 if req.amount >= 10000 else 5.0
    total_debit = req.amount + fee
    if float(from_account["balance"]) < total_debit:
        conn.close()
        raise HTTPException(status_code=400, detail="Insufficient balance")

    tx_id = f"TX-{uuid.uuid4().hex[:12].upper()}"
    now = datetime.utcnow().isoformat(timespec="seconds")

    cur.execute("UPDATE accounts SET balance = balance - ? WHERE account_id = ?", (total_debit, req.from_account))
    cur.execute("UPDATE accounts SET balance = balance + ? WHERE account_id = ?", (req.amount, req.to_account))
    cur.execute(
        """
        INSERT INTO transactions(tx_id, from_account, to_account, amount, currency, fee, status, created_at, idempotency_key, note)
        VALUES (?, ?, ?, ?, ?, ?, 'SUCCESS', ?, ?, ?)
        """,
        (tx_id, req.from_account, req.to_account, req.amount, from_account["currency"], fee, now, idempotency_key.strip(), req.note),
    )
    cur.execute(
        "INSERT INTO transfer_idempotency(user_id, idempotency_key, tx_id, created_at) VALUES (?, ?, ?, ?)",
        (user_id, idempotency_key.strip(), tx_id, now),
    )

    conn.commit()

    cur.execute("SELECT balance FROM accounts WHERE account_id = ?", (req.from_account,))
    new_balance = float(cur.fetchone()["balance"])
    conn.close()

    return {
        "status": "success",
        "transaction": {
            "tx_id": tx_id,
            "from_account": req.from_account,
            "to_account": req.to_account,
            "amount": req.amount,
            "fee": fee,
            "currency": from_account["currency"],
            "created_at": now,
        },
        "source_account_after_balance": round(new_balance, 2),
    }
