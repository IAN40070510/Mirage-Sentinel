import os
import re
import uuid
import logging
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, BackgroundTasks, Header, HTTPException, Request
from pydantic import BaseModel, Field

from core.api_mirage import harden_deception_response
from core.mirage import advance_deceptive_login_flow, start_deceptive_login_flow
from core.sentinel import analyze_intent
from core.traffic_db import log_traffic_event
from api.db.operations import DBOperations
from api.db.session import is_real_db_enabled

router = APIRouter(prefix="/banking", tags=["Banking API"])
logger = logging.getLogger(__name__)

VULN_BANK_BASE_URL = os.getenv("VULN_BANK_BASE_URL", "http://127.0.0.1:5000").rstrip(
    "/"
)
VULN_BANK_USERNAME = os.getenv("VULN_BANK_USERNAME", "admin")
VULN_BANK_PASSWORD = os.getenv("VULN_BANK_PASSWORD", "admin123")
TIMEOUT_SECONDS = float(os.getenv("VULN_BANK_TIMEOUT", "10"))

_USER_TO_ACCOUNT: dict[str, str] = {}


class CreateBeneficiaryRequest(BaseModel):
    nickname: str = Field(min_length=1, max_length=80)
    bank_code: str = Field(min_length=3, max_length=10)
    account_id: str = Field(min_length=6, max_length=40)


class TransferRequest(BaseModel):
    from_account: str = Field(min_length=6, max_length=40)
    to_account: str = Field(min_length=6, max_length=40)
    amount: int = Field(gt=0)
    currency: str = Field(default="TWD", min_length=3, max_length=3)
    note: str | None = Field(default=None, max_length=200)


class DeceptiveLoginStartRequest(BaseModel):
    username: str | None = Field(default=None, min_length=3, max_length=64)
    device_id: str | None = Field(default=None, min_length=3, max_length=128)


class DeceptiveLoginVerifyRequest(BaseModel):
    password: str | None = Field(default=None, max_length=128)
    otp: str | None = Field(default=None, max_length=12)
    security_answer: str | None = Field(default=None, max_length=120)
    device_fingerprint: str | None = Field(default=None, max_length=256)


class _VulnBankError(RuntimeError):
    pass


def _fallback_account(account_id: str = "VB-UNKNOWN") -> dict:
    return {
        "account_id": account_id,
        "customer_name": "vuln-bank-offline",
        "account_display": f"{account_id}(fallback)",
        "currency": "USD",
        "balance": 0,
        "status": "DEGRADED",
        "created_at": _now_ms_iso(),
    }


def _now_ms_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _is_suspicious(user_agent: str, payload: str, risk_score: int) -> bool:
    ua = (user_agent or "").lower()
    text = (payload or "").lower()
    tokens = ("sqlmap", "curl", "python-requests", "scanner", "bot", "nmap")
    if risk_score >= 60:
        return True
    if any(t in ua for t in tokens):
        return True
    return any(
        t in text for t in ("' or '1'='1", "union select", "../", "openapi", "swagger")
    )


def _is_unauthorized(user_id: str | None) -> bool:
    raw = (user_id or "").strip()
    return not re.fullmatch(r"CIF\d{9}", raw)


def _resolve_user_id(user_id: str | None) -> str:
    raw = (user_id or "").strip()
    return raw or "CIF000001001"


def _request_payload(request: Request, extra: str = "") -> str:
    base_payload = f"path={request.url.path};query={request.url.query}"
    if extra:
        return f"{base_payload};{extra}"
    return base_payload


def _request_risk(request: Request, payload: str) -> tuple[bool, int, str, str]:
    is_attack, confidence, attack_vector = analyze_intent(payload)
    risk_score = int(confidence * 100) if is_attack else 0
    user_agent = request.headers.get("user-agent", "Unknown")
    return is_attack, risk_score, attack_vector, user_agent


def _should_divert_to_sandbox(user_agent: str, payload: str, risk_score: int) -> bool:
    return _is_suspicious(user_agent, payload, risk_score)


async def _maybe_divert_to_sandbox_response(
    request: Request,
    background_tasks: BackgroundTasks,
    x_user_id: str | None,
    source_endpoint: str,
    payload: str,
    sandbox_builder,
) -> dict | None:
    _is_attack, risk_score, attack_vector, user_agent = _request_risk(request, payload)

    if not _should_divert_to_sandbox(user_agent, payload, risk_score):
        return None

    sandbox_response = await sandbox_builder()
    hardened = await harden_deception_response(
        sandbox_response,
        user_agent=user_agent,
        raw_payload=payload,
        risk_score=max(risk_score, 72),
        deception_reason=attack_vector or "suspicious_bank_activity",
    )

    user_ref = _resolve_user_id(x_user_id)
    background_tasks.add_task(
        log_traffic_event,
        {
            "request_at": _now_ms_iso(),
            "response_at": _now_ms_iso(),
            "process_ms": 0,
            "client_ip": _client_ip(request),
            "location": f"banking:{source_endpoint}:sandbox_diversion",
            "is_proxy": bool(request.headers.get("x-forwarded-for")),
            "user_agent": user_agent,
            "tls_fingerprint": request.headers.get("x-tls-fingerprint", "N/A"),
            "query_id": user_ref,
            "is_attack": 1,
            "raw_payload": payload,
            "response_payload": hardened,
            "attack_vector": attack_vector or "suspicious_bank_activity",
            "risk_level": max(risk_score, 72),
            "hits": 1,
            "interaction_depth": 1,
            "dwell_time": 0.0,
            "mitigation_status": "sandbox_diversion",
        },
    )
    return hardened


async def _maybe_divert_to_deception_auth(
    request: Request,
    background_tasks: BackgroundTasks,
    x_user_id: str | None,
    source_endpoint: str,
) -> dict | None:
    payload = f"path={request.url.path};query={request.url.query}"
    is_attack, confidence, attack_vector = analyze_intent(payload)
    risk_score = int(confidence * 100) if is_attack else 0
    user_agent = request.headers.get("user-agent", "Unknown")

    if not _is_unauthorized(x_user_id):
        return None

    if not _is_suspicious(user_agent, payload, risk_score):
        return None

    user_ref = (x_user_id or "").strip() or f"anonymous:{_client_ip(request)}"
    challenge = start_deceptive_login_flow(
        client_ip=_client_ip(request),
        user_ref=user_ref,
        reason=f"auto_divert:{source_endpoint}:{attack_vector or 'suspicious'}",
    )
    challenge["source_endpoint"] = source_endpoint

    hardened = await harden_deception_response(
        challenge,
        user_agent=user_agent,
        raw_payload=payload,
        risk_score=max(risk_score, 72),
        deception_reason=attack_vector or "suspicious_unauthorized",
    )

    background_tasks.add_task(
        log_traffic_event,
        {
            "request_at": _now_ms_iso(),
            "response_at": _now_ms_iso(),
            "process_ms": 0,
            "client_ip": _client_ip(request),
            "location": f"banking:{source_endpoint}:auto_deceptive_auth",
            "is_proxy": bool(request.headers.get("x-forwarded-for")),
            "user_agent": user_agent,
            "tls_fingerprint": request.headers.get("x-tls-fingerprint", "N/A"),
            "query_id": user_ref,
            "is_attack": 1,
            "raw_payload": payload,
            "response_payload": hardened,
            "attack_vector": "deception_auth",
            "risk_level": max(risk_score, 72),
            "hits": 1,
            "interaction_depth": 1,
            "dwell_time": 0.0,
            "mitigation_status": "deception_auth",
        },
    )
    return hardened


async def _vuln_bank_login() -> tuple[str, str]:
    async with httpx.AsyncClient(timeout=TIMEOUT_SECONDS) as client:
        response = await client.post(
            f"{VULN_BANK_BASE_URL}/login",
            json={"username": VULN_BANK_USERNAME, "password": VULN_BANK_PASSWORD},
        )

    if response.status_code != 200:
        raise _VulnBankError(f"vuln-bank login failed: {response.status_code}")

    data = response.json()
    token = data.get("token")
    account_number = data.get("accountNumber")
    if not token or not account_number:
        raise _VulnBankError("vuln-bank login response missing token/accountNumber")
    return token, account_number


async def _vuln_bank_get(path: str, token: str | None = None) -> dict:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    async with httpx.AsyncClient(timeout=TIMEOUT_SECONDS) as client:
        response = await client.get(f"{VULN_BANK_BASE_URL}{path}", headers=headers)
    if response.status_code >= 400:
        raise _VulnBankError(f"vuln-bank GET {path} failed: {response.status_code}")
    return response.json()


async def _vuln_bank_post(path: str, body: dict, token: str | None = None) -> dict:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    async with httpx.AsyncClient(timeout=TIMEOUT_SECONDS) as client:
        response = await client.post(
            f"{VULN_BANK_BASE_URL}{path}", json=body, headers=headers
        )
    if response.status_code >= 400:
        raise _VulnBankError(f"vuln-bank POST {path} failed: {response.status_code}")
    return response.json()


async def _deception_accounts_response() -> dict:
    try:
        token, account_number = await _vuln_bank_login()
        balance_res = await _vuln_bank_get(f"/check_balance/{account_number}")
        return {
            "user_id": VULN_BANK_USERNAME,
            "accounts": [
                {
                    "account_id": account_number,
                    "customer_name": balance_res.get("username", "vuln-bank-user"),
                    "account_display": f"{account_number}(vuln-bank)",
                    "currency": "USD",
                    "balance": int(float(balance_res.get("balance", 0))),
                    "status": "ACTIVE",
                    "created_at": _now_ms_iso(),
                }
            ],
            "notice": "(sandbox illusion: vuln-bank target)",
            "target": "Commando-X/vuln-bank",
            "token_preview": token[:16],
        }
    except _VulnBankError as exc:
        fallback = _fallback_account()
        return {
            "user_id": VULN_BANK_USERNAME,
            "accounts": [fallback],
            "notice": f"(sandbox illusion unavailable fallback: {exc})",
            "target": "Commando-X/vuln-bank",
        }


async def _deception_balance_response(account_id: str) -> dict:
    try:
        data = await _vuln_bank_get(f"/check_balance/{account_id}")
        return {
            "account_id": account_id,
            "customer_name": data.get("username", "vuln-bank-user"),
            "account_display": f"{account_id}(vuln-bank)",
            "currency": "USD",
            "balance": int(float(data.get("balance", 0))),
            "status": "ACTIVE",
            "notice": "(sandbox illusion: vuln-bank target)",
        }
    except _VulnBankError as exc:
        fallback = _fallback_account(account_id)
        fallback["notice"] = f"(sandbox illusion unavailable fallback: {exc})"
        return fallback


async def _deception_transactions_response(account_id: str) -> dict:
    try:
        data = await _vuln_bank_get(f"/transactions/{account_id}")
        txs = []
        for row in data.get("transactions", []):
            txs.append(
                {
                    "tx_id": f"VB-{row.get('id')}",
                    "from_account": row.get("from_account", ""),
                    "from_account_display": f"{row.get('from_account', '')}(vuln-bank)",
                    "from_customer_name": "vuln-bank-user",
                    "to_account": row.get("to_account", ""),
                    "to_account_display": f"{row.get('to_account', '')}(vuln-bank)",
                    "to_customer_name": "vuln-bank-user",
                    "amount": int(float(row.get("amount", 0))),
                    "currency": "USD",
                    "fee": 0,
                    "status": "success",
                    "created_at": row.get("timestamp", _now_ms_iso()),
                    "note": row.get("description"),
                }
            )
        return {
            "account_id": account_id,
            "customer_name": "vuln-bank-user",
            "account_display": f"{account_id}(vuln-bank)",
            "transactions": txs,
            "notice": "(sandbox illusion: vuln-bank target)",
        }
    except _VulnBankError as exc:
        return {
            "account_id": account_id,
            "customer_name": "vuln-bank-offline",
            "account_display": f"{account_id}(fallback)",
            "transactions": [],
            "notice": f"(sandbox illusion unavailable fallback: {exc})",
        }


async def _deception_beneficiaries_response(user_id: str) -> dict:
    return {
        "user_id": user_id,
        "beneficiaries": [
            {
                "id": 1,
                "user_id": user_id,
                "nickname": "vuln-target",
                "bank_code": "VBK",
                "account_id": "0000000000",
                "beneficiary_name": "Commando-X vuln-bank",
                "account_display": "0000000000(vuln-bank)",
                "created_at": _now_ms_iso(),
            }
        ],
        "notice": "(sandbox illusion: vuln-bank target)",
    }


async def _deception_create_beneficiary_response(
    user_id: str, req: CreateBeneficiaryRequest
) -> dict:
    fake_id = int(uuid.uuid4().int % 100000)
    return {
        "status": "created",
        "beneficiary_id": fake_id,
        "account_id": req.account_id,
        "beneficiary_name": req.nickname,
        "account_display": f"{req.account_id}(vuln-bank)",
        "notice": f"(sandbox illusion: vuln-bank target; user={user_id})",
    }


async def _deception_transfer_response(user_id: str, req: TransferRequest) -> dict:
    try:
        token, account_number = await _vuln_bank_login()
        res = await _vuln_bank_post(
            "/transfer",
            {
                "to_account": req.to_account,
                "amount": req.amount,
                "description": req.note or "Mirage transfer",
            },
            token=token,
        )

        return {
            "status": (
                "completed" if res.get("status") == "success" else "queued_review"
            ),
            "transaction": {
                "tx_id": f"VB-{uuid.uuid4().hex[:12].upper()}",
                "from_account": account_number,
                "from_account_display": f"{account_number}(vuln-bank)",
                "from_customer_name": VULN_BANK_USERNAME,
                "to_account": req.to_account,
                "to_account_display": f"{req.to_account}(vuln-bank)",
                "to_customer_name": "vuln-bank-user",
                "amount": req.amount,
                "fee": 0,
                "currency": req.currency,
                "created_at": _now_ms_iso(),
                "note": req.note,
            },
            "source_account_after_balance": int(float(res.get("new_balance", 0))),
            "source_account_display": f"{account_number}(vuln-bank)",
            "source_customer_name": VULN_BANK_USERNAME,
            "destination_customer_name": "vuln-bank-user",
            "notice": "(sandbox illusion: vuln-bank target)",
            "upstream": res,
        }
    except _VulnBankError as exc:
        return {
            "status": "queued_review",
            "transaction": {
                "tx_id": f"FB-{uuid.uuid4().hex[:12].upper()}",
                "from_account": req.from_account,
                "from_account_display": f"{req.from_account}(fallback)",
                "from_customer_name": "vuln-bank-offline",
                "to_account": req.to_account,
                "to_account_display": f"{req.to_account}(fallback)",
                "to_customer_name": "vuln-bank-offline",
                "amount": req.amount,
                "fee": 0,
                "currency": req.currency,
                "created_at": _now_ms_iso(),
                "note": req.note,
            },
            "source_account_after_balance": 0,
            "source_account_display": f"{req.from_account}(fallback)",
            "source_customer_name": "vuln-bank-offline",
            "destination_customer_name": "vuln-bank-offline",
            "notice": f"(sandbox illusion unavailable fallback: {exc})",
        }


def _real_accounts_response(user_id: str) -> dict | None:
    seeded = DBOperations.ensure_user_account(user_id)
    accounts = DBOperations.get_user_accounts(user_id)
    if accounts is None:
        return None
    if not accounts and seeded:
        accounts = [
            {
                "account_id": seeded["account_id"],
                "customer_name": DBOperations.get_account_customer_name(
                    seeded["account_id"]
                ),
                "account_type": "Checking",
                "currency": seeded.get("currency", "TWD"),
                "balance": int(seeded.get("balance", 0)),
                "status": seeded.get("status", "ACTIVE"),
                "open_date": seeded.get("open_date"),
                "created_at": _now_ms_iso(),
            }
        ]
    return {
        "user_id": user_id,
        "accounts": accounts,
        "notice": "(real banking target)",
        "target": "Mirage-Sentinel banking DB",
    }


def _real_balance_response(account_id: str, user_id: str) -> dict | None:
    if not DBOperations.account_belongs_to_user(account_id, user_id):
        return None

    data = DBOperations.get_account_balance(account_id, user_id)
    if not data:
        return None

    data["notice"] = "(real banking target)"
    data["target"] = "Mirage-Sentinel banking DB"
    return data


def _real_transactions_response(account_id: str, user_id: str) -> dict | None:
    if not DBOperations.account_belongs_to_user(account_id, user_id):
        return None

    txs = DBOperations.get_account_transactions(account_id, user_id)
    if txs is None:
        return None

    return {
        "account_id": account_id,
        "customer_name": DBOperations.get_account_customer_name(account_id),
        "account_display": f"{account_id}(real)",
        "transactions": txs,
        "notice": "(real banking target)",
        "target": "Mirage-Sentinel banking DB",
    }


def _real_beneficiaries_response(user_id: str) -> dict | None:
    beneficiaries = DBOperations.get_user_beneficiaries(user_id)
    if beneficiaries is None:
        return None

    return {
        "user_id": user_id,
        "beneficiaries": beneficiaries,
        "notice": "(real banking target)",
        "target": "Mirage-Sentinel banking DB",
    }


def _real_create_beneficiary_response(
    user_id: str, req: CreateBeneficiaryRequest
) -> dict | None:
    created = DBOperations.create_beneficiary(
        user_id=user_id,
        nickname=req.nickname,
        bank_code=req.bank_code,
        account_id=req.account_id,
        beneficiary_name=req.nickname,
    )
    if not created:
        return None

    created["notice"] = "(real banking target)"
    created["target"] = "Mirage-Sentinel banking DB"
    return created


def _real_transfer_response(user_id: str, req: TransferRequest) -> dict | None:
    transferred = DBOperations.transfer_money(
        user_id=user_id,
        from_account=req.from_account,
        to_account=req.to_account,
        amount=req.amount,
        fee=0,
        note=req.note or "Mirage transfer",
    )
    if not transferred:
        return None

    return {
        "status": "completed",
        "transaction": {
            "tx_id": transferred["tx_id"],
            "from_account": transferred["from_account"],
            "from_account_display": f"{transferred['from_account']}(real)",
            "from_customer_name": transferred.get("from_customer_name", "Unknown"),
            "to_account": transferred["to_account"],
            "to_account_display": f"{transferred['to_account']}(real)",
            "to_customer_name": transferred.get("to_customer_name", "Unknown"),
            "amount": transferred["amount"],
            "fee": transferred["fee"],
            "currency": transferred["currency"],
            "created_at": transferred["created_at"],
            "note": req.note,
        },
        "source_account_after_balance": transferred["new_balance"],
        "source_account_display": f"{transferred['from_account']}(real)",
        "source_customer_name": transferred.get("from_customer_name", "Unknown"),
        "destination_customer_name": transferred.get("to_customer_name", "Unknown"),
        "notice": "(real banking target)",
        "target": "Mirage-Sentinel banking DB",
    }


@router.post("/auth/login")
async def start_deceptive_login(
    request: Request,
    background_tasks: BackgroundTasks,
    req: DeceptiveLoginStartRequest,
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
):
    user_ref = (
        (x_user_id or "").strip() or req.username or f"anonymous:{_client_ip(request)}"
    )
    challenge = start_deceptive_login_flow(
        client_ip=_client_ip(request),
        user_ref=user_ref,
        reason="manual_start",
    )
    return await harden_deception_response(
        challenge,
        user_agent=request.headers.get("user-agent", "Unknown"),
        raw_payload=f"path={request.url.path};query={request.url.query}",
        risk_score=72,
        deception_reason="deception_auth_manual_start",
    )


@router.post("/auth/login/{flow_id}/verify")
async def verify_deceptive_login(
    flow_id: str,
    req: DeceptiveLoginVerifyRequest,
    request: Request,
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
):
    user_ref = (x_user_id or "").strip() or f"anonymous:{_client_ip(request)}"
    payload = advance_deceptive_login_flow(
        client_ip=_client_ip(request),
        flow_id=flow_id,
        user_ref=user_ref,
        reason="manual_verify",
        password=req.password,
        otp=req.otp,
        security_answer=req.security_answer,
    )
    return await harden_deception_response(
        payload,
        user_agent=request.headers.get("user-agent", "Unknown"),
        raw_payload=f"path={request.url.path};query={request.url.query}",
        risk_score=74,
        deception_reason="deception_auth_verify",
    )


@router.get("/accounts")
async def list_accounts(
    request: Request,
    background_tasks: BackgroundTasks,
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
):
    try:
        user_id = _resolve_user_id(x_user_id)
        diverted = await _maybe_divert_to_sandbox_response(
            request,
            background_tasks,
            x_user_id,
            "accounts",
            _request_payload(request, f"user_id={user_id}"),
            lambda: _deception_accounts_response(),
        )
        if diverted is not None:
            return diverted

        try:
            real_response = _real_accounts_response(user_id)
        except Exception as exc:
            logger.exception("Real banking accounts query failed: %s", exc)
            if is_real_db_enabled():
                raise HTTPException(
                    status_code=503,
                    detail="Real banking database is temporarily unavailable",
                )
            real_response = None

        if real_response is not None:
            return real_response

        if is_real_db_enabled():
            raise HTTPException(
                status_code=503,
                detail="Real banking database is temporarily unavailable",
            )

        return await _deception_accounts_response()
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Unhandled error in /banking/accounts: %s", exc)
        raise HTTPException(
            status_code=503,
            detail="Banking service is temporarily unavailable",
        )


@router.get("/accounts/{account_id}/balance")
async def get_balance(
    account_id: str,
    request: Request,
    background_tasks: BackgroundTasks,
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
):
    user_id = _resolve_user_id(x_user_id)
    diverted = await _maybe_divert_to_sandbox_response(
        request,
        background_tasks,
        x_user_id,
        "balance",
        _request_payload(request, f"account_id={account_id};user_id={user_id}"),
        lambda: _deception_balance_response(account_id),
    )
    if diverted is not None:
        return diverted

    real_response = _real_balance_response(account_id, user_id)
    if real_response is not None:
        return real_response

    if is_real_db_enabled():
        raise HTTPException(status_code=404, detail="Account not found")

    return await _deception_balance_response(account_id)


@router.get("/accounts/{account_id}/transactions")
async def get_transactions(
    account_id: str,
    request: Request,
    background_tasks: BackgroundTasks,
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
):
    user_id = _resolve_user_id(x_user_id)
    diverted = await _maybe_divert_to_sandbox_response(
        request,
        background_tasks,
        x_user_id,
        "transactions",
        _request_payload(request, f"account_id={account_id};user_id={user_id}"),
        lambda: _deception_transactions_response(account_id),
    )
    if diverted is not None:
        return diverted

    real_response = _real_transactions_response(account_id, user_id)
    if real_response is not None:
        return real_response

    if is_real_db_enabled():
        raise HTTPException(status_code=404, detail="Account not found")

    return await _deception_transactions_response(account_id)


@router.get("/beneficiaries")
async def list_beneficiaries(
    request: Request,
    background_tasks: BackgroundTasks,
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
):
    user_id = _resolve_user_id(x_user_id)
    diverted = await _maybe_divert_to_sandbox_response(
        request,
        background_tasks,
        x_user_id,
        "beneficiaries",
        _request_payload(request, f"user_id={user_id}"),
        lambda: _deception_beneficiaries_response(user_id),
    )
    if diverted is not None:
        return diverted

    real_response = _real_beneficiaries_response(user_id)
    if real_response is not None:
        return real_response

    if is_real_db_enabled():
        raise HTTPException(
            status_code=500, detail="Real banking database is unavailable"
        )

    return await _deception_beneficiaries_response(user_id)


@router.post("/beneficiaries")
async def create_beneficiary(
    request: Request,
    background_tasks: BackgroundTasks,
    req: CreateBeneficiaryRequest,
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
):
    user_id = _resolve_user_id(x_user_id)
    diverted = await _maybe_divert_to_sandbox_response(
        request,
        background_tasks,
        x_user_id,
        "beneficiaries_create",
        _request_payload(
            request,
            f"user_id={user_id};nickname={req.nickname};bank_code={req.bank_code};account_id={req.account_id}",
        ),
        lambda: _deception_create_beneficiary_response(user_id, req),
    )
    if diverted is not None:
        return diverted

    real_response = _real_create_beneficiary_response(user_id, req)
    if real_response is not None:
        return real_response

    if is_real_db_enabled():
        raise HTTPException(
            status_code=409, detail="Beneficiary already exists or cannot be created"
        )

    return await _deception_create_beneficiary_response(user_id, req)


@router.post("/transfers")
async def transfer(
    request: Request,
    background_tasks: BackgroundTasks,
    req: TransferRequest,
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
):
    user_id = _resolve_user_id(x_user_id)
    diverted = await _maybe_divert_to_sandbox_response(
        request,
        background_tasks,
        x_user_id,
        "transfer",
        _request_payload(
            request,
            (
                f"user_id={user_id};from_account={req.from_account};"
                f"to_account={req.to_account};amount={req.amount};currency={req.currency}"
            ),
        ),
        lambda: _deception_transfer_response(user_id, req),
    )
    if diverted is not None:
        return diverted

    real_response = _real_transfer_response(user_id, req)
    if real_response is not None:
        return real_response

    if is_real_db_enabled():
        raise HTTPException(status_code=400, detail="Transfer could not be completed")

    return await _deception_transfer_response(user_id, req)
