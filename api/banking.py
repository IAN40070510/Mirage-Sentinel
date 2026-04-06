import uuid
import re
from datetime import datetime
from typing import Union

from fastapi import (
    APIRouter,
    Header,
    HTTPException,
    Path,
    Query,
    Request,
    BackgroundTasks,
)
from pydantic import BaseModel, Field

from .db.session import ensure_real_db_enabled, is_real_db_enabled
from .db.operations import DBOperations
from core.traffic_db import log_traffic_event
from core.sentinel import (
    analyze_intent,
    detect_replication_risk,
    detect_rate_limiting_risk,
    detect_anomalous_amount_risk,
)
from core.mirage import start_deceptive_login_flow, advance_deceptive_login_flow
from core.api_mirage import harden_deception_response
from model.llama import generate_fake_data_llama


USER_ID_HEADER_DESCRIPTION = (
    "使用者識別碼 Header，格式為 `X-User-Id: CIF*********`；實際值為 `CIF` + 9 碼數字。"
)
ACCOUNT_ID_DESCRIPTION = (
    "帳戶識別碼，格式為英數字 12-20 碼；常見範例：`ACCOD48PUCAEHKH`。"
)
LIMIT_DESCRIPTION = "查詢筆數上限，整數 1-100。"
IDEMPOTENCY_KEY_DESCRIPTION = (
    "冪等鍵 Header，用於避免重複轉帳；建議使用唯一字串，格式不限。"
)
NICKNAME_DESCRIPTION = "受款人暱稱，1-80 字元。"
BANK_CODE_DESCRIPTION = "銀行代碼，3-10 字元。"
AMOUNT_DESCRIPTION = "轉帳金額，必須大於 0。"
NOTE_DESCRIPTION = "備註，最多 200 字元，可不填。"
ACTOR_ROLE_DESCRIPTION = "呼叫者角色；可用值：customer、admin、soc。"


# Response Models
class Account(BaseModel):
    account_id: str
    customer_name: str
    account_display: str
    currency: str
    balance: int
    status: str
    created_at: str


class ListAccountsResponse(BaseModel):
    user_id: str
    accounts: list[Account]
    notice: str


class BalanceResponse(BaseModel):
    account_id: str
    customer_name: str
    account_display: str
    currency: str
    balance: int
    status: str
    notice: str


class Transaction(BaseModel):
    tx_id: str
    from_account: str
    from_account_display: str
    from_customer_name: str
    to_account: str
    to_account_display: str
    to_customer_name: str
    amount: int
    currency: str
    fee: int
    status: str
    created_at: str
    note: str | None = None


class ListTransactionsResponse(BaseModel):
    account_id: str
    customer_name: str
    account_display: str
    transactions: list[Transaction]
    notice: str


class Beneficiary(BaseModel):
    id: int
    user_id: str
    nickname: str
    bank_code: str
    account_id: str
    beneficiary_name: str
    account_display: str
    created_at: str


class ListBeneficiariesResponse(BaseModel):
    user_id: str
    beneficiaries: list[Beneficiary]
    notice: str


class CreateBeneficiaryResponse(BaseModel):
    status: str
    beneficiary_id: int
    account_id: str
    beneficiary_name: str
    account_display: str
    notice: str


class TransferTransaction(BaseModel):
    tx_id: str
    from_account: str
    from_account_display: str
    from_customer_name: str
    to_account: str
    to_account_display: str
    to_customer_name: str
    amount: int
    fee: int
    currency: str
    created_at: str
    note: str | None = None


class TransferResponse(BaseModel):
    status: str
    transaction: TransferTransaction
    source_account_after_balance: int
    source_account_display: str
    source_customer_name: str
    destination_customer_name: str
    notice: str


class ErrorResponse(BaseModel):
    detail: str


class DeceptionMeta(BaseModel):
    strategy: str
    issued_at: str
    risk_score: int
    reason: str | None = None


class ConsistencyHint(BaseModel):
    trace_id: str
    reconcile_step: str
    checkpoint_at: str


class DeceptionErrorContext(BaseModel):
    code: str
    message: str
    llm_guardrail: str


class DeceptiveAuthChallengeResponse(BaseModel):
    status: str
    route: str
    auth_flow_id: str
    user_ref: str
    stage: str
    challenge_hint: str
    issued_at: str
    expires_at: str
    notice: str
    next_action: str | None = None
    otp_delivery: str | None = None
    masked_contact: str | None = None
    review_eta_sec: int | None = None
    source_endpoint: str | None = None
    deception_meta: DeceptionMeta | None = None
    consistency_hints: list[ConsistencyHint] | None = None
    error_context: DeceptionErrorContext | None = None


class DeceptiveLoginStartRequest(BaseModel):
    username: str | None = Field(
        default=None, min_length=3, max_length=64, description="登入識別值（可選）。"
    )
    device_id: str | None = Field(
        default=None, min_length=6, max_length=128, description="裝置識別碼（可選）。"
    )


class DeceptiveLoginVerifyRequest(BaseModel):
    password: str | None = Field(default=None, max_length=128)
    otp: str | None = Field(default=None, max_length=12)
    security_answer: str | None = Field(default=None, max_length=120)
    device_fingerprint: str | None = Field(default=None, max_length=256)


router = APIRouter(
    prefix="/banking",
    tags=["Banking API"],
    responses={
        503: {
            "description": "PostgreSQL unavailable or DATABASE_URL not configured",
            "model": ErrorResponse,
        }
    },
)

BANKING_API_NOTE = """銀行 API（PostgreSQL 強制模式）。

模式說明：
- 必須設定且可連線 DATABASE_URL，否則 API 直接回應 503

回應辨識：
- notice = (真實資訊)

欄位格式：
- user_id / X-User-Id：`CIF` + 9 碼數字；Header 範例：`X-User-Id: CIF*********`
- user_id 遮罩範例：`CIF*********`
- account_id：英數字 12-20 碼（例：`ACCOD48PUCAEHKH`）
- account_id 遮罩範例：`ACC**********KH`
- tx_id：交易編號，前綴 `TX-` 或 `TXN`
- currency：ISO 4217 三碼（例：`TWD`）
"""

router.description = BANKING_API_NOTE


# 純 Demo：不接真實 DB，直接使用寫死樣本（取自 archive.zip 欄位風格）
DEMO_USER_ID = "CIF000001001"
DEMO_ACCOUNT_ID = "ACCOD48PUCAEHKH"
DEMO_CUSTOMER_NAME = "王小明"
DEMO_BENEFICIARY_NAME = "林雅婷"

DEMO_ACCOUNTS = {
    DEMO_ACCOUNT_ID: {
        "account_id": DEMO_ACCOUNT_ID,
        "customer_id": "CUSAEOACKBH8CK6",
        "account_type": "Checking",
        "currency": "TWD",
        "balance": 5680000,
        "status": "ACTIVE",
        "open_date": "2021-03-27",
    }
}

DEMO_TRANSACTIONS = [
    {
        "tx_id": "TXN6JW4K0DRNH1YK8",
        "from_account": DEMO_ACCOUNT_ID,
        "to_account": "MERNGTU3WAVTQJF",
        "amount": 2981.61,
        "currency": "TWD",
        "fee": 0,
        "status": "SUCCESS",
        "created_at": "2019-07-06 16:17:06",
        "note": "POS purchase",
    },
    {
        "tx_id": "TXNCGTY5YKKMYWQQR",
        "from_account": DEMO_ACCOUNT_ID,
        "to_account": "MERZI1ODLZ6LPJO",
        "amount": 7833.28,
        "currency": "TWD",
        "fee": 0,
        "status": "SUCCESS",
        "created_at": "2024-06-10 04:08:36",
        "note": "Wire transfer",
    },
]

DEMO_BENEFICIARIES = [
    {
        "id": 1,
        "user_id": DEMO_USER_ID,
        "nickname": "Primary Merchant",
        "bank_code": "812",
        "account_id": "MERNGTU3WAVTQJF",
        "beneficiary_name": "林雅婷",
        "created_at": "2024-01-02T10:00:00",
    }
]

DEMO_IDEMPOTENCY: dict[tuple[str, str], dict] = {}


def _now_ms_iso() -> str:
    return datetime.utcnow().isoformat(timespec="milliseconds") + "Z"


def _mask_user_id(user_id: str | None) -> str:
    if not user_id:
        return "CIF*********"
    if not user_id.startswith("CIF"):
        return "CIF*********"
    return "CIF*********"


def _mask_account_id(account_id: str | None) -> str:
    if not account_id:
        return "ACC**********KH"
    if len(account_id) < 5:
        return "ACC**********KH"
    return f"{account_id[:3]}**********{account_id[-2:]}"


def _compute_risk_score(
    x_user_id: str | None, request: Request
) -> tuple[int, str, str]:
    """簡易風險評分：先做可運行分流骨架，後續可替換為更完整規則引擎。"""
    score = 0
    reasons: list[str] = []
    user_id = (x_user_id or "").strip()

    if not user_id:
        score += 55
        reasons.append("missing_user_id")
    elif not re.fullmatch(r"CIF\d{8,9}", user_id):
        score += 35
        reasons.append("invalid_user_id_format")

    user_agent = (request.headers.get("user-agent") or "").lower()
    suspicious_agents = ("sqlmap", "nmap", "curl", "wget", "python-requests")
    if any(token in user_agent for token in suspicious_agents):
        score += 30
        reasons.append("suspicious_user_agent")

    detection_target = " ".join(
        [
            user_id,
            request.url.path,
            request.url.query,
            request.headers.get("referer", ""),
            request.headers.get("x-forwarded-for", ""),
            user_agent,
        ]
    ).strip()
    is_attack, confidence, attack_vector = analyze_intent(detection_target)
    if is_attack:
        score += int(confidence * 100)
        reasons.append(f"sentinel:{attack_vector}")

    score = min(score, 100)
    reason_text = ",".join(reasons) if reasons else "none"
    route = "deception" if score >= 60 else "real"
    return score, reason_text, route


def _compute_transfer_risk_score(
    x_user_id: str | None,
    request: Request,
    transfer_amount: int | None = None,
    from_account: str | None = None,
) -> tuple[int, str, str]:
    """交易風險評分：在基礎風險分數基礎上加入交易特定規則（重放、高頻、異常金額）。"""
    # 先執行基礎風險評分
    score, reason_text, route = _compute_risk_score(x_user_id, request)

    # 若已確定為欺敵路由，直接返回
    if route == "deception":
        return score, reason_text, route

    reasons = reason_text.split(",") if reason_text and reason_text != "none" else []
    client_ip = request.client.host if request.client else "unknown"
    user_id = (x_user_id or "").strip()

    # 構建原始 payload（用於重放檢測）
    raw_payload = (
        f"path={request.url.path};query={request.url.query};amount={transfer_amount}"
    )

    # 規則 1：重放檢測
    is_replication, replication_reason = detect_replication_risk(
        user_id, raw_payload, limit_seconds=30
    )
    if is_replication:
        score += 40
        reasons.append(replication_reason)

    # 規則 2：高頻檢測
    is_rate_limited, rate_reason = detect_rate_limiting_risk(
        client_ip, limit_seconds=10, threshold=20
    )
    if is_rate_limited:
        score += 35
        reasons.append(rate_reason)

    # 規則 3：異常金額檢測
    if transfer_amount and transfer_amount > 0:
        is_anomalous, amount_reason = detect_anomalous_amount_risk(
            user_id, transfer_amount, limit_hours=24
        )
        if is_anomalous:
            score += 25
            reasons.append(amount_reason)

    score = min(score, 100)
    reason_text = ",".join(reasons) if reasons else "none"
    route = "deception" if score >= 60 else "real"
    return score, reason_text, route


def _log_banking_route_event(
    request: Request,
    user_id: str | None,
    endpoint: str,
    route: str,
    risk_score: int,
    deception_reason: str,
) -> None:
    client_ip = request.client.host if request.client else "unknown"
    now = _now_ms_iso()
    log_traffic_event(
        {
            "request_at": now,
            "response_at": now,
            "process_ms": 0,
            "client_ip": client_ip,
            "location": f"banking:{endpoint}",
            "is_proxy": bool(request.headers.get("x-forwarded-for")),
            "user_agent": request.headers.get("user-agent", "Unknown"),
            "tls_fingerprint": request.headers.get("x-tls-fingerprint", "N/A"),
            "query_id": user_id or "anonymous",
            "is_attack": route == "deception",
            "raw_payload": f"path={request.url.path};query={request.url.query}",
            "response_payload": {
                "route": route,
                "risk_score": risk_score,
                "deception_reason": deception_reason,
                "endpoint": endpoint,
            },
            "attack_vector": "banking_route_decision",
            "risk_level": risk_score,
            "hits": 1,
            "interaction_depth": 1,
            "dwell_time": 0.0,
            "mitigation_status": route,
        }
    )


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


async def _apply_counter_ai_on_deception(
    request: Request,
    payload: dict,
    risk_score: int,
    deception_reason: str,
) -> dict:
    return await harden_deception_response(
        payload,
        user_agent=request.headers.get("user-agent", "Unknown"),
        raw_payload=f"path={request.url.path};query={request.url.query}",
        risk_score=risk_score,
        deception_reason=deception_reason,
    )


def _extract_login_user_ref(
    x_user_id: str | None,
    req_username: str | None,
    client_ip: str,
) -> str:
    if x_user_id and x_user_id.strip():
        return x_user_id.strip()
    if req_username and req_username.strip():
        return req_username.strip()
    return f"anonymous:{client_ip}"


def _is_unauthorized_suspicious(
    x_user_id: str | None,
    risk_score: int,
    deception_reason: str,
) -> bool:
    """Detect requests that should be diverted to deceptive auth flow.

    條件：
    1) 未授權（缺少或格式不合法 user id）
    2) 可疑（高風險或命中可疑指標）
    """
    raw_user_id = (x_user_id or "").strip()
    unauthorized = (not raw_user_id) or (not re.fullmatch(r"CIF\d{8,9}", raw_user_id))
    if not unauthorized:
        return False

    reasons = set(filter(None, (deception_reason or "").split(",")))
    suspicious_markers = {
        "suspicious_user_agent",
        "missing_user_id",
        "invalid_user_id_format",
    }
    has_sentinel_signal = any(r.startswith("sentinel:") for r in reasons)
    has_marker = bool(reasons.intersection(suspicious_markers))

    return risk_score >= 60 or has_sentinel_signal or has_marker


async def _auto_divert_to_deceptive_auth_if_needed(
    *,
    request: Request,
    background_tasks: BackgroundTasks,
    x_user_id: str | None,
    risk_score: int,
    deception_reason: str,
    source_endpoint: str,
) -> dict | None:
    """Return deceptive auth challenge when request is unauthorized and suspicious."""
    if not _is_unauthorized_suspicious(x_user_id, risk_score, deception_reason):
        return None

    client_ip = _client_ip(request)
    user_ref = _extract_login_user_ref(x_user_id, None, client_ip)
    auth_challenge = start_deceptive_login_flow(
        client_ip=client_ip,
        user_ref=user_ref,
        reason=f"auto_divert:{source_endpoint}:{deception_reason}",
    )
    auth_challenge["source_endpoint"] = source_endpoint

    hardened = await _apply_counter_ai_on_deception(
        request,
        auth_challenge,
        max(risk_score, 72),
        deception_reason,
    )

    background_tasks.add_task(
        _log_banking_route_event,
        request,
        user_ref,
        f"{source_endpoint}:auto_deceptive_auth",
        "deception",
        max(risk_score, 72),
        deception_reason,
    )
    return hardened


def _log_banking_transfer_event(
    request: Request,
    user_id: str | None,
    from_account: str | None,
    to_account: str | None,
    amount: int | None,
    route: str,
    risk_score: int,
    deception_reason: str,
) -> None:
    """轉帳專用日誌記錄，包括金額與帳戶資訊供後續規則檢測使用。"""
    client_ip = request.client.host if request.client else "unknown"
    now = _now_ms_iso()
    log_traffic_event(
        {
            "request_at": now,
            "response_at": now,
            "process_ms": 0,
            "client_ip": client_ip,
            "location": "banking:transfers",
            "is_proxy": bool(request.headers.get("x-forwarded-for")),
            "user_agent": request.headers.get("user-agent", "Unknown"),
            "tls_fingerprint": request.headers.get("x-tls-fingerprint", "N/A"),
            "query_id": user_id or "anonymous",
            "is_attack": route == "deception",
            "raw_payload": f"path={request.url.path};from={from_account};to={to_account};amount={amount}",
            "response_payload": {
                "route": route,
                "risk_score": risk_score,
                "deception_reason": deception_reason,
                "endpoint": "transfers",
                "transaction": {
                    "from_account": from_account,
                    "to_account": to_account,
                    "amount": amount,
                },
            },
            "attack_vector": "banking_transfer_decision",
            "risk_level": risk_score,
            "hits": 1,
            "interaction_depth": 1,
            "dwell_time": 0.0,
            "mitigation_status": route,
        }
    )


@router.post(
    "/auth/login",
    summary="啟動欺敵登入流程",
    description="針對未授權或可疑來源啟動多步擬真登入狀態機。",
)
async def start_deceptive_login(
    request: Request,
    background_tasks: BackgroundTasks,
    req: DeceptiveLoginStartRequest,
    x_user_id: str | None = Header(
        default=None,
        alias="X-User-Id",
        description=USER_ID_HEADER_DESCRIPTION,
    ),
):
    risk_score, deception_reason, _ = _compute_risk_score(x_user_id, request)
    client_ip = _client_ip(request)
    user_ref = _extract_login_user_ref(x_user_id, req.username, client_ip)

    response = start_deceptive_login_flow(
        client_ip=client_ip,
        user_ref=user_ref,
        reason=deception_reason,
    )
    hardened = await _apply_counter_ai_on_deception(
        request,
        response,
        max(risk_score, 70),
        deception_reason,
    )

    background_tasks.add_task(
        _log_banking_route_event,
        request,
        user_ref,
        "auth/login",
        "deception",
        max(risk_score, 70),
        deception_reason,
    )
    return hardened


@router.post(
    "/auth/login/{flow_id}/verify",
    summary="推進欺敵登入流程",
    description="提交密碼/OTP/安全問題答案，推進擬真登入狀態機。",
)
async def verify_deceptive_login(
    request: Request,
    background_tasks: BackgroundTasks,
    req: DeceptiveLoginVerifyRequest,
    flow_id: str = Path(..., min_length=8, max_length=40),
    x_user_id: str | None = Header(
        default=None,
        alias="X-User-Id",
        description=USER_ID_HEADER_DESCRIPTION,
    ),
):
    risk_score, deception_reason, _ = _compute_risk_score(x_user_id, request)
    client_ip = _client_ip(request)
    user_ref = _extract_login_user_ref(x_user_id, None, client_ip)

    response = advance_deceptive_login_flow(
        client_ip=client_ip,
        flow_id=flow_id,
        user_ref=user_ref,
        reason=deception_reason,
        password=req.password,
        otp=req.otp,
        security_answer=req.security_answer,
    )
    hardened = await _apply_counter_ai_on_deception(
        request,
        response,
        max(risk_score, 72),
        deception_reason,
    )

    background_tasks.add_task(
        _log_banking_route_event,
        request,
        user_ref,
        "auth/login/verify",
        "deception",
        max(risk_score, 72),
        deception_reason,
    )
    return hardened


def _deception_accounts_response(user_id: str | None, reason: str) -> dict:
    seed = _llama_deception_seed(user_id, reason)
    fake_account_id = f"ACC{uuid.uuid4().hex[:13].upper()}"
    return {
        "user_id": _mask_user_id(user_id),
        "accounts": [
            {
                "account_id": fake_account_id,
                "customer_name": seed.get("name", "系統維護用戶"),
                "account_display": f"{fake_account_id}(校驗中)",
                "currency": "TWD",
                "balance": int(seed.get("balance", 999000)),
                "status": "PENDING_REVIEW",
                "created_at": _now_ms_iso(),
            }
        ],
        "notice": f"(欺敵回應: {reason})",
    }


def _deception_balance_response(account_id: str, reason: str) -> dict:
    seed = _llama_deception_seed(account_id, reason)
    return {
        "account_id": _mask_account_id(account_id),
        "customer_name": seed.get("name", "系統校驗中"),
        "account_display": f"{_mask_account_id(account_id)}(校驗中)",
        "currency": "TWD",
        "balance": int(seed.get("balance", 778000)),
        "status": "PENDING_REVIEW",
        "notice": f"(欺敵回應: {reason})",
    }


def _deception_transactions_response(account_id: str, reason: str) -> dict:
    seed = _llama_deception_seed(account_id, reason)
    fake_tx_id = f"TX-{uuid.uuid4().hex[:12].upper()}"
    now = _now_ms_iso()
    masked_account = _mask_account_id(account_id)
    fake_to = f"ACC{uuid.uuid4().hex[:13].upper()}"
    customer_name = seed.get("name", "系統校驗中")
    return {
        "account_id": masked_account,
        "customer_name": customer_name,
        "account_display": f"{masked_account}(校驗中)",
        "transactions": [
            {
                "tx_id": fake_tx_id,
                "from_account": masked_account,
                "from_account_display": f"{masked_account}(校驗中)",
                "from_customer_name": customer_name,
                "to_account": fake_to,
                "to_account_display": f"{fake_to}(待確認)",
                "to_customer_name": "外部清算節點",
                "amount": 1200,
                "currency": "TWD",
                "fee": 5,
                "status": "PENDING_REVIEW",
                "created_at": now,
                "note": "Pending AML review",
            }
        ],
        "notice": f"(欺敵回應: {reason})",
    }


def _deception_transfer_response(req: "TransferRequest", reason: str) -> dict:
    seed = _llama_deception_seed(req.from_account, reason)
    fake_tx_id = f"TX-{uuid.uuid4().hex[:12].upper()}"
    from_masked = _mask_account_id(req.from_account)
    to_masked = _mask_account_id(req.to_account)
    fee = 15 if req.amount >= 10000 else 5
    customer_name = seed.get("name", "系統校驗中")
    projected_balance = int(seed.get("balance", 780000))
    return {
        "status": "queued_review",
        "transaction": {
            "tx_id": fake_tx_id,
            "from_account": from_masked,
            "from_account_display": f"{from_masked}(校驗中)",
            "from_customer_name": customer_name,
            "to_account": to_masked,
            "to_account_display": f"{to_masked}(待確認)",
            "to_customer_name": "外部清算節點",
            "amount": req.amount,
            "fee": fee,
            "currency": "TWD",
            "created_at": _now_ms_iso(),
            "note": req.note,
        },
        "source_account_after_balance": max(0, projected_balance - req.amount - fee),
        "source_account_display": f"{from_masked}(校驗中)",
        "source_customer_name": customer_name,
        "destination_customer_name": "外部清算節點",
        "notice": f"(欺敵回應: {reason})",
    }


def _llama_deception_seed(query_id: str | None, reason: str) -> dict:
    """惡意分流一律呼叫 Llama；若例外則降級回固定模板。"""
    seed_id = (query_id or "CIF000000000").strip() or "CIF000000000"
    try:
        return generate_fake_data_llama(query_id=seed_id, attack_vector=reason)
    except Exception:
        return {
            "user_id": seed_id,
            "name": "系統維護用戶",
            "balance": 999000,
            "status": "Normal",
        }


def _real_account_label(account_id: str) -> str:
    return f"{account_id}(真實帳戶)"


def _account_display(account_id: str) -> str:
    if account_id in DEMO_ACCOUNTS:
        return _real_account_label(account_id)
    return account_id


def _real_query_meta() -> dict:
    """Return metadata based on whether real DB is being used"""
    if is_real_db_enabled():
        return {"notice": "(真實資訊)"}
    else:
        return {"notice": "(Demo 資料)"}


def _get_customer_name_by_account(account_id: str) -> str:
    """根據帳戶 ID 查詢客戶名稱。如果不在受款人清單中，返回 'Unknown'。"""
    if account_id == DEMO_ACCOUNT_ID:
        return DEMO_CUSTOMER_NAME
    for beneficiary in DEMO_BENEFICIARIES:
        if beneficiary["account_id"] == account_id:
            return beneficiary.get("beneficiary_name", "Unknown")
    return "Unknown"


def _transaction_with_display(tx: dict) -> dict:
    tx_item = dict(tx)
    tx_item["from_account_display"] = _account_display(tx["from_account"])
    tx_item["to_account_display"] = _account_display(tx["to_account"])
    tx_item["from_customer_name"] = DEMO_CUSTOMER_NAME
    # 收款人名稱從交易記錄中取得，若有則用；否則從帳戶 ID 查詢
    tx_item["to_customer_name"] = tx.get(
        "to_customer_name", _get_customer_name_by_account(tx["to_account"])
    )
    return tx_item


def _resolve_real_account_id(account_id: str, is_destination: bool = False) -> str:
    if is_real_db_enabled():
        return account_id
    """
    解析帳戶 ID。
    - 來源帳戶（from_account）：永遠映射到 DEMO_ACCOUNT_ID
    - 目標帳戶（to_account）：如果在受款人清單中，保留；否則映射到 DEMO_ACCOUNT_ID
    """
    if not is_destination:
        return DEMO_ACCOUNT_ID
    # 檢查是否在受款人清單中
    for beneficiary in DEMO_BENEFICIARIES:
        if beneficiary["account_id"] == account_id:
            return account_id
    # 如果是 DEMO_ACCOUNT，也保留
    if account_id == DEMO_ACCOUNT_ID:
        return account_id
    # 其他情況映射到 DEMO_ACCOUNT_ID
    return DEMO_ACCOUNT_ID


def _resolve_real_user_id(_user_id: str | None) -> str:
    # 保留呼叫端送入的 user_id，避免在 Demo 模式下被強制映射成同一帳號。
    return (_user_id or "").strip()


class BeneficiaryCreateRequest(BaseModel):
    nickname: str = Field(
        ..., min_length=1, max_length=80, description=NICKNAME_DESCRIPTION
    )
    bank_code: str = Field(
        ..., min_length=3, max_length=10, description=BANK_CODE_DESCRIPTION
    )
    account_id: str = Field(
        ..., min_length=6, max_length=40, description=ACCOUNT_ID_DESCRIPTION
    )


class TransferRequest(BaseModel):
    from_account: str = Field(
        ...,
        min_length=6,
        max_length=40,
        description="扣款帳戶識別碼，格式同 `ACC**********KH`。",
    )
    to_account: str = Field(
        ...,
        min_length=6,
        max_length=40,
        description="收款帳戶識別碼，格式同 `ACC**********KH`。",
    )
    amount: int = Field(..., gt=0, description="轉帳金額（整數），必須大於 0。")
    note: str | None = Field(default=None, max_length=200, description=NOTE_DESCRIPTION)


def _require_user(x_user_id: str | None) -> str:
    ensure_real_db_enabled()
    if not is_real_db_enabled():
        raise HTTPException(
            status_code=503,
            detail="PostgreSQL mode is required. Please configure DATABASE_URL.",
        )

    if not x_user_id or not x_user_id.strip():
        raise HTTPException(status_code=401, detail="Missing X-User-Id header")

    user_id = _resolve_real_user_id(x_user_id)
    if not re.fullmatch(r"CIF\d{8,9}", user_id):
        raise HTTPException(
            status_code=422,
            detail="X-User-Id format invalid. Expected CIF + 8~9 digits.",
        )

    # 真實 DB 模式：確保合法 CIF 用戶有預設帳戶（idempotent）
    if is_real_db_enabled():
        DBOperations.ensure_user_account(user_id)

    return user_id


def _normalize_actor_role(x_actor_role: str | None) -> str:
    role = (x_actor_role or "customer").strip().lower()
    if role not in {"customer", "admin", "soc"}:
        raise HTTPException(
            status_code=422,
            detail="X-Actor-Role format invalid. Expected one of: customer, admin, soc.",
        )
    return role


def _require_actor_role(x_actor_role: str | None, allowed_roles: set[str]) -> str:
    role = _normalize_actor_role(x_actor_role)
    if role not in allowed_roles:
        raise HTTPException(status_code=403, detail="Forbidden by role policy")
    return role


def _ensure_transfer_destination_authorized(user_id: str, to_account: str) -> None:
    """Object-level authorization for destination account in real DB mode."""
    if DBOperations.account_belongs_to_user(to_account, user_id):
        return
    if DBOperations.is_authorized_beneficiary(user_id, to_account):
        return
    raise HTTPException(
        status_code=403,
        detail="Forbidden by object-level authorization: destination account is not authorized",
    )


def _ensure_account_owner(account_id: str, user_id: str) -> dict:
    if is_real_db_enabled():
        row = DBOperations.get_account_balance(account_id, user_id)
        if not row:
            raise HTTPException(status_code=404, detail="Account not found")
        return row

    resolved_account_id = _resolve_real_account_id(account_id)
    row = DEMO_ACCOUNTS.get(resolved_account_id)
    if not row:
        raise HTTPException(status_code=404, detail="Account not found")
    if user_id != DEMO_USER_ID:
        raise HTTPException(
            status_code=403, detail="Forbidden by object-level authorization"
        )
    return row


@router.get(
    "/accounts",
    summary="查詢帳戶清單",
    description="取得目前使用者可存取的帳戶清單；請在 Header 帶入 `X-User-Id`。",
    response_model=Union[ListAccountsResponse, DeceptiveAuthChallengeResponse],
    responses={
        200: {
            "description": "成功回傳帳戶清單",
            "content": {
                "application/json": {
                    "example": {
                        "user_id": "CIF*********",
                        "accounts": [],
                        "notice": "(真實資訊)",
                    }
                }
            },
        }
    },
)
async def list_accounts(
    request: Request,
    background_tasks: BackgroundTasks,
    x_user_id: str | None = Header(
        default=None,
        alias="X-User-Id",
        description=USER_ID_HEADER_DESCRIPTION,
    ),
):
    risk_score, deception_reason, route = _compute_risk_score(x_user_id, request)
    background_tasks.add_task(
        _log_banking_route_event,
        request,
        x_user_id,
        "accounts",
        route,
        risk_score,
        deception_reason,
    )

    if route == "deception":
        diverted = await _auto_divert_to_deceptive_auth_if_needed(
            request=request,
            background_tasks=background_tasks,
            x_user_id=x_user_id,
            risk_score=risk_score,
            deception_reason=deception_reason,
            source_endpoint="accounts",
        )
        if diverted is not None:
            return diverted

        return await _apply_counter_ai_on_deception(
            request,
            _deception_accounts_response(x_user_id, deception_reason),
            risk_score,
            deception_reason,
        )

    user_id = _require_user(x_user_id)

    # Try real database first
    if is_real_db_enabled():
        db_items = DBOperations.get_user_accounts(user_id)
        if db_items is None:
            db_items = []
        items = [
            {
                "account_id": item["account_id"],
                "customer_name": item.get("customer_name", "Unknown"),
                "account_display": f"{item['account_id']}(真實帳戶)",
                "currency": item["currency"],
                "balance": item["balance"],
                "status": item["status"],
                "created_at": item["open_date"],
            }
            for item in db_items
        ]
        return {"user_id": user_id, "accounts": items, **_real_query_meta()}

    # Fallback to mock data：僅 DEMO_USER_ID 可看到 demo 帳戶。
    if user_id == DEMO_USER_ID:
        items = [
            {
                "account_id": v["account_id"],
                "customer_name": DEMO_CUSTOMER_NAME,
                "account_display": _real_account_label(v["account_id"]),
                "currency": v["currency"],
                "balance": v["balance"],
                "status": v["status"],
                "created_at": v["open_date"],
            }
            for v in DEMO_ACCOUNTS.values()
        ]
    else:
        items = []
    return {"user_id": user_id, "accounts": items, **_real_query_meta()}


@router.get(
    "/accounts/{account_id}/balance",
    summary="查詢帳戶餘額",
    description="查詢單一帳戶餘額；請提供 `X-User-Id: CIF*********`，且路徑上的 `account_id` 格式為 `ACC**********KH`。",
    response_model=Union[BalanceResponse, DeceptiveAuthChallengeResponse],
)
async def get_balance(
    request: Request,
    background_tasks: BackgroundTasks,
    account_id: str = Path(..., description=ACCOUNT_ID_DESCRIPTION),
    x_user_id: str | None = Header(
        default=None,
        alias="X-User-Id",
        description=USER_ID_HEADER_DESCRIPTION,
    ),
):
    risk_score, deception_reason, route = _compute_risk_score(x_user_id, request)
    background_tasks.add_task(
        _log_banking_route_event,
        request,
        x_user_id,
        f"accounts/{account_id}/balance",
        route,
        risk_score,
        deception_reason,
    )
    if route == "deception":
        diverted = await _auto_divert_to_deceptive_auth_if_needed(
            request=request,
            background_tasks=background_tasks,
            x_user_id=x_user_id,
            risk_score=risk_score,
            deception_reason=deception_reason,
            source_endpoint="balance",
        )
        if diverted is not None:
            return diverted

        return await _apply_counter_ai_on_deception(
            request,
            _deception_balance_response(account_id, deception_reason),
            risk_score,
            deception_reason,
        )

    user_id = _require_user(x_user_id)
    row = _ensure_account_owner(account_id, user_id)
    return {
        "account_id": row["account_id"],
        "customer_name": DEMO_CUSTOMER_NAME,
        "account_display": _real_account_label(row["account_id"]),
        "currency": row["currency"],
        "balance": int(row["balance"]),
        "status": row["status"],
        **_real_query_meta(),
    }


@router.get(
    "/accounts/{account_id}/transactions",
    summary="查詢帳戶交易明細",
    description="查詢該帳戶最近交易；請提供 `X-User-Id: CIF*********`，`account_id` 格式為 `ACC**********KH`，`limit` 為 1-100 的整數。",
    response_model=Union[ListTransactionsResponse, DeceptiveAuthChallengeResponse],
)
async def get_transactions(
    request: Request,
    background_tasks: BackgroundTasks,
    account_id: str = Path(..., description=ACCOUNT_ID_DESCRIPTION),
    limit: int = Query(20, ge=1, le=100, description=LIMIT_DESCRIPTION),
    x_user_id: str | None = Header(
        default=None,
        alias="X-User-Id",
        description=USER_ID_HEADER_DESCRIPTION,
    ),
):
    risk_score, deception_reason, route = _compute_risk_score(x_user_id, request)
    background_tasks.add_task(
        _log_banking_route_event,
        request,
        x_user_id,
        f"accounts/{account_id}/transactions",
        route,
        risk_score,
        deception_reason,
    )
    if route == "deception":
        diverted = await _auto_divert_to_deceptive_auth_if_needed(
            request=request,
            background_tasks=background_tasks,
            x_user_id=x_user_id,
            risk_score=risk_score,
            deception_reason=deception_reason,
            source_endpoint="transactions",
        )
        if diverted is not None:
            return diverted

        return await _apply_counter_ai_on_deception(
            request,
            _deception_transactions_response(account_id, deception_reason),
            risk_score,
            deception_reason,
        )

    user_id = _require_user(x_user_id)

    if is_real_db_enabled():
        _ensure_account_owner(account_id, user_id)
        db_items = DBOperations.get_account_transactions(account_id, user_id, limit)
        if db_items is None:
            db_items = []
        items = [_transaction_with_display(tx) for tx in db_items]
        return {
            "account_id": account_id,
            "customer_name": _get_customer_name_by_account(account_id),
            "account_display": _real_account_label(account_id),
            "transactions": items,
            **_real_query_meta(),
        }

    resolved_account_id = _resolve_real_account_id(account_id)
    _ensure_account_owner(resolved_account_id, user_id)
    raw_items = [
        x
        for x in DEMO_TRANSACTIONS
        if x["from_account"] == resolved_account_id
        or x["to_account"] == resolved_account_id
    ][:limit]
    items = [_transaction_with_display(tx) for tx in raw_items]
    return {
        "account_id": resolved_account_id,
        "customer_name": DEMO_CUSTOMER_NAME,
        "account_display": _real_account_label(resolved_account_id),
        "transactions": items,
        **_real_query_meta(),
    }


@router.get(
    "/beneficiaries",
    summary="查詢受款人清單",
    description="列出目前使用者的受款人清單；請在 Header 帶入 `X-User-Id`。",
    response_model=Union[ListBeneficiariesResponse, DeceptiveAuthChallengeResponse],
)
async def list_beneficiaries(
    request: Request,
    background_tasks: BackgroundTasks,
    x_user_id: str | None = Header(
        default=None,
        alias="X-User-Id",
        description=USER_ID_HEADER_DESCRIPTION,
    ),
    x_actor_role: str | None = Header(
        default=None,
        alias="X-Actor-Role",
        description=ACTOR_ROLE_DESCRIPTION,
    ),
):
    risk_score, deception_reason, route = _compute_risk_score(x_user_id, request)
    background_tasks.add_task(
        _log_banking_route_event,
        request,
        x_user_id,
        "beneficiaries",
        route,
        risk_score,
        deception_reason,
    )
    if route == "deception":
        diverted = await _auto_divert_to_deceptive_auth_if_needed(
            request=request,
            background_tasks=background_tasks,
            x_user_id=x_user_id,
            risk_score=risk_score,
            deception_reason=deception_reason,
            source_endpoint="beneficiaries",
        )
        if diverted is not None:
            return diverted

        return await _apply_counter_ai_on_deception(
            request,
            {
                "user_id": _mask_user_id(x_user_id),
                "beneficiaries": [],
                "notice": f"(欺敵回應: {deception_reason})",
            },
            risk_score,
            deception_reason,
        )

    user_id = _require_user(x_user_id)
    _require_actor_role(x_actor_role, {"customer", "admin"})

    if is_real_db_enabled():
        db_items = DBOperations.get_user_beneficiaries(user_id)
        if db_items is None:
            db_items = []
        items = []
        for beneficiary in db_items:
            item = dict(beneficiary)
            item["user_id"] = user_id
            item["account_display"] = _account_display(beneficiary["account_id"])
            items.append(item)
        return {"user_id": user_id, "beneficiaries": items, **_real_query_meta()}

    items = []
    for beneficiary in DEMO_BENEFICIARIES:
        if beneficiary["user_id"] != user_id:
            continue
        item = dict(beneficiary)
        item["beneficiary_name"] = DEMO_BENEFICIARY_NAME
        item["account_display"] = _account_display(beneficiary["account_id"])
        items.append(item)
    return {"user_id": user_id, "beneficiaries": items, **_real_query_meta()}


@router.post(
    "/beneficiaries",
    summary="新增受款人",
    description="建立新的受款人資料；請在 Header 帶入 `X-User-Id: CIF*********`，並在 Body 填入 `nickname`、`bank_code`、`account_id(ACC**********KH)`。",
    response_model=Union[CreateBeneficiaryResponse, DeceptiveAuthChallengeResponse],
)
async def create_beneficiary(
    request: Request,
    background_tasks: BackgroundTasks,
    req: BeneficiaryCreateRequest,
    x_user_id: str | None = Header(
        default=None,
        alias="X-User-Id",
        description=USER_ID_HEADER_DESCRIPTION,
    ),
    x_actor_role: str | None = Header(
        default=None,
        alias="X-Actor-Role",
        description=ACTOR_ROLE_DESCRIPTION,
    ),
):
    risk_score, deception_reason, route = _compute_risk_score(x_user_id, request)
    background_tasks.add_task(
        _log_banking_route_event,
        request,
        x_user_id,
        "beneficiaries:create",
        route,
        risk_score,
        deception_reason,
    )
    if route == "deception":
        diverted = await _auto_divert_to_deceptive_auth_if_needed(
            request=request,
            background_tasks=background_tasks,
            x_user_id=x_user_id,
            risk_score=risk_score,
            deception_reason=deception_reason,
            source_endpoint="beneficiaries:create",
        )
        if diverted is not None:
            return diverted

        return await _apply_counter_ai_on_deception(
            request,
            {
                "status": "queued_review",
                "beneficiary_id": 0,
                "account_id": _mask_account_id(req.account_id),
                "beneficiary_name": _llama_deception_seed(
                    req.account_id, deception_reason
                ).get("name", "系統校驗中"),
                "account_display": f"{_mask_account_id(req.account_id)}(校驗中)",
                "notice": f"(欺敵回應: {deception_reason})",
            },
            risk_score,
            deception_reason,
        )

    user_id = _require_user(x_user_id)
    _require_actor_role(x_actor_role, {"customer", "admin"})

    if is_real_db_enabled():
        if DBOperations.account_belongs_to_user(req.account_id, user_id):
            raise HTTPException(
                status_code=400, detail="Cannot add your own account as beneficiary"
            )
        if not DBOperations.account_exists(req.account_id):
            raise HTTPException(status_code=404, detail="Destination account not found")
        created = DBOperations.create_beneficiary(
            user_id=user_id,
            nickname=req.nickname,
            bank_code=req.bank_code,
            account_id=req.account_id,
            beneficiary_name=DEMO_BENEFICIARY_NAME,
        )
        if not created:
            raise HTTPException(
                status_code=409, detail="Beneficiary already exists for this account"
            )
        return {
            "status": "created",
            "beneficiary_id": created["id"],
            "account_id": created["account_id"],
            "beneficiary_name": created["beneficiary_name"] or DEMO_BENEFICIARY_NAME,
            "account_display": _account_display(created["account_id"]),
            **_real_query_meta(),
        }

    resolved_account_id = _resolve_real_account_id(req.account_id, is_destination=True)

    # 驗證：不允許添加自己帳戶作為受款人
    if resolved_account_id == DEMO_ACCOUNT_ID:
        raise HTTPException(
            status_code=400, detail="Cannot add your own account as beneficiary"
        )

    # 驗證：檢查是否已存在相同的受款人
    for existing in DEMO_BENEFICIARIES:
        if (
            existing["user_id"] == user_id
            and existing["account_id"] == resolved_account_id
        ):
            raise HTTPException(
                status_code=409, detail="Beneficiary already exists for this account"
            )

    now = datetime.utcnow().isoformat(timespec="seconds")
    created_id = (
        (max([x["id"] for x in DEMO_BENEFICIARIES]) + 1) if DEMO_BENEFICIARIES else 1
    )
    DEMO_BENEFICIARIES.append(
        {
            "id": created_id,
            "user_id": user_id,
            "nickname": req.nickname,
            "bank_code": req.bank_code,
            "account_id": resolved_account_id,
            "beneficiary_name": DEMO_BENEFICIARY_NAME,
            "created_at": now,
        }
    )
    return {
        "status": "created",
        "beneficiary_id": created_id,
        "account_id": resolved_account_id,
        "beneficiary_name": DEMO_BENEFICIARY_NAME,
        "account_display": _account_display(resolved_account_id),
        **_real_query_meta(),
    }


@router.post(
    "/transfers",
    summary="執行轉帳",
    description="執行轉帳；請帶 `X-User-Id: CIF*********` 與 `Idempotency-Key`，並在 Body 提供 `from_account(ACC**********KH)`、`to_account(ACC**********KH)`、`amount(>0)` 與可選 `note`。",
    response_model=Union[TransferResponse, DeceptiveAuthChallengeResponse],
)
async def transfer_money(
    request: Request,
    background_tasks: BackgroundTasks,
    req: TransferRequest,
    x_user_id: str | None = Header(
        default=None,
        alias="X-User-Id",
        description=USER_ID_HEADER_DESCRIPTION,
    ),
    x_actor_role: str | None = Header(
        default=None,
        alias="X-Actor-Role",
        description=ACTOR_ROLE_DESCRIPTION,
    ),
    idempotency_key: str | None = Header(
        default=None,
        alias="Idempotency-Key",
        description=IDEMPOTENCY_KEY_DESCRIPTION,
    ),
):
    risk_score, deception_reason, route = _compute_transfer_risk_score(
        x_user_id, request, req.amount, req.from_account
    )
    background_tasks.add_task(
        _log_banking_transfer_event,
        request,
        x_user_id,
        req.from_account,
        req.to_account,
        req.amount,
        route,
        risk_score,
        deception_reason,
    )
    if route == "deception":
        diverted = await _auto_divert_to_deceptive_auth_if_needed(
            request=request,
            background_tasks=background_tasks,
            x_user_id=x_user_id,
            risk_score=risk_score,
            deception_reason=deception_reason,
            source_endpoint="transfers",
        )
        if diverted is not None:
            return diverted

        return await _apply_counter_ai_on_deception(
            request,
            _deception_transfer_response(req, deception_reason),
            risk_score,
            deception_reason,
        )

    user_id = _require_user(x_user_id)
    _require_actor_role(x_actor_role, {"customer", "admin"})
    if not idempotency_key or not idempotency_key.strip():
        raise HTTPException(status_code=400, detail="Missing Idempotency-Key header")
    key = (user_id, idempotency_key.strip())

    if is_real_db_enabled():
        existing_tx_id = DBOperations.get_idempotent_transaction(
            user_id, idempotency_key.strip()
        )
        if existing_tx_id:
            cached_tx = DBOperations.get_transaction_by_id(existing_tx_id)
            if not cached_tx:
                raise HTTPException(
                    status_code=404, detail="Idempotent transaction not found"
                )
            owner = _ensure_account_owner(cached_tx["from_account"], user_id)
            return {
                "status": "already_processed",
                "transaction": _transaction_with_display(cached_tx),
                "source_account_after_balance": int(owner["balance"]),
                "source_account_display": _account_display(cached_tx["from_account"]),
                "source_customer_name": _get_customer_name_by_account(
                    cached_tx["from_account"]
                ),
                "destination_customer_name": _get_customer_name_by_account(
                    cached_tx["to_account"]
                ),
                **_real_query_meta(),
            }

        if req.from_account == req.to_account:
            raise HTTPException(
                status_code=400, detail="Cannot transfer to the same account"
            )

        from_owner = _ensure_account_owner(req.from_account, user_id)
        _ensure_transfer_destination_authorized(user_id, req.to_account)
        fee = 15 if req.amount >= 10000 else 5
        total_debit = req.amount + fee
        if int(from_owner["balance"]) < total_debit:
            raise HTTPException(status_code=400, detail="Insufficient balance")

        tx = DBOperations.transfer_money(
            user_id=user_id,
            from_account=req.from_account,
            to_account=req.to_account,
            amount=req.amount,
            fee=fee,
            note=req.note,
        )
        if not tx:
            raise HTTPException(status_code=400, detail="Transfer failed")

        DBOperations.record_idempotency(user_id, idempotency_key.strip(), tx["tx_id"])

        return {
            "status": "success",
            "transaction": _transaction_with_display(tx),
            "source_account_after_balance": int(tx["new_balance"]),
            "source_account_display": _account_display(tx["from_account"]),
            "source_customer_name": _get_customer_name_by_account(tx["from_account"]),
            "destination_customer_name": _get_customer_name_by_account(
                tx["to_account"]
            ),
            **_real_query_meta(),
        }

    # 冪等：同 user + key 若已存在，直接回傳既有交易
    if key in DEMO_IDEMPOTENCY:
        cached_tx = DEMO_IDEMPOTENCY[key]
        # 重新計算該交易後的帳戶餘額
        from_account_id = cached_tx["from_account"]
        from_account = DEMO_ACCOUNTS.get(from_account_id)
        cached_balance = from_account["balance"] if from_account else 0

        return {
            "status": "already_processed",
            "transaction": _transaction_with_display(cached_tx),
            "source_account_after_balance": int(cached_balance),
            "source_account_display": _account_display(from_account_id),
            "source_customer_name": DEMO_CUSTOMER_NAME,
            "destination_customer_name": _get_customer_name_by_account(
                cached_tx["to_account"]
            ),
            **_real_query_meta(),
        }

    from_account_id = _resolve_real_account_id(req.from_account, is_destination=False)
    to_account_id = _resolve_real_account_id(req.to_account, is_destination=True)

    # 防止轉帳給自己
    if from_account_id == to_account_id:
        raise HTTPException(
            status_code=400, detail="Cannot transfer to the same account"
        )

    from_account = _ensure_account_owner(from_account_id, user_id)

    # 目標帳戶驗證：在 DEMO_ACCOUNTS 中或是受款人清單中
    to_account = DEMO_ACCOUNTS.get(to_account_id)
    if not to_account:
        # 檢查是否是受款人帳戶
        is_beneficiary = any(
            b["account_id"] == to_account_id for b in DEMO_BENEFICIARIES
        )
        if not is_beneficiary:
            raise HTTPException(status_code=404, detail="Destination account not found")
        # 建立外部受款帳戶的臨時檢核資料（不落地）
        to_account = {
            "account_id": to_account_id,
            "status": "ACTIVE",
            "currency": "TWD",
            "balance": 999999999,  # 無限餘額
        }

    if to_account["status"] != "ACTIVE":
        raise HTTPException(status_code=400, detail="Destination account is not active")

    if from_account["status"] != "ACTIVE":
        raise HTTPException(status_code=400, detail="Source account is not active")

    if from_account["currency"] != to_account["currency"]:
        raise HTTPException(status_code=400, detail="Currency mismatch")

    fee = 15 if req.amount >= 10000 else 5
    total_debit = req.amount + fee
    if int(from_account["balance"]) < total_debit:
        raise HTTPException(status_code=400, detail="Insufficient balance")

    tx_id = f"TX-{uuid.uuid4().hex[:12].upper()}"
    now = datetime.utcnow().isoformat(timespec="seconds")

    DEMO_ACCOUNTS[from_account_id]["balance"] = (
        int(from_account["balance"]) - total_debit
    )
    # 仅當目標帳戶存在於 DEMO_ACCOUNTS 中時，才更新其餘額
    if to_account_id in DEMO_ACCOUNTS:
        DEMO_ACCOUNTS[to_account_id]["balance"] = (
            int(to_account["balance"]) + req.amount
        )

    # 取得收款人名稱
    to_customer_name = _get_customer_name_by_account(to_account_id)

    tx = {
        "tx_id": tx_id,
        "from_account": from_account_id,
        "from_customer_name": DEMO_CUSTOMER_NAME,
        "to_account": to_account_id,
        "to_customer_name": to_customer_name,
        "amount": req.amount,
        "currency": from_account["currency"],
        "fee": fee,
        "status": "SUCCESS",
        "created_at": now,
        "note": req.note,
    }
    DEMO_TRANSACTIONS.insert(0, tx)
    DEMO_IDEMPOTENCY[key] = tx

    new_balance = DEMO_ACCOUNTS[from_account_id]["balance"]

    return {
        "status": "success",
        "transaction": _transaction_with_display(tx),
        "source_account_after_balance": int(new_balance),
        "source_account_display": _account_display(from_account_id),
        "source_customer_name": DEMO_CUSTOMER_NAME,
        "destination_customer_name": to_customer_name,
        **_real_query_meta(),
    }
