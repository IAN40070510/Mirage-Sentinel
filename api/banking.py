import uuid
import re
from datetime import datetime

from fastapi import APIRouter, Header, HTTPException, Path, Query
from pydantic import BaseModel, Field

from .db.session import is_real_db_enabled
from .db.operations import DBOperations


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
    response_model=ListAccountsResponse,
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
    x_user_id: str | None = Header(
        default=None,
        alias="X-User-Id",
        description=USER_ID_HEADER_DESCRIPTION,
    ),
):
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
    response_model=BalanceResponse,
)
async def get_balance(
    account_id: str = Path(..., description=ACCOUNT_ID_DESCRIPTION),
    x_user_id: str | None = Header(
        default=None,
        alias="X-User-Id",
        description=USER_ID_HEADER_DESCRIPTION,
    ),
):
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
    response_model=ListTransactionsResponse,
)
async def get_transactions(
    account_id: str = Path(..., description=ACCOUNT_ID_DESCRIPTION),
    limit: int = Query(20, ge=1, le=100, description=LIMIT_DESCRIPTION),
    x_user_id: str | None = Header(
        default=None,
        alias="X-User-Id",
        description=USER_ID_HEADER_DESCRIPTION,
    ),
):
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
    response_model=ListBeneficiariesResponse,
)
async def list_beneficiaries(
    x_user_id: str | None = Header(
        default=None,
        alias="X-User-Id",
        description=USER_ID_HEADER_DESCRIPTION,
    ),
):
    user_id = _require_user(x_user_id)

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
    response_model=CreateBeneficiaryResponse,
)
async def create_beneficiary(
    req: BeneficiaryCreateRequest,
    x_user_id: str | None = Header(
        default=None,
        alias="X-User-Id",
        description=USER_ID_HEADER_DESCRIPTION,
    ),
):
    user_id = _require_user(x_user_id)

    if is_real_db_enabled():
        if req.account_id == DEMO_ACCOUNT_ID:
            raise HTTPException(
                status_code=400, detail="Cannot add your own account as beneficiary"
            )
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
    response_model=TransferResponse,
)
async def transfer_money(
    req: TransferRequest,
    x_user_id: str | None = Header(
        default=None,
        alias="X-User-Id",
        description=USER_ID_HEADER_DESCRIPTION,
    ),
    idempotency_key: str | None = Header(
        default=None,
        alias="Idempotency-Key",
        description=IDEMPOTENCY_KEY_DESCRIPTION,
    ),
):
    user_id = _require_user(x_user_id)
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
