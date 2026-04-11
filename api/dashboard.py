import logging

from fastapi import APIRouter, Header, HTTPException, Path, Query
from pydantic import BaseModel, Field

from services import dashboard_service as ws

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


class MisjudgmentRequest(BaseModel):
    client_ip: str = Field(..., min_length=7, max_length=45, description="IP address")
    reason: str = Field(
        ..., min_length=3, max_length=500, description="Misjudgment reason"
    )


# Renamed to avoid redeclaration error
class DashboardCategoryRequest(BaseModel):
    category_name: str = Field(
        ..., min_length=1, max_length=100, description="Category name"
    )
    items: list[str] | None = None


class CommandRequest(BaseModel):
    command_text: str = Field(
        ..., min_length=1, max_length=1000, description="Command text"
    )
    selected_ip: str | None = Field(
        default=None, max_length=45, description="Selected IP"
    )


def verify_api_key(x_api_key: str | None):
    if not ws.validate_api_key(x_api_key):
        raise HTTPException(status_code=401, detail="Invalid API key")


from typing import Dict, Any


@router.get("", summary="Dashboard API 入口")
async def dashboard_root() -> Dict[str, Any]:
    return {
        "service": "Mirage Dashboard API",
        "hint": "Use /api/v1/dashboard/* endpoints with X-API-Key",
        "examples": [
            "/api/v1/dashboard/recent_traffic",
            "/api/v1/dashboard/live_ips",
            "/api/v1/dashboard/traffic_compare",
            "/api/v1/dashboard/ip_bundle/127.0.0.1",
        ],
    }


@router.get("/dwell_time/{client_ip}", summary="獲取駭客滯留時間與活躍狀態")
async def get_hacker_analysis(
    client_ip: str,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
):
    verify_api_key(x_api_key)
    try:
        return ws.get_hacker_dwell_time(client_ip)
    except Exception as exc:
        raise HTTPException(
            status_code=500, detail=f"取得駭客滯留時間失敗: {exc}"
        ) from exc


@router.get("/interaction_depth/{client_ip}", summary="分析誘餌互動深度")
async def get_interaction_depth(
    client_ip: str,
    query_id: str = Query(..., description="指定查詢或互動識別碼"),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
):
    verify_api_key(x_api_key)
    try:
        return ws.analyze_interaction_depth(client_ip, query_id)
    except Exception as exc:
        logger.error("分析互動深度失敗: %r", exc)
        raise HTTPException(status_code=500, detail=f"分析互動深度失敗: {exc}") from exc


@router.get("/attack_timeline/{client_ip}", summary="獲取攻擊行為路徑時間軸")
async def get_attack_timeline(
    client_ip: str,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
):
    verify_api_key(x_api_key)
    try:
        return ws.get_attack_timeline(client_ip)
    except Exception as exc:
        logger.error("取得攻擊時間軸失敗: %r", exc)
        raise HTTPException(
            status_code=500, detail=f"取得攻擊時間軸失敗: {exc}"
        ) from exc


@router.get("/recent_traffic", summary="獲取近期流量日誌")
async def get_recent_traffic(
    limit: int = Query(100, ge=1, le=500, description="筆數上限"),
    mode: str = Query(
        "all", pattern="^(all|attacks)$", description="all=全流量, attacks=僅攻擊"
    ),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
):
    verify_api_key(x_api_key)
    try:
        return ws.fetch_recent_traffic(limit, mode)
    except Exception as exc:
        logger.error("取得近期流量失敗: %r", exc)
        raise HTTPException(status_code=500, detail=f"取得近期流量失敗: {exc}") from exc


@router.get("/auto_updates", summary="儀表板自動更新檢查")
async def get_auto_updates(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
):
    verify_api_key(x_api_key)
    try:
        return ws.auto_updates()
    except Exception as exc:
        logger.error("取得更新狀態失敗: %r", exc)
        raise HTTPException(status_code=500, detail=f"取得更新狀態失敗: {exc}") from exc


@router.post("/misjudgment", summary="標記誤判並存入資料夾")
async def log_misjudgment_event(
    req: MisjudgmentRequest,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
):
    verify_api_key(x_api_key)
    try:
        ws.log_misjudgment(req.client_ip, req.reason)
        return {
            "status": "success",
            "message": f"IP {req.client_ip} 已記錄至誤判資料夾",
        }
    except Exception as exc:
        logger.error("記錄誤判失敗: %r", exc)
        raise HTTPException(status_code=500, detail=f"記錄誤判失敗: {exc}") from exc


@router.get("/command_heatmap", summary="獲取最常輸入指令前十名")
async def get_top_commands(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
):
    verify_api_key(x_api_key)
    try:
        return ws.get_command_heatmap()["top_commands"]
    except Exception as exc:
        logger.error("取得指令熱區圖資料失敗: %r", exc)
        raise HTTPException(
            status_code=500, detail=f"取得指令熱區圖資料失敗: {exc}"
        ) from exc


@router.get("/ip_details/{client_ip}", summary="取得特定 IP 詳細資訊")
async def get_ip_detail(
    client_ip: str,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
):
    verify_api_key(x_api_key)
    try:
        result = ws.get_ip_details(client_ip)
        if not result:
            raise HTTPException(status_code=404, detail="查無此 IP 詳細資料")
        return result
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("取得 IP 詳細資料失敗: %r", exc)
        raise HTTPException(
            status_code=500, detail=f"取得 IP 詳細資料失敗: {exc}"
        ) from exc


# --- Add Pydantic model for report response ---
from pydantic import BaseModel
from typing import Any


class HackerReportResponse(BaseModel):
    report_title: str
    summary: Any
    details: Any
    full_trajectory: Any


@router.get(
    "/report/{client_ip}",
    summary="生成特定駭客行為報告書",
    response_model=HackerReportResponse,
)
async def get_hacker_report(
    client_ip: str,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
):
    verify_api_key(x_api_key)
    try:
        analysis = ws.get_hacker_dwell_time(client_ip)
        timeline = ws.get_attack_timeline(client_ip)["timeline"]
        details = ws.get_ip_details(client_ip)
        if not details:
            raise HTTPException(status_code=404, detail="查無此 IP 紀錄")
        return HackerReportResponse(
            report_title=f"Hacker Forensic Report - {client_ip}",
            summary=analysis,
            details=details,
            full_trajectory=timeline,
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("生成報告失敗: %r", exc)
        raise HTTPException(status_code=500, detail=f"生成報告失敗: {exc}") from exc


@router.get("/live_ips", summary="取得資料庫中所有 IP 與簡易流量資訊")
async def get_live_ips(
    limit: int = Query(500, ge=1, le=2000, description="IP 筆數上限"),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
):
    verify_api_key(x_api_key)
    try:
        return ws.fetch_all_client_ips(limit)["items"]
    except Exception as exc:
        logger.error("取得 IP 清單失敗: %r", exc)
        raise HTTPException(status_code=500, detail=f"取得 IP 清單失敗: {exc}") from exc


@router.get("/traffic_compare", summary="取得正常與攻擊流量比較")
async def get_traffic_compare(
    limit: int = Query(1000, ge=1, le=10000, description="統計筆數上限"),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
):
    verify_api_key(x_api_key)
    try:
        return ws.compare_traffic(limit)
    except Exception as exc:
        logger.error("取得流量比較失敗: %r", exc)
        raise HTTPException(status_code=500, detail=f"取得流量比較失敗: {exc}") from exc


# 假設 CategoryItem 為 items 的型別，若未定義則補上
from typing import Any
from pydantic import BaseModel


class CategoryItem(BaseModel):
    # 根據實際 items 結構調整欄位
    name: str
    value: Any


class CategoryRequest(BaseModel):
    category_name: str
    items: list[CategoryItem] | None = None


# 明確指定 set_log_category 的 items 型別
from typing import TypedDict


class LogCategoryItem(TypedDict):
    name: str
    value: Any


@router.post("/set_category", summary="設定前端分類資料")
async def post_set_category(
    req: CategoryRequest,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
):
    verify_api_key(x_api_key)
    try:
        # 型別安全：直接產生 list[dict[str, Any]] | None
        items: list[dict[str, Any]] | None = (
            [item.model_dump() for item in req.items] if req.items is not None else None
        )
        return ws.set_log_category(req.category_name, items)
    except Exception as exc:
        logger.error("設定分類失敗: %r", exc)
        raise HTTPException(status_code=500, detail=f"設定分類失敗: {exc}") from exc


@router.post("/terminal_cmd", summary="接收前端指令框命令")
async def post_terminal_cmd(
    req: CommandRequest,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
):
    verify_api_key(x_api_key)
    try:
        return ws.execute_terminal_cmd(req.command_text, req.selected_ip)
    except Exception as exc:
        logger.error("執行指令失敗: %r", exc)
        raise HTTPException(status_code=500, detail=f"執行指令失敗: {exc}") from exc


@router.get("/report_payload/{client_ip}", summary="取得 PDF 報告預備資料")
async def get_report_payload(
    client_ip: str,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
):
    verify_api_key(x_api_key)
    try:
        return ws.generate_hacker_pdf(client_ip)
    except Exception as exc:
        logger.error("取得報告資料失敗: %r", exc)
        raise HTTPException(status_code=500, detail=f"取得報告資料失敗: {exc}") from exc


@router.get("/ip_bundle/{client_ip}", summary="取得主視窗整合資訊")
async def get_ip_bundle(
    client_ip: str,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
):
    verify_api_key(x_api_key)
    try:
        result = ws.get_dashboard_ip_bundle(client_ip)
        if not result:
            raise HTTPException(status_code=404, detail="查無此 IP 整合資料")
        return result
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("取得 IP 整合資料失敗: %r", exc)
        raise HTTPException(
            status_code=500, detail=f"取得 IP 整合資料失敗: {exc}"
        ) from exc


@router.get("/statistics/country", summary="按國家統計攻擊數與連線")
async def get_country_stats(
    limit: int = Query(20, ge=1, le=100, description="國家數上限"),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
):
    verify_api_key(x_api_key)
    try:
        return ws.get_country_statistics(limit)
    except Exception as exc:
        logger.error("取得國家統計失敗: %r", exc)
        raise HTTPException(status_code=500, detail=f"取得國家統計失敗: {exc}") from exc


@router.get("/statistics/attack_vectors", summary="攻擊類型分布")
async def get_attack_vectors(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
):
    verify_api_key(x_api_key)
    try:
        return ws.get_attack_vector_distribution()
    except Exception as exc:
        logger.error("取得攻擊類型分布失敗: %r", exc)
        raise HTTPException(
            status_code=500, detail=f"取得攻擊類型分布失敗: {exc}"
        ) from exc


@router.get("/statistics/top_source_ips", summary="源 IP 熱點分布")
async def get_source_ips(
    limit: int = Query(20, ge=1, le=100, description="IP 筆數上限"),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
):
    verify_api_key(x_api_key)
    try:
        return ws.get_top_source_ips(limit)
    except Exception as exc:
        logger.error("取得源 IP 分布失敗: %r", exc)
        raise HTTPException(
            status_code=500, detail=f"取得源 IP 分布失敗: {exc}"
        ) from exc


@router.get("/statistics/time_series", summary="時間序列統計（小時粒度）")
async def get_time_series(
    hours: int = Query(24, ge=1, le=168, description="統計時間範圍（小時）"),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
):
    verify_api_key(x_api_key)
    try:
        return ws.get_time_series_stats(hours)
    except Exception as exc:
        logger.error("取得時間序列統計失敗: %r", exc)
        raise HTTPException(
            status_code=500, detail=f"取得時間序列統計失敗: {exc}"
        ) from exc


# ========== 鑑識事件標準化查詢層 API (Forensic Event Standardized Queries) ==========


@router.get(
    "/events/by_route/{route}",
    summary="按路由分類查詢事件（real 或 deception）",
    description="查詢按分流路由分類的事件。支援 real（真實用戶）或 deception（欺敵路由）。",
)
async def get_events_by_route(
    route: str,
    limit: int = Query(100, ge=1, le=500, description="筆數上限"),
    offset: int = Query(0, ge=0, description="分頁偏移"),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
):
    verify_api_key(x_api_key)
    try:
        return ws.get_events_by_route(route, limit=limit, offset=offset)
    except Exception as exc:
        logger.error("查詢路由事件失敗: %r", exc)
        raise HTTPException(status_code=500, detail=f"查詢路由事件失敗: {exc}") from exc


@router.get(
    "/events/by_risk_score",
    summary="按風險分數範圍查詢事件",
    description="查詢特定風險分數範圍內的事件（0-100）。",
)
async def get_events_by_risk_score(
    min_score: int = Query(0, ge=0, le=100, description="最低風險分數"),
    max_score: int = Query(100, ge=0, le=100, description="最高風險分數"),
    limit: int = Query(100, ge=1, le=500, description="筆數上限"),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
):
    verify_api_key(x_api_key)
    try:
        return ws.get_events_by_risk_score(min_score, max_score, limit)
    except Exception as exc:
        logger.error("查詢風險分數事件失敗: %r", exc)
        raise HTTPException(
            status_code=500, detail=f"查詢風險分數事件失敗: {exc}"
        ) from exc


@router.get(
    "/replay/{query_id}",
    summary="回放攻擊鏈",
    description="按 query_id 回放完整的一條攻擊鏈，包含時間軸、每步決策理由、風險評分。",
)
async def get_deception_chain_replay(
    query_id: str = Path(
        ..., min_length=1, max_length=100, description="用戶識別碼或查詢 ID"
    ),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
):
    verify_api_key(x_api_key)
    try:
        result = ws.get_deception_chain(query_id)
        if "error" in result and result.get("chain_length", 0) == 0:
            raise HTTPException(status_code=404, detail="查無該攻擊鏈事件")
        return result
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("回放攻擊鏈失敗: %r", exc)
        raise HTTPException(status_code=500, detail=f"回放攻擊鏈失敗: {exc}") from exc
