import logging
from fastapi import APIRouter, HTTPException, Query, Header
from pydantic import BaseModel, Field, validator
from services import web_service as ws

# 配置日誌記錄
logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/dashboard",
    tags=["Dashboard"]
)


# ===== Request Models =====

class MisjudgmentRequest(BaseModel):
    client_ip: str = Field(..., min_length=7, max_length=45, description="IP address")
    reason: str = Field(..., min_length=3, max_length=500, description="Misjudgment reason")


class CategoryRequest(BaseModel):
    category_name: str = Field(..., min_length=1, max_length=100, description="Category name")
    items: list | None = None


class CommandRequest(BaseModel):
    command_text: str = Field(..., min_length=3, max_length=1000, description="Command text")
    selected_ip: str | None = Field(default=None, max_length=45, description="Selected IP")


class TrafficQueryParams(BaseModel):
    """驗證流量查詢參數"""
    limit: int = Field(default=1000, ge=1, le=10000)
    mode: str = Field(default="all", pattern="^(all|attacks)$")


class RecentTrafficParams(BaseModel):
    """驗證近期流量查詢參數"""
    limit: int = Field(default=100, ge=1, le=500)
    mode: str = Field(default="all", pattern="^(all|attacks)$")


class LiveIpsParams(BaseModel):
    """驗證 IP 清單查詢參數"""
    limit: int = Field(default=500, ge=1, le=2000)


# ===== API Key 驗證 =====

def verify_api_key(x_api_key: str | None):
    if not x_api_key or not ws.validate_api_key(x_api_key):
        raise HTTPException(status_code=401, detail="Invalid API key")


# ===== 既有 API =====

@router.get("", summary="Dashboard API 入口")
async def dashboard_root():
    return {
        "service": "Mirage Dashboard API",
        "hint": "Use /api/v1/dashboard/* endpoints with X-API-Key",
        "examples": [
            "/api/v1/dashboard/recent_traffic",
            "/api/v1/dashboard/live_ips",
            "/api/v1/dashboard/traffic_compare",
        ],
    }

@router.get("/dwell_time/{client_ip}", summary="獲取駭客滯留時間與活躍狀態")
async def get_hacker_analysis(
    client_ip: str,
    x_api_key: str | None = Header(default=None, alias="X-API-Key")
):
    """
    根據 client_ip 取得：
    - ip
    - dwell_seconds
    - is_active
    """
    verify_api_key(x_api_key)
    try:
        result = ws.get_hacker_dwell_time(client_ip)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"取得駭客滯留時間失敗: {str(e)}")


@router.get("/interaction_depth/{client_ip}", summary="分析誘餌互動深度")
async def get_interaction_depth(
    client_ip: str,
    query_id: str = Query(..., description="指定查詢或互動識別碼"),
    x_api_key: str | None = Header(default=None)
):
    """
    根據 client_ip + query_id 分析互動深度
    """
    verify_api_key(x_api_key)
    try:
        result = ws.analyze_interaction_depth(client_ip, query_id)
        return result
    except Exception as e:
        logger.error(f"分析互動深度失敗: {repr(e)}")
        raise HTTPException(status_code=500, detail=f"分析互動深度失敗: {str(e)}")


@router.get("/attack_timeline/{client_ip}", summary="獲取攻擊行為路徑時間軸")
async def get_attack_timeline(
    client_ip: str,
    x_api_key: str | None = Header(default=None, alias="X-API-Key")
):
    """
    取得該 client_ip 的時間軸行為資料
    """
    verify_api_key(x_api_key)
    try:
        result = ws.get_attack_timeline(client_ip)
        return result
    except Exception as e:
        logger.error(f"取得攻擊時間軸失敗: {repr(e)}")
        raise HTTPException(status_code=500, detail=f"取得攻擊時間軸失敗: {str(e)}")


@router.get("/recent_traffic", summary="獲取近期流量日誌")
async def get_recent_traffic(
    limit: int = Query(100, ge=1, le=500, description="筆數上限"),
    mode: str = Query("all", pattern="^(all|attacks)$", description="all=全流量, attacks=僅攻擊"),
    x_api_key: str | None = Header(default=None, alias="X-API-Key")
):
    verify_api_key(x_api_key)
    try:
        return ws.fetch_recent_traffic(limit, mode)
    except Exception as e:
        logger.error(f"取得近期流量失敗: {repr(e)}")
        raise HTTPException(status_code=500, detail=f"取得近期流量失敗: {str(e)}")


@router.get("/auto_updates", summary="儀表板自動更新檢查")
async def get_auto_updates(
    x_api_key: str | None = Header(default=None, alias="X-API-Key")
):
    verify_api_key(x_api_key)
    try:
        return ws.auto_updates()
    except Exception as e:
        logger.error(f"取得更新狀態失敗: {repr(e)}")
        raise HTTPException(status_code=500, detail=f"取得更新狀態失敗: {str(e)}")


@router.post("/misjudgment", summary="標記誤判並存入資料夾")
async def log_misjudgment_event(
    req: MisjudgmentRequest,
    x_api_key: str | None = Header(default=None, alias="X-API-Key")
):
    """
    將誤判 IP 與原因寫入 error_log 資料夾
    """
    verify_api_key(x_api_key)
    try:
        ws.log_misjudgment(req.client_ip, req.reason)
        return {
            "status": "success",
            "message": f"IP {req.client_ip} 已記錄至誤判資料夾"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"記錄誤判失敗: {repr(e)}")
        raise HTTPException(status_code=500, detail=f"記錄誤判失敗: {str(e)}")


@router.get("/command_heatmap", summary="獲取最常輸入指令前十名")
async def get_top_commands(
    x_api_key: str | None = Header(default=None, alias="X-API-Key")
):
    """
    取得 raw_payload 前十名統計
    """
    verify_api_key(x_api_key)
    try:
        return ws.get_command_heatmap()["top_commands"]
    except Exception as e:
        logger.error(f"取得指令熱區圖資料失敗: {repr(e)}")
        raise HTTPException(status_code=500, detail=f"取得指令熱區圖資料失敗: {str(e)}")


@router.get("/ip_details/{client_ip}", summary="取得特定 IP 詳細資訊")
async def get_ip_detail(
    client_ip: str,
    x_api_key: str | None = Header(default=None, alias="X-API-Key")
):
    """
    取得單一 client_ip 的詳細資料
    """
    verify_api_key(x_api_key)
    try:
        result = ws.get_ip_details(client_ip)
        if not result:
            raise HTTPException(status_code=404, detail="查無此 IP 詳細資料")
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"取得 IP 詳細資料失敗: {repr(e)}")
        raise HTTPException(status_code=500, detail=f"取得 IP 詳細資料失敗: {str(e)}")


@router.get("/report/{client_ip}", summary="生成特定駭客行為報告書")
async def get_hacker_report(
    client_ip: str,
    x_api_key: str | None = Header(default=None, alias="X-API-Key")
):
    """
    綜合 dwell_time、attack_timeline、ip_details 產生報告
    """
    verify_api_key(x_api_key)
    try:
        analysis = ws.get_hacker_dwell_time(client_ip)
        timeline = ws.get_attack_timeline(client_ip)["timeline"]
        details = ws.get_ip_details(client_ip)

        if not details:
            raise HTTPException(status_code=404, detail="查無此 IP 紀錄")

        return {
            "report_title": f"Hacker Forensic Report - {client_ip}",
            "summary": analysis,
            "details": details,
            "full_trajectory": timeline
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"生成報告失敗: {repr(e)}")
        raise HTTPException(status_code=500, detail=f"生成報告失敗: {str(e)}")

@router.get("/live_ips", summary="取得資料庫中所有 IP 與簡易流量資訊")
async def get_live_ips(
    limit: int = Query(500, ge=1, le=2000, description="IP 筆數上限"),
    x_api_key: str | None = Header(default=None, alias="X-API-Key")
):
    verify_api_key(x_api_key)
    try:
        return ws.fetch_all_client_ips(limit)["items"]
    except Exception as e:
        logger.error(f"取得 IP 清單失敗: {repr(e)}")
        raise HTTPException(status_code=500, detail=f"取得 IP 清單失敗: {str(e)}")


@router.get("/traffic_compare", summary="取得正常與攻擊流量比較")
async def get_traffic_compare(
    limit: int = Query(1000, ge=1, le=10000, description="統計筆數上限"),
    x_api_key: str | None = Header(default=None, alias="X-API-Key")
):
    verify_api_key(x_api_key)
    try:
        data = ws.compare_traffic(limit)

        return data
    except Exception as e:
        logger.error(f"取得流量比較失敗: {repr(e)}")
        raise HTTPException(status_code=500, detail=f"取得流量比較失敗: {str(e)}")


@router.post("/set_category", summary="設定前端分類資料")
async def post_set_category(
    req: CategoryRequest,
    x_api_key: str | None = Header(default=None, alias="X-API-Key")
):
    verify_api_key(x_api_key)
    try:
        return ws.set_log_category(req.category_name, req.items)
    except Exception as e:
        logger.error(f"設定分類失敗: {repr(e)}")
        raise HTTPException(status_code=500, detail=f"設定分類失敗: {str(e)}")


@router.post("/terminal_cmd", summary="接收前端指令框命令")
async def post_terminal_cmd(
    req: CommandRequest,
    x_api_key: str | None = Header(default=None, alias="X-API-Key")
):
    verify_api_key(x_api_key)
    try:
        return ws.execute_terminal_cmd(req.command_text, req.selected_ip)
    except Exception as e:
        logger.error(f"執行指令失敗: {repr(e)}")
        raise HTTPException(status_code=500, detail=f"執行指令失敗: {str(e)}")


@router.get("/report_payload/{client_ip}", summary="取得 PDF 報告預備資料")
async def get_report_payload(
    client_ip: str,
    x_api_key: str | None = Header(default=None, alias="X-API-Key")
):
    verify_api_key(x_api_key)
    try:
        return ws.generate_hacker_pdf(client_ip)
    except Exception as e:
        logger.error(f"取得報告資料失敗: {repr(e)}")
        raise HTTPException(status_code=500, detail=f"取得報告資料失敗: {str(e)}")


@router.get("/ip_bundle/{client_ip}", summary="取得主視窗整合資訊")
async def get_ip_bundle(
    client_ip: str,
    x_api_key: str | None = Header(default=None, alias="X-API-Key")
):
    verify_api_key(x_api_key)
    try:
        result = ws.get_dashboard_ip_bundle(client_ip)
        if not result:
            raise HTTPException(status_code=404, detail="查無此 IP 整合資料")
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"取得 IP 整合資料失敗: {repr(e)}")
        raise HTTPException(status_code=500, detail=f"取得 IP 整合資料失敗: {str(e)}")