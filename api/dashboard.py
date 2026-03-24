from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from services import web_service as ws

router = APIRouter(
    prefix="/dashboard",
    tags=["Dashboard"]
)


class MisjudgmentRequest(BaseModel):
    client_ip: str
    reason: str


@router.get("/dwell_time/{client_ip}", summary="獲取駭客滯留時間與活躍狀態")
async def get_hacker_analysis(client_ip: str):
    """
    根據 client_ip 取得：
    - client_ip
    - dwell_seconds
    - is_active
    """
    try:
        result = ws.get_hacker_dwell_time(client_ip)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"取得駭客滯留時間失敗: {str(e)}")


@router.get("/interaction_depth/{client_ip}", summary="分析誘餌互動深度")
async def get_interaction_depth(
    client_ip: str,
    query_id: str = Query(..., description="指定查詢或互動識別碼")
):
    """
    根據 client_ip + query_id 分析互動深度
    """
    try:
        result = ws.analyze_interaction_depth(client_ip, query_id)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"分析互動深度失敗: {str(e)}")


@router.get("/attack_timeline/{client_ip}", summary="獲取攻擊行為路徑時間軸")
async def get_attack_timeline(client_ip: str):
    """
    取得該 client_ip 的時間軸行為資料
    """
    try:
        result = ws.get_attack_timeline(client_ip)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"取得攻擊時間軸失敗: {str(e)}")


@router.get("/recent_traffic", summary="獲取近期流量日誌")
async def get_recent_traffic(
    limit: int = Query(100, ge=1, le=500, description="筆數上限"),
    mode: str = Query("all", pattern="^(all|attacks)$", description="all=全流量, attacks=僅攻擊"),
):
    try:
        return ws.fetch_recent_traffic(limit, mode)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"取得近期流量失敗: {str(e)}")


@router.get("/auto_updates", summary="儀表板自動更新檢查")
async def get_auto_updates():
    try:
        return ws.auto_updates()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"取得更新狀態失敗: {str(e)}")


@router.post("/misjudgment", summary="標記誤判並存入資料夾")
async def log_misjudgment_event(req: MisjudgmentRequest):
    """
    將誤判 IP 與原因寫入 error_log 資料夾
    """
    try:
        ws.log_misjudgment(req.client_ip, req.reason)
        return {
            "status": "success",
            "message": f"IP {req.client_ip} 已記錄至誤判資料夾"
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"記錄誤判失敗: {str(e)}")


@router.get("/command_heatmap", summary="獲取最常輸入指令前十名")
async def get_top_commands():
    """
    取得 raw_payload 前十名統計
    """
    try:
        result = ws.get_command_heatmap()
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"取得指令熱區圖資料失敗: {str(e)}")


@router.get("/ip_details/{client_ip}", summary="取得特定 IP 詳細資訊")
async def get_ip_detail(client_ip: str):
    """
    取得單一 client_ip 的詳細資料
    """
    try:
        result = ws.get_ip_details(client_ip)
        if not result:
            raise HTTPException(status_code=404, detail="查無此 IP 詳細資料")
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"取得 IP 詳細資料失敗: {str(e)}")


@router.get("/report/{client_ip}", summary="生成特定駭客行為報告書")
async def get_hacker_report(client_ip: str):
    """
    綜合 dwell_time、attack_timeline、ip_details 產生報告
    """
    try:
        analysis = ws.get_hacker_dwell_time(client_ip)
        timeline = ws.get_attack_timeline(client_ip)
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
        raise HTTPException(status_code=500, detail=f"生成報告失敗: {str(e)}")