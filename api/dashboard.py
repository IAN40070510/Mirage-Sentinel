from fastapi import APIRouter, HTTPException
from services import web_service as ws
from pydantic import BaseModel

router = APIRouter()

class MisjudgmentRequest(BaseModel):
    attacker_ip: str
    reason: str

# 駭客滯留時間與詳細資訊分析
@router.get("/dwell_time/{ip}", summary="獲取駭客滯留時間與活躍狀態")
async def get_hacker_analysis(ip: str):
    result = ws.get_hacker_dwell_time(ip)
    if not result:
        raise HTTPException(status_code=404, detail="查無此 IP 紀錄")
    return result

# 誘餌互動深度
@router.get("/interaction_depth/{ip}", summary="分析誘餌互動深度")
async def get_interaction_depth(ip: str, query_id: str):
    return ws.analyze_interaction_depth(ip, query_id)

# 攻擊軌跡時間軸
@router.get("/attack_timeline/{ip}", summary="獲取攻擊行為路徑時間軸")
async def get_attack_timeline(ip: str):
    return ws.get_attack_timeline(ip)

# 糾錯機制
@router.post("/misjudgment", summary="標記誤判並存入資料夾")
async def log_misjudgment_event(req: MisjudgmentRequest):
    try:
        ws.log_misjudgment(req.attacker_ip, req.reason)
        return {"status": "success", "message": f"IP {req.attacker_ip} 已記錄至誤判資料夾"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# 攻擊指令熱區圖
@router.get("/command_heatmap", summary="獲取最常輸入指令前十名")
async def get_top_commands():
    return ws.get_command_heatmap()

# 自動更新狀態 (供前端 5 秒輪詢確認)
@router.get("/update-status", summary="自動更新同步檢查")
async def get_update_status():
    return ws.auto_updates()

# 特定駭客資訊報告 (鎖定特定駭客)
@router.get("/report/{ip}", summary="生成特定駭客行為報告書")
async def get_hacker_report(ip: str):
    # 這裡調用 timeline 與 analysis 的綜合數據作為報告
    analysis = ws.get_hacker_dwell_time(ip)
    timeline = ws.get_attack_timeline(ip)
    return {
        "report_title": f"Hacker Forensic Report - {ip}",
        "summary": analysis,
        "full_trajectory": timeline
    }