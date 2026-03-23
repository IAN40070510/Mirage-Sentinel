from fastapi import APIRouter
from services import web_service as ws

router = APIRouter()

@router.get("/analysis/{ip}")
async def get_ip_analysis(ip: str):
    return ws.get_hacker_dwell_time(ip)