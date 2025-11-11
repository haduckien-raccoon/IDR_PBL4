from fastapi import APIRouter, Request, Form, HTTPException
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from app.models import BlockedIPModel
from app.workers.blocker import enqueue_block
import redis

router = APIRouter(prefix="/api/ip", tags=["block_ip"])
templates = Jinja2Templates(directory="app/templates")

# Redis connection (dùng để publish lệnh block/unblock nếu cần)
redis_conn = redis.Redis(host="localhost", port=6379, db=0)

@router.get("/")
async def index(request: Request):
    """
    Trang chính của API block_ip
    """
    blocked_ips = BlockedIPModel.get_all()
    return templates.TemplateResponse("block_ip_index.html", {"request": request, "blocked_ips": blocked_ips})

@router.post("/blocked")
async def block_ip(ip_address: str = Form(...), reason: str = Form("manual")):
    """
    Chặn IP thủ công
    """
    if not ip_address:
        raise HTTPException(status_code=400, detail="IP không hợp lệ")
    enqueue_block(ip_address, reason=reason)
    return RedirectResponse(url="/api/ip", status_code=303)

@router.post("/unblock_ip")
async def unblock_ip(ip_address: str = Form(...)):
    """
    Gỡ chặn IP
    """
    if not ip_address:
        raise HTTPException(status_code=400, detail="IP không hợp lệ")
    # gỡ khỏi DB và publish lệnh unblock
    redis_conn.publish("iptables_commands", f"UNBLOCK {ip_address}")
    BlockedIPModel.unblock_ip(ip_address)
    return RedirectResponse(url="/api/ip", status_code=303)
