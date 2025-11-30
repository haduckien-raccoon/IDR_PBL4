from fastapi import APIRouter, Request, Form, HTTPException
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from app.models import BlockedIPModel
from app.workers.blocker import enqueue_block
import redis

router = APIRouter(prefix="/blockip", tags=["block_ip"])
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
    
    # Đưa job cho worker xử lý iptables (nếu bạn đang dùng queue)
    try:
        enqueue_block(ip_address, reason=reason)
    except Exception:
        # Nếu worker chưa chạy thì bỏ qua, vẫn cập nhật DB
        pass

    # Cập nhật DB ngay để giao diện phản ánh trạng thái
    try:
        # Hàm này nên set status = "blocked", cập nhật lý do + thời gian
        BlockedIPModel.block_ip(ip_address, reason)
    except AttributeError:
        # Nếu project cũ chưa có hàm block_ip, bỏ qua (UI sẽ phụ thuộc worker)
        pass
    return RedirectResponse(url="/blockip", status_code=303)

@router.post("/unblock_ip")
async def unblock_ip(ip_address: str = Form(...)):
    """
    Gỡ chặn IP
    """
    if not ip_address:
        raise HTTPException(status_code=400, detail="IP không hợp lệ")
    if redis_conn is not None:
        try:
            redis_conn.publish("iptables_commands", f"UNBLOCK {ip_address}")
        except Exception:
            # có thể log ra nếu muốn, nhưng không để 500
            pass
    BlockedIPModel.unblock_ip(ip_address)
    return RedirectResponse(url="/blockip", status_code=303)
