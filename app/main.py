# from fastapi import FastAPI
# from app.api import api_router
# from app.database import init_db
# from fastapi.staticfiles import StaticFiles
# from fastapi.templating import Jinja2Templates
# import uvicorn
# # from app.workers.send_mail_worker import start_mail_workers

# app = FastAPI(title="IDR Project API")
# app.mount("/static", StaticFiles(directory="app/static"), name="static")

# templates = Jinja2Templates(directory="app/templates")

# @app.on_event("startup")
# def on_startup():
#     init_db()
#     # start_mail_workers(num_workers=1) 

# # Gắn các router API
# app.include_router(api_router)

# if __name__ == "__main__":
#     uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)


from pathlib import Path
from fastapi import FastAPI, Request, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager  # 👈 [THÊM VÀO] Thêm contextlib
from typing import Optional  # 👈 Import Optional for type hinting

from app.core.config import settings
from app.core.logging import get_logger
from app.database import init_db
from app.api.dashboard import router as dashboard_router
from app.api.ws import router as ws_router
from app.api.alerts import router as alerts_router
from app.api import api_router
from app.api.incident import router as incident_router
from app.api.rules import router as rules_router
from app.api.analytics import router as analytics_router
from app.api.ssh_terminal import router as ssh_router
from app.api.reverse_proxy import router as reverse_proxy_router
from app.api import view_log   


logger = get_logger(__name__)

# ------------------------------------------------------
# 1️⃣ Xác định đường dẫn tuyệt đối
# ------------------------------------------------------
APP_DIR = Path(__file__).parent
STATIC_DIR = APP_DIR / "static"
TEMPLATES_DIR = APP_DIR / "templates"


# ------------------------------------------------------
# 2️⃣ [SỬA] Định nghĩa Lifespan (Startup/Shutdown)
# ------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Quản lý các sự kiện khi ứng dụng khởi động và tắt.
    """
    logger.info("🚀 Ứng dụng đang khởi động...")
    
    # --- KHỞI TẠO DATABASE ---
    try:
        init_db()
        logger.info("✅ Database initialized successfully.")
    except Exception as e:
        logger.critical(f"❌ DATABASE INITIALIZATION FAILED: {e}", exc_info=True)

    # --- ĐĂNG KÝ ROUTER ---
    try:
        app.include_router(dashboard_router)
        app.include_router(ws_router)
        app.include_router(alerts_router)
        app.include_router(api_router)
        app.include_router(incident_router, prefix="/api", tags=["Incidents"])
        app.include_router(rules_router, prefix="/api", tags=["Rules"])
        app.include_router(analytics_router, prefix="/api", tags=["Analytics"])
        app.include_router(ssh_router, prefix="/api", tags=["SSH"])
        app.include_router(reverse_proxy_router, prefix="/api", tags=["Reverse Proxy"])
        app.include_router(view_log.router)
        # Khởi động tailer đọc traffic.log và ai_alerts.log
        await view_log.start_log_tailers()
        logger.info("✅ Routers registered successfully.")
    except Exception as e:
        logger.error(f"❌ Failed to include routers: {e}")

    # Ứng dụng hiện đã sẵn sàng
    yield
    logger.info("🛑 Ứng dụng đang tắt...")


# ------------------------------------------------------
# 3️⃣ Khởi tạo ứng dụng FastAPI (sử dụng lifespan)
# ------------------------------------------------------
app = FastAPI(
    title="IDR Project",
    version="1.0.0",
    description="Intrusion Detection & Response backend (FastAPI version)",
    lifespan=lifespan
)

# Giữ lại SECRET_KEY (nếu cần dùng cho JWT/session)
app.state.SECRET_KEY = settings.SECRET_KEY

# ------------------------------------------------------
# 4️⃣ Cấu hình Templates và Static (Dùng đường dẫn tuyệt đối)
# ------------------------------------------------------

# Trỏ đến thư mục 'templates' của bạn
templates = Jinja2Templates(directory=TEMPLATES_DIR)

# Trỏ đến thư mục 'static'
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# ------------------------------------------------------
# 5️⃣ XÓA BỎ LỆNH GỌI init_db() VÀ ROUTER TỪ ĐÂY
# ------------------------------------------------------

def _tpl_ctx(request: Request) -> dict:
    return {
        "request": request,
        "api_base": "",   # same-origin API
        "ws_path": "/ws"  # adjust if needed
    }

# ------------------------------------------------------
# 6️⃣ Định nghĩa đường dẫn cho Trang chủ (/)
# ------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
async def get_homepage(request: Request):
    """
    Đây là đường dẫn (route) cho trang chủ.
    Nó sẽ trả về file 'index.html' từ thư mục 'app/templates'.
    """
    try:
        return templates.TemplateResponse("index.html",  _tpl_ctx(request))
    except Exception as e:
        logger.error(f"Lỗi render template 'index.html': {e}", exc_info=True)
        return HTMLResponse(content="<h1>Lỗi 500: Không thể tải template.</h1>", status_code=500)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    """
    Trang Dashboard chính.
    """
    return templates.TemplateResponse("index.html",  _tpl_ctx(request))


@app.get("/incidents", response_class=HTMLResponse)
async def incidents_page(request: Request):
    """
    Trang quản lý sự kiện tấn công.
    """
    return templates.TemplateResponse("incident.html", {"request": request})

@app.get("/alerts", response_class=HTMLResponse)
async def alerts_page(request: Request):
    """
    Trang IDS Alerts (DB) – khác với Alert Logs từ file.
    """
    return templates.TemplateResponse("alerts.html", {"request": request})

@app.get("/traffic", response_class=HTMLResponse)
async def alerts_page(request: Request):
    return templates.TemplateResponse("traffic.html", {"request": request})


@app.get("/analytics", response_class=HTMLResponse)
async def analytics_page(request: Request):
    """
    Trang phân tích & thống kê.
    """
    return templates.TemplateResponse("analytics.html", {"request": request})


@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    """
    Trang cấu hình hệ thống.
    """
    ctx = {
        "request": request,
        "db_url": "mysql+pymysql://idr_user:***@localhost:3306/ids_honeypot",
        "smtp_host": "smtp.gmail.com",
        "api_base": "/api"
    }
    return templates.TemplateResponse("settings.html", ctx)

@app.get("/ssh")
async def ssh_page(request: Request):
    """
    Trang ssh terminal.
    """
    return templates.TemplateResponse("ssh.html", {"request": request})

@app.get("/rules", response_class=HTMLResponse)
async def rules_page(request: Request):
    """
    Trang quản lý IDS Rules.
    """
    return templates.TemplateResponse("rules.html", {"request": request})

@app.get("/ai", response_class=HTMLResponse)
async def ai_page(request: Request):
    """
    Trang quản lý IDS AI.
    """
    return templates.TemplateResponse("view_ai.html", {"request": request})
    
@app.get("/reverse-proxy", response_class=HTMLResponse)
async def proxy_page(request: Request):
    """Trang cấu hình Reverse Proxy"""
    return templates.TemplateResponse("reverse_proxy.html", {"request": request})

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """
    Trang đăng nhập hệ thống.
    """
    return templates.TemplateResponse("login.html", {"request": request})

# ------------------------------------------------------
# 7️⃣ Endpoint kiểm tra tình trạng hệ thống
# ------------------------------------------------------
@app.get("/health")
async def health():
    """Kiểm tra trạng thái server."""
    return JSONResponse(content={"status": "ok"})