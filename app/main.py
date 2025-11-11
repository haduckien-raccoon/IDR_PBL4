from fastapi import FastAPI
from app.api import api_router
from app.database import init_db
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn

app = FastAPI(title="IDR Project API")
app.mount("/static", StaticFiles(directory="app/static"), name="static")

templates = Jinja2Templates(directory="app/templates")

@app.on_event("startup")
def on_startup():
    init_db()

# Gắn các router API
app.include_router(api_router)

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)


# from pathlib import Path
# from fastapi import FastAPI, Request
# from fastapi.responses import HTMLResponse, JSONResponse
# from fastapi.templating import Jinja2Templates
# from fastapi.staticfiles import StaticFiles
# from contextlib import asynccontextmanager  # 👈 [THÊM VÀO] Thêm contextlib

# from app.core.config import settings
# from app.core.logging import get_logger
# from app.database import init_db
# from app.api.dashboard import router as dashboard_router
# from app.api.ws import router as ws_router
# from app.api.alerts import router as alerts_router

# logger = get_logger(__name__)

# # ------------------------------------------------------
# # 1️⃣ Xác định đường dẫn tuyệt đối
# # ------------------------------------------------------
# APP_DIR = Path(__file__).parent
# STATIC_DIR = APP_DIR / "static"
# TEMPLATES_DIR = APP_DIR / "templates"


# # ------------------------------------------------------
# # 2️⃣ [SỬA] Định nghĩa Lifespan (Startup/Shutdown)
# # ------------------------------------------------------
# @asynccontextmanager
# async def lifespan(app: FastAPI):
#     """
#     Quản lý các sự kiện khi ứng dụng khởi động và tắt.
#     """
#     logger.info("🚀 Ứng dụng đang khởi động...")
    
#     # --- KHỞI TẠO DATABASE ---
#     # Di chuyển init_db() vào đây để đảm bảo nó chỉ chạy khi 
#     # ứng dụng khởi động, không phải khi tệp được nhập.
#     try:
#         init_db()
#         logger.info("✅ Database initialized successfully.")
#     except Exception as e:
#         logger.critical(f"❌ DATABASE INITIALIZATION FAILED: {e}", exc_info=True)
#         # Bạn có thể muốn 'raise' lỗi ở đây để dừng ứng dụng
#         # nếu không có DB thì ứng dụng không thể chạy.
#         # raise

#     # --- ĐĂNG KÝ ROUTER ---
#     # Cũng có thể thực hiện việc này ở đây hoặc bên ngoài. 
#     # Để ở đây giúp log startup sạch sẽ hơn.
#     try:
#         app.include_router(dashboard_router)
#         app.include_router(ws_router)
#         app.include_router(alerts_router)
#         logger.info("✅ Routers registered successfully.")
#     except Exception as e:
#         logger.error(f"❌ Failed to include routers: {e}")

#     # Ứng dụng hiện đã sẵn sàng
#     yield
    
#     # --- SHUTDOWN ---
#     # (Thêm code dọn dẹp nếu cần)
#     logger.info("🛑 Ứng dụng đang tắt...")


# # ------------------------------------------------------
# # 3️⃣ Khởi tạo ứng dụng FastAPI (sử dụng lifespan)
# # ------------------------------------------------------
# app = FastAPI(
#     title="IDR Project",
#     version="1.0.0",
#     description="Intrusion Detection & Response backend (FastAPI version)",
#     lifespan=lifespan  # 👈 [SỬA] Gán hàm lifespan cho app
# )

# # Giữ lại SECRET_KEY (nếu cần dùng cho JWT/session)
# app.state.SECRET_KEY = settings.SECRET_KEY

# # ------------------------------------------------------
# # 4️⃣ Cấu hình Templates và Static (Dùng đường dẫn tuyệt đối)
# # ------------------------------------------------------

# # Trỏ đến thư mục 'templates' của bạn
# templates = Jinja2Templates(directory=TEMPLATES_DIR)

# # Trỏ đến thư mục 'static'
# app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# # ------------------------------------------------------
# # 5️⃣ XÓA BỎ LỆNH GỌI init_db() VÀ ROUTER TỪ ĐÂY
# # ------------------------------------------------------
# # (Đã di chuyển logic này vào trong hàm 'lifespan' ở trên)


# # ------------------------------------------------------
# # 6️⃣ Định nghĩa đường dẫn cho Trang chủ (/)
# # ------------------------------------------------------
# @app.get("/", response_class=HTMLResponse)
# async def get_homepage(request: Request):
#     """
#     Đây là đường dẫn (route) cho trang chủ.
#     Nó sẽ trả về file 'index.html' từ thư mục 'app/templates'.
#     """
#     try:
#         return templates.TemplateResponse("index.html", {"request": request})
#     except Exception as e:
#         logger.error(f"Lỗi render template 'index.html': {e}", exc_info=True)
#         return HTMLResponse(content="<h1>Lỗi 500: Không thể tải template.</h1>", status_code=500)

# @app.get("/dashboard", response_class=HTMLResponse)
# async def dashboard_page(request: Request):
#     """
#     Trang Dashboard chính.
#     """
#     return templates.TemplateResponse("index.html", {"request": request})


# @app.get("/incidents", response_class=HTMLResponse)
# async def incidents_page(request: Request):
#     """
#     Trang quản lý sự kiện tấn công.
#     """
#     return templates.TemplateResponse("incident.html", {"request": request})


# @app.get("/analytics", response_class=HTMLResponse)
# async def analytics_page(request: Request):
#     """
#     Trang phân tích & thống kê.
#     """
#     return templates.TemplateResponse("analytics.html", {"request": request})


# @app.get("/settings", response_class=HTMLResponse)
# async def settings_page(request: Request):
#     """
#     Trang cấu hình hệ thống.
#     """
#     ctx = {
#         "request": request,
#         "db_url": "mysql+pymysql://idr_user:***@localhost:3306/ids_honeypot",
#         "smtp_host": "smtp.gmail.com",
#         "api_base": "/api"
#     }
#     return templates.TemplateResponse("settings.html", ctx)

# @app.get("/rules", response_class=HTMLResponse)
# async def rules_page(request: Request):
#     """
#     Trang quản lý IDS Rules.
#     """
#     return templates.TemplateResponse("rules.html", {"request": request})

# @app.get("/login", response_class=HTMLResponse)
# async def login_page(request: Request):
#     """
#     Trang đăng nhập hệ thống.
#     """
#     return templates.TemplateResponse("login.html", {"request": request})

# # ------------------------------------------------------
# # 7️⃣ Endpoint kiểm tra tình trạng hệ thống
# # ------------------------------------------------------
# @app.get("/health")
# async def health():
#     """Kiểm tra trạng thái server."""
#     return JSONResponse(content={"status": "ok"})