# #!/usr/bin/env python3
# import os, re, shutil, time, subprocess
# from fastapi import FastAPI, Request, Form, APIRouter
# from fastapi.responses import HTMLResponse, RedirectResponse
# from fastapi.templating import Jinja2Templates
# from fastapi.staticfiles import StaticFiles
# from starlette.websockets import WebSocket

# app = FastAPI()
# router = APIRouter(prefix="/api/reverse-proxy", tags=["rules"])
# templates = Jinja2Templates(directory="app/templates")

# # mount static files
# app.mount("/static", StaticFiles(directory="app/static"), name="static")

# NGINX_CONF = "/etc/nginx/sites-available/reverse-proxy"
# BACKUP_DIR = "/etc/nginx/backups"
# os.makedirs(BACKUP_DIR, exist_ok=True)

# DEFAULT_PROXY_RE = re.compile(r"proxy_pass\s+[^;]+;")

# def timestamp():
#     return time.strftime("%Y%m%d%H%M%S")

# def backup_file(path):
#     backup = os.path.join(BACKUP_DIR, f"{os.path.basename(path)}.{timestamp()}.bak")
#     shutil.copy(path, backup)
#     return backup

# def patch_proxy_pass(content: str, new_target: str) -> str | None:
#     new_directive = f"proxy_pass {new_target};"
#     new_content, n = DEFAULT_PROXY_RE.subn(new_directive, content, count=1)
#     return new_content if n > 0 else None

# def nginx_test_reload() -> tuple[bool, str]:
#     test = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
#     if test.returncode != 0:
#         return False, test.stderr
#     reload = subprocess.run(["systemctl", "reload", "nginx"], capture_output=True, text=True)
#     if reload.returncode != 0:
#         return False, reload.stderr
#     return True, "Reload OK"

# @router.get("/", response_class=HTMLResponse)
# async def index(request: Request, msg: str = "", category: str = ""):
#     with open(NGINX_CONF) as f:
#         cfg = f.read()
#     return templates.TemplateResponse("reverse_proxy.html", {
#         "request": request,
#         "config": cfg,
#         "msg": msg,
#         "category": category
#     })

# @router.post("/update")
# async def update(target: str = Form(...)):
#     with open(NGINX_CONF) as f:
#         orig = f.read()

#     backup = backup_file(NGINX_CONF)
#     new_content = patch_proxy_pass(orig, target)
#     if not new_content:
#         return RedirectResponse(url=f"/?msg=No+proxy_pass+directive+found!&category=error", status_code=303)

#     with open(NGINX_CONF, "w") as f:
#         f.write(new_content)

#     ok, msg = nginx_test_reload()
#     if not ok:
#         shutil.copy(backup, NGINX_CONF)
#         return RedirectResponse(url=f"/?msg=Error:+{msg}.+Rolled+back.&category=error", status_code=303)
#     else:
#         return RedirectResponse(url=f"/?msg=Proxy+updated+to+{target}.+{msg}&category=success", status_code=303)

# # optional: realtime log streaming with WebSocket
# @router.websocket("/ws")
# async def websocket_endpoint(websocket: WebSocket):
#     await websocket.accept()
#     await websocket.send_text("WebSocket connected. Future: stream nginx logs here.")
#     await websocket.close()
#!/usr/bin/env python3
import os, re, shutil, time, subprocess
from fastapi import FastAPI, Request, Form, APIRouter
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from starlette.websockets import WebSocket

app = FastAPI()
router = APIRouter(prefix="/api/reverse-proxy", tags=["rules"])
templates = Jinja2Templates(directory="app/templates")

# mount static files
app.mount("/static", StaticFiles(directory="app/static"), name="static")

NGINX_CONF = "/etc/nginx/sites-available/reverse-proxy"
BACKUP_DIR = "/etc/nginx/backups"
os.makedirs(BACKUP_DIR, exist_ok=True)

DEFAULT_PROXY_RE = re.compile(r"proxy_pass\s+[^;]+;")

def timestamp():
    return time.strftime("%Y%m%d%H%M%S")

def backup_file(path):
    backup = os.path.join(BACKUP_DIR, f"{os.path.basename(path)}.{timestamp()}.bak")
    shutil.copy(path, backup)
    return backup

def patch_proxy_pass(content: str, new_target: str) -> str | None:
    new_directive = f"proxy_pass {new_target};"
    new_content, n = DEFAULT_PROXY_RE.subn(new_directive, content, count=1)
    return new_content if n > 0 else None

def nginx_test_reload() -> tuple[bool, str]:
    test = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
    if test.returncode != 0:
        return False, test.stderr
    reload = subprocess.run(["systemctl", "reload", "nginx"], capture_output=True, text=True)
    if reload.returncode != 0:
        return False, reload.stderr
    return True, "Reload OK"

@router.get("/", response_class=HTMLResponse)
async def index(request: Request, msg: str = "", category: str = ""):
    try:
        with open(NGINX_CONF) as f:
            cfg = f.read()
    except Exception as e:
        cfg = f"[Error reading config: {e}]"
    return templates.TemplateResponse("reverse_proxy.html", {
        "request": request,
        "config": cfg,
        "msg": msg,
        "category": category
    })

@router.post("/update")
async def update(target: str = Form(...)):
    with open(NGINX_CONF) as f:
        orig = f.read()

    backup = backup_file(NGINX_CONF)
    new_content = patch_proxy_pass(orig, target)
    if not new_content:
        return RedirectResponse(
            url=f"/api/reverse-proxy/?msg=No+proxy_pass+directive+found!&category=error",
            status_code=303
        )

    with open(NGINX_CONF, "w") as f:
        f.write(new_content)

    ok, msg = nginx_test_reload()
    if not ok:
        # rollback
        shutil.copy(backup, NGINX_CONF)
        return RedirectResponse(
            url=f"/api/reverse-proxy/?msg=Error:+{msg}.+Rolled+back.&category=error",
            status_code=303
        )
    else:
        return RedirectResponse(
            url=f"/api/reverse-proxy/?msg=Proxy+updated+to+{target}.+{msg}&category=success",
            status_code=303
        )

# optional: realtime log streaming with WebSocket
@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    await websocket.send_text("WebSocket connected. Future: stream nginx logs here.")
    await websocket.close()

# mount the router
app.include_router(router)
