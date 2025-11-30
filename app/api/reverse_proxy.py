# app/api/reverse_proxy.py
import os, re, shutil, time, subprocess
from fastapi import APIRouter, HTTPException, Form
from pydantic import BaseModel

router = APIRouter(prefix="/api/reverse-proxy", tags=["reverse-proxy"])

# --- CẤU HÌNH ---
# Trong môi trường dev Window, bạn có thể trỏ đến file giả lập
NGINX_CONF = "/etc/nginx/sites-available/reverse-proxy" 
# Nếu chạy trên Windows để test giao diện, hãy dùng file tạm:
if os.name == 'nt':
    NGINX_CONF = "nginx_mock.conf"
    if not os.path.exists(NGINX_CONF):
        with open(NGINX_CONF, "w") as f:
            f.write("server { listen 80; location / { proxy_pass http://127.0.0.1:8080; } }")

BACKUP_DIR = "backups/nginx"
os.makedirs(BACKUP_DIR, exist_ok=True)

DEFAULT_PROXY_RE = re.compile(r"proxy_pass\s+[^;]+;")

class ProxyConfigResponse(BaseModel):
    content: str
    target: str

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
    # Nếu đang chạy dev mode (không phải Linux server thật), bỏ qua reload
        
    test = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
    if test.returncode != 0:
        return False, test.stderr
    reload = subprocess.run(["systemctl", "reload", "nginx"], capture_output=True, text=True)
    if reload.returncode != 0:
        return False, reload.stderr
    return True, "Reload OK"

@router.get("/config")
def get_config():
    """Đọc nội dung file config hiện tại"""
    try:
        with open(NGINX_CONF, "r") as f:
            content = f.read()
        
        # Trích xuất target hiện tại để điền vào input
        match = DEFAULT_PROXY_RE.search(content)
        current_target = ""
        if match:
            # Lấy chuỗi 'http://...' từ 'proxy_pass http://...;'
            raw = match.group(0) # proxy_pass http://...;
            current_target = raw.replace("proxy_pass", "").replace(";", "").strip()

        return {"content": content, "target": current_target}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/update")
def update_config(target: str = Form(...)):
    """Cập nhật proxy_pass và reload nginx"""
    try:
        with open(NGINX_CONF, "r") as f:
            orig = f.read()

        backup = backup_file(NGINX_CONF)
        new_content = patch_proxy_pass(orig, target)
        
        if not new_content:
            return {"status": "error", "message": "No 'proxy_pass' directive found in config file!"}

        with open(NGINX_CONF, "w") as f:
            f.write(new_content)

        ok, msg = nginx_test_reload()
        if not ok:
            # Rollback nếu lỗi
            shutil.copy(backup, NGINX_CONF)
            return {"status": "error", "message": f"Nginx Error: {msg}. Rolled back."}
        
        return {"status": "success", "message": f"Updated proxy to {target}. {msg}", "new_content": new_content}

    except Exception as e:
        return {"status": "error", "message": str(e)}