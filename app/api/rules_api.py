import os
import uuid as uuid_lib
from fastapi import FastAPI, Request, Form, APIRouter
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from app.services.manager_rules import RulesManager
import datetime
from datetime import timedelta  

RULES_FILE = "app/capture_packet/rules.json"
app = FastAPI(title="IDS Rules API")
rules_manager = RulesManager(RULES_FILE)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

router = APIRouter(prefix="/api/rules", tags=["rules"])

WINDOW_DEFAULT = timedelta(hours=24)
@router.get("/", response_class=HTMLResponse)
def get_rules_ui(request: Request):
    rules = rules_manager.get_rules()
    return templates.TemplateResponse("rules.html", {"request": request, "rules": rules})


@router.post("/add_rule")
def add_rule(
    group_id: str = Form(...),
    message: str = Form(...),
    severity: str = Form("medium"),
    proto: str = Form("ANY"),
    dst_port: str = Form(None),
    pattern_regex_bytes: str = Form(None),
    use_aho: bool = Form(False),
    action: str = Form("alert"),
):
    payload = {
        "uuid": str(uuid_lib.uuid4()),
        "group_id": group_id,
        "message": message,
        "severity": severity,
        "proto": proto,
        "dst_port": dst_port,
        "pattern_regex_bytes": pattern_regex_bytes,
        "use_aho": use_aho,
        "action": action,
    }
    rules_manager.add_or_update(payload)
    return JSONResponse(content={"status": "success", "message": "Rule added"})


@router.post("/update_rules")
def update_rule(
    uuid: str = Form(...),
    group_id: str = Form(...),
    message: str = Form(...),
    severity: str = Form("medium"),
    proto: str = Form("ANY"),
    dst_port: str = Form(None),
    pattern_regex_bytes: str = Form(None),
    use_aho: bool = Form(False),
    action: str = Form("alert"),
):
    payload = {
        "uuid": uuid,
        "group_id": group_id,
        "message": message,
        "severity": severity,
        "proto": proto,
        "dst_port": dst_port,
        "pattern_regex_bytes": pattern_regex_bytes,
        "use_aho": use_aho,
        "action": action,
    }
    rules_manager.add_or_update(payload)
    return JSONResponse(content={"status": "success", "message": "Rule updated"})


@router.post("/delete_rule")
def delete_rule(uuid: str = Form(...)):
    ok = rules_manager.delete_by_uuid(uuid)
    if ok:
        return JSONResponse(content={"status": "success", "message": "Rule deleted"})
    else:
        return JSONResponse(content={"status": "error", "message": "Rule not found"})
