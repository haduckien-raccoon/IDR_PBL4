# app/api/rules.py

from fastapi import APIRouter, HTTPException
from typing import List, Dict, Any, Optional
import json
import os
from uuid import uuid4

router = APIRouter()

# === ĐƯỜNG DẪN TỚI rules.json ===
RULES_FILE_PATH = os.path.join(
    os.path.dirname(__file__),  # app/api
    "..",                       # app
    "capture_packet",
    "rules.json"
)

# ============= HÀM ĐỌC / GHI FILE ============= #

def get_rules_data() -> List[Dict[str, Any]]:
    """Đọc rules từ rules.json"""
    try:
        path = os.path.abspath(RULES_FILE_PATH)
        print(f"[rules.py] Loading rules from: {path}")
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            raise HTTPException(status_code=500, detail="rules.json must be an array")
        return data
    except Exception as e:
        print("[rules.py] ERROR:", e)
        raise HTTPException(status_code=500, detail="Cannot load rules.json")


def save_rules_data(rules: List[Dict[str, Any]]) -> None:
    """Ghi lại rules vào rules.json"""
    try:
        path = os.path.abspath(RULES_FILE_PATH)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(rules, f, ensure_ascii=False, indent=4)
        print(f"[rules.py] Saved {len(rules)} rules to {path}")
    except Exception as e:
        print("[rules.py] ERROR saving:", e)
        raise HTTPException(status_code=500, detail="Cannot save rules.json")


# ============= HÀM CHUẨN HÓA GIÁ TRỊ ============= #

def normalize(value: Optional[str]):
    """Chuyển ALL / Any / '' thành None để dễ xử lý"""
    if not value:
        return None
    v = value.strip().lower()
    if v in ("all", "any", "none"):
        return None
    return v


def get_severity(rule: Dict[str, Any]) -> str:
    """Fix luôn lỗi 'severity' viết sai thành 'severty' """
    return str(rule.get("severity", rule.get("severty", "low"))).lower()


# ============= API RULE LIST (GET + FILTER) ============= #

@router.get("/rules")
async def read_all_rules(
    severity: Optional[str] = None,
    proto: Optional[str] = None,
    group_name: Optional[str] = None
):
    """
    API lọc rules:
    - severity: high, medium, low, critical
    - proto: tcp, udp, http, any
    - group_name: tên nhóm rule (group_id)
    """

    rules = get_rules_data()
    result = []

    # Chuẩn hóa filter
    f_severity = normalize(severity)
    f_proto = normalize(proto)
    f_group = normalize(group_name)

    for rule in rules:
        # ----- LỌC SEVERITY -----
        r_sev = get_severity(rule)
        if f_severity and r_sev != f_severity:
            continue

        # ----- LỌC PROTOCOL -----
        r_proto = str(rule.get("proto", "any")).lower()
        # cho phép nhiều proto: "tcp/udp/http"
        r_proto_list = [p.strip() for p in r_proto.replace("/", ",").split(",") if p.strip()]

        if f_proto:
            if f_proto not in r_proto_list and f_proto != "any":
                continue

        # ----- LỌC GROUP NAME -----
        # luôn chuyển về string, strip và lower để so sánh cho chắc
        r_group = str(rule.get("group_id", "")).strip().lower()
        if f_group and r_group != f_group:
            continue

        result.append(rule)

    return result


# ============= API STATS ============= #

@router.get("/rules/stats")
async def get_rules_statistics():
    rules = get_rules_data()

    severity_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for r in rules:
        sev = get_severity(r)
        if sev in severity_count:
            severity_count[sev] += 1

    groups = sorted({r.get("group_id", "N/A") for r in rules})

    return {
        "total": len(rules),
        "critical": severity_count["critical"],
        "high": severity_count["high"],
        "medium": severity_count["medium"],
        "low": severity_count["low"],
        "group_names": groups
    }


# ============= API CREATE RULE ============= #

@router.post("/rules")
async def create_rule(rule: Dict[str, Any]):
    """
    Thêm rule mới vào rules.json.
    Nếu frontend không gửi uuid thì backend tự sinh.
    """
    rules = get_rules_data()

    # sinh uuid nếu thiếu
    if not rule.get("uuid"):
        rule["uuid"] = str(uuid4())

    # đảm bảo có severity (đúng key)
    if "severity" not in rule and "severty" in rule:
        rule["severity"] = rule.pop("severty")

    # ép kiểu một số field
    if isinstance(rule.get("dst_port"), str) and rule["dst_port"].isdigit():
        rule["dst_port"] = int(rule["dst_port"])

    # field / flow / content có thể là string => convert sang list
    for key in ("field", "flow", "content"):
        if isinstance(rule.get(key), str):
            rule[key] = [s.strip() for s in rule[key].split(",") if s.strip()]

    rules.append(rule)
    save_rules_data(rules)
    return rule


# ============= API UPDATE RULE ============= #

@router.put("/rules/{uuid}")
async def update_rule(uuid: str, rule_update: Dict[str, Any]):
    """
    Cập nhật rule theo uuid. Chỉ sửa các field gửi từ frontend.
    """
    rules = get_rules_data()
    for idx, r in enumerate(rules):
        if r.get("uuid") == uuid:
            # không cho sửa uuid
            rule_update["uuid"] = uuid

            if "severity" not in rule_update and "severty" in rule_update:
                rule_update["severity"] = rule_update.pop("severty")

            # ép kiểu dst_port nếu cần
            if isinstance(rule_update.get("dst_port"), str) and rule_update["dst_port"].isdigit():
                rule_update["dst_port"] = int(rule_update["dst_port"])

            for key in ("field", "flow", "content"):
                if isinstance(rule_update.get(key), str):
                    rule_update[key] = [s.strip() for s in rule_update[key].split(",") if s.strip()]

            # giữ lại các field cũ nếu frontend không gửi
            updated = {**r, **rule_update}
            rules[idx] = updated
            save_rules_data(rules)
            return updated

    raise HTTPException(status_code=404, detail=f"Rule with uuid={uuid} not found")


# ============= API DELETE RULE ============= #

@router.delete("/rules/{uuid}")
async def delete_rule(uuid: str):
    rules = get_rules_data()
    new_rules = [r for r in rules if r.get("uuid") != uuid]

    if len(new_rules) == len(rules):
        raise HTTPException(status_code=404, detail=f"Rule with uuid={uuid} not found")

    save_rules_data(new_rules)
    return {"deleted": True, "uuid": uuid}
