# app/workers/ai_traffic_worker.py
import asyncio
import os
import json
from datetime import datetime
from typing import List
import uuid
from uuid import uuid4 as generate_uuid
import base64
import requests
from asyncio import to_thread
from app.services.cai_project.testGM import main_cai_flow
from app.api.alerts import _send_email_sync
import random
from app.core.config import settings
from app.core.logging import get_logger
from app.database import get_session
from app.models import AttackType, Event, Alert
from app.api.alerts import map_severity_to_alert_level, emit_alert_realtime
from app.database import db, get_session
from app.services.analyzer import Analyzer
from app.models import Event, Alert, AttackType, IncidentReport
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from datetime import timezone
#im port request for api call
import requests

engine = create_engine(settings.DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
LOG_FILE = "app/logs/traffic.log"
STATE_FILE = "app/workers/ai_state.json"
ALERT_LOG = "app/logs/ai_alerts.log"
API_ALERT_ENDPOINT = "http://127.0.0.1:8000/api/alerts/raw"
POLL_INTERVAL = 2
THROTTLE_MIN = 1  # giây
THROTTLE_MAX = 3  # giây
logger = get_logger(__name__)

# ---- Offset helpers ----
def load_offset() -> int:
    try:
        if not os.path.exists(STATE_FILE):
            return 0
        with open(STATE_FILE, "r") as f:
            state = json.load(f)
            return int(state.get("offset", 0))
    except (IOError, json.JSONDecodeError, ValueError) as e:
        print(f"[WARN] Failed to load offset, starting from beginning. Reason: {e}")
        return 0


def save_offset(offset: int):
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        tmp_file = STATE_FILE + ".tmp"
        with open(tmp_file, "w") as f:
            json.dump({"offset": offset}, f)
        os.replace(tmp_file, STATE_FILE)
    except IOError as e:
        print(f"[ERROR] Could not save offset: {e}")


# ---- Alert logging ----
def append_alert(result: dict, raw_block: str):
    try:
        os.makedirs(os.path.dirname(ALERT_LOG), exist_ok=True)
        with open(ALERT_LOG, "a", encoding="utf-8") as f:
            f.write(f"[{datetime.now().isoformat()}] ALERT\n")
            json.dump(result, f, ensure_ascii=False, indent=2)
            f.write("\nRAW_BLOCK:\n" + raw_block + "\n" + "-" * 80 + "\n")
    except IOError as e:
        print(f"[WARN] append_alert failed: {e}")


# ---- SUSPICIOUS DETECTION ----
def is_suspicious_block(block: str) -> bool:
    b = block.lower()
    keywords = [
        "union select", " or 1=1", "information_schema", "benchmark(", "sleep(",
        "<script", "javascript:", "onerror=", "onload=", "../etc/passwd",
        "system(", "exec(", "popen(", "cmd=", "powershell -", "phpmyadmin",
        "base64,", ".php", ".asp", ".jsp", ".aspx", "htaccess"
    ]
    if any(kw in b for kw in keywords):
        return True

    if "entropy=" in block:
        try:
            ent_str = block.split("entropy=")[1].split()[0]
            if float(ent_str) >= 5.5:
                return True
        except (ValueError, IndexError):
            pass
    return False


# ---- Tách block log ----
def extract_blocks_from_lines(lines: List[str]) -> List[str]:
    blocks, current_block = [], ""
    for line in lines:
        is_start_of_block = line[:4].isdigit() and ("[TRAFFIC]" in line or "TRAFFIC" in line)

        if is_start_of_block and current_block:
            blocks.append(current_block)
            current_block = ""

        current_block += line

    if current_block:
        blocks.append(current_block)
    return blocks


# ---- Worker AI xử lý block ----
async def ai_process_block(queue: asyncio.Queue):
    while True:
        block = await queue.get()
        try:
            result = await main_cai_flow(block)
            label = result.get("label", "Normal")

            if label != "Normal":
                print("=" * 100)
                print(f"[{datetime.now().isoformat()}] ⚠️  Suspicious Traffic Detected by AI")
                print(f"Label     : {label}")
                print(f"Severity  : {result.get('severity', 'medium')}")
                print(f"Protocol  : {result.get('proto', 'N/A')}")
                print(f"Entropy   : {result.get('entropy', 0.0)}")
                print(f"Summary   : {result.get('summary', 'No summary')}")
                print(f"Block ↓\n{block.strip()}")
                print("=" * 100 + "\n")

                append_alert(result, block)
                reason = result.get("reason", "No summary")
                description = " ".join(reason).strip() if isinstance(reason, list) else str(reason).strip()
                #fill bằng hexdump lấy hết
                description += f"\n--- Hexdump ---\n{block.strip()}\n--- End Hexdump ---"
                alert_id, event_id = None, None
                session = SessionLocal()
                try:
                    # 1️⃣ Tạo hoặc lấy AttackType
                    attack_name = result.get("label", "Unknown")
                    category = "AI Detection"
                    attack = session.query(AttackType).filter(AttackType.attack_name == attack_name).first()
                    if not attack:
                        attack = AttackType(attack_name=attack_name, category=category, description=None)
                        session.add(attack)
                        session.flush()
                        logger.info(f"Created new AttackType: {attack_name}")

                    # 2️⃣ Tạo Event
                    desc = result.get("reason") or result.get("summary", "No description")
                    if isinstance(desc, (list, tuple)):
                        desc = " ".join(str(d) for d in desc)
                    e = Event(
                        source_ip=result.get("src", "0.0.0.0"),
                        destination_ip=result.get("dst", "0.0.0.0"),
                        attack_id=attack.attack_id,
                        severity=result.get("severity", "low"),
                        description=desc,
                        detected_by="AI",
                        status="new"
                    )
                    session.add(e)
                    session.flush()
                    logger.info(f"Created Event #{e.event_id} with severity={e.severity}")

                    # 3️⃣ Tạo Alert
                    level = map_severity_to_alert_level(e.severity)
                    alert_message = result.get("summary") or f"{attack_name} detected"
                    a = Alert(
                        event_id=e.event_id,
                        alert_message=str(alert_message),
                        alert_level=level,
                        is_sent=False
                    )
                    session.add(a)
                    session.flush()
                    logger.info(f"Created Alert #{a.alert_id} with level={level}")

                    # 4️⃣ Gửi realtime (nếu có)
                    alert_dict = {
                        "alert_id": str(a.alert_id),
                        "alert_message": a.alert_message,
                        "alert_level": a.alert_level,
                        "is_sent": a.is_sent
                    }

                    event_dict = {
                        "event_id": str(e.event_id),
                        "source_ip": e.source_ip,
                        "destination_ip": e.destination_ip,
                        "severity": e.severity,
                        "description": e.description
                    }

                    alert_id = str(a.alert_id)
                    event_id = str(e.event_id)

                    try:
                        alert_dict = Alert(**alert_dict)
                        event_dict = Event(**event_dict)
                        asyncio.create_task(emit_alert_realtime(alert_dict, event_dict))
                    except RuntimeError:
                        await emit_alert_realtime(alert_dict, event_dict)
                    session.commit()
                except Exception as db_err:
                    session.rollback()
                    logger.exception(f"[DB ERROR] Failed to insert alert: {db_err}")
                finally:
                    session.close()
                # api_payload = {
                #     "sent_at": datetime.now().isoformat(),
                #     "alert_id": alert_id,
                #     "event_id": event_id,
                #     "message": label,
                #     "alert_message": "AI " + label,
                #     "src_ip": result.get("src", "0.0.0.0"),
                #     "dst_ip": result.get("dst", "0.0.0.0"),
                #     "proto": result.get("proto", "TCP"),
                #     "entropy": result.get("entropy", 0.0),
                #     "hexdump": block.strip(),
                #     "severity": result.get("severity", "medium")+"-"+str(result.get("confidence", "0.5"))+"-"+result.get("action", "warning"),
                #     "alert_level": result.get("severity", "medium"),
                #     "confidence": result.get("confidence", 0.5),
                #     "payload_b64": base64.b64encode(block.encode()).decode('ascii'),
                #     "description": description,
                #     "action": result.get("action", "monitor"),
                #     "captured_file": LOG_FILE,
                #     "timestamp": datetime.now().isoformat(),
                #     "status": "New",
                #     "source_ip": result.get("src", "0.0.0.0"),
                #     "destination_ip": result.get("dst", "0.0.0.0"),
                #     "payload_b64": base64.b64encode(block.encode()).decode('ascii'),
                # }
                # email_attempted = False
                api_payload = {
                    # 🔑 BẮT BUỘC
                    "rid": result.get("label", "AI_DETECTED"),
                    "message": result.get("summary") or label,

                    # 🔑 IP (dùng alias backend)
                    "src": result.get("src", "0.0.0.0"),
                    "dst": result.get("dst", "0.0.0.0"),

                    # 🔹 OPTIONAL
                    "sport": result.get("sport"),
                    "dport": result.get("dport"),
                    "protocol": "TCP",
                    "entropy": result.get("entropy", 0.0),

                    "severity": result.get("severity", "medium"),
                    "action": result.get("action", "monitor"),

                    # 🔹 RAW DATA
                    "hexdump": block.strip(),
                    "payload_b64": base64.b64encode(block.encode()).decode("ascii"),
                }
            #     try:
            #         response = requests.post(API_ALERT_ENDPOINT, json=api_payload, timeout=10)
            #         response.raise_for_status()
            #         if response.status_code == 200 or response.status_code == 201:
            #             print(f"[INFO] API alert sent successfully for alert_id: {api_payload['alert_id']}")
            #         else:
            #             print(f"[WARN] API alert returned status {response.status_code} for alert_id: {api_payload['alert_id']}")
            #     except Exception as e:
            #         print(f"[WARN] Failed to send API alert: {e}")

            # else:
            #     print(f"[{datetime.now().isoformat()}] Normal traffic block skipped.")
            try:
                response = requests.post(
                    API_ALERT_ENDPOINT,
                    json=api_payload,
                    timeout=60
                )

                print("[API DEBUG] status =", response.status_code)
                if response.text:
                    print("[API DEBUG] body =", response.text)

                response.raise_for_status()
                print(f"[INFO] API raw alert sent successfully (rid={api_payload['rid']})")

            except Exception as e:
                print(f"[WARN] Failed to send raw alert to API: {e}")

            # 🔹 Throttle 1-3 giây giữa các request
            await asyncio.sleep(random.uniform(THROTTLE_MIN, THROTTLE_MAX))

        except Exception as e:
            print(f"[ERROR] AI analysis failed: {e}")
        finally:
            queue.task_done()


# ---- Worker chính ----
async def ai_traffic_worker(poll_interval: int = POLL_INTERVAL):
    print(f"[{datetime.now().isoformat()}] AI traffic worker starting. Reading {LOG_FILE}")
    offset = load_offset()
    print(f"[{datetime.now().isoformat()}] Starting from offset: {offset}")

    queue = asyncio.Queue()
    # chạy 1 worker duy nhất để tránh overload
    worker_task = asyncio.create_task(ai_process_block(queue))

    try:
        while True:
            try:
                if not os.path.exists(LOG_FILE):
                    await asyncio.sleep(poll_interval)
                    continue

                with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
                    f.seek(offset)
                    new_content = f.read()

                    if not new_content:
                        await asyncio.sleep(poll_interval)
                        continue

                    lines = new_content.splitlines(keepends=True)
                    blocks = extract_blocks_from_lines(lines)

                    current_block_offset = offset
                    for block in blocks:
                        block_bytes_len = len(block.encode('utf-8', errors='ignore'))
                        next_offset = current_block_offset + block_bytes_len

                        if is_suspicious_block(block):
                            await queue.put(block)

                        offset = next_offset
                        save_offset(offset)
                        current_block_offset = next_offset

            except KeyboardInterrupt:
                print("\n[INFO] Ctrl+C detected, stopping worker...")
                break
            except Exception as e:
                print(f"[ERROR] Worker loop exception: {e}")
                await asyncio.sleep(poll_interval * 2)

    finally:
        await queue.join()  # chờ queue trống trước khi kết thúc
        worker_task.cancel()
        save_offset(offset)
        print(f"[{datetime.now().isoformat()}] Worker stopped. Final offset saved: {offset}")


if __name__ == "__main__":
    try:
        asyncio.run(ai_traffic_worker())
    except Exception as e:
        print(f"[FATAL] Worker exited with an unhandled exception: {e}")
