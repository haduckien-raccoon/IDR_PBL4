from app.api.alerts import _send_email_sync
import requests

payload = {
    "alert_id": 999,
    "event_id": 999,
    "alert_message": "Test alert from Python",
    "alert_level": "info",
    "sent_at": "2025-11-08T18:00:00Z",
    "timestamp": "2025-11-08T18:00:00Z",
    "severity": "low",
    "status": "new",
    "source_ip": "127.0.0.1",
    "destination_ip": "127.0.0.1",
    "payload_b64": None,
    "action": None,
    "reason":"hahahahahaah"
}

_send_email_sync(payload)
response = requests.post("http://127.0.0.1:8000/api/alerts/analyze", json=payload)
print("Response status code:", response.status_code)
print("Response JSON:", response.json())
