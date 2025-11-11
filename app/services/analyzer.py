# app/services/analyzer.py
from dataclasses import dataclass
from typing import Any, Dict

@dataclass
class AnalysisResult:
    should_alert: bool
    alert_type: str | None = None
    severity: str = "low"            # one of: low, medium, high, critical
    source: str | None = None
    destination: str | None = None
    description: str = ""

class Analyzer:
    """
    Analyzer tối giản để demo.
    - Nhận payload từ API /alerts/analyze
    - Heuristic nhanh để quyết định có tạo alert hay không
    """

    # vài mẫu dấu hiệu đơn giản
    SIG_PATTERNS = {
        "SQL Injection": [
            "union select", "' or 1=1", "\" or 1=1", " admin'--", " sleep(", "information_schema",
            "sqlmap", "or 1=1", "xp_cmdshell"
        ],
        "XSS": [
            "<script", "javascript:", "onerror=", "onload=", "alert(", "<img src=x onerror", "<svg/onload="
        ],
        "Path Traversal": [
            "../", "..\\", "%2e%2e%2f", "%2e%2e\\", "/etc/passwd", "C:\\Windows\\System32"
        ],
        "RCE": [
            ";nc ", "; bash -c", "`whoami`", "$(id)", "curl http", "wget http", "&& id", "&& uname -a"
        ]
    }

    def analyze(self, data: Dict[str, Any]) -> AnalysisResult:
        # Lấy các trường phổ biến từ payload người gọi
        src = data.get("src_ip") or data.get("source") or data.get("src")
        dst = data.get("dst_ip") or data.get("destination") or data.get("dst")
        text = " ".join([str(v) for v in self._flatten_values(data)]).lower()

        detected_type: str | None = None
        severity = "low"

        for atype, patterns in self.SIG_PATTERNS.items():
            if any(p in text for p in patterns):
                detected_type = atype
                # map severity đơn giản
                if atype in ("RCE",):
                    severity = "critical"
                elif atype in ("SQL Injection", "Path Traversal"):
                    severity = "high"
                elif atype in ("XSS",):
                    severity = "medium"
                break

        # Cho phép client gợi ý loại tấn công/severity
        detected_type = detected_type or data.get("attack_name") or data.get("event") or "Unknown"
        if "severity" in data:
            sv = str(data["severity"]).lower()
            if sv in {"low","medium","high","critical"}:
                severity = sv

        should = detected_type != "Unknown" or bool(data.get("force_alert"))

        desc = data.get("description") or f"Auto-detected {detected_type}"
        return AnalysisResult(
            should_alert=bool(should),
            alert_type=detected_type,
            severity=severity,
            source=src,
            destination=dst,
            description=desc
        )

    def _flatten_values(self, obj):
        """Lấy tất cả giá trị string trong dict để quét pattern."""
        if isinstance(obj, dict):
            for v in obj.values():
                yield from self._flatten_values(v)
        elif isinstance(obj, (list, tuple, set)):
            for v in obj:
                yield from self._flatten_values(v)
        else:
            yield obj