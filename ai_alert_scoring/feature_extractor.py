# ai_alert_scoring/feature_extractor.py
from typing import Dict, Any, List
import ipaddress

def _as_int(v, default=0):
    try:
        # handles str/int/float -> int where possible
        return int(float(v))
    except Exception:
        return default

def _is_private_ip(ip: str) -> int:
    try:
        return int(ipaddress.ip_address(ip).is_private)
    except Exception:
        return 0

def extract_features(alert: Dict[str, Any]) -> List[float]:
    """
    Convert a parsed alert/event dict into a numeric feature vector.

    Tries both Suricata EVE fields and Zeek-like fields so the same
    extractor works after you correlate/normalize events.
    """
    # Severity (Suricata: alert.severity is 1/2/3; sometimes 'severity' at top level)
    sev = _as_int(
        (alert.get("alert") or {}).get("severity", alert.get("severity", 0)),
        default=0
    )

    # IPs and ports (Suricata: src_ip/src_port/dest_ip/dest_port)
    # (Zeek: id.orig_h/id.orig_p/id.resp_h/id.resp_p)
    src_ip = alert.get("src_ip") or alert.get("id.orig_h") or ""
    dst_ip = alert.get("dest_ip") or alert.get("id.resp_h") or ""
    src_p  = _as_int(alert.get("src_port") or alert.get("id.orig_p", 0))
    dst_p  = _as_int(alert.get("dest_port") or alert.get("id.resp_p", 0))

    # Protocol
    proto_raw = (alert.get("proto") or alert.get("transport") or "").upper()
    proto_map = {"TCP": 0, "UDP": 1, "ICMP": 2}
    proto = proto_map.get(proto_raw, 3)

    # Bytes/length (Zeek has orig_bytes/resp_bytes; Suricata may have "length")
    total_bytes = _as_int(alert.get("orig_bytes", 0)) + _as_int(alert.get("resp_bytes", 0))
    if total_bytes == 0:
        total_bytes = _as_int(alert.get("length", 0))

    # Private IP flags
    src_priv = _is_private_ip(src_ip)
    dst_priv = _is_private_ip(dst_ip)

    # Final feature vector (keep order stable; document it in README)
    return [
        sev,          # 0
        src_p,        # 1
        dst_p,        # 2
        proto,        # 3
        src_priv,     # 4
        dst_priv,     # 5
        total_bytes,  # 6
    ]
