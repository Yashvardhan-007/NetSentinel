# suricata_alerts/parse_suricata.py
from __future__ import annotations
import json, gzip, csv
from pathlib import Path
from typing import Dict, Any, Iterable, List

def _read_text(path: Path) -> str:
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8") as f:
            return f.read()
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

def _iter_events(path: Path) -> Iterable[Dict[str, Any]]:
    """Yield Suricata events from JSON, JSON array, or JSON Lines."""
    text = _read_text(path)
    # Try whole-file JSON first
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            yield data
            return
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    yield item
            return
    except json.JSONDecodeError:
        pass
    # Fallback: line-delimited JSON (NDJSON)
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                yield obj
        except json.JSONDecodeError:
            continue

def _as_int(v, default=0) -> int:
    try:
        return int(float(v))
    except Exception:
        return default

def normalize(e: Dict[str, Any]) -> Dict[str, Any]:
    """Map raw Suricata event to a flat, dashboard-friendly schema."""
    alert = e.get("alert") or {}
    return {
        "timestamp": e.get("timestamp") or e.get("@timestamp") or e.get("flow", {}).get("start") or e.get("ts", ""),
        "src_ip": e.get("src_ip") or e.get("srcip") or "",
        "src_port": _as_int(e.get("src_port") or e.get("sport", 0)),
        "dest_ip": e.get("dest_ip") or e.get("dst_ip") or "",
        "dest_port": _as_int(e.get("dest_port") or e.get("dport", 0)),
        "proto": (e.get("proto") or "").upper(),
        "severity": _as_int(alert.get("severity", e.get("severity", 0))),
        "signature": alert.get("signature", ""),
        "category": alert.get("category", ""),
        "engine": "suricata",
    }

def write_csv(records: List[Dict[str, Any]], out_path: Path) -> None:
    fields = ["timestamp","src_ip","src_port","dest_ip","dest_port","proto","severity","signature","category","engine"]
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in records:
            w.writerow({k: r.get(k, "") for k in fields})

def load_suricata_alerts(file_path: str) -> List[Dict[str, Any]]:
    """Backwards-compatible API used elsewhere in your code."""
    p = Path(file_path)
    return list(_iter_events(p))

if __name__ == "__main__":
    import argparse
    default_in = Path(__file__).with_name("sample_suricata.json")
    default_out = Path(__file__).parents[1] / "visualization" / "alert_data.csv"

    ap = argparse.ArgumentParser(description="Parse Suricata EVE logs to CSV.")
    ap.add_argument("input", nargs="?", default=str(default_in), help="Path to EVE JSON/JSONL(.gz)")
    ap.add_argument("output_csv", nargs="?", default=str(default_out), help="Output CSV path")
    args = ap.parse_args()

    events = [normalize(e) for e in _iter_events(Path(args.input))]
    write_csv(events, Path(args.output_csv))
    print(f"Wrote {len(events)} Suricata rows → {args.output_csv}")
