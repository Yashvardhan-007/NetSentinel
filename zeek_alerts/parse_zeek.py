# zeek_alerts/parse_zeek.py
from __future__ import annotations
import csv, gzip
from pathlib import Path
from typing import Dict, Any, Iterable, List
from datetime import datetime, timezone

FIELDS = ["timestamp","src_ip","src_port","dest_ip","dest_port","proto","severity","signature","category","engine"]

def _open(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8")
    return open(path, "r", encoding="utf-8")

def _parse_separator(line: str) -> str:
    # Zeek: "#separator \x09"
    raw = line.split(None, 1)[1].strip() if " " in line else r"\x09"
    try:
        return bytes(raw, "utf-8").decode("unicode_escape")
    except Exception:
        return "\t"

def _iter_rows(path: Path) -> Iterable[Dict[str, str]]:
    sep = "\t"
    fields: List[str] = []
    with _open(path) as f:
        for line in f:
            if not line or line.startswith("#close"):
                continue
            if line.startswith("#separator"):
                sep = _parse_separator(line)
                continue
            if line.startswith("#fields"):
                # "#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto ..."
                parts = line.strip().split()
                fields = parts[1:]
                continue
            if line.startswith("#"):
                continue
            if not fields:
                # fallback if #fields missing: assume tab/whitespace split
                parts = line.rstrip("\n").split(sep)
                if len(parts) == 1:
                    parts = line.split()
                yield {"raw": line.strip(), "engine": "zeek"}
                continue
            parts = line.rstrip("\n").split(sep)
            if len(parts) != len(fields):
                # try whitespace split if tabs didn’t match
                parts = line.split()
            row = dict(zip(fields, parts))
            yield row

def _as_int(v, default=0) -> int:
    try:
        return int(float(v))
    except Exception:
        return default

def _iso_from_epoch(ts: str) -> str:
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()
    except Exception:
        return ""

def normalize_zeek(row: Dict[str, Any]) -> Dict[str, Any]:
    # Map Zeek conn fields to our unified schema
    return {
        "timestamp": _iso_from_epoch(row.get("ts","")),
        "src_ip": row.get("id.orig_h",""),
        "src_port": _as_int(row.get("id.orig_p", 0)),
        "dest_ip": row.get("id.resp_h",""),
        "dest_port": _as_int(row.get("id.resp_p", 0)),
        "proto": (row.get("proto","") or "").upper(),
        "severity": 0,            # Zeek conn doesn’t have severity; leave 0
        "signature": "",          # (filled by Suricata; Zeek is flow data)
        "category": "",
        "engine": "zeek",
    }

def write_csv(records: List[Dict[str, Any]], out_path: Path, append: bool = True) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if append and out_path.exists() else "w"
    with open(out_path, mode, newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        if mode == "w":
            w.writeheader()
        for r in records:
            w.writerow({k: r.get(k, "") for k in FIELDS})

if __name__ == "__main__":
    import argparse
    default_in = Path(__file__).with_name("sample_conn.log")
    default_out = Path(__file__).parents[1] / "visualization" / "alert_data.csv"

    ap = argparse.ArgumentParser(description="Parse Zeek conn.log to CSV.")
    ap.add_argument("input", nargs="?", default=str(default_in))
    ap.add_argument("output_csv", nargs="?", default=str(default_out))
    args = ap.parse_args()

    events = [normalize_zeek(r) for r in _iter_rows(Path(args.input))]
    write_csv(events, Path(args.output_csv), append=True)
    print(f"Wrote {len(events)} Zeek rows → {args.output_csv}")
