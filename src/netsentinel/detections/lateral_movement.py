# src/netsentinel/detections/lateral_movement.py
from __future__ import annotations
import pandas as pd
from typing import Tuple, List

LATERAL_PORTS = {445, 3389, 5985, 5986}  # SMB/RDP/WinRM

def score_lateral(df: pd.DataFrame, window_minutes: int = 10) -> pd.DataFrame:
    """
    Heuristic: high fan-out to internal hosts + sensitive ports within a short window.
    Adds columns: fanout, lm_indicators, lm_score.
    """
    d = df.copy()
    d["is_lateral_port"] = d["dest_port"].isin(LATERAL_PORTS)
    d["minute"] = d["timestamp"].dt.floor("T")

    # fan-out per src over the window
    window = f"{window_minutes}T"
    fanout = (
        d.set_index("timestamp")
         .groupby("src_ip")["dest_ip"]
         .rolling(window).apply(lambda s: s.nunique(), raw=False)
         .reset_index(name="fanout")
    )
    d = d.merge(fanout, on=["src_ip","timestamp"], how="left")
    d["fanout"] = d["fanout"].fillna(1).astype(int)

    # Indicators
    d["ind_port"] = d["is_lateral_port"].astype(int)
    d["ind_correlated"] = d.get("correlated", pd.Series(False, index=d.index)).astype(int)

    # Simple score (0–100)
    d["lm_score"] = (d["fanout"].clip(0, 20) * 3 + d["ind_port"] * 20 + d["ind_correlated"] * 10).clip(0, 100)

    # MITRE tags (example)
    d["mitre_techniques"] = d.apply(
        lambda r: ";".join(
            ["T1021.002/SMB" if r["dest_port"] == 445 else "",
             "T1021.001/RDP" if r["dest_port"] == 3389 else ""]
        ).strip(";"),
        axis=1
    )
    return d

def top_findings(d: pd.DataFrame, k: int = 20) -> pd.DataFrame:
    cols = ["timestamp","src_ip","dest_ip","dest_port","proto","signature","category",
            "evidence_count","fanout","lm_score","mitre_techniques"]
    present = [c for c in cols if c in d.columns]
    return d.sort_values("lm_score", ascending=False)[present].head(k)

if __name__ == "__main__":
    inp = "artifacts/correlated.csv"
    out = "artifacts/lm_scored.csv"
    df = pd.read_csv(inp, parse_dates=["timestamp"])
    scored = score_lateral(df)
    scored.to_csv(out, index=False)
    print(f"Wrote {len(scored)} scored rows → {out}")
