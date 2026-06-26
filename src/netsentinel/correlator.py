from pathlib import Path
import pandas as pd

INP = "visualization/alert_data.csv"
OUT = Path("artifacts/correlated.csv")
OUT.parent.mkdir(exist_ok=True)

def correlate(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)

    keys = ["src_ip","src_port","dest_ip","dest_port","proto"]
    suri = df[df["engine"].eq("suricata")].rename(columns={"severity":"severity_suri"})
    zeek = df[df["engine"].eq("zeek")].copy()

    suri = suri.sort_values("timestamp")
    zeek = zeek.sort_values("timestamp")

    merged = pd.merge_asof(
        suri, zeek,
        on="timestamp",
        by=keys,
        direction="nearest",
        tolerance=pd.Timedelta("60s"),
        suffixes=("", "_zeek"),
    )

    out = merged[[
        "timestamp","src_ip","src_port","dest_ip","dest_port","proto",
        "severity_suri","signature","category"
    ]].copy()

    out["correlated"] = merged["engine_zeek"].eq("zeek").fillna(False)
    out["evidence_count"] = 1 + out["correlated"].astype(int)
    return out

def run():
    df = pd.read_csv(INP)
    out = correlate(df)
    out.to_csv(OUT, index=False)
    print(f"Wrote {len(out)} correlated rows -> {OUT}")
    return len(out), str(OUT)

if __name__ == "__main__":
    run()
