import pandas as pd
from src.netsentinel.correlator import correlate

def test_correlate_basic():
    df = pd.DataFrame([
        {"timestamp":"2025-06-12T00:00:00Z","src_ip":"10.0.0.1","src_port":1111,"dest_ip":"10.0.0.5","dest_port":445,"proto":"TCP","severity":3,"signature":"ET Test","category":"Malware","engine":"suricata"},
        {"timestamp":"2025-06-12T00:00:20Z","src_ip":"10.0.0.1","src_port":1111,"dest_ip":"10.0.0.5","dest_port":445,"proto":"TCP","severity":0,"signature":"","category":"","engine":"zeek"},
    ])
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    out = correlate(df, window_seconds=60)
    assert out["correlated"].any()
    assert out["evidence_count"].max() >= 2
