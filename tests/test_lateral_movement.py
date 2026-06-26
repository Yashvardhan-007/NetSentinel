import pandas as pd
from src.netsentinel.detections.lateral_movement import score_lateral

def test_lm_score_ports():
    df = pd.DataFrame([
        {"timestamp":"2025-06-12T00:00:00Z","src_ip":"10.0.0.1","src_port":1111,"dest_ip":"10.0.0.5","dest_port":445,"proto":"TCP","evidence_count":2},
        {"timestamp":"2025-06-12T00:01:00Z","src_ip":"10.0.0.1","src_port":1111,"dest_ip":"10.0.0.6","dest_port":3389,"proto":"TCP","evidence_count":1},
    ])
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    scored = score_lateral(df)
    assert (scored["lm_score"] > 0).all()
