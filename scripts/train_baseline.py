# scripts/train_baseline.py
from __future__ import annotations
from pathlib import Path
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib

INP = Path("artifacts/lm_scored.csv")
OUT = Path("ai_alert_scoring/model.pkl")

def demo_labels(df: pd.DataFrame) -> pd.Series:
    # Demo: treat high lm_score or high severity as positive
    return ((df["lm_score"] >= 40) | (df.get("severity", 0) >= 3)).astype(int)

def main():
    df = pd.read_csv(INP)
    # Minimal numeric features
    feats = ["fanout","lm_score","dest_port","evidence_count","severity"]
    for f in feats:
        if f not in df.columns:
            df[f] = 0
    X = df[feats].values
    y = demo_labels(df).values
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)
    clf = LogisticRegression(max_iter=1000)
    clf.fit(Xtr, ytr)
    print(classification_report(yte, clf.predict(Xte)))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, OUT)
    print(f"Saved model → {OUT.resolve()}")

if __name__ == "__main__":
    main()
