# ai_alert_scoring/ai_model.py
from pathlib import Path
import joblib
from typing import Any, Sequence

def load_model(path: str = "model.pkl") -> Any:
    """
    Load a serialized scikit-learn–style model.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(
            f"Model file not found at {p.resolve()}. "
            "Train or place a model.pkl in the repo root."
        )
    return joblib.load(p)

def predict_threat(features: Sequence[float], model: Any):
    """
    Return the model's class prediction for a single example.
    """
    return model.predict([list(features)])[0]

def predict_threat_proba(features: Sequence[float], model: Any):
    """
    Optional: probability/confidence, if the model supports predict_proba.
    """
    if hasattr(model, "predict_proba"):
        return model.predict_proba([list(features)])[0]
    return None
