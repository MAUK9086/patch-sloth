"""Task B bump classifier: TabPFN (GPU), HistGBT (CPU, also the serve-time fallback) and logistic
regression. Plus threshold selection and save/load of a fitted (FeatureBuilder, model) bundle."""
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from .config import MODELS
from .features import FeatureBuilder


def make_model(name: str):
    if name == "tabpfn":
        from tabpfn import TabPFNClassifier
        return TabPFNClassifier(device="cuda")
    if name == "hgb":
        from sklearn.ensemble import HistGradientBoostingClassifier
        return HistGradientBoostingClassifier(max_iter=400, learning_rate=0.05, random_state=0)
    if name == "logreg":
        from sklearn.linear_model import LogisticRegression
        from sklearn.pipeline import make_pipeline
        from sklearn.preprocessing import StandardScaler
        return make_pipeline(StandardScaler(), LogisticRegression(max_iter=3000))
    raise ValueError(name)


def fit(model_name: str, X: pd.DataFrame, y) -> object:
    clf = make_model(model_name)
    clf.fit(X.fillna(0).values, np.asarray(y).astype(int))
    return clf


def predict_proba(clf, X: pd.DataFrame, batch: int = 5000) -> np.ndarray:
    Xs = X.fillna(0).values
    if len(Xs) == 0:
        return np.zeros(0)
    return np.concatenate([clf.predict_proba(Xs[i:i + batch])[:, 1] for i in range(0, len(Xs), batch)])


def choose_tau(y, p, min_precision: float = 0.5, top_frac: float | None = None) -> float:
    """Lowest threshold whose flagged set has precision >= min_precision (SPEC §9.2).
    Falls back to the top `top_frac` quantile when no threshold reaches the target."""
    y, p = np.asarray(y).astype(int), np.asarray(p)
    order = np.argsort(-p)
    prec = np.cumsum(y[order]) / np.arange(1, len(y) + 1)
    ok = np.where(prec >= min_precision)[0]
    ok = ok[ok >= 9]  # need at least 10 flags for a stable estimate
    if len(ok):
        return float(p[order][ok.max()])
    return float(np.quantile(p, 1 - (top_frac or 0.1)))


class BumpModel:
    """Fitted features + classifier, as used at serve time."""

    def __init__(self, fb: FeatureBuilder, clf, name: str):
        self.fb, self.clf, self.name = fb, clf, name

    def predict(self, df: pd.DataFrame) -> np.ndarray:
        return predict_proba(self.clf, self.fb.transform(df))

    def save(self, path: Path | None = None) -> Path:
        path = Path(path or MODELS / f"bump_{self.name}.joblib")
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)
        return path

    @staticmethod
    def load(path: Path | None = None, name: str = "hgb") -> "BumpModel":
        return joblib.load(Path(path or MODELS / f"bump_{name}.joblib"))
