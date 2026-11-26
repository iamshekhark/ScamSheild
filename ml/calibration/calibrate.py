"""
ScamShield Probability Calibration Module
Compares Uncalibrated, Temperature Scaling, Platt Scaling (Logistic/Sigmoid),
and Isotonic Regression using VALIDATION data ONLY (never touching test data).
"""

from typing import Any, Dict, List, Optional, Tuple
import numpy as np
from scipy.optimize import minimize_scalar
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression


def softmax_probs(logits: np.ndarray, temperature: float = 1.0) -> np.ndarray:
    scaled = logits / max(float(temperature), 1e-3)
    shifted = scaled - np.max(scaled, axis=1, keepdims=True)
    exps = np.exp(shifted)
    return exps / np.sum(exps, axis=1, keepdims=True)


def get_raw_scores_and_probs(model: Any, X, classes: List[str]) -> Tuple[np.ndarray, np.ndarray]:
    """Extract decision scores/logits and raw probabilities from a fitted classifier."""
    if hasattr(model, "predict_proba"):
        probs = np.asarray(model.predict_proba(X), dtype=float)
        probs = np.clip(probs, 1e-7, 1.0 - 1e-7)
        probs = probs / np.sum(probs, axis=1, keepdims=True)
    else:
        probs = None

    if hasattr(model, "decision_function"):
        raw = np.asarray(model.decision_function(X), dtype=float)
        if len(classes) == 2 and raw.ndim == 1:
            logits = np.column_stack([-raw / 2.0, raw / 2.0])
        else:
            logits = raw
        if probs is None:
            probs = softmax_probs(logits, 1.0)
    else:
        logits = np.log(np.clip(probs, 1e-7, 1.0))

    return logits, probs


def compute_calibration_metrics(
    probs: np.ndarray,
    y_true: List[str],
    classes: List[str],
    n_bins: int = 10,
) -> Dict[str, Any]:
    """Compute multiclass Brier score, Expected Calibration Error (ECE), NLL, and reliability bins."""
    class_to_idx = {c: i for i, c in enumerate(classes)}
    valid_idx = [i for i, y in enumerate(y_true) if y in class_to_idx]
    if not valid_idx:
        return {"brier_score": None, "ece": None, "nll": None, "reliability_bins": []}

    probs_v = np.clip(probs[valid_idx], 1e-7, 1.0 - 1e-7)
    probs_v = probs_v / np.sum(probs_v, axis=1, keepdims=True)
    y_idx = np.array([class_to_idx[y_true[i]] for i in valid_idx])
    one_hot = np.eye(len(classes))[y_idx]

    brier = float(np.mean(np.sum((probs_v - one_hot) ** 2, axis=1)))
    nll = float(-np.mean(np.log(probs_v[np.arange(len(y_idx)), y_idx])))

    confs = np.max(probs_v, axis=1)
    preds = np.argmax(probs_v, axis=1)
    correct = (preds == y_idx).astype(float)

    bins = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    reliability_bins = []
    n = len(y_idx)
    for b in range(n_bins):
        lo, hi = float(bins[b]), float(bins[b + 1])
        mask = (confs >= lo) & (confs <= hi if b == n_bins - 1 else confs < hi)
        cnt = int(np.sum(mask))
        if cnt > 0:
            avg_conf = float(np.mean(confs[mask]))
            avg_acc = float(np.mean(correct[mask]))
            ece += (cnt / max(n, 1)) * abs(avg_acc - avg_conf)
            reliability_bins.append({
                "bin": f"{lo:.1f}-{hi:.1f}",
                "count": cnt,
                "avg_confidence": round(avg_conf, 4),
                "empirical_accuracy": round(avg_acc, 4),
                "gap": round(abs(avg_acc - avg_conf), 4),
            })

    return {
        "brier_score": round(brier, 4),
        "ece": round(float(ece), 4),
        "nll": round(nll, 4),
        "reliability_bins": reliability_bins,
    }


class CalibratedProbabilityWrapper:
    """
    Applies a validation-selected calibration method ('temperature', 'platt', 'isotonic', or 'none')
    and enforces uncertainty / out-of-distribution handling.
    """

    def __init__(
        self,
        method: str,
        classes: List[str],
        temperature: float = 1.0,
        platt_models: Optional[List[Optional[LogisticRegression]]] = None,
        isotonic_models: Optional[List[Optional[IsotonicRegression]]] = None,
        uncertainty_threshold: float = 0.55,
    ):
        self.method = method
        self.classes = list(classes)
        self.temperature = float(temperature)
        self.platt_models = platt_models
        self.isotonic_models = isotonic_models
        self.uncertainty_threshold = float(uncertainty_threshold)

    def transform_probs(self, logits: np.ndarray, raw_probs: np.ndarray) -> np.ndarray:
        if self.method == "temperature":
            return softmax_probs(logits, self.temperature)

        if self.method == "platt" and self.platt_models is not None:
            cols = []
            for k, m in enumerate(self.platt_models):
                if m is None:
                    cols.append(raw_probs[:, k])
                else:
                    cols.append(m.predict_proba(logits[:, k].reshape(-1, 1))[:, 1])
            p = np.column_stack(cols)
            p = np.clip(p, 1e-7, 1.0)
            return p / np.sum(p, axis=1, keepdims=True)

        if self.method == "isotonic" and self.isotonic_models is not None:
            cols = []
            for k, m in enumerate(self.isotonic_models):
                if m is None:
                    cols.append(raw_probs[:, k])
                else:
                    cols.append(m.predict(raw_probs[:, k]))
            p = np.column_stack(cols)
            p = np.clip(p, 1e-7, 1.0)
            return p / np.sum(p, axis=1, keepdims=True)

        return raw_probs

    def to_metadata(self) -> Dict[str, Any]:
        return {
            "method": self.method,
            "temperature": round(self.temperature, 4) if self.method == "temperature" else 1.0,
            "uncertainty_threshold": self.uncertainty_threshold,
            "calibrated": self.method != "none",
        }


def fit_best_calibrator(
    model: Any,
    X_val,
    y_val: List[str],
    classes: List[str],
    uncertainty_threshold: float = 0.55,
) -> Tuple[CalibratedProbabilityWrapper, Dict[str, Any]]:
    """
    Evaluate Uncalibrated, Temperature Scaling, Platt Scaling, and Isotonic Regression
    on VALIDATION data only, and return the best calibrator by validation Brier score.
    """
    class_to_idx = {c: i for i, c in enumerate(classes)}
    valid_idx = [i for i, y in enumerate(y_val) if y in class_to_idx]
    if len(valid_idx) < 10:
        wrapper = CalibratedProbabilityWrapper("none", classes, uncertainty_threshold=uncertainty_threshold)
        return wrapper, {"selected_method": "none", "reason": "Insufficient validation samples (<10)"}

    X_v = X_val[valid_idx]
    y_v = [y_val[i] for i in valid_idx]
    y_idx = np.array([class_to_idx[y] for y in y_v])

    logits_v, raw_probs_v = get_raw_scores_and_probs(model, X_v, classes)
    candidates: Dict[str, Tuple[CalibratedProbabilityWrapper, Dict[str, Any]]] = {}

    # 1. Uncalibrated baseline
    uncal_metrics = compute_calibration_metrics(raw_probs_v, y_v, classes)
    candidates["none"] = (
        CalibratedProbabilityWrapper("none", classes, uncertainty_threshold=uncertainty_threshold),
        uncal_metrics,
    )

    # 2. Temperature scaling
    def nll_fn(temp: float) -> float:
        p = np.clip(softmax_probs(logits_v, temp), 1e-7, 1.0 - 1e-7)
        return float(-np.mean(np.log(p[np.arange(len(y_idx)), y_idx])))

    res = minimize_scalar(nll_fn, bounds=(0.3, 5.0), method="bounded")
    best_t = float(round(res.x, 4))
    temp_wrapper = CalibratedProbabilityWrapper("temperature", classes, temperature=best_t, uncertainty_threshold=uncertainty_threshold)
    temp_probs = temp_wrapper.transform_probs(logits_v, raw_probs_v)
    candidates["temperature"] = (temp_wrapper, compute_calibration_metrics(temp_probs, y_v, classes))

    # 3. Platt scaling (one-vs-rest logistic regression on validation logits)
    platt_models: List[Optional[LogisticRegression]] = []
    for k in range(len(classes)):
        y_bin = (y_idx == k).astype(int)
        if len(np.unique(y_bin)) < 2:
            platt_models.append(None)
        else:
            lr_cal = LogisticRegression(C=1.0, solver="lbfgs")
            lr_cal.fit(logits_v[:, k].reshape(-1, 1), y_bin)
            platt_models.append(lr_cal)
    platt_wrapper = CalibratedProbabilityWrapper("platt", classes, platt_models=platt_models, uncertainty_threshold=uncertainty_threshold)
    platt_probs = platt_wrapper.transform_probs(logits_v, raw_probs_v)
    candidates["platt"] = (platt_wrapper, compute_calibration_metrics(platt_probs, y_v, classes))

    # 4. Isotonic regression (one-vs-rest on validation probabilities)
    iso_models: List[Optional[IsotonicRegression]] = []
    for k in range(len(classes)):
        y_bin = (y_idx == k).astype(int)
        if len(np.unique(y_bin)) < 2 or len(y_bin) < 20:
            iso_models.append(None)
        else:
            iso = IsotonicRegression(out_of_bounds="clip")
            iso.fit(raw_probs_v[:, k], y_bin)
            iso_models.append(iso)
    iso_wrapper = CalibratedProbabilityWrapper("isotonic", classes, isotonic_models=iso_models, uncertainty_threshold=uncertainty_threshold)
    iso_probs = iso_wrapper.transform_probs(logits_v, raw_probs_v)
    candidates["isotonic"] = (iso_wrapper, compute_calibration_metrics(iso_probs, y_v, classes))

    best_name = min(
        candidates.keys(),
        key=lambda k: (candidates[k][1]["brier_score"], candidates[k][1]["ece"]),
    )
    best_wrapper, best_metrics = candidates[best_name]
    report = {
        "selected_method": best_name,
        "validation_comparison": {name: met for name, (_, met) in candidates.items()},
        "selected_validation_metrics": best_metrics,
    }
    return best_wrapper, report
