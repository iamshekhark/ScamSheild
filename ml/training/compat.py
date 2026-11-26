"""
ScamShield ML Pipeline - Artifact Compatibility & Version Validation Module
Enforces strict scikit-learn and Python version compatibility before loading Python model artifacts.
Prevents unhandled runtime warnings and unpickling bugs across differing sklearn versions.
"""

import sys
import os
import sklearn
import joblib


class IncompatibleArtifactError(Exception):
    """Raised when a pickled model artifact was generated with an incompatible scikit-learn or Python version."""
    pass


def get_environment_metadata() -> dict:
    return {
        "python_version": sys.version,
        "python_version_tuple": list(sys.version_info[:3]),
        "sklearn_version": sklearn.__version__,
        "joblib_version": joblib.__version__
    }


def validate_artifact_compatibility(bundle: dict, artifact_name: str = "model") -> bool:
    """
    Validates that the model bundle's scikit-learn version is compatible with the active environment.
    """
    artifact_sklearn = bundle.get("sklearn_version")
    active_sklearn = sklearn.__version__

    if not artifact_sklearn:
        raise IncompatibleArtifactError(
            f"Artifact [{artifact_name}] lacks required 'sklearn_version' metadata. "
            f"Retrain with 'python ml/training/train.py' to generate valid artifacts."
        )

    # Compare major.minor versions
    def major_minor(v_str: str):
        parts = v_str.split(".")
        return parts[0], parts[1] if len(parts) > 1 else "0"

    art_major, art_minor = major_minor(artifact_sklearn)
    act_major, act_minor = major_minor(active_sklearn)

    if (art_major, art_minor) != (act_major, act_minor):
        raise IncompatibleArtifactError(
            f"Artifact [{artifact_name}] scikit-learn version ({artifact_sklearn}) differs from active environment ({active_sklearn}). "
            f"Loading incompatible pickled estimators can lead to unpredictable behavior. "
            f"Retrain using: python ml/training/train.py"
        )

    return True


def load_model_bundle(joblib_path: str) -> dict:
    """
    Loads a joblib model bundle and validates version compatibility before returning it.
    """
    if not os.path.exists(joblib_path):
        raise FileNotFoundError(f"Model artifact not found at {joblib_path}")

    bundle = joblib.load(joblib_path)
    if not isinstance(bundle, dict):
        raise IncompatibleArtifactError(f"Corrupt artifact at {joblib_path}: expected dictionary bundle.")

    validate_artifact_compatibility(bundle, artifact_name=os.path.basename(joblib_path))
    return bundle
