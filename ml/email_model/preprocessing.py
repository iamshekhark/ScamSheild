"""
ScamShield Email Preprocessing & Feature Extraction
Normalizes subject/body/sender, scrubs sensitive PII, and extracts structured
security & lexical features alongside text for TF-IDF.
"""

import os
import re
import sys
from typing import Any, Dict, List
import numpy as np
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler

ML_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ML_ROOT not in sys.path:
    sys.path.insert(0, ML_ROOT)

from prepare_datasets import scrub_pii  # noqa: E402
from quality_analyzer import normalize_text  # noqa: E402

PREPROCESSING_VERSION = "email-prep-v1.0.0"

URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
RISKY_TLD_RE = re.compile(r"\.(?:xyz|top|click|buzz|tk|ml|ga|cf|gq|icu|cyou|site|online)\b", re.IGNORECASE)
URGENCY_RE = re.compile(r"\b(?:urgent|immediately|act now|24 hours|expires today|suspended|blocked|verify now)\b", re.IGNORECASE)
CREDENTIAL_RE = re.compile(r"\b(?:password|otp|pin|cvv|login|verify account|kyc|pan|aadhaar)\b", re.IGNORECASE)
FINANCIAL_RE = re.compile(r"\b(?:bank|invoice|wire|transfer|payment|refund|lottery|prize|usd|inr|rs\.?)\b", re.IGNORECASE)
HTML_RE = re.compile(r"<[^>]+>")


def preprocess_email_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize and scrub a single email record without mutating input."""
    subject = scrub_pii(normalize_text(str(record.get("subject") or "")))
    body = scrub_pii(normalize_text(str(record.get("body") or record.get("text") or record.get("content") or "")))
    sender = str(record.get("sender") or record.get("sender_domain") or "").strip().lower()
    combined = f"{subject} {body}".strip() if subject else body
    return {
        "subject": subject,
        "body": body,
        "sender": sender,
        "combined_text": combined,
    }


def extract_email_structured_features(records: List[Dict[str, Any]]) -> np.ndarray:
    """Extract numeric security/structural features from normalized email records."""
    rows = []
    for rec in records:
        prep = preprocess_email_record(rec)
        txt = prep["combined_text"]
        lower = txt.lower()
        n_chars = max(len(txt), 1)
        urls = URL_RE.findall(txt)
        upper_cnt = sum(1 for c in txt if c.isupper())
        digit_cnt = sum(1 for c in txt if c.isdigit())
        excl_cnt = txt.count("!")

        rows.append([
            float(len(txt)),
            float(len(txt.split())),
            float(len(urls)),
            float(len(RISKY_TLD_RE.findall(lower))),
            float(len(URGENCY_RE.findall(lower))),
            float(len(CREDENTIAL_RE.findall(lower))),
            float(len(FINANCIAL_RE.findall(lower))),
            float(1 if HTML_RE.search(txt) else 0),
            float(upper_cnt / n_chars),
            float(digit_cnt / n_chars),
            float(excl_cnt),
        ])
    return np.asarray(rows, dtype=np.float64)


class EmailHybridFeaturizer:
    """Combines word n-gram TF-IDF with scaled structured email security features."""

    def __init__(self, max_features: int = 8000, use_structured: bool = True):
        self.max_features = max_features
        self.use_structured = use_structured
        self.vectorizer = TfidfVectorizer(
            analyzer="word",
            ngram_range=(1, 2),
            max_features=max_features,
            sublinear_tf=True,
            lowercase=True,
            min_df=2,
        )
        self.scaler = StandardScaler(with_mean=False)
        self._fitted = False

    def fit_transform(self, records: List[Dict[str, Any]]):
        texts = [preprocess_email_record(r)["combined_text"] for r in records]
        X_tfidf = self.vectorizer.fit_transform(texts)
        if not self.use_structured:
            self._fitted = True
            return X_tfidf
        X_struct = extract_email_structured_features(records)
        X_struct_scaled = self.scaler.fit_transform(X_struct)
        self._fitted = True
        return hstack([X_tfidf, csr_matrix(X_struct_scaled)]).tocsr()

    def __call__(self, records: List[Dict[str, Any]]):
        if not self._fitted:
            raise RuntimeError("EmailHybridFeaturizer must be fitted before transform.")
        texts = [preprocess_email_record(r)["combined_text"] for r in records]
        X_tfidf = self.vectorizer.transform(texts)
        if not self.use_structured:
            return X_tfidf
        X_struct = extract_email_structured_features(records)
        X_struct_scaled = self.scaler.transform(X_struct)
        return hstack([X_tfidf, csr_matrix(X_struct_scaled)]).tocsr()
