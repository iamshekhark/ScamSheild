"""
ScamShield URL Feature Extraction
Extracts structured lexical, domain, host, path, subdomain, IP, punycode,
and character distribution features without treating weak lexical signals
as standalone proof of maliciousness.
"""

import math
import os
import re
import sys
from collections import Counter
from typing import Any, Dict, List
from urllib.parse import urlparse

import numpy as np
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler

ML_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ML_ROOT not in sys.path:
    sys.path.insert(0, ML_ROOT)

from prepare_datasets import extract_registrable_domain  # noqa: E402
from quality_analyzer import normalize_url  # noqa: E402

PREPROCESSING_VERSION = "url-feat-v1.0.0"

RISKY_TLDS = {
    "xyz", "top", "click", "buzz", "club", "tk", "ml", "ga", "cf", "gq",
    "icu", "cyou", "site", "online", "shop", "work", "live", "support", "ru",
}
SUSPICIOUS_TOKENS = (
    "login", "verify", "secure", "update", "kyc", "account", "signin",
    "confirm", "banking", "wallet", "refund", "claim",
)
IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

STRUCTURED_FEATURE_NAMES = [
    "url_length",
    "host_length",
    "path_length",
    "query_length",
    "subdomain_count",
    "is_https",
    "is_ip_host",
    "is_punycode",
    "is_risky_tld",
    "hyphen_count_host",
    "dot_count_host",
    "digit_ratio_url",
    "special_char_count",
    "has_at_symbol",
    "suspicious_token_hits",
    "host_entropy",
]


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def extract_single_url_features(raw_url: str) -> List[float]:
    norm = normalize_url(str(raw_url or ""))
    if not norm:
        return [0.0] * len(STRUCTURED_FEATURE_NAMES)

    try:
        parsed = urlparse(norm)
    except Exception:
        return [0.0] * len(STRUCTURED_FEATURE_NAMES)

    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    reg_domain = extract_registrable_domain(host)
    host_parts = [p for p in host.split(".") if p]
    reg_parts = [p for p in reg_domain.split(".") if p]
    subdomain_count = max(0, len(host_parts) - len(reg_parts))
    tld = host_parts[-1] if host_parts else ""

    n_url = max(len(norm), 1)
    digit_count = sum(1 for c in norm if c.isdigit())
    special_count = sum(norm.count(ch) for ch in ("-", "_", "?", "=", "&", "%", "@"))
    lower = norm.lower()
    token_hits = sum(1 for tok in SUSPICIOUS_TOKENS if tok in lower)

    return [
        float(len(norm)),
        float(len(host)),
        float(len(path)),
        float(len(query)),
        float(subdomain_count),
        1.0 if parsed.scheme == "https" else 0.0,
        1.0 if IPV4_RE.match(host) else 0.0,
        1.0 if any(p.startswith("xn--") for p in host_parts) else 0.0,
        1.0 if tld in RISKY_TLDS else 0.0,
        float(host.count("-")),
        float(host.count(".")),
        float(digit_count / n_url),
        float(special_count),
        1.0 if "@" in parsed.netloc else 0.0,
        float(token_hits),
        float(round(shannon_entropy(host), 4)),
    ]


def extract_url_structured_matrix(records: List[Any]) -> np.ndarray:
    rows = []
    for r in records:
        u = r.get("url") or r.get("content") or "" if isinstance(r, dict) else str(r or "")
        rows.append(extract_single_url_features(u))
    return np.asarray(rows, dtype=np.float64)


class UrlHybridFeaturizer:
    """Combines character n-gram TF-IDF with scaled structured URL lexical/domain features."""

    def __init__(self, max_features: int = 4000, use_tfidf: bool = True):
        self.max_features = max_features
        self.use_tfidf = use_tfidf
        self.vectorizer = TfidfVectorizer(
            analyzer="char_wb",
            ngram_range=(3, 5),
            max_features=max_features,
            sublinear_tf=True,
            lowercase=True,
        )
        self.scaler = StandardScaler(with_mean=False)
        self._fitted = False

    def _urls(self, records: List[Any]) -> List[str]:
        return [
            normalize_url(str(r.get("url") or r.get("content") or "")) if isinstance(r, dict) else normalize_url(str(r or ""))
            for r in records
        ]

    def fit_transform(self, records: List[Any]):
        X_struct = extract_url_structured_matrix(records)
        X_struct_scaled = self.scaler.fit_transform(X_struct)
        if not self.use_tfidf:
            self._fitted = True
            return X_struct_scaled
        X_tfidf = self.vectorizer.fit_transform(self._urls(records))
        self._fitted = True
        return hstack([X_tfidf, csr_matrix(X_struct_scaled)]).tocsr()

    def __call__(self, records: List[Any]):
        if not self._fitted:
            raise RuntimeError("UrlHybridFeaturizer must be fitted before transform.")
        X_struct = extract_url_structured_matrix(records)
        X_struct_scaled = self.scaler.transform(X_struct)
        if not self.use_tfidf:
            return X_struct_scaled
        X_tfidf = self.vectorizer.transform(self._urls(records))
        return hstack([X_tfidf, csr_matrix(X_struct_scaled)]).tocsr()
