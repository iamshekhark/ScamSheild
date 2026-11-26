"""
ScamShield Track B — Message Feature Extraction (SMS / WhatsApp / General Messages)
Combines character n-grams, word n-grams, and structured security features:
- URL, UPI ID, and phone number extraction counts
- Payment demand, urgency/coercion, brand impersonation, and contextual prize-to-payment link
- Negation awareness (e.g. "never share OTP")
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

URL_RE = re.compile(r"https?://[^\s<>\"']+|wa\.me/[^\s<>\"']+", re.IGNORECASE)
UPI_RE = re.compile(r"\b[a-zA-Z0-9.\-_]{2,64}@(?:okhdfcbank|okaxis|oksbi|okicici|ybl|ibl|axl|paytm|sbi|upi|icici|hdfcbank)\b", re.IGNORECASE)
PHONE_RE = re.compile(r"(?:\+?91[\s-]?)?[6-9]\d{9}\b")
OTP_NEGATION_RE = re.compile(r"\b(?:do\s+not|never|don't)\s+(?:share|give|send|disclose)\b.{0,30}\b(?:otp|pin|password|cvv)\b", re.IGNORECASE)
COERCION_RE = re.compile(r"\b(?:digital\s+arrest|cbi|arrest\s+warrant|disconnected\s+tonight|account\s+blocked|suspended|anydesk|teamviewer)\b", re.IGNORECASE)
PAY_DEMAND_RE = re.compile(r"\b(?:pay|deposit|send|transfer|remit)\b.{0,40}\b(?:fee|charges?|processing|tax|upi\s*pin)\b", re.IGNORECASE)
BRAND_RE = re.compile(r"\b(?:sbi|hdfc|icici|paytm|phonepe|gpay|amazon|flipkart|irctc|india\s*post)\b", re.IGNORECASE)
PRIZE_PAY_RE = re.compile(
    r"(?:\b(?:won|winner|lottery|lucky\s*draw|prize|cashback)\b.{0,100}\b(?:pay|deposit|fee|processing)\b|\b(?:pay|deposit|send|transfer)\b.{0,60}\b(?:fee|charges?|processing|tax)\b.{0,80}\b(?:prize|lottery|jackpot|winnings)\b)",
    re.IGNORECASE,
)


def extract_message_structured_features(texts: List[str]) -> np.ndarray:
    rows = []
    for raw in texts:
        txt = normalize_text(str(raw or ""))
        lower = txt.lower()
        n = max(len(txt), 1)
        rows.append([
            float(len(txt)),
            float(len(txt.split())),
            float(len(URL_RE.findall(txt))),
            float(len(UPI_RE.findall(txt))),
            float(len(PHONE_RE.findall(txt))),
            1.0 if OTP_NEGATION_RE.search(lower) else 0.0,
            float(len(COERCION_RE.findall(lower))),
            float(len(PAY_DEMAND_RE.findall(lower))),
            float(len(BRAND_RE.findall(lower))),
            1.0 if PRIZE_PAY_RE.search(lower) else 0.0,
            float(sum(1 for c in txt if c.isupper()) / n),
            float(sum(1 for c in txt if c.isdigit()) / n),
        ])
    return np.asarray(rows, dtype=np.float64)


class MessageHybridFeaturizer:
    """Combines word n-grams, char_wb n-grams, and scaled structured message security features."""

    def __init__(self, word_max: int = 5000, char_max: int = 5000):
        self.word_vec = TfidfVectorizer(analyzer="word", ngram_range=(1, 2), max_features=word_max, sublinear_tf=True, min_df=2)
        self.char_vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), max_features=char_max, sublinear_tf=True, min_df=2)
        self.scaler = StandardScaler(with_mean=False)
        self._fitted = False

    def _clean(self, records: List[Any]) -> List[str]:
        out = []
        for r in records:
            txt = r.get("content") or r.get("text") or "" if isinstance(r, dict) else str(r or "")
            out.append(scrub_pii(normalize_text(str(txt))))
        return out

    def fit_transform(self, records: List[Any]):
        texts = self._clean(records)
        Xw = self.word_vec.fit_transform(texts)
        Xc = self.char_vec.fit_transform(texts)
        Xs = self.scaler.fit_transform(extract_message_structured_features(texts))
        self._fitted = True
        return hstack([Xw, Xc, csr_matrix(Xs)]).tocsr()

    def __call__(self, records: List[Any]):
        if not self._fitted:
            raise RuntimeError("MessageHybridFeaturizer must be fitted first.")
        texts = self._clean(records)
        Xw = self.word_vec.transform(texts)
        Xc = self.char_vec.transform(texts)
        Xs = self.scaler.transform(extract_message_structured_features(texts))
        return hstack([Xw, Xc, csr_matrix(Xs)]).tocsr()
