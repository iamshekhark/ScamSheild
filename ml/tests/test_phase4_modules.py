"""
Automated Unit Tests for ScamShield Phase 4 Modules:
- Track A: OCR field extractor, CER/WER, PII redaction
- Track B: Message hybrid featurizer & OTP-negation feature
- Track C: UPI 7-state verifier, handle registry & ReputationStore corroboration
- Track D: Cross-modal EvidenceEnvelope & correlator invariants
"""

import os
import sys
import unittest

ML_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ML_ROOT not in sys.path:
    sys.path.insert(0, ML_ROOT)

from cross_modal.correlator import EvidenceEnvelope, correlate_evidence  # noqa: E402
from message_model.features import MessageHybridFeaturizer, extract_message_structured_features  # noqa: E402
from ocr_model.field_extractor import compute_cer, compute_wer, extract_ocr_fields  # noqa: E402
from upi_verifier.verifier import ReputationStore, verify_upi_id  # noqa: E402


class TestPhase4Modules(unittest.TestCase):
    def test_ocr_field_extraction_and_privacy(self):
        txt = "Paid Rs 1,427.25 to irctc@paytm. UTR: 519283746510. Call +919876543210."
        res = extract_ocr_fields(txt, ocr_confidence=91.0)
        self.assertFalse(res["settlement_verified"])
        self.assertEqual(res["fields"]["upi_ids"][0]["value"], "irctc@paytm")
        self.assertEqual(res["fields"]["amounts"][0]["value"], "1427.25")
        self.assertEqual(res["fields"]["transaction_refs"][0]["value"], "519283746510")
        self.assertEqual(res["fields"]["phone_numbers"][0]["value"], "[REDACTED_PHONE]")
        self.assertGreater(compute_cer("1000", "1OOO"), 0.0)
        self.assertGreater(compute_wer("pay Rs 100", "pay Rs 1OO"), 0.0)

    def test_message_features_and_negation(self):
        feats = extract_message_structured_features([
            "Never share your OTP with anyone.",
            "Urgent: pay Rs 500 fee to claim lottery prize at http://scam.xyz via a@ybl",
        ])
        self.assertEqual(feats[0, 5], 1.0)  # OTP negation
        self.assertEqual(feats[1, 9], 1.0)  # contextual prize-to-payment
        hyb = MessageHybridFeaturizer(word_max=50, char_max=50)
        X = hyb.fit_transform([{"content": "hello world message"}, {"content": "urgent lottery prize message"}])
        self.assertEqual(X.shape[0], 2)

    def test_upi_verifier_states_and_reputation(self):
        store = ReputationStore()
        store.add_signal("one@ybl", source="u1", verified=False, confidence=0.5, reason="unverified")
        store.add_signal("two@ybl", source="u1", verified=False, confidence=0.6, reason="r1")
        store.add_signal("two@ybl", source="u2", verified=False, confidence=0.7, reason="r2")

        r_known = verify_upi_id("merchant@okhdfcbank", reputation_store=store)
        self.assertTrue(r_known["format_valid"])
        self.assertTrue(r_known["handle_supported"])
        self.assertFalse(r_known["recipient_verified"])
        self.assertFalse(r_known["provider_lookup_available"])

        r_unknown = verify_upi_id("shop@unknownpsp", reputation_store=store)
        self.assertTrue(r_unknown["format_valid"])
        self.assertFalse(r_unknown["suspicious_pattern"])
        self.assertIn("UNKNOWN", r_unknown["states"])

        r_single = verify_upi_id("one@ybl", reputation_store=store)
        self.assertFalse(r_single["suspicious_pattern"])

        r_corrob = verify_upi_id("two@ybl", reputation_store=store)
        self.assertTrue(r_corrob["suspicious_pattern"])

    def test_cross_modal_correlator_invariants(self):
        res = correlate_evidence([
            EvidenceEnvelope("email_model", "email", "webpage", "phishing", 0.99, True, "email-v1", [{"indicator_type": "ML", "target": "site"}]),
            EvidenceEnvelope("upi_verifier", "upi", "upi_id", "malicious", None, False, "upi-v1", [{"indicator_type": "UPI_IMPERSONATION", "target": "x@ybl", "severity": "critical"}]),
            EvidenceEnvelope("deterministic_rules", "upi", "upi_id", "malicious", 1.0, True, "rules-v2", [{"indicator_type": "UPI_IMPERSONATION", "target": "x@ybl", "severity": "critical"}]),
        ])
        self.assertEqual(res["overall_verdict"], "critical_threat")
        self.assertEqual(len(res["rejected_incompatible_models"]), 1)
        self.assertEqual(res["evidence_count"], 1)
        self.assertFalse(res["payment_settlement_verified"])


if __name__ == "__main__":
    unittest.main()
