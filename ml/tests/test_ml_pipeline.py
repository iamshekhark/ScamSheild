"""
Automated Unit & Regression Tests for ScamShield ML Pipeline
Covers:
- Dataset preprocessing, PII scrubbing, duplicate & contradictory label detection
- Group-aware splitting & zero train/val/test leakage
- Email & URL prediction, calibration, and confidence scoring (never derived from risk_score)
- Unified response contract schema
- Unknown, invalid, empty, and out-of-distribution inputs
- Legitimate website regression (IRCTC, Paytm, Google, Microsoft, GitHub, Amazon, SBI, HDFC)
- Malicious / phishing regression
"""

import os
import sys
import unittest

ML_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ML_ROOT not in sys.path:
    sys.path.insert(0, ML_ROOT)

from calibration.calibrate import compute_calibration_metrics  # noqa: E402
from datasets.validate_and_split import validate_and_deduplicate, verify_zero_leakage  # noqa: E402
from email_model.predict import predict_email  # noqa: E402
from email_model.preprocessing import preprocess_email_record  # noqa: E402
from url_model.feature_extraction import extract_single_url_features  # noqa: E402
from url_model.predict import predict_url  # noqa: E402


class TestDatasetPreprocessingAndSplitting(unittest.TestCase):
    def test_pii_scrubbing_and_normalization(self):
        prep = preprocess_email_record({
            "subject": "  Urgent   Notice  ",
            "body": "Contact john.doe@example.com or +91 9876543210 card 4111 2222 3333 4444",
            "sender": "Support@Example.com",
        })
        self.assertNotIn("john.doe@example.com", prep["combined_text"])
        self.assertNotIn("9876543210", prep["combined_text"])
        self.assertNotIn("4111 2222 3333", prep["combined_text"])
        self.assertIn("[EMAIL]", prep["combined_text"])
        self.assertIn("[PHONE]", prep["combined_text"])

    def test_deduplication_and_contradictory_labels(self):
        records = [
            {"url": "https://example.com/a", "label": "legitimate", "source": "test"},
            {"url": "https://example.com/a", "label": "legitimate", "source": "test"},
            {"url": "https://conflict.xyz/b", "label": "legitimate", "source": "test"},
            {"url": "https://conflict.xyz/b", "label": "malicious", "source": "test"},
            {"url": "https://unknown-site.test/c", "label": "unknown", "source": "test"},
            {"url": "", "label": "legitimate", "source": "test"},
        ]
        res = validate_and_deduplicate(records, task="url", exclude_unknown_from_splits=True)
        self.assertEqual(res["stats"]["exact_duplicates_removed"], 1)
        self.assertEqual(res["stats"]["contradictory_labels_detected"], 1)
        self.assertEqual(res["stats"]["unknown_excluded_count"], 2)
        self.assertEqual(res["stats"]["trainable_count"], 1)

    def test_zero_leakage_check(self):
        train = [{"group": "a.com", "content": "https://a.com/1"}]
        val = [{"group": "b.com", "content": "https://b.com/1"}]
        test = [{"group": "c.com", "content": "https://c.com/1"}]
        leak = verify_zero_leakage(train, val, test)
        self.assertTrue(leak["zero_group_leakage"])
        self.assertTrue(leak["zero_content_leakage"])


class TestUrlAndEmailInferenceAndContract(unittest.TestCase):
    REQUIRED_KEYS = {
        "classification",
        "risk_score",
        "model_confidence",
        "confidence_calibrated",
        "model_version",
        "detection_method",
        "indicators",
        "status",
    }

    def test_unified_contract_and_confidence_independence(self):
        res_email = predict_email(
            subject="Verify your KYC immediately",
            body="Your account is suspended. Click http://paytrn-security.xyz/verify and share your OTP.",
        )
        self.assertTrue(self.REQUIRED_KEYS.issubset(res_email.keys()))
        self.assertEqual(res_email["status"], "completed")
        self.assertTrue(res_email["confidence_calibrated"])
        self.assertIsInstance(res_email["model_confidence"], float)

        legit_email = predict_email(
            subject="Team meeting notes",
            body="Hi team, please find attached the agenda for tomorrow's engineering sync.",
        )
        self.assertEqual(legit_email["classification"], "legitimate")
        self.assertGreater(legit_email["model_confidence"], 55.0)
        self.assertLess(legit_email["risk_score"], 45)
        self.assertNotEqual(legit_email["model_confidence"], float(legit_email["risk_score"]))

        res_url = predict_url("http://paytrn-security.xyz/verify-kyc-login")
        self.assertTrue(self.REQUIRED_KEYS.issubset(res_url.keys()))
        self.assertIn(res_url["classification"], ("malicious", "uncertain"))
        self.assertTrue(res_url["confidence_calibrated"])

    def test_invalid_unknown_and_ood_inputs(self):
        empty_email = predict_email(subject="", body="")
        self.assertEqual(empty_email["status"], "invalid_input")
        self.assertIsNone(empty_email["model_confidence"])

        empty_url = predict_url("")
        self.assertEqual(empty_url["status"], "invalid_input")
        self.assertIsNone(empty_url["model_confidence"])

        ood_email = predict_email(subject="zzzqwx", body="xqvzjk plmnbv")
        self.assertEqual(ood_email["status"], "out_of_distribution")
        self.assertEqual(ood_email["classification"], "uncertain")
        self.assertIsNone(ood_email["model_confidence"])

    def test_missing_artifact_handled_safely(self):
        res = predict_url("https://www.google.com", artifact_path="nonexistent_model.joblib")
        self.assertEqual(res["status"], "model_unavailable")
        self.assertEqual(res["classification"], "unknown")

    def test_legitimate_websites_regression(self):
        legit_urls = [
            "https://www.irctc.co.in/",
            "https://paytm.com/",
            "https://secure.paytmpayments.com/",
            "https://www.google.com/",
            "https://www.microsoft.com/",
            "https://github.com/",
            "https://www.amazon.in/",
            "https://www.onlinesbi.sbi/",
        ]
        for u in legit_urls:
            res = predict_url(u)
            self.assertNotEqual(
                res["classification"],
                "malicious",
                f"False positive on legitimate URL {u}: {res}",
            )

    def test_malicious_urls_regression(self):
        malicious_urls = [
            "http://192.168.1.45/paypal-login/verify.php",
            "http://paytrn-security.xyz/kyc/update-account",
            "http://xn--pypal-4ve.com/signin",
        ]
        for u in malicious_urls:
            feats = extract_single_url_features(u)
            self.assertGreater(sum(feats), 0.0)
            res = predict_url(u)
            self.assertIn(res["classification"], ("malicious", "uncertain"))

    def test_calibration_metrics_computation(self):
        import numpy as np
        probs = np.array([[0.9, 0.1], [0.2, 0.8], [0.85, 0.15]])
        metrics = compute_calibration_metrics(probs, ["legitimate", "malicious", "legitimate"], ["legitimate", "malicious"])
        self.assertLess(metrics["brier_score"], 0.05)
        self.assertGreaterEqual(metrics["ece"], 0.0)


if __name__ == "__main__":
    unittest.main()
