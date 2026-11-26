#!/usr/bin/env python3
"""
Python vs JavaScript Inference Parity Verification
Loads trained scikit-learn models and tests parity against the JavaScript ml_inference engine
using Node.js execution. Confirms feature extraction, dot-product, and Softmax match.
"""

import os
import sys
import json
import joblib
import subprocess
import numpy as np

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MODELS_DIR = os.path.join(BASE_DIR, "models")
EXT_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "extension"))
JS_INFERENCE_PATH = os.path.join(EXT_DIR, "ml_inference.js")

TEST_INPUTS = {
    "url": [
        "https://paypa1.com/login-verify",
        "https://www.google.com/search?q=cybersecurity",
        "http://sbi-reward-points-claim.xyz/update-kyc",
        "https://apple.com/iphone-16-pro"
    ],
    "text_email": [
        "Urgent: You are placed under Digital Arrest by CBI. Join Skype interrogation immediately.",
        "Your one-time password (OTP) is 482910 for transaction on Amazon. NEVER share your OTP with anyone.",
        "Dear Customer, Your SBI YONO Account will be blocked today. Please click http://sbi-kyc.xyz",
        "Exclusive discount: Get 70% off luxury Swiss replica watches this weekend only!"
    ],
    "payment": [
        "upi://pay?pa=support-refund@okhdfcbank&pn=Amazon+Refund&tn=Enter+UPI+PIN+to+receive+Rs+4500",
        "swiggy@axisbank",
        "paytm-nodal-support@ybl",
        "rahul.sharma@oksbi"
    ]
}


def run_js_prediction(task: str, text: str) -> dict:
    """Run JS inference via Node.js script using ScamML."""
    json_model_path = os.path.join(MODELS_DIR, f"{task}_classifier.json").replace("\\", "/")
    js_runner = f"""
    const ScamML = require('{JS_INFERENCE_PATH.replace('\\', '/')}');
    const fs = require('fs');
    const model = JSON.parse(fs.readFileSync('{json_model_path}', 'utf8'));
    ScamML.registerModel('{task}', model);
    const res = ScamML.predict('{task}', {json.dumps(text)}, {{ allowExperimental: true }});
    console.log(JSON.stringify(res));
    """
    proc = subprocess.run(
        ["node", "-e", js_runner],
        capture_output=True,
        text=True,
        check=True
    )
    return json.loads(proc.stdout.strip())


def main():
    print("=" * 60)
    print("ScamShield ML: Python vs JavaScript Parity Verification")
    print("=" * 60)

    all_passed = True
    max_prob_diff_overall = 0.0

    for task, test_cases in TEST_INPUTS.items():
        joblib_path = os.path.join(MODELS_DIR, f"{task}_classifier.joblib")
        if not os.path.exists(joblib_path):
            print(f"Skipping {task}: Python model not found.")
            continue

        bundle = joblib.load(joblib_path)
        vectorizer = bundle["vectorizer"]
        clf = bundle["classifier"]
        classes = list(clf.classes_)
        json_path = os.path.join(MODELS_DIR, f"{task}_classifier.json")
        temperature = 1.0
        if os.path.exists(json_path):
            with open(json_path, "r", encoding="utf-8") as jf:
                temperature = float(json.load(jf).get("calibration", {}).get("temperature", 1.0))

        print(f"\nVerifying Task [{task}] ({len(test_cases)} test cases, T={temperature})...")

        for text in test_cases:
            # 1. Python prediction (with matching temperature scaling)
            X = vectorizer.transform([text])
            raw = clf.decision_function(X)
            if len(classes) == 2 and raw.ndim == 1:
                logits = np.array([-raw[0] / 2.0, raw[0] / 2.0])
            else:
                logits = raw[0]
            scaled = logits / max(temperature, 0.1)
            exps = np.exp(scaled - np.max(scaled))
            py_probs = exps / np.sum(exps)
            py_pred_idx = np.argmax(py_probs)
            py_pred_class = classes[py_pred_idx]
            py_prob_dict = {classes[i]: float(py_probs[i]) for i in range(len(classes))}

            # 2. JavaScript prediction
            js_res = run_js_prediction(task, text)
            js_pred_class = js_res["predicted_class"]
            js_probs = js_res["probabilities"]

            # 3. Compare class prediction
            classes_match = py_pred_class == js_pred_class

            # 4. Compare probability distributions
            prob_diffs = []
            for c in classes:
                p_py = py_prob_dict.get(c, 0.0)
                p_js = js_probs.get(c, 0.0)
                diff = abs(p_py - p_js)
                prob_diffs.append(diff)
                if diff > max_prob_diff_overall:
                    max_prob_diff_overall = diff

            max_diff = max(prob_diffs)
            is_close = max_diff < 0.05  # Within 5% numerical tolerance for rounding / float representation

            status = "PASS" if (classes_match and is_close) else "FAIL"
            if status == "FAIL":
                all_passed = False

            print(f"  [{status}] \"{text[:45]}...\"")
            print(f"         Python: {py_pred_class} (p={py_probs[py_pred_idx]:.4f})")
            print(f"         JS:     {js_pred_class} (p={js_res['confidence']:.4f}) | Max Prob Diff: {max_diff:.5f}")

            if not classes_match:
                print(f"         ERROR: Class mismatch! Py={py_pred_class} vs JS={js_pred_class}")

    print("\n" + "=" * 60)
    print(f"Parity Verification Result: {'PASSED' if all_passed else 'FAILED'}")
    print(f"Maximum Probability Divergence across all tests: {max_prob_diff_overall:.5f}")
    print("=" * 60)

    if not all_passed:
        sys.exit(1)


if __name__ == "__main__":
    main()
