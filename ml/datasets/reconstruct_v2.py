"""
ScamShield Phase 2 — Hard-Negative Dataset Reconstruction (v2.3.0)
Builds leakage-free, bias-controlled URL and Email datasets without modifying v1 datasets.

Provenance categories strictly preserved on every record:
- verified_public_data: Tranco Top 1M, OpenPhish, Mitchell Krogza Phishing.Database,
  HuggingFace Phishing Email, UCI SMS Spam, verified_samples.json
- curated_hard_negative: ScamShield curated legitimate & malicious hard-negatives
  covering realistic auth/OAuth/payment/checkout URLs and transactional/security emails.

Outputs (never overwriting v1):
- ml/datasets/splits_v2/{url,email}_{train,validation,test}.json
- ml/datasets/manifests/{url,email}_v2_manifest.json
- ml/reports/dataset_v2_validation_report.{json,md}
"""

import argparse
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List

import numpy as np

ML_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ML_ROOT not in sys.path:
    sys.path.insert(0, ML_ROOT)

from common import MANIFESTS_DIR, RAW_DIR, REPORTS_DIR  # noqa: E402
from datasets.validate_and_split import validate_and_deduplicate, verify_zero_leakage  # noqa: E402
from prepare_datasets import group_split  # noqa: E402

DATASET_VERSION = "2.3.0"
RANDOM_SEED = 42
SPLITS_V2_DIR = os.path.join(ML_ROOT, "datasets", "splits_v2")
os.makedirs(SPLITS_V2_DIR, exist_ok=True)

# ---------------------------------------------------------------------------
# Curated Legitimate URL Hard-Negatives (Verified Official Domains & Patterns)
# ---------------------------------------------------------------------------
CURATED_LEGIT_URLS: List[Dict[str, str]] = [
    # IRCTC (nested paths, search, query params, login, booking)
    {"url": "https://www.irctc.co.in/", "category": "root_domain"},
    {"url": "https://www.irctc.co.in/nget/train-search", "category": "nested_path"},
    {"url": "https://www.irctc.co.in/nget/booking/train-list", "category": "nested_path"},
    {"url": "https://www.irctc.co.in/nget/booking/check-train-schedule?trainNo=12951", "category": "query_param"},
    {"url": "https://www.irctc.co.in/nget/enquiry/pnr-enquiry?pnr=2418923411", "category": "query_param"},
    {"url": "https://www.irctc.co.in/nget/profile/user-login", "category": "auth_page"},
    # Paytm & Paytm Payments Services (checkout, API, OAuth, transaction status)
    {"url": "https://paytm.com/", "category": "root_domain"},
    {"url": "https://paytm.com/recharge", "category": "nested_path"},
    {"url": "https://paytm.com/electricity-bill-payment", "category": "payment_page"},
    {"url": "https://accounts.paytm.com/oauth2/authorize?client_id=paytm-web&response_type=code&redirect_uri=https%3A%2F%2Fpaytm.com%2Fcallback", "category": "oauth_auth"},
    {"url": "https://accounts.paytm.com/oauth2/callback?code=auth_98213a&state=xyz123", "category": "oauth_callback"},
    {"url": "https://secure.paytmpayments.com/", "category": "root_domain"},
    {"url": "https://secure.paytmpayments.com/theia/api/v1/showPaymentPage?mid=IRCTC123&orderId=ORD998877", "category": "checkout_page"},
    {"url": "https://secure.paytmpayments.com/theia/processTransaction?orderId=TXN2026112601", "category": "payment_page"},
    {"url": "https://secure.paytmpayments.com/merchant-status/check?orderId=ORD112233&token=ab92cd", "category": "tx_status"},
    {"url": "https://business.paytm.com/payment-gateway", "category": "nested_path"},
    # SBI / HDFC / ICICI / Axis / Kotak (Banking & Netbanking)
    {"url": "https://www.onlinesbi.sbi/", "category": "root_domain"},
    {"url": "https://retail.onlinesbi.sbi/retail/login.htm", "category": "banking_page"},
    {"url": "https://retail.onlinesbi.sbi/retail/mypage.htm?action=accountSummary", "category": "banking_page"},
    {"url": "https://corp.onlinesbi.sbi/corporate/sbi/login.html", "category": "banking_page"},
    {"url": "https://www.hdfcbank.com/", "category": "root_domain"},
    {"url": "https://netbanking.hdfcbank.com/netbanking/", "category": "banking_page"},
    {"url": "https://netbanking.hdfcbank.com/netbanking/entry?fldLoginUserId=cust", "category": "auth_page"},
    {"url": "https://www.icicibank.com/Personal-Banking/insta-banking/internet-banking/index.page", "category": "banking_page"},
    {"url": "https://infinity.icicibank.com/corp/AuthenticationController?FORMSGROUP_ID__=AuthenticationFG", "category": "auth_page"},
    {"url": "https://www.axisbank.com/bank-smart/internet-banking/getting-started", "category": "banking_page"},
    {"url": "https://omni.axisbank.co.in/axisretailbanking/", "category": "banking_page"},
    # Razorpay / Stripe / PayPal / NPCI (Payment Gateways & Checkout)
    {"url": "https://razorpay.com/docs/payments/payment-gateway/", "category": "nested_path"},
    {"url": "https://api.razorpay.com/v1/checkout/public?key_id=rzp_live_123456", "category": "api_endpoint"},
    {"url": "https://checkout.razorpay.com/v1/checkout.js", "category": "checkout_page"},
    {"url": "https://dashboard.razorpay.com/app/payments?status=captured", "category": "tx_status"},
    {"url": "https://checkout.stripe.com/c/pay/cs_live_a1b2c3d4e5f6g7h8", "category": "checkout_page"},
    {"url": "https://dashboard.stripe.com/login?redirect=%2Fpayments", "category": "auth_page"},
    {"url": "https://www.paypal.com/signin", "category": "auth_page"},
    {"url": "https://www.paypal.com/checkoutnow?token=EC-982716253412", "category": "checkout_page"},
    {"url": "https://www.npci.org.in/what-we-do/upi/product-overview", "category": "nested_path"},
    # Google / Microsoft / GitHub / Amazon / Apple (Search, OAuth, Settings, E-commerce)
    {"url": "https://www.google.com/search?q=irctc+pnr+status", "category": "search_page"},
    {"url": "https://accounts.google.com/o/oauth2/v2/auth?client_id=12345.apps.googleusercontent.com&redirect_uri=https%3A%2F%2Fexample.com%2Fcb&response_type=code&scope=openid%20email", "category": "oauth_auth"},
    {"url": "https://accounts.google.com/signin/v2/identifier?service=mail&flowName=GlifWebSignIn", "category": "auth_page"},
    {"url": "https://myaccount.google.com/security?hl=en", "category": "account_settings"},
    {"url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=1234&response_type=code&redirect_uri=https%3A%2F%2Fportal.azure.com", "category": "oauth_auth"},
    {"url": "https://account.microsoft.com/security?lang=en-US", "category": "account_settings"},
    {"url": "https://portal.azure.com/#home", "category": "nested_path"},
    {"url": "https://github.com/login?return_to=%2Fsettings%2Fprofile", "category": "auth_page"},
    {"url": "https://github.com/login/oauth/authorize?client_id=Iv1.8a61f9b3a7aba766&scope=read:user", "category": "oauth_auth"},
    {"url": "https://github.com/settings/security", "category": "account_settings"},
    {"url": "https://api.github.com/repos/scikit-learn/scikit-learn/releases?per_page=10", "category": "api_endpoint"},
    {"url": "https://www.amazon.in/ap/signin?openid.pape.max_auth_age=0&openid.return_to=https%3A%2F%2Fwww.amazon.in%2F", "category": "auth_page"},
    {"url": "https://www.amazon.in/gp/your-account/order-history?orderFilter=months-3", "category": "tx_status"},
    {"url": "https://www.amazon.in/s?k=mechanical+keyboard&ref=nb_sb_noss", "category": "search_page"},
    {"url": "https://appleid.apple.com/auth/authorize?client_id=com.example.web&response_type=code", "category": "oauth_auth"},
    {"url": "https://www.flipkart.com/account/orders?link=home_orders", "category": "tx_status"},
    {"url": "https://www.swiggy.com/checkout", "category": "checkout_page"},
    {"url": "https://www.zomato.com/india/order-history", "category": "tx_status"},
    # Developer, Docs, Government & Long Query URLs
    {"url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy", "category": "nested_path"},
    {"url": "https://docs.python.org/3/library/urllib.parse.html#urllib.parse.urlparse", "category": "nested_path"},
    {"url": "https://en.wikipedia.org/wiki/Phishing?oldid=123456789", "category": "query_param"},
    {"url": "https://stackoverflow.com/questions/tagged/python?tab=Newest&page=2", "category": "search_page"},
    {"url": "https://www.npmjs.com/package/tesseract.js?activeTab=versions", "category": "query_param"},
    {"url": "https://pypi.org/project/scikit-learn/#files", "category": "nested_path"},
    {"url": "https://www.incometax.gov.in/iec/foportal/", "category": "nested_path"},
    {"url": "https://uidai.gov.in/en/my-aadhaar/get-aadhaar.html", "category": "nested_path"},
    {"url": "https://www.digilocker.gov.in/signin?redirect_uri=https%3A%2F%2Fwww.digilocker.gov.in%2Fdashboard", "category": "redirect_url"},
    {"url": "https://auth.wikimedia.org/enwiki/wiki/Special:UserLogin?returnto=Main_Page", "category": "redirect_url"},
    {"url": "https://login.salesforce.com/?ec=302&startURL=%2Flightning%2Fpage%2Fhome", "category": "redirect_url"},
    {"url": "https://slack.com/oauth/v2/authorize?client_id=123.456&scope=channels:read&user_scope=identity.basic", "category": "oauth_auth"},
    {"url": "https://zoom.us/oauth/authorize?response_type=code&client_id=abc123&redirect_uri=https%3A%2F%2Fzoom.us%2Fcb", "category": "oauth_auth"},
]

# ---------------------------------------------------------------------------
# Curated Malicious URL Hard-Negatives (HTTPS, Root-Only, Realistic Structures)
# ---------------------------------------------------------------------------
CURATED_MALICIOUS_URLS: List[Dict[str, str]] = [
    # HTTPS root-only phishing (breaks is_https=1 & path_length=1 shortcut)
    {"url": "https://paytm-kyc-update-2026.xyz/", "category": "https_root_phish"},
    {"url": "https://sbi-yono-verify.top/", "category": "https_root_phish"},
    {"url": "https://hdfc-netbanking-secure.site/", "category": "https_root_phish"},
    {"url": "https://irctc-tatkal-refund.club/", "category": "https_root_phish"},
    {"url": "https://paypal-resolution-center.icu/", "category": "https_root_phish"},
    {"url": "https://microsoft-account-recovery.online/", "category": "https_root_phish"},
    {"url": "https://amazon-prize-claim.click/", "category": "https_root_phish"},
    {"url": "https://icici-pan-update.buzz/", "category": "https_root_phish"},
    # HTTPS nested-path & query-parameter phishing
    {"url": "https://paytrn-security.xyz/auth/login?session=expired", "category": "https_nested_phish"},
    {"url": "https://secure-paytmpayments-verify.com/theia/processTransaction?orderId=fake99", "category": "fake_payment_page"},
    {"url": "https://onlinesbi-kyc-portal.top/retail/login.htm?verify=otp", "category": "fake_banking_login"},
    {"url": "https://hdfcbank-reward-claim.site/netbanking/entry?token=91823", "category": "fake_banking_login"},
    {"url": "https://accounts-google-security.xyz/o/oauth2/v2/auth?client_id=evil&redirect_uri=https%3A%2F%2Fsteal.xyz", "category": "fake_oauth"},
    {"url": "https://login-microsoftonline-verify.icu/common/oauth2/authorize?client_id=phish", "category": "fake_oauth"},
    {"url": "https://github-security-alert.site/login?return_to=%2Fverify-token", "category": "credential_theft"},
    {"url": "https://razorpay-merchant-refund.top/v1/checkout/claim?id=8812", "category": "fake_checkout"},
    # Homograph, punycode, subdomain impersonation, redirect & shortener abuse
    {"url": "https://xn--pypal-4ve.com/signin", "category": "punycode_homograph"},
    {"url": "https://xn--g00gle-y1a.xyz/login", "category": "punycode_homograph"},
    {"url": "https://paytm.com.verify-wallet-kyc.xyz/login", "category": "subdomain_impersonation"},
    {"url": "https://sbi.co.in.account-unblock.top/kyc", "category": "subdomain_impersonation"},
    {"url": "https://paypal.com.user-session-check.site/webscr?cmd=_login", "category": "subdomain_impersonation"},
    {"url": "https://bit.ly/sbi-kyc-urgent-verify", "category": "shortener_abuse"},
    {"url": "https://tinyurl.com/paytm-cashback-claim-pin", "category": "shortener_abuse"},
    {"url": "https://redirect-auth-check.xyz/go?next=http%3A%2F%2F192.168.55.12%2Fsteal.php", "category": "redirect_phish"},
    {"url": "http://198.51.100.42/paytm/login.php?otp=required", "category": "ip_phish"},
    {"url": "https://203.0.113.77/sbi-netbanking/verify.html", "category": "ip_phish"},
]

# ---------------------------------------------------------------------------
# Curated Email Hard-Negatives (Legitimate Advisories/Transactional vs Scams)
# ---------------------------------------------------------------------------
CURATED_LEGIT_EMAILS: List[Dict[str, str]] = [
    {"subject": "Security Advisory: Protect your account from OTP fraud", "body": "State Bank of India never asks for your OTP, PIN, CVV, or netbanking password over phone, SMS, or email. Never share your OTP with anyone.", "category": "bank_security_advisory"},
    {"subject": "Important Security Reminder from HDFC Bank", "body": "Do not click unknown links to update KYC or PAN. HDFC Bank representatives will never ask for your debit card number, CVV, or login password.", "category": "bank_security_advisory"},
    {"subject": "Paytm Security Tip: Keep your UPI PIN private", "body": "Remember: You only enter your UPI PIN to send money, never to receive cashback or refunds. Report suspicious calls to cybercrime.gov.in.", "category": "bank_security_advisory"},
    {"subject": "Payment Successful: Rs 499.00 paid to Swiggy", "body": "Your UPI payment of Rs 499.00 to Swiggy Bundl Technologies via HDFC Bank is successful. UPI Ref / UTR: 426819284712. If you did not authorize this, contact bank support.", "category": "payment_notification"},
    {"subject": "Payment Receipt - IRCTC eTicketing", "body": "Thank you for your payment of Rs 1,427.25 via Paytm Payment Gateway. Order ID: IRCTC99881122. Your PNR status is confirmed.", "category": "payment_notification"},
    {"subject": "Your Amazon.in order #402-8819201-1234567 has shipped", "body": "Your package containing Logitech MX Master 3S has been dispatched and will arrive tomorrow by 8 PM. Track your package in Your Orders on amazon.in.", "category": "order_confirmation"},
    {"subject": "Flipkart Order Confirmed - OD3319284712", "body": "Hi, your order for SanDisk 1TB SSD has been confirmed. Expected delivery: Friday. Manage your order in the Flipkart app.", "category": "delivery_notification"},
    {"subject": "Your one-time verification code", "body": "482910 is your one-time password (OTP) to sign in to your account. This code expires in 10 minutes. Do not share this code with anyone.", "category": "otp_message"},
    {"subject": "Password reset requested for your GitHub account", "body": "We heard that you lost your GitHub password. If you did not request a password reset, you can safely ignore this email. Only use the link if you initiated this request.", "category": "password_reset"},
    {"subject": "[GitHub] New personal access token added to your account", "body": "A new fine-grained personal access token was added to your GitHub account. Review your security log in Settings if this was not you.", "category": "account_security_notification"},
    {"subject": "Microsoft account security info: New sign-in detected", "body": "We noticed a new sign-in to your Microsoft account from Windows in Bengaluru. If this was you, you can safely ignore this notification.", "category": "account_security_notification"},
    {"subject": "HDFC Bank Account Transaction Alert", "body": "Rs 2,500.00 debited from A/C **4821 on 26-11-2026 via UPI. Available balance: Rs 45,120.50. Not you? Call 1800-202-6161.", "category": "transaction_alert"},
    {"subject": "Monthly Product Updates & Engineering Digest", "body": "Welcome to our November newsletter! Read about our latest release notes, performance benchmarks, and upcoming community webinars.", "category": "marketing_newsletter"},
    {"subject": "Re: Ticket #48291 - Your billing invoice inquiry", "body": "Hello, thank you for contacting customer support. We have attached the PDF copy of your GST invoice for October. Please reply if you need further assistance.", "category": "customer_support"},
]

CURATED_MALICIOUS_EMAILS: List[Dict[str, str]] = [
    {"subject": "Urgent: Account Suspended", "body": "Your bank account is suspended today. Verify KYC at http://sbi-kyc-unblock.xyz within 2 hours.", "label": "phishing", "category": "short_phishing"},
    {"subject": "Action Required: KYC Expired", "body": "Update PAN & Aadhaar now or netbanking blocked: https://hdfc-kyc-update.top/auth", "label": "phishing", "category": "short_phishing"},
    {"subject": "P-a-y-t-m W-a-l-l-e-t S-u-s-p-e-n-d-e-d", "body": "Dear user, your w@llet is locked. S.h.a.r.e your 6-digit O.T.P at http://paytrn-verify.icu to restore access.", "label": "phishing", "category": "obfuscated_phishing"},
    {"subject": "Payment Failed - Refund Pending Rs 4,999", "body": "Your recent UPI payment failed. Enter your UPI PIN in the collect link http://upi-refund-claim.xyz to receive Rs 4,999 credit.", "label": "phishing", "category": "fake_payment_notification"},
    {"subject": "Amazon Order Cancelled - Refund Action Needed", "body": "Your Amazon order #99182 was cancelled. Submit your debit card number, CVV, and OTP at http://amazon-refund-desk.site to get instant refund.", "label": "phishing", "category": "fake_order_cancellation"},
    {"subject": "Microsoft 365: Password Expiry Notice", "body": "Your corporate Microsoft password expires today. Keep the same password by signing in at https://login-microsoftonline-verify.icu/auth", "label": "phishing", "category": "impersonation"},
    {"subject": "GitHub Security: Unauthorized SSH Key", "body": "Your GitHub repository access will be terminated in 24 hours. Verify credentials immediately at https://github-security-alert.site/login", "label": "phishing", "category": "fake_account_suspension"},
    {"subject": "OVERDUE INVOICE #88120 - LEGAL ACTION", "body": "Our banking details have changed. Wire $3,850 immediately to our new offshore account to avoid court proceedings.", "label": "phishing", "category": "urgent_financial_fraud"},
    {"subject": "CONGRATULATIONS! Claim your Rs 50,000 Cashback", "body": "You won Paytm VIP cashback! Pay Rs 199 processing fee via http://paytm-cashback-win.xyz to unlock prize.", "label": "spam", "category": "prize_spam"},
    {"subject": "Part-time work from home: Earn Rs 5,000/day", "body": "Like YouTube videos and complete Telegram prepaid tasks to earn daily payouts. Message HR now.", "label": "spam", "category": "job_spam"},
]


def load_json(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def reconstruct_url_v2(seed: int = RANDOM_SEED) -> Dict[str, Any]:
    rng = np.random.RandomState(seed)
    ext_dir = os.path.join(RAW_DIR, "external")
    phish_raw = load_json(os.path.join(ext_dir, "phishing_urls.json"))
    legit_raw = load_json(os.path.join(ext_dir, "legitimate_urls.json"))
    verified_raw = load_json(os.path.join(RAW_DIR, "verified_samples.json"))
    urls_raw = load_json(os.path.join(RAW_DIR, "urls_raw.json"))

    # Balance public sources so mitchellkrogza (all HTTP) & tranco (all root HTTPS) do not drown out HTTPS phishing/legit paths
    mk_items = [x for x in phish_raw if x.get("source") == "mitchellkrogza_phishing"]
    op_items = [x for x in phish_raw if x.get("source") == "openphish_feed"]
    rng.shuffle(mk_items)
    rng.shuffle(legit_raw)

    records: List[Dict[str, Any]] = []
    for x in mk_items[:1500]:
        records.append({**x, "provenance_type": "verified_public_data", "collection_date": "2026-10-31"})
    for x in op_items:
        records.append({**x, "provenance_type": "verified_public_data", "collection_date": "2026-10-31"})
    for x in legit_raw[:1500]:
        records.append({**x, "provenance_type": "verified_public_data", "collection_date": "2026-10-31"})

    for x in verified_raw:
        if x.get("task") == "url":
            records.append({
                "url": x.get("content", ""),
                "label": x.get("label"),
                "source": x.get("source", "verified_review"),
                "provenance_type": "verified_public_data",
                "collection_date": x.get("reviewed_at", "2026-10-31"),
            })
    for x in urls_raw:
        records.append({
            "url": x.get("url") or x.get("content", ""),
            "label": x.get("label"),
            "source": x.get("source", "synthetic_seed"),
            "provenance_type": "curated_hard_negative",
            "collection_date": "2026-10-31",
        })

    for x in CURATED_LEGIT_URLS:
        records.append({
            "url": x["url"],
            "label": "legitimate",
            "source": "scamshield_curated_legit_urls",
            "category": x["category"],
            "provenance_type": "curated_hard_negative",
            "collection_date": "2026-11-26",
        })
    for x in CURATED_MALICIOUS_URLS:
        records.append({
            "url": x["url"],
            "label": "malicious",
            "source": "scamshield_curated_malicious_urls",
            "category": x["category"],
            "provenance_type": "curated_hard_negative",
            "collection_date": "2026-11-26",
        })

    validated = validate_and_deduplicate(records, task="url", exclude_unknown_from_splits=True)
    _, train_items, val_items, test_items = group_split(validated["clean_items"], test_ratio=0.15, val_ratio=0.15, seed=seed)
    leakage = verify_zero_leakage(train_items, val_items, test_items)
    if not leakage["zero_group_leakage"]:
        raise RuntimeError(f"URL v2 group leakage detected: {leakage}")

    for split_name, split_items in (("train", train_items), ("validation", val_items), ("test", test_items)):
        with open(os.path.join(SPLITS_V2_DIR, f"url_{split_name}.json"), "w", encoding="utf-8") as f:
            json.dump({"task": "url", "dataset_version": DATASET_VERSION, "split": split_name, "count": len(split_items), "samples": split_items}, f, indent=2)

    manifest = {
        "task": "url",
        "dataset_version": DATASET_VERSION,
        "random_seed": seed,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "grouping_strategy": "public_suffix_list_registrable_domain",
        "splits": {
            s: {"count": len(items), "classes": dict(Counter(x["label"] for x in items)), "sources": dict(Counter(x["source"] for x in items))}
            for s, items in (("train", train_items), ("validation", val_items), ("test", test_items))
        },
        "validation_stats": validated["stats"],
        "leakage_check": leakage,
    }
    with open(os.path.join(MANIFESTS_DIR, "url_v2_manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    return manifest


def reconstruct_email_v2(seed: int = RANDOM_SEED) -> Dict[str, Any]:
    rng = np.random.RandomState(seed)
    ext_dir = os.path.join(RAW_DIR, "external")
    email_raw = load_json(os.path.join(ext_dir, "email_samples.json"))
    sms_raw = load_json(os.path.join(ext_dir, "sms_samples.json"))
    curated_threats = load_json(os.path.join(ext_dir, "curated_threats.json"))
    verified_raw = load_json(os.path.join(RAW_DIR, "verified_samples.json"))

    # Keep balanced public email + SMS samples
    rng.shuffle(email_raw)
    rng.shuffle(sms_raw)

    records: List[Dict[str, Any]] = []
    for x in email_raw[:6000]:
        records.append({**x, "provenance_type": "verified_public_data", "collection_date": "2026-10-31"})
    for x in sms_raw[:3000]:
        records.append({**x, "provenance_type": "verified_public_data", "collection_date": "2026-10-31"})
    for x in curated_threats:
        records.append({**x, "provenance_type": "curated_hard_negative", "collection_date": "2026-10-31"})
    for x in verified_raw:
        if x.get("task") == "text_email":
            records.append({
                "text": x.get("content", ""),
                "label": x.get("label"),
                "source": x.get("source", "verified_review"),
                "provenance_type": "verified_public_data",
                "collection_date": x.get("reviewed_at", "2026-10-31"),
            })

    for x in CURATED_LEGIT_EMAILS:
        records.append({
            "subject": x["subject"],
            "body": x["body"],
            "label": "legitimate",
            "source": "scamshield_curated_legit_emails",
            "category": x["category"],
            "provenance_type": "curated_hard_negative",
            "collection_date": "2026-11-26",
        })
    for x in CURATED_MALICIOUS_EMAILS:
        records.append({
            "subject": x["subject"],
            "body": x["body"],
            "label": x["label"],
            "source": "scamshield_curated_malicious_emails",
            "category": x["category"],
            "provenance_type": "curated_hard_negative",
            "collection_date": "2026-11-26",
        })

    validated = validate_and_deduplicate(records, task="email", exclude_unknown_from_splits=True)
    _, train_items, val_items, test_items = group_split(validated["clean_items"], test_ratio=0.15, val_ratio=0.15, seed=seed)
    leakage = verify_zero_leakage(train_items, val_items, test_items)
    if not leakage["zero_group_leakage"]:
        raise RuntimeError(f"Email v2 group leakage detected: {leakage}")

    for split_name, split_items in (("train", train_items), ("validation", val_items), ("test", test_items)):
        with open(os.path.join(SPLITS_V2_DIR, f"email_{split_name}.json"), "w", encoding="utf-8") as f:
            json.dump({"task": "email", "dataset_version": DATASET_VERSION, "split": split_name, "count": len(split_items), "samples": split_items}, f, indent=2)

    manifest = {
        "task": "email",
        "dataset_version": DATASET_VERSION,
        "random_seed": seed,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "grouping_strategy": "normalized_template_prefix",
        "splits": {
            s: {"count": len(items), "classes": dict(Counter(x["label"] for x in items)), "sources": dict(Counter(x["source"] for x in items))}
            for s, items in (("train", train_items), ("validation", val_items), ("test", test_items))
        },
        "validation_stats": validated["stats"],
        "leakage_check": leakage,
    }
    with open(os.path.join(MANIFESTS_DIR, "email_v2_manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    return manifest


def main():
    parser = argparse.ArgumentParser(description="Reconstruct ScamShield v2.3.0 hard-negative datasets.")
    parser.add_argument("--seed", type=int, default=RANDOM_SEED)
    args = parser.parse_args()

    url_m = reconstruct_url_v2(args.seed)
    email_m = reconstruct_email_v2(args.seed)

    report = {"dataset_version": DATASET_VERSION, "url": url_m, "email": email_m}
    with open(os.path.join(REPORTS_DIR, "dataset_v2_validation_report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"[OK] URL v2: train={url_m['splits']['train']['count']}, val={url_m['splits']['validation']['count']}, test={url_m['splits']['test']['count']} | zero_leakage={url_m['leakage_check']['zero_group_leakage']}")
    print(f"[OK] EMAIL v2: train={email_m['splits']['train']['count']}, val={email_m['splits']['validation']['count']}, test={email_m['splits']['test']['count']} | zero_leakage={email_m['leakage_check']['zero_group_leakage']}")


if __name__ == "__main__":
    main()
