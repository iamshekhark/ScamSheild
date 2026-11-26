"""
ScamShield ML Pipeline - Automated Data Source Ingestion
Fetches, normalizes, and stages open-source cybersecurity datasets:
- Mitchell Krogza Phishing.Database & OpenPhish (phishing URLs)
- Tranco Research Top 1M (legitimate domains/URLs)
- HuggingFace Phishing Email Dataset (safe & phishing emails)
- UCI SMS Spam Collection (legitimate & spam messages)
- Curated Indian cyber threat vectors (Digital Arrest, Hinglish OTP, courier fraud)
- Curated Indian UPI & payment fraud vectors (corporate VPAs, reverse-collect lures)
"""

import os
import sys
import json
import zipfile
import io
import urllib.request
import urllib.error
import hashlib
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_DIR = os.path.join(BASE_DIR, "datasets", "raw")
EXTERNAL_DIR = os.path.join(RAW_DIR, "external")
REGISTRY_PATH = os.path.join(BASE_DIR, "data_sources", "source_registry.json")

os.makedirs(EXTERNAL_DIR, exist_ok=True)

USER_AGENT = "ScamShield-ML-Pipeline/2.0 (+https://github.com/scamshield/scamshield-extension)"

def fetch_url(url: str, timeout: int = 45) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.read()

def download_phishing_urls(max_records: int = 8000) -> list:
    print(f"[*] Ingesting phishing URLs from Mitchell Krogza & OpenPhish...")
    urls = []
    
    # 1. Mitchell Krogza Phishing.Database
    krogza_url = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt"
    try:
        content = fetch_url(krogza_url)
        lines = content.decode("utf-8", errors="ignore").splitlines()
        for line in lines:
            line = line.strip()
            if line and not line.startswith("#"):
                if not line.startswith(("http://", "https://")):
                    line = "http://" + line
                urls.append({
                    "url": line,
                    "label": "phishing",
                    "source": "mitchellkrogza_phishing"
                })
                if len(urls) >= max_records:
                    break
        print(f"    Loaded {len(urls)} samples from Mitchell Krogza.")
    except Exception as e:
        print(f"    [!] Failed to download Mitchell Krogza feed: {e}")

    # 2. OpenPhish feed
    openphish_url = "https://openphish.com/feed.txt"
    try:
        content = fetch_url(openphish_url)
        lines = content.decode("utf-8", errors="ignore").splitlines()
        added_op = 0
        for line in lines:
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append({
                    "url": line,
                    "label": "phishing",
                    "source": "openphish_feed"
                })
                added_op += 1
        print(f"    Loaded {added_op} samples from OpenPhish feed.")
    except Exception as e:
        print(f"    [!] Failed to download OpenPhish feed: {e}")

    return urls

def download_tranco_legitimate(max_records: int = 8000) -> list:
    print(f"[*] Ingesting top legitimate domains from Tranco Research 1M list...")
    tranco_url = "https://tranco-list.eu/top-1m.csv.zip"
    records = []
    try:
        data = fetch_url(tranco_url, timeout=60)
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            csv_filename = [n for n in z.namelist() if n.endswith(".csv")][0]
            with z.open(csv_filename) as f:
                count = 0
                for line in f:
                    decoded = line.decode("utf-8", errors="ignore").strip()
                    if not decoded or "," not in decoded:
                        continue
                    parts = decoded.split(",", 1)
                    domain = parts[1].strip().lower()
                    if not domain:
                        continue
                    
                    # Synthesize clean representative HTTPS URL
                    url_str = f"https://{domain}/"
                    records.append({
                        "url": url_str,
                        "label": "legitimate",
                        "source": "tranco_top_1m"
                    })
                    count += 1
                    if count >= max_records:
                        break
        print(f"    Loaded {len(records)} legitimate URLs from Tranco.")
    except Exception as e:
        print(f"    [!] Failed to download Tranco list: {e}")
    return records

def download_uci_sms_spam() -> list:
    print(f"[*] Ingesting SMS messages from UCI SMS Spam Collection...")
    url = "https://raw.githubusercontent.com/justmarkham/DAT8/master/data/sms.tsv"
    records = []
    try:
        data = fetch_url(url).decode("utf-8", errors="ignore")
        for line in data.splitlines():
            line = line.strip()
            if not line or "\t" not in line:
                continue
            parts = line.split("\t", 1)
            raw_label = parts[0].strip().lower()
            text = parts[1].strip()
            if not text:
                continue
            
            label = "spam" if raw_label == "spam" else "legitimate"
            records.append({
                "text": text,
                "label": label,
                "source": "uci_sms_spam"
            })
        print(f"    Loaded {len(records)} samples from UCI SMS dataset.")
    except Exception as e:
        print(f"    [!] Failed to download UCI SMS dataset: {e}")
    return records

def download_huggingface_emails(max_records: int = 10000) -> list:
    print(f"[*] Ingesting emails from HuggingFace Phishing Email dataset...")
    url = "https://huggingface.co/datasets/zefang-liu/phishing-email-dataset/resolve/main/Phishing_Email.csv"
    records = []
    try:
        import csv
        data = fetch_url(url, timeout=90).decode("utf-8", errors="ignore")
        reader = csv.reader(io.StringIO(data))
        header = next(reader, None)
        # Expected columns: ['', 'Email Text', 'Email Type']
        for row in reader:
            if len(row) < 3:
                continue
            email_text = row[1].strip()
            email_type = row[2].strip()
            
            if not email_text or email_text.lower() == "empty":
                continue
            
            label = "phishing" if "phishing" in email_type.lower() else "legitimate"
            # Truncate overly long emails to 1000 chars for browser feature parity
            snippet = email_text[:1000].strip()
            records.append({
                "text": snippet,
                "label": label,
                "source": "huggingface_phishing_email"
            })
            if len(records) >= max_records:
                break
        print(f"    Loaded {len(records)} samples from HuggingFace Email dataset.")
    except Exception as e:
        print(f"    [!] Failed to download HuggingFace Email dataset: {e}")
    return records

def get_curated_indian_threats() -> list:
    print(f"[*] Generating curated Indian cyber threat corpus (CERT-In / I4C / RBI patterns)...")
    curated = [
        # Digital Arrest & Extortion
        {"text": "URGENT CBI ARREST NOTICE: Your Aadhaar card is implicated in 16 money laundering cases with Jet Airways founder. Join Skype interrogation immediately to avoid non-bailable warrant.", "label": "scam", "source": "cert_in_i4c_curated"},
        {"text": "MUMBAI POLICE CYBER CELL: An illegal parcel containing 140g MDMA narcotics and 5 fake passports seized at Mumbai customs booked under your mobile number. Contact officer at wa.me/+919876543210 immediately.", "label": "scam", "source": "cert_in_i4c_curated"},
        {"text": "DELHI POLICE CYBER CRIME: You are under 24 hour digital arrest. Do not disconnect this call or video stream. Liquidate your fixed deposits and transfer to RBI verification vault account.", "label": "scam", "source": "cert_in_i4c_curated"},
        {"text": "TRAI NOTICE: All mobile outgoing and incoming services on this number will be permanently disconnected within 2 hours due to illegal advertising and obscene broadcasts. Press 9 for DOT officer.", "label": "scam", "source": "cert_in_i4c_curated"},
        {"text": "ENFORCEMENT DIRECTORATE (ED): PMLA summons issued against your PAN. Transfer assets into National Cyber Security reserve account to obtain clean financial clearance certificate.", "label": "scam", "source": "cert_in_i4c_curated"},
        
        # Electricity Bill Disconnection
        {"text": "Dear consumer, your electricity power connection will be disconnected tonight at 9:30 PM from the sub-station because your previous month bill was not updated. Contact electricity officer Mr. Sharma 9823145678 immediately.", "label": "scam", "source": "cert_in_i4c_curated"},
        {"text": "URGENT POWER UPDATE: Power supply will be disconnected at 10 PM. Download Mahavitaran Quick Support APK from http://bijli-bill-support.top to clear unpaid Rs 12.00 surcharge.", "label": "scam", "source": "cert_in_i4c_curated"},
        {"text": "BSES Rajdhani notice: Electricity supply disconnection notice generated for CA 100982345. Call power controller 9711098234 or your power supply will be cut off within 1 hour.", "label": "scam", "source": "cert_in_i4c_curated"},

        # Banking KYC & Hinglish OTP
        {"text": "SBI YONO Alert: Dear customer your SBI NetBanking profile password and YONO account has been blocked today. Please click http://sbi-yono-kyc-update.online to re-activate your netbanking immediately.", "label": "phishing", "source": "cert_in_i4c_curated"},
        {"text": "HDFC Alert: Your HDFC Debit Card reward points worth Rs 9,850 are expiring today at 23:59. Redeem cash directly to your savings account by submitting card details at http://hdfc-rewards-cash.xyz", "label": "phishing", "source": "cert_in_i4c_curated"},
        {"text": "Aapke SBI account me KYC pending hai. Agar aapne turant update nahi kiya toh aapka account freeze ho jayega. Click kare: http://sbi-kyc-verification.in", "label": "phishing", "source": "cert_in_i4c_curated"},
        {"text": "Namaskar, main Bank Manager bol raha hoon. Aapke account se Rs 25,000 deduct hone wala hai. Agar cancel karna hai toh abhi aaya hua 6-digit verification code turant share karein.", "label": "scam", "source": "cert_in_i4c_curated"},
        {"text": "ICICI Bank: Your ICICI internet banking access is temporarily suspended due to missing PAN linking. Complete biometric verification here: http://icici-pan-link.biz", "label": "phishing", "source": "cert_in_i4c_curated"},

        # Part-time Work / Telegram Task Scam
        {"text": "YouTube Review Job: Earn Rs 3,000 to Rs 8,000 daily by simply liking YouTube videos and rating hotels on Google Maps. No experience needed. Payout every 30 mins via UPI. Contact HR on WhatsApp +917029812345.", "label": "scam", "source": "cert_in_i4c_curated"},
        {"text": "Amazon Part-Time Hiring: Congratulations! You are shortlisted for Amazon product review specialist. Salary Rs 45,000/month. Join our official Telegram task group: https://t.me/amazon_task_india", "label": "scam", "source": "cert_in_i4c_curated"},
        {"text": "Hotel Rating Work From Home: Earn Rs 500 per hotel review. Prepaid tasks available. Invest Rs 5,000 to unlock VIP merchant commission of Rs 18,000. Contact supervisor on Telegram.", "label": "scam", "source": "cert_in_i4c_curated"},

        # Fake Courier & Customs
        {"text": "India Post Tracking: Your consignment package ID-IN892341 could not be delivered due to missing house number and address proof. Pay re-delivery fee of Rs 48 at http://indiapost-parcel-redelivery.top", "label": "phishing", "source": "cert_in_i4c_curated"},
        {"text": "BlueDart Express: Package #BD98231 held at airport warehouse. Clearance fee Rs 25 pending. Click http://bluedart-tracking-support.link to confirm delivery address.", "label": "phishing", "source": "cert_in_i4c_curated"},
        {"text": "FedEx Customs Notice: High value international package containing gold ornaments held at IGI Airport. Pay customs clearance tariff of Rs 14,500 to account 50100492100 to release parcel.", "label": "scam", "source": "cert_in_i4c_curated"},

        # Legitimate Alerts & Notifications (Hard Negatives)
        {"text": "HDFC Bank Alert: Rs 1,450.00 debited from a/c **4092 on 31-OCT-26 14:22 via UPI to SWIGGY. Info: UPI/109283749102. If not done by you, call 18002026161.", "label": "legitimate", "source": "cert_in_i4c_curated"},
        {"text": "SBI Alert: OTP for login to SBI NetBanking is 482910. Valid for 3 mins. Never share OTP with anyone including bank officials. SBI never asks for OTP.", "label": "legitimate", "source": "cert_in_i4c_curated"},
        {"text": "Dear Customer, your electricity bill for CA No 102938491 for Rs 2,410 is due on 05-NOV-2026. Pay online via Tata Power portal or BSES Delhi app.", "label": "legitimate", "source": "cert_in_i4c_curated"},
        {"text": "IRCTC: PNR 2849102948 Train 12952 TEJAS RAJ EXP, 31-OCT-26, 3A - B4/42 (CNF). Charting done. Please carry original government ID during journey.", "label": "legitimate", "source": "cert_in_i4c_curated"},
        {"text": "Your Swiggy delivery partner Rahul is on the way with your order #928341. Expected delivery time 18 minutes. Enjoy your meal!", "label": "legitimate", "source": "cert_in_i4c_curated"},
        {"text": "Amazon India: Your order #402-9182374-192831 has been dispatched via ATS and will be delivered tomorrow by 8 PM. Track at amazon.in/orders", "label": "legitimate", "source": "cert_in_i4c_curated"},
        {"text": "Aadhaar authentication successful for PAN verification at Income Tax portal on 31-10-2026 16:30:12 IST. If this was not you, lock biometrics via mAadhaar app.", "label": "legitimate", "source": "cert_in_i4c_curated"}
    ]
    return curated

def get_curated_payment_corpus() -> list:
    print(f"[*] Generating curated UPI and Payment fraud detection corpus...")
    curated = [
        # Legitimate Merchant VPAs & Transactions
        {"vpa": "swiggy@icici", "amount": 450.0, "note": "Food delivery order #482910", "type": "merchant_payment", "label": "legitimate", "source": "curated_payments"},
        {"vpa": "zomato@hdfcbank", "amount": 620.0, "note": "Order ZOM-892134", "type": "merchant_payment", "label": "legitimate", "source": "curated_payments"},
        {"vpa": "flipkart@axisbank", "amount": 3499.0, "note": "Electronics purchase FK82910", "type": "merchant_payment", "label": "legitimate", "source": "curated_payments"},
        {"vpa": "amazonpay@apl", "amount": 1299.0, "note": "Amazon Prime annual renewal", "type": "merchant_payment", "label": "legitimate", "source": "curated_payments"},
        {"vpa": "irctc@sbi", "amount": 2150.0, "note": "Train booking PNR 4920194821", "type": "merchant_payment", "label": "legitimate", "source": "curated_payments"},
        {"vpa": "tatapower@yesbank", "amount": 1840.0, "note": "Electricity bill CA-891023", "type": "bill_payment", "label": "legitimate", "source": "curated_payments"},
        {"vpa": "airtel.bill@airtel", "amount": 799.0, "note": "Broadband postpaid recharge", "type": "bill_payment", "label": "legitimate", "source": "curated_payments"},
        {"vpa": "uber@hdfcbank", "amount": 320.0, "note": "Ride fare Bangalore airport", "type": "merchant_payment", "label": "legitimate", "source": "curated_payments"},
        {"vpa": "netflix@icici", "amount": 649.0, "note": "Monthly subscription auto-debit", "type": "merchant_payment", "label": "legitimate", "source": "curated_payments"},
        {"vpa": "bescom@kbl", "amount": 2100.0, "note": "Bangalore power utility bill payment", "type": "bill_payment", "label": "legitimate", "source": "curated_payments"},
        {"vpa": "cultfit@hdfcbank", "amount": 12500.0, "note": "Annual fitness gym membership", "type": "merchant_payment", "label": "legitimate", "source": "curated_payments"},
        {"vpa": "bookmyshow@kotak", "amount": 890.0, "note": "Cinema tickets 2x IMAX 3D", "type": "merchant_payment", "label": "legitimate", "source": "curated_payments"},
        {"vpa": "ola@axisbank", "amount": 210.0, "note": "Cab trip settlement", "type": "merchant_payment", "label": "legitimate", "source": "curated_payments"},
        {"vpa": "make_my_trip@icici", "amount": 8450.0, "note": "Flight ticket DEL-BOM booking", "type": "merchant_payment", "label": "legitimate", "source": "curated_payments"},
        {"vpa": "cred.bill@axisbank", "amount": 35200.0, "note": "Credit card bill payment HDFC Regalia", "type": "card_payment", "label": "legitimate", "source": "curated_payments"},
        {"vpa": "rohit.sharma@okaxis", "amount": 2500.0, "note": "Dinner split weekend cafe", "type": "p2p_transfer", "label": "legitimate", "source": "curated_payments"},
        {"vpa": "priya.nair@oksbi", "amount": 12000.0, "note": "Flat rent November share", "type": "p2p_transfer", "label": "legitimate", "source": "curated_payments"},

        # Fraudulent Collect Requests & Reverse-Collect Lures
        {"vpa": "refund-desk-googlepay@okaxis", "amount": 9999.0, "note": "Enter UPI PIN to receive Rs 9999 cash refund from Google Pay customer care", "type": "collect_request", "label": "fraudulent", "source": "curated_payments"},
        {"vpa": "phonepe-cashback-claim@ybl", "amount": 4999.0, "note": "Pay 4999 to claim 100000 scratch card jackpot reward instantly into bank", "type": "collect_request", "label": "fraudulent", "source": "curated_payments"},
        {"vpa": "olx-army-officer-buy@oksbi", "amount": 25000.0, "note": "Scan QR and accept collect request to receive advance payment for furniture", "type": "reverse_collect_lure", "label": "fraudulent", "source": "curated_payments"},
        {"vpa": "rbi-security-vault-audit@icici", "amount": 95000.0, "note": "CBI digital arrest bail bond deposit. Fund verification fee refundable", "type": "extortion_transfer", "label": "fraudulent", "source": "curated_payments"},
        {"vpa": "telegram-task-recharge@paytm", "amount": 15000.0, "note": "Prepaid task deposit level 3. Payout Rs 48000 after transaction confirmation", "type": "advance_fee_fraud", "label": "fraudulent", "source": "curated_payments"},
        {"vpa": "electricity-bill-urgent-clear@ybl", "amount": 12.0, "note": "Bijli bill arrears update surcharge to prevent power cut tonight", "type": "collect_request", "label": "fraudulent", "source": "curated_payments"},
        {"vpa": "customs-duty-release-officer@axl", "amount": 28500.0, "note": "Narcotics parcel clearance customs tariff penalty settlement", "type": "extortion_transfer", "label": "fraudulent", "source": "curated_payments"},
        {"vpa": "fastag-recharge-failed-refund@airtel", "amount": 2999.0, "note": "FASTag balance refund. Approve collect request to get money in wallet", "type": "collect_request", "label": "fraudulent", "source": "curated_payments"},
        {"vpa": "crypto-bot-binance-earn@okaxis", "amount": 50000.0, "note": "VIP trading signal bot deposit. Guaranteed 300% daily profit return", "type": "advance_fee_fraud", "label": "fraudulent", "source": "curated_payments"},
        {"vpa": "sbi-kyc-reactivation-fee@barodampay", "amount": 5.0, "note": "Bank biometric verification fee. Enter 6-digit MPIN to unlock savings account", "type": "collect_request", "label": "fraudulent", "source": "curated_payments"},

        # Suspicious Payment Requests
        {"vpa": "admin928371@ybl", "amount": 8500.0, "note": "Immediate urgent transfer required urgently without invoice", "type": "unverified_vpa", "label": "suspicious", "source": "curated_payments"},
        {"vpa": "randomguy99@postbank", "amount": 49000.0, "note": "Government lottery registration fee processing", "type": "collect_request", "label": "suspicious", "source": "curated_payments"},
        {"vpa": "support-verification928@okbizaxis", "amount": 1500.0, "note": "Profile KYC fee re-attempt", "type": "collect_request", "label": "suspicious", "source": "curated_payments"},
        {"vpa": "merchant-settlement-temp@icici", "amount": 12000.0, "note": "Vendor payout adjustment", "type": "p2p_transfer", "label": "suspicious", "source": "curated_payments"},
        {"vpa": "hr-recruitment-onboarding@apl", "amount": 3500.0, "note": "Laptop security deposit for home onboarding kit", "type": "unverified_vpa", "label": "suspicious", "source": "curated_payments"}
    ]
    return curated

def main():
    print("=" * 70)
    print("ScamShield ML Pipeline - Automated Data Acquisition")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print("=" * 70)

    # 1. URLs
    phish_urls = download_phishing_urls(max_records=6000)
    legit_urls = download_tranco_legitimate(max_records=6000)
    
    with open(os.path.join(EXTERNAL_DIR, "phishing_urls.json"), "w", encoding="utf-8") as f:
        json.dump(phish_urls, f, indent=2)
    with open(os.path.join(EXTERNAL_DIR, "legitimate_urls.json"), "w", encoding="utf-8") as f:
        json.dump(legit_urls, f, indent=2)
        
    print(f"[+] URLs Staged: {len(phish_urls)} phishing, {len(legit_urls)} legitimate (Total: {len(phish_urls) + len(legit_urls)})")

    # 2. Text / Email / SMS
    sms_samples = download_uci_sms_spam()
    email_samples = download_huggingface_emails(max_records=8000)
    threat_curated = get_curated_indian_threats()
    
    with open(os.path.join(EXTERNAL_DIR, "sms_samples.json"), "w", encoding="utf-8") as f:
        json.dump(sms_samples, f, indent=2)
    with open(os.path.join(EXTERNAL_DIR, "email_samples.json"), "w", encoding="utf-8") as f:
        json.dump(email_samples, f, indent=2)
    with open(os.path.join(EXTERNAL_DIR, "curated_threats.json"), "w", encoding="utf-8") as f:
        json.dump(threat_curated, f, indent=2)
        
    total_text = len(sms_samples) + len(email_samples) + len(threat_curated)
    print(f"[+] Text/Email Staged: {len(sms_samples)} SMS, {len(email_samples)} Emails, {len(threat_curated)} Curated Threats (Total: {total_text})")

    # 3. Payments
    payments_curated = get_curated_payment_corpus()
    with open(os.path.join(EXTERNAL_DIR, "curated_payments.json"), "w", encoding="utf-8") as f:
        json.dump(payments_curated, f, indent=2)
    print(f"[+] Payment Corpus Staged: {len(payments_curated)} reviewed payment vectors.")

    print("\n[SUCCESS] Ingestion completed successfully.")
    print("=" * 70)

if __name__ == "__main__":
    main()
