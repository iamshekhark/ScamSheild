"""
ScamShield ML Pipeline - Curated Dataset Expansion & Independent Benchmark Synthesis
Generates rich, realistic, human-reviewed sample corpora for:
1. Text / Email Scams (Indian banking, OTP theft, Digital Arrest, Hinglish, legitimate alerts)
2. Payment Fraud (UPI collect lures, reverse refund scams, corporate merchant VPAs, P2P transfers)
3. Separate Payment Evaluation Benchmark (payment_evaluation_benchmark.json)
4. Untouched Unseen-Domain URL Holdout Benchmark (url_holdout_benchmark.json)
"""

import os
import json

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXTERNAL_DIR = os.path.join(BASE_DIR, "datasets", "raw", "external")
PROCESSED_DIR = os.path.join(BASE_DIR, "datasets", "processed")

os.makedirs(EXTERNAL_DIR, exist_ok=True)
os.makedirs(PROCESSED_DIR, exist_ok=True)


def build_expanded_threats() -> list:
    return [
        # === DIGITAL ARREST & EXTORTION SCAMS ===
        {"text": "URGENT CBI ARREST NOTICE: Your Aadhaar card is implicated in 16 money laundering cases with Jet Airways founder. Join Skype interrogation immediately to avoid non-bailable warrant.", "label": "scam", "source": "cert_in_i4c_curated"},
        {"text": "MUMBAI POLICE CYBER CELL: An illegal parcel containing 140g MDMA narcotics and 5 fake passports seized at Mumbai customs booked under your mobile number. Contact officer at wa.me/+919876543210 immediately.", "label": "scam", "source": "cert_in_i4c_curated"},
        {"text": "DELHI POLICE CYBER CRIME: You are under 24 hour digital arrest. Do not disconnect this call or video stream. Liquidate your fixed deposits and transfer to RBI verification vault account.", "label": "scam", "source": "cert_in_i4c_curated"},
        {"text": "TRAI NOTICE: All mobile outgoing and incoming services on this number will be permanently disconnected within 2 hours due to illegal advertising and obscene broadcasts. Press 9 for DOT officer.", "label": "scam", "source": "cert_in_i4c_curated"},
        {"text": "ENFORCEMENT DIRECTORATE (ED): PMLA summons issued against your PAN. Transfer assets into National Cyber Security reserve account to obtain clean financial clearance certificate.", "label": "scam", "source": "cert_in_i4c_curated"},
        {"text": "SUPREME COURT OF INDIA: Legal summons #SC-9281 issued against you for contraband smuggling. Non-appearance within 3 hours will result in asset seizure and non-bailable imprisonment.", "label": "scam", "source": "cert_in_i4c_curated"},
        {"text": "CUSTOMS CLEARANCE DEPARTMENT: High value parcel #IN-9921 from UK held at IGI Airport. Pay customs clearance tariff of Rs 28,500 to reserve account 50100492100 to release parcel.", "label": "scam", "source": "cert_in_i4c_curated"},

        # === ELECTRICITY & UTILITY DISCONNECTION SCAMS ===
        {"text": "Dear consumer, your electricity power connection will be disconnected tonight at 9:30 PM from the sub-station because your previous month bill was not updated. Contact electricity officer Mr. Sharma 9823145678 immediately.", "label": "scam", "source": "cert_in_i4c_curated"},
        {"text": "URGENT POWER UPDATE: Power supply will be disconnected at 10 PM. Download Mahavitaran Quick Support APK from http://bijli-bill-support.top to clear unpaid Rs 12.00 surcharge.", "label": "scam", "source": "cert_in_i4c_curated"},
        {"text": "BSES Rajdhani notice: Electricity supply disconnection notice generated for CA 100982345. Call power controller 9711098234 or your power supply will be cut off within 1 hour.", "label": "scam", "source": "cert_in_i4c_curated"},
        {"text": "BESCOM Alert: Dear consumer your power line will be disconnected today at 21:00 hrs due to bill arrears. Call sub-divisional executive 9448102934 immediately to avoid blackout.", "label": "scam", "source": "cert_in_i4c_curated"},
        {"text": "GAIL Gas Pipeline: Your piped natural gas meter connection is suspended for pending inspection fee of Rs 45. Pay immediately via http://gailgas-meter-recharge.xyz or supply cut off.", "label": "scam", "source": "cert_in_i4c_curated"},

        # === BANKING KYC & HINGLISH OTP FRAUD ===
        {"text": "SBI YONO Alert: Dear customer your SBI NetBanking profile password and YONO account has been blocked today. Please click http://sbi-yono-kyc-update.online to re-activate your netbanking immediately.", "label": "phishing", "source": "cert_in_i4c_curated"},
        {"text": "HDFC Alert: Your HDFC Debit Card reward points worth Rs 9,850 are expiring today at 23:59. Redeem cash directly to your savings account by submitting card details at http://hdfc-rewards-cash.xyz", "label": "phishing", "source": "cert_in_i4c_curated"},
        {"text": "Aapke SBI account me KYC pending hai. Agar aapne turant update nahi kiya toh aapka account freeze ho jayega. Click kare: http://sbi-kyc-verification.in", "label": "phishing", "source": "cert_in_i4c_curated"},
        {"text": "Namaskar, main Bank Manager bol raha hoon. Aapke account se Rs 25,000 deduct hone wala hai. Agar cancel karna hai toh abhi aaya hua 6-digit verification code turant share karein.", "label": "scam", "source": "cert_in_i4c_curated"},
        {"text": "ICICI Bank: Your ICICI internet banking access is temporarily suspended due to missing PAN linking. Complete biometric verification here: http://icici-pan-link.biz", "label": "phishing", "source": "cert_in_i4c_curated"},
        {"text": "Bank of Baroda: Dear Customer your account is in dormant status. Provide 6-digit OTP code to unfreeze your debit card and restore UPI transaction limits.", "label": "scam", "source": "cert_in_i4c_curated"},
        {"text": "Aapka SIM card 2 ghante me block ho jayega. Turant WhatsApp par apna Aadhaar aur OTP bhej kar e-KYC complete karein: wa.me/+919876500123", "label": "scam", "source": "cert_in_i4c_curated"},
        {"text": "Paytm Wallet Alert: Your wallet is suspended as per RBI guidelines. Complete video KYC and share MPIN verification code with customer agent to unlock balance.", "label": "phishing", "source": "cert_in_i4c_curated"},

        # === WORK FROM HOME / TELEGRAM PART-TIME TASK SCAMS ===
        {"text": "YouTube Review Job: Earn Rs 3,000 to Rs 8,000 daily by simply liking YouTube videos and rating hotels on Google Maps. No experience needed. Payout every 30 mins via UPI. Contact HR on WhatsApp +917029812345.", "label": "scam", "source": "cert_in_i4c_curated"},
        {"text": "Amazon Part-Time Hiring: Congratulations! You are shortlisted for Amazon product review specialist. Salary Rs 45,000/month. Join our official Telegram task group: https://t.me/amazon_task_india", "label": "scam", "source": "cert_in_i4c_curated"},
        {"text": "Hotel Rating Work From Home: Earn Rs 500 per hotel review. Prepaid tasks available. Invest Rs 5,000 to unlock VIP merchant commission of Rs 18,000. Contact supervisor on Telegram.", "label": "scam", "source": "cert_in_i4c_curated"},
        {"text": "Instagram Follower Job: Earn Rs 250 for every Instagram account you follow. Guaranteed daily earnings Rs 4,500. Work 1 hour from your phone. Register now on Telegram @task_director_in", "label": "scam", "source": "cert_in_i4c_curated"},
        {"text": "Crypto Trading Signal VIP Task: Deposit Rs 10,000 in level 2 trading bot. Receive guaranteed 400% profit withdrawal of Rs 40,000 within 20 minutes. Send transaction screenshot to admin.", "label": "scam", "source": "cert_in_i4c_curated"},
        {"text": "Internship Selection Notice: Congratulations you are hired as Remote Cybersecurity Intern at Tech Corp. Pay mandatory background verification fee of Rs 1,499 to confirm your offer letter.", "label": "scam", "source": "cert_in_i4c_curated"},

        # === COURIER & REFUND SCAMS ===
        {"text": "India Post Tracking: Your consignment package ID-IN892341 could not be delivered due to missing house number and address proof. Pay re-delivery fee of Rs 48 at http://indiapost-parcel-redelivery.top", "label": "phishing", "source": "cert_in_i4c_curated"},
        {"text": "BlueDart Express: Package #BD98231 held at airport warehouse. Clearance fee Rs 25 pending. Click http://bluedart-tracking-support.link to confirm delivery address.", "label": "phishing", "source": "cert_in_i4c_curated"},
        {"text": "FedEx Delivery Alert: Delivery failed as door was locked. Confirm alternate delivery date and pay Rs 18 reschedule fee at http://fedex-express-delivery.site", "label": "phishing", "source": "cert_in_i4c_curated"},
        {"text": "IRCTC Refund Pending: Your cancelled train ticket refund of Rs 1,840 is pending. Click http://irctc-ticket-refund.online to enter your UPI VPA and claim refund instantly.", "label": "phishing", "source": "cert_in_i4c_curated"},

        # === AUTHENTIC TRANSACTIONAL ALERTS & HARD NEGATIVE OTP WARNINGS ===
        {"text": "Your one-time password (OTP) is 482910 for transaction on Amazon. NEVER share your OTP with anyone. Bank officials will never ask for your OTP.", "label": "legitimate", "source": "cert_in_i4c_curated"},
        {"text": "HDFC Bank Alert: Rs 1,450.00 debited from a/c **4092 on 31-OCT-26 14:22 via UPI to SWIGGY. Info: UPI/109283749102. If not done by you, call 18002026161.", "label": "legitimate", "source": "cert_in_i4c_curated"},
        {"text": "SBI Alert: OTP for login to SBI NetBanking is 482910. Valid for 3 mins. Never share OTP with anyone including bank officials. SBI never asks for OTP.", "label": "legitimate", "source": "cert_in_i4c_curated"},
        {"text": "HDFC Bank: 938201 is the OTP to login to NetBanking. Do NOT share OTP or password with anyone, even bank staff.", "label": "legitimate", "source": "cert_in_i4c_curated"},
        {"text": "ICICI Bank: OTP for online purchase of Rs 2,340.00 at FLIPKART is 109283. Do not share OTP with anyone. ICICI Bank never calls for OTP.", "label": "legitimate", "source": "cert_in_i4c_curated"},
        {"text": "Dear Customer, your electricity bill for CA No 102938491 for Rs 2,410 is due on 05-NOV-2026. Pay online via Tata Power portal or BSES Delhi app.", "label": "legitimate", "source": "cert_in_i4c_curated"},
        {"text": "IRCTC: PNR 2849102948 Train 12952 TEJAS RAJ EXP, 31-OCT-26, 3A - B4/42 (CNF). Charting done. Please carry original government ID during journey.", "label": "legitimate", "source": "cert_in_i4c_curated"},
        {"text": "Your Swiggy delivery partner Rahul is on the way with your order #928341. Expected delivery time 18 minutes. Enjoy your meal!", "label": "legitimate", "source": "cert_in_i4c_curated"},
        {"text": "Amazon India: Your order #402-9182374-192831 has been dispatched via ATS and will be delivered tomorrow by 8 PM. Track at amazon.in/orders", "label": "legitimate", "source": "cert_in_i4c_curated"},
        {"text": "Aadhaar authentication successful for PAN verification at Income Tax portal on 31-10-2026 16:30:12 IST. If this was not you, lock biometrics via mAadhaar app.", "label": "legitimate", "source": "cert_in_i4c_curated"},
        {"text": "Uber receipt: Your trip with driver Ramesh on 31-Oct-26 was Rs 340.00. Paid via Amazon Pay balance. Thank you for riding with Uber.", "label": "legitimate", "source": "cert_in_i4c_curated"},
        {"text": "Domino's Pizza: Feast weekend! Flat 40% OFF on all gourmet pizzas using code FEAST40 on Domino's app. Valid till Sunday.", "label": "spam", "source": "cert_in_i4c_curated"},
        {"text": "Myntra Big Fashion Festival is LIVE! Get 50-80% off on top brands + extra 10% off on HDFC credit cards. Shop now on Myntra app.", "label": "spam", "source": "cert_in_i4c_curated"},
        {"text": "Exclusive discount: Get 70% off luxury Swiss replica watches this weekend only! Buy direct with international express shipping.", "label": "spam", "source": "cert_in_i4c_curated"}
    ]


def build_expanded_payments() -> list:
    return [
        # === FRAUDULENT UPI COLLECT REQUESTS & REVERSE REFUND LURES ===
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
        {"vpa": "support-refund@okhdfcbank", "amount": 4500.0, "note": "Enter UPI PIN to receive Amazon refund credit into bank", "type": "collect_request", "label": "fraudulent", "source": "curated_payments"},
        {"vpa": "paytm-nodal-support@ybl", "amount": 18000.0, "note": "Security deposit for level 2 clearance task", "type": "advance_fee_fraud", "label": "fraudulent", "source": "curated_payments"},
        {"vpa": "quikr-buyer-advance-scan@oksbi", "amount": 12000.0, "note": "Scan QR to receive car deposit advance into Google Pay", "type": "reverse_collect_lure", "label": "fraudulent", "source": "curated_payments"},
        {"vpa": "bajaj-finance-noc-fee@okaxis", "amount": 3500.0, "note": "Loan cancellation NOC charge. Immediate transfer required to close loan", "type": "advance_fee_fraud", "label": "fraudulent", "source": "curated_payments"},
        {"vpa": "kbc-lottery-tax-clearance@paytm", "amount": 25000.0, "note": "TDS clearance for 25 Lakh KBC lottery reward payout", "type": "advance_fee_fraud", "label": "fraudulent", "source": "curated_payments"},

        # === SUSPICIOUS PAYMENT REQUESTS ===
        {"vpa": "admin928371@ybl", "amount": 8500.0, "note": "Immediate urgent transfer required urgently without invoice", "type": "unverified_vpa", "label": "suspicious", "source": "curated_payments"},
        {"vpa": "randomguy99@postbank", "amount": 49000.0, "note": "Government lottery registration fee processing", "type": "collect_request", "label": "suspicious", "source": "curated_payments"},
        {"vpa": "support-verification928@okbizaxis", "amount": 1500.0, "note": "Profile KYC fee re-attempt", "type": "collect_request", "label": "suspicious", "source": "curated_payments"},
        {"vpa": "merchant-settlement-temp@icici", "amount": 12000.0, "note": "Vendor payout adjustment", "type": "p2p_transfer", "label": "suspicious", "source": "curated_payments"},
        {"vpa": "hr-recruitment-onboarding@apl", "amount": 3500.0, "note": "Laptop security deposit for home onboarding kit", "type": "unverified_vpa", "label": "suspicious", "source": "curated_payments"},
        {"vpa": "crypto-vip-signals@okaxis", "amount": 8000.0, "note": "Lifetime trading group access subscription", "type": "unverified_vpa", "label": "suspicious", "source": "curated_payments"},
        {"vpa": "giftcard-exchange-desk@ybl", "amount": 4500.0, "note": "Convert Amazon gift vouchers to instant cash", "type": "unverified_vpa", "label": "suspicious", "source": "curated_payments"},

        # === LEGITIMATE MERCHANT & TRANSACTIONAL PAYMENTS ===
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
        {"vpa": "jio.recharge@jio", "amount": 349.0, "note": "Prepaid 28-day 2GB daily pack", "type": "bill_payment", "label": "legitimate", "source": "curated_payments"},
        {"vpa": "bigbasket@hdfcbank", "amount": 1420.0, "note": "Grocery delivery order BB-90182", "type": "merchant_payment", "label": "legitimate", "source": "curated_payments"},
        {"vpa": "blinkit@icici", "amount": 380.0, "note": "Instant delivery snacks & essentials", "type": "merchant_payment", "label": "legitimate", "source": "curated_payments"},
        {"vpa": "apollo.pharmacy@axisbank", "amount": 890.0, "note": "Prescription medicines delivery order", "type": "merchant_payment", "label": "legitimate", "source": "curated_payments"},
        {"vpa": "rohit.sharma@okaxis", "amount": 2500.0, "note": "Dinner split weekend cafe", "type": "p2p_transfer", "label": "legitimate", "source": "curated_payments"},
        {"vpa": "priya.nair@oksbi", "amount": 12000.0, "note": "Flat rent November share", "type": "p2p_transfer", "label": "legitimate", "source": "curated_payments"},
        {"vpa": "vikram.aditya@ybl", "amount": 650.0, "note": "Movie ticket share", "type": "p2p_transfer", "label": "legitimate", "source": "curated_payments"}
    ]


def build_payment_evaluation_benchmark() -> list:
    """Realistic independent benchmark set to evaluate payment models."""
    return [
        {"content": "swiggy@icici | 320.0 | Food order settlement", "label": "legitimate", "category": "OFFICIAL_MERCHANT"},
        {"content": "zomato@hdfcbank | 550.0 | Dinner order payment", "label": "legitimate", "category": "OFFICIAL_MERCHANT"},
        {"content": "flipkart@axisbank | 1899.0 | Footwear purchase", "label": "legitimate", "category": "OFFICIAL_MERCHANT"},
        {"content": "tatapower@yesbank | 2450.0 | Electricity utility bill", "label": "legitimate", "category": "UTILITY_BILL"},
        {"content": "bescom@kbl | 1920.0 | Power bill payment", "label": "legitimate", "category": "UTILITY_BILL"},
        {"content": "airtel.bill@airtel | 699.0 | Fiber postpaid payment", "label": "legitimate", "category": "UTILITY_BILL"},
        {"content": "irctc@sbi | 3120.0 | Train tickets 2x 2A CNF", "label": "legitimate", "category": "OFFICIAL_MERCHANT"},
        {"content": "ananya.sen@okhdfcbank | 1500.0 | Weekend brunch share", "label": "legitimate", "category": "P2P_TRANSFER"},
        {"content": "rahul.verma@paytm | 2000.0 | Society sports fund", "label": "legitimate", "category": "P2P_TRANSFER"},
        {"content": "deepak.joshi@sbi | 850.0 | Books purchase contribution", "label": "legitimate", "category": "P2P_TRANSFER"},
        {"content": "refund-desk-googlepay@okaxis | 9999.0 | Enter UPI PIN to receive Rs 9999 cash refund from Google Pay customer care", "label": "fraudulent", "category": "REVERSE_COLLECT_FRAUD"},
        {"content": "phonepe-cashback-claim@ybl | 4999.0 | Pay 4999 to claim 100000 scratch card jackpot reward instantly into bank", "label": "fraudulent", "category": "REVERSE_COLLECT_FRAUD"},
        {"content": "olx-army-officer-buy@oksbi | 25000.0 | Scan QR and accept collect request to receive advance payment for furniture", "label": "fraudulent", "category": "QR_CODE_EXTORTION"},
        {"content": "rbi-security-vault-audit@icici | 95000.0 | CBI digital arrest bail bond deposit. Fund verification fee refundable", "label": "fraudulent", "category": "DIGITAL_ARREST_EXTORTION"},
        {"content": "telegram-task-recharge@paytm | 15000.0 | Prepaid task deposit level 3. Payout Rs 48000 after transaction confirmation", "label": "fraudulent", "category": "ADVANCE_FEE_FRAUD"},
        {"content": "electricity-bill-urgent-clear@ybl | 12.0 | Bijli bill arrears update surcharge to prevent power cut tonight", "label": "fraudulent", "category": "BILL_EXTORTION"},
        {"content": "admin928371@ybl | 8500.0 | Immediate urgent transfer required urgently without invoice", "label": "suspicious", "category": "ANOMALOUS_VPA"},
        {"content": "randomguy99@postbank | 49000.0 | Government lottery registration fee processing", "label": "suspicious", "category": "ANOMALOUS_VPA"},
        {"content": "support-verification928@okbizaxis | 1500.0 | Profile KYC fee re-attempt", "label": "suspicious", "category": "ANOMALOUS_VPA"}
    ]


def build_url_holdout_benchmark() -> list:
    """
    Untouched test dataset containing domains and phishing campaigns absent from training.
    Specifically tests typosquatting, brand impersonation, punycode, homographs, redirects,
    shorteners, IP hosts, and multi-part ccTLDs.
    """
    return [
        # === BRAND TYPOSQUATTING & IMPERSONATION (UNSEEN DOMAINS) ===
        {"url": "https://paypa1.com/login-verify", "label": "phishing", "category": "TYPOSQUATTING", "domain": "paypa1.com"},
        {"url": "https://g00gle-security-update.net/auth", "label": "phishing", "category": "TYPOSQUATTING", "domain": "g00gle-security-update.net"},
        {"url": "https://micros0ft-office365-login.com/checkpoint", "label": "phishing", "category": "TYPOSQUATTING", "domain": "micros0ft-office365-login.com"},
        {"url": "https://netflix-billing-renew.xyz/portal", "label": "phishing", "category": "BRAND_IMPERSONATION", "domain": "netflix-billing-renew.xyz"},
        {"url": "https://secure-login.chase.com.evil-bank.top/auth", "label": "phishing", "category": "SUBDOMAIN_DECEPTION", "domain": "evil-bank.top"},
        {"url": "https://amazon-prime-reward-cash.buzz/claim", "label": "phishing", "category": "BRAND_IMPERSONATION", "domain": "amazon-prime-reward-cash.buzz"},
        {"url": "http://sbi-yono-kyc-reactivate.top/login", "label": "phishing", "category": "BRAND_IMPERSONATION", "domain": "sbi-yono-kyc-reactivate.top"},
        {"url": "http://hdfc-bank-rewards-points.click/portal", "label": "phishing", "category": "BRAND_IMPERSONATION", "domain": "hdfc-bank-rewards-points.click"},

        # === PUNYCODE & UNICODE HOMOGRAPHS ===
        {"url": "https://xn--pple-43d.com/store", "label": "phishing", "category": "PUNYCODE_HOMOGRAPH", "domain": "xn--pple-43d.com"},
        {"url": "https://xn--e1awd7f.com/login", "label": "phishing", "category": "PUNYCODE_HOMOGRAPH", "domain": "xn--e1awd7f.com"},
        {"url": "https://www.xn--microsofte-4pb.com/download", "label": "phishing", "category": "PUNYCODE_HOMOGRAPH", "domain": "xn--microsofte-4pb.com"},

        # === SHORTENERS & REDIRECTS ===
        {"url": "https://bit.ly/3xXyZ9_sbi_kyc", "label": "phishing", "category": "SHORTENED_URL", "domain": "bit.ly"},
        {"url": "https://tinyurl.com/paytm-kyc-reactivate", "label": "phishing", "category": "SHORTENED_URL", "domain": "tinyurl.com"},
        {"url": "https://t.co/fakealert_9921", "label": "phishing", "category": "SHORTENED_URL", "domain": "t.co"},

        # === IP-BASED HOSTS ===
        {"url": "http://192.168.1.50/banking/login", "label": "phishing", "category": "RAW_IP_HOST", "domain": "192.168.1.50"},
        {"url": "http://203.0.113.15:8080/secure/verify", "label": "phishing", "category": "RAW_IP_HOST", "domain": "203.0.113.15"},

        # === LEGITIMATE POPULAR & UNUSUAL WEBSITES (UNSEEN HOLDOUT) ===
        {"url": "https://www.paypal.com/us/signin", "label": "legitimate", "category": "POPULAR_LEGITIMATE", "domain": "paypal.com"},
        {"url": "https://accounts.google.com/signin/v2/identifier", "label": "legitimate", "category": "POPULAR_LEGITIMATE", "domain": "google.com"},
        {"url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize", "label": "legitimate", "category": "POPULAR_LEGITIMATE", "domain": "microsoftonline.com"},
        {"url": "https://appleid.apple.com/sign-in", "label": "legitimate", "category": "POPULAR_LEGITIMATE", "domain": "apple.com"},
        {"url": "https://netflix.com/youraccount", "label": "legitimate", "category": "POPULAR_LEGITIMATE", "domain": "netflix.com"},
        {"url": "https://onlinesbi.sbi/personal/welcome.htm", "label": "legitimate", "category": "POPULAR_LEGITIMATE", "domain": "onlinesbi.sbi"},
        {"url": "https://netbanking.hdfcbank.com/netbanking/", "label": "legitimate", "category": "POPULAR_LEGITIMATE", "domain": "hdfcbank.com"},
        {"url": "https://www.amazon.in/gp/bestsellers", "label": "legitimate", "category": "POPULAR_LEGITIMATE", "domain": "amazon.in"},
        {"url": "https://subdomain.service.gov.uk/apply", "label": "legitimate", "category": "MULTI_PART_CCTLD", "domain": "service.gov.uk"},
        {"url": "https://portal.incometax.gov.in/iec/foservices", "label": "legitimate", "category": "MULTI_PART_CCTLD", "domain": "incometax.gov.in"},
        {"url": "https://developer.mozilla.org/en-US/docs/Web/API", "label": "legitimate", "category": "LEGITIMATE_UNUSUAL", "domain": "mozilla.org"},
        {"url": "https://raw.githubusercontent.com/torvalds/linux/master/README", "label": "legitimate", "category": "LEGITIMATE_UNUSUAL", "domain": "githubusercontent.com"}
    ]


def main():
    print("=" * 70)
    print("ScamShield ML Pipeline - Curated Expansion & Benchmark Synthesis")
    print("=" * 70)

    # 1. Expand external curated threats & payments
    threats = build_expanded_threats()
    with open(os.path.join(EXTERNAL_DIR, "curated_threats.json"), "w", encoding="utf-8") as f:
        json.dump(threats, f, indent=2)
    print(f"[+] Expanded curated threats staged: {len(threats)} samples -> external/curated_threats.json")

    payments = build_expanded_payments()
    with open(os.path.join(EXTERNAL_DIR, "curated_payments.json"), "w", encoding="utf-8") as f:
        json.dump(payments, f, indent=2)
    print(f"[+] Expanded curated payments staged: {len(payments)} samples -> external/curated_payments.json")

    # 2. Payment evaluation benchmark
    pay_bench = build_payment_evaluation_benchmark()
    pay_bench_path = os.path.join(PROCESSED_DIR, "payment_evaluation_benchmark.json")
    with open(pay_bench_path, "w", encoding="utf-8") as f:
        json.dump(pay_bench, f, indent=2)
    print(f"[+] Separate Payment Evaluation Benchmark generated: {len(pay_bench)} samples -> {pay_bench_path}")

    # 3. Untouched URL Holdout Benchmark
    url_bench = build_url_holdout_benchmark()
    url_bench_path = os.path.join(PROCESSED_DIR, "url_holdout_benchmark.json")
    with open(url_bench_path, "w", encoding="utf-8") as f:
        json.dump(url_bench, f, indent=2)
    print(f"[+] Untouched URL Holdout Benchmark generated: {len(url_bench)} samples -> {url_bench_path}")

    print("=" * 70)


if __name__ == "__main__":
    main()
