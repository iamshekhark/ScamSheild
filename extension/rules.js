// ScamShield Core Offline Detection Engine
// Allows the browser extension to detect scams instantly without network overhead or backend dependency.

(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.ScamEngine = factory();
  }
})(typeof self !== "undefined" ? self : this, function () {

  const BRANDS = [
    { name: "Paytm", token: "paytm", domains: ["paytm.com", "paytmbank.com"], lookalikes: ["paytrn", "pay-tm", "paytmm", "payt-m"] },
    { name: "Amazon", token: "amazon", domains: ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazonaws.com"], lookalikes: ["amaz0n", "amazn", "amazon-security", "amzon"] },
    { name: "PayPal", token: "paypal", domains: ["paypal.com", "paypal.me"], lookalikes: ["paypa1", "pay-pal", "paypai", "paypal-verify"] },
    { name: "SBI / State Bank", token: "sbi", domains: ["onlinesbi.sbi", "sbi.co.in", "sbi.bank.in", "sbi.co"], lookalikes: ["sbi-reward", "onlinesbi-kyc", "sbikyc", "sbi-secure-login"] },
    { name: "HDFC Bank", token: "hdfcbank", domains: ["hdfcbank.com", "hdfcbank.net"], lookalikes: ["hdfc-update", "hdfc-netbanking", "hdfcbank-kyc"] },
    { name: "Netflix", token: "netflix", domains: ["netflix.com"], lookalikes: ["netflx", "netflix-login", "netfIix"] },
    { name: "Google", token: "google", domains: ["google.com", "google.co.in", "gstatic.com", "googleapis.com", "youtube.com", "accounts.google.com"], lookalikes: ["g00gle", "google-security", "googIe"] },
    { name: "Microsoft", token: "microsoft", domains: ["microsoft.com", "microsoftonline.com", "live.com", "office.com", "outlook.com"], lookalikes: ["micros0ft", "microsoft-verify"] },
    { name: "GitHub", token: "github", domains: ["github.com", "github.io"], lookalikes: ["g1thub", "github-auth"] },
    { name: "Apple", token: "apple", domains: ["apple.com", "icloud.com"], lookalikes: ["appl0", "apple-id-verify"] }
  ];

  function isOfficialHost(host, brand) {
    if (!host || !brand || !brand.domains) return false;
    return brand.domains.some((d) => host === d || host.endsWith("." + d));
  }

  const RISKY_TLDS = new Set([
    "xyz", "top", "click", "buzz", "club", "tk", "ml", "ga", "cf", "gq",
    "icu", "cyou", "site", "online", "shop", "work", "live", "support", "ru"
  ]);

  const SUSPICIOUS_PATH_KEYWORDS = [
    "verify", "unblock", "suspended", "security-check", "update-kyc",
    "claim-reward", "lottery", "restore-access", "wallet-validation"
  ];

  const HOMOGLYPHS = { "0": "o", "1": "l", "3": "e", "5": "s", "@": "a", "$": "s" };
  const norm = (s) => (s || "").replace(/[0135@$]/g, (c) => HOMOGLYPHS[c] || c).replace(/rn/g, "m").replace(/vv/g, "w");

  function editDistanceAtMost1(a, b) {
    if (a === b) return true;
    if (Math.abs(a.length - b.length) > 1) return false;
    let i = 0, j = 0, edits = 0;
    while (i < a.length && j < b.length) {
      if (a[i] === b[j]) { i++; j++; continue; }
      if (++edits > 1) return false;
      if (a.length > b.length) i++; else if (a.length < b.length) j++; else { i++; j++; }
    }
    return edits + (a.length - i) + (b.length - j) <= 1;
  }

  function analyzeUrl(rawUrl) {
    if (!rawUrl || typeof rawUrl !== "string" || !rawUrl.trim()) {
      return [];
    }
    const cleanUrl = rawUrl.trim();
    const evidence = [];

    // 0. Non-HTTP / Dangerous execution schemes
    const lowerScheme = cleanUrl.toLowerCase();
    if (/^(?:javascript|data|file|vbscript):/i.test(lowerScheme)) {
      return [{
        category: "UNSAFE_SCHEME",
        severity: "HIGH",
        reason: `Suspicious execution scheme [${cleanUrl.split(":")[0]}]. Web links must use HTTP or HTTPS.`
      }];
    }

    let url;
    try {
      url = new URL(cleanUrl.startsWith("http://") || cleanUrl.startsWith("https://") ? cleanUrl : "https://" + cleanUrl);
    } catch {
      return [{ category: "URL_STRUCTURE", severity: "HIGH", reason: "Invalid or malformed URL syntax" }];
    }

    const host = url.hostname.toLowerCase();
    const full = url.href.toLowerCase();

    // 1. Userinfo credential spoofing (e.g., https://microsoft.com@evil.com)
    if (url.username || url.password || (cleanUrl.includes("@") && cleanUrl.indexOf("@") < (cleanUrl.indexOf("/", 8) > 0 ? cleanUrl.indexOf("/", 8) : cleanUrl.length))) {
      evidence.push({
        category: "USERINFO_SPOOFING",
        severity: "HIGH",
        reason: `URL contains deceptive userinfo credentials before '@'. The real destination is host [${host}].`
      });
    }

    // 2. Non-HTTPS
    if (url.protocol === "http:" && !["localhost", "127.0.0.1"].includes(host)) {
      evidence.push({
        category: "URL_SECURITY",
        severity: "MEDIUM",
        reason: "Connection is not secure (HTTP instead of HTTPS)"
      });
    }

    // 3. Raw IP address host
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
      evidence.push({
        category: "SUSPICIOUS_IP_URL",
        severity: "HIGH",
        reason: `Link uses raw IP address host [${host}] instead of a registered domain`
      });
    }

    // 4. Punycode (internationalized lookalikes)
    const parts = host.split(".");
    if (parts.some((p) => p.startsWith("xn--"))) {
      evidence.push({
        category: "PUNYCODE_LOOKALIKE",
        severity: "HIGH",
        reason: "Domain uses Punycode (internationalized characters) frequently used to imitate known brands"
      });
    }

    // 5. Risky TLD
    const tld = parts[parts.length - 1];
    if (RISKY_TLDS.has(tld)) {
      evidence.push({
        category: "DOMAIN_STRUCTURE",
        severity: "LOW",
        reason: `Domain ends in '.${tld}', a top-level domain frequently associated with throwaway phishing sites`
      });
    }

    // 6. Known URL Shorteners
    const SHORTENER_HOSTS = new Set(["bit.ly", "tinyurl.com", "t.co", "cutt.ly", "rb.gy", "is.gd", "ow.ly", "buff.ly"]);
    if (SHORTENER_HOSTS.has(host) || (parts.length >= 2 && SHORTENER_HOSTS.has(parts.slice(-2).join(".")))) {
      evidence.push({
        category: "URL_SHORTENER",
        severity: "LOW",
        reason: `Destination hidden behind URL shortener [${host}]. Expand and inspect final destination before entering credentials.`
      });
    }

    // 7. Excessive subdomains or hyphens
    if (parts.length > 4) {
      evidence.push({
        category: "URL_STRUCTURE",
        severity: "MEDIUM",
        reason: `Excessive subdomain nesting (${parts.length} levels) often used to disguise actual destination`
      });
    }
    if ((host.match(/-/g) || []).length >= 3) {
      evidence.push({
        category: "URL_STRUCTURE",
        severity: "MEDIUM",
        reason: "Domain contains multiple hyphens mimicking legitimate service names"
      });
    }

    // 8. Lookalike Brand & Typosquatting Checks
    for (const b of BRANDS) {
      // If host is an official verified domain of this brand, never flag impersonation!
      if (isOfficialHost(host, b)) {
        continue;
      }

      // Explicit lookalike check
      for (const trick of b.lookalikes) {
        if (host.includes(trick)) {
          evidence.push({
            category: "BRAND_IMPERSONATION",
            severity: "HIGH",
            reason: `Potential brand impersonation: '${trick}' mimics ${b.name}`
          });
          break;
        }
      }

      // Typosquatting and Subdomain Brand Embedding
      for (const label of parts) {
        const normalized = norm(label);

        // Typosquat check (edit distance 1, e.g. paypa1, g00gle)
        if (b.token.length >= 4 && editDistanceAtMost1(normalized, b.token) && label !== b.token) {
          evidence.push({
            category: "BRAND_IMPERSONATION",
            severity: "CRITICAL",
            reason: `Domain label '${label}' is a deceptive typosquat/homoglyph mimicking ${b.name} (${b.domains[0]})`
          });
          break;
        }

        // Subdomain brand on an unofficial host (e.g. github.com.evil.ru or sbi-secure-login.xyz)
        if (label === b.token || (normalized.includes(b.token) && !isOfficialHost(host, b))) {
          const isRisky = RISKY_TLDS.has(tld) || parts.length > 2;
          evidence.push({
            category: "BRAND_IMPERSONATION",
            severity: isRisky ? "HIGH" : "MEDIUM",
            reason: `Brand '${b.name}' appears inside unofficial host [${host}]`
          });
          break;
        }
      }
    }

    // 9. Suspicious path keywords
    for (const kw of SUSPICIOUS_PATH_KEYWORDS) {
      if (url.pathname.toLowerCase().includes(kw)) {
        evidence.push({
          category: "SUSPICIOUS_KEYWORD",
          severity: "LOW",
          reason: `URL path contains urgency keyword '${kw}'`
        });
        break;
      }
    }

    return evidence;
  }

  function analyzeText(rawText) {
    if (!rawText || typeof rawText !== "string" || !rawText.trim()) {
      return [];
    }
    const text = rawText.toLowerCase();
    const evidence = [];

    // Negation check: e.g. "do not share your otp", "never send your pin"
    const hasOtpNegation = /(do\s+not|never|don't)\s+(share|give|send|disclose)\s+.*(otp|code|pin)/i.test(text);

    // 1. OTP Request (English & Hinglish)
    if (!hasOtpNegation) {
      if (/(share|send|tell|provide|enter|reveal|reply\s+with)\b.{0,25}\b(otp|one[-\s]time\s+password|verification\s+code|6-digit\s+code)\b/i.test(text)) {
        evidence.push({
          category: "OTP_REQUEST",
          severity: "HIGH",
          reason: "Requests your one-time password (OTP) or verification code"
        });
      }
      if (/(?:otp\s+batao|otp\s+share\s+karo|pin\s+daalo|paisa\s+aane\s+ke\s+liye\s+pin|paise\s+receive\s+karne\s+ke\s+liye\s+pin|otp\s+bhej\s*(?:do|dena|de)|bhai\s+otp|otp\s+dedo|otp\s+de\s*do|otp\s+bhejo)/i.test(text) ||
          /\b(?:bhej|bata|de)\s*(?:do|dena)\b.{0,15}\b(?:otp|pin|cvv)\b/i.test(text) ||
          /\b(?:pin|upi\s*pin)\b.{0,15}\b(?:daalo|dalo|dal\s*do|enter\s*karo)\b/i.test(text)) {
        evidence.push({
          category: "OTP_REQUEST",
          severity: "HIGH",
          reason: "Requests verification OTP or PIN in Hindi/Hinglish phrasing"
        });
      }
    }

    // 2. Digital Arrest / Fake Law Enforcement Pretext (CRITICAL)
    if (/(?:digital\s+arrest|cbi\s+arrest|police\s+interrogation|customs\s+department\s+narcotics|mha\s+cyber\s+crime\s+notice|arrest\s+warrant\s+issued\s+against\s+you|illegal\s+parcel\s+in\s+your\s+name)/i.test(text)) {
      evidence.push({
        category: "DIGITAL_ARREST_EXTORTION",
        severity: "CRITICAL",
        reason: "Coercive legal threat or 'Digital Arrest' scam: Police, CBI, or Customs never interrogate or arrest citizens over Skype/WhatsApp video calls"
      });
    }

    // 3. Job / Part-Time Task Scam (HIGH)
    if (/(?:part[- ]time\s+job|youtube\s+(?:like|subscribe)\s+and\s+earn|earn\s+(?:rs\.?|inr|₹)?\s*\d{3,}\s*(?:daily|per\s+day)|telegram\s+(?:task|prepaid\s+task))/i.test(text)) {
      evidence.push({
        category: "JOB_TASK_FRAUD",
        severity: "HIGH",
        reason: "Prepaid task or fake part-time job scheme: Attackers request deposits before releasing promised earnings"
      });
    }

    // 4. Prize / Advance-Fee / Lottery Scam (HIGH)
    if (/\b(?:won|winner|lottery|lucky\s*draw|jackpot|prize|congratulations)\b/i.test(text) &&
        /\b(?:fee|charges?|tax|processing|deposit|claim|pay)\b/i.test(text)) {
      evidence.push({
        category: "PRIZE_ADVANCE_FEE",
        severity: "HIGH",
        reason: "Advance-fee or lottery scheme asking for fee/charges to release a prize. Genuine lotteries never demand advance processing payments."
      });
    } else if (/\byou\s+(?:have\s+)?won\b.{0,40}\b(?:iphone|car|cash|gift|reward|gold|lottery)\b/i.test(text)) {
      evidence.push({
        category: "PRIZE_ADVANCE_FEE",
        severity: "HIGH",
        reason: "Unexpected prize claim (iPhone, cash, reward) used as common phishing hook."
      });
    }

    // 5. Courier / Customs Parcel Extortion (HIGH)
    if (/\b(?:parcel|courier|customs|package|shipment|india\s*post)\b/i.test(text) &&
        /\b(?:fee|fine|pay|release|held|seized|customs\s*duty)\b/i.test(text)) {
      evidence.push({
        category: "COURIER_CUSTOMS",
        severity: "HIGH",
        reason: "Courier or customs parcel detention extortion demanding fees to release detained packages."
      });
    }

    // 6. KYC / PAN / Aadhaar Phishing
    if (/\b(?:kyc|pan|aadhaar|aadhar|bank\s*account)\b.{0,50}\b(?:expire[sd]?|suspend(?:ed)?|block(?:ed)?|update|verify|deactivat(?:ed|e))\b/i.test(text)) {
      const hasLink = /(?:https?:\/\/|bit\.ly|tinyurl|\.xyz|\.top|\.click|\.site)/i.test(text);
      evidence.push({
        category: "KYC_PHISHING",
        severity: hasLink ? "CRITICAL" : "HIGH",
        reason: "Threatens immediate KYC, PAN, or account deactivation. Banks never demand KYC updates via SMS/WhatsApp links."
      });
    }

    // 7. Urgency
    if (/\b(immediately|urgent|act\s+now|within\s+24\s+hours|expires\s+today|final\s+notice|instant\s+action)\b/i.test(text)) {
      evidence.push({
        category: "URGENCY",
        severity: "MEDIUM",
        reason: "Uses high-pressure wording urging immediate action"
      });
    }

    // 8. Threat & Account Suspension
    if (/\b(account\s+suspended|blocked|deactivated|legal\s+action|police\s+complaint|court\s+order|card\s+blocked|frozen)\b/i.test(text)) {
      evidence.push({
        category: "THREAT",
        severity: "MEDIUM",
        reason: "Employs intimidation or claims of account suspension/legal penalties"
      });
    }

    // 9. Financial / Credential bait
    if (/\b(debit\s+card\s+number|cvv|atm\s+pin|netbanking\s+password|verify\s+pan|update\s+kyc)\b/i.test(text)) {
      evidence.push({
        category: "CREDENTIAL_REQUEST",
        severity: "HIGH",
        reason: "Requests confidential banking credentials or KYC documentation"
      });
    }

    // 10. Embedded URLs
    const urlMatches = rawText.match(/(https?:\/\/[^\s]+|[a-zA-Z0-9-]+\.(?:com|in|org|net|xyz|top|site|online)\b[^\s]*)/gi) || [];
    for (const u of urlMatches.slice(0, 3)) {
      const uEv = analyzeUrl(u);
      for (const e of uEv) {
        evidence.push({
          category: e.category,
          severity: e.severity,
          reason: `[Link ${u}] ${e.reason}`
        });
      }
    }

    return evidence;
  }

  function calculateRisk(evidence) {
    if (!evidence || evidence.length === 0) {
      return {
        risk_score: 0,
        risk_level: "SAFE",
        evidence: [],
        recommendations: [
          "No phishing or scam signals detected.",
          "Connection is secured and domain structure appears standard."
        ]
      };
    }

    let score = 0;
    for (const e of evidence) {
      if (e.severity === "CRITICAL") score += 85;
      else if (e.severity === "HIGH") score += 42;
      else if (e.severity === "MEDIUM") score += 20;
      else if (e.severity === "INFO") score += 0;
      else score += 8;
    }

    // Combination bonus
    if (evidence.length >= 3) score += 12;

    let risk_score = Math.min(100, Math.max(0, score));

    let risk_level = "SAFE";
    if (risk_score > 80) risk_level = "CRITICAL";
    else if (risk_score > 60) risk_level = "HIGH";
    else if (risk_score > 40) risk_level = "MEDIUM";
    else if (risk_score > 20) risk_level = "LOW";

    // Safety floor (H6): Ensure risk_level reflects the highest severity evidence
    // Rules cannot prove safety: any result with HIGH or CRITICAL evidence must never be SAFE.
    const ORDER = ["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
    const FLOOR = {
      CRITICAL: "CRITICAL",
      HIGH: "HIGH",
      MEDIUM: "MEDIUM",
      LOW: "SAFE",
      INFO: "SAFE"
    };

    let highestSeverity = "SAFE";
    for (const e of evidence) {
      const mapped = FLOOR[e.severity] || "SAFE";
      if (ORDER.indexOf(mapped) > ORDER.indexOf(highestSeverity)) {
        highestSeverity = mapped;
      }
    }

    if (ORDER.indexOf(highestSeverity) > ORDER.indexOf(risk_level)) {
      risk_level = highestSeverity;
    }

    if (risk_level === "CRITICAL" && risk_score <= 80) {
      risk_score = 85;
    } else if (risk_level === "HIGH" && risk_score <= 60) {
      risk_score = 65;
    } else if (risk_level === "MEDIUM" && risk_score <= 40) {
      risk_score = 45;
    }

    const recommendations = [];
    if (evidence.some((e) => e.category === "REVERSE_COLLECT_FRAUD")) {
      recommendations.push("CRITICAL: In UPI, receiving money or refunds NEVER requires entering your UPI PIN. Entering your PIN will debit your account.");
    }
    if (evidence.some((e) => e.category === "REMOTE_ACCESS_TOOL")) {
      recommendations.push("NEVER install AnyDesk, TeamViewer, QuickSupport, or share your screen. Fraudsters use this to steal bank OTPs and drain accounts.");
    }
    if (evidence.some((e) => e.category === "UTILITY_EXTORTION")) {
      recommendations.push("Electricity boards do not threaten same-day power cuts via personal SMS/WhatsApp. Check bill status on your official utility portal.");
    }
    if (evidence.some((e) => e.category === "OTP_REQUEST")) {
      recommendations.push("Never disclose your OTP, PIN, or login code to anyone, even if they claim to be customer support.");
    }
    if (evidence.some((e) => e.category.includes("URL") || e.category === "BRAND_IMPERSONATION")) {
      recommendations.push("Do not click or enter credentials on this link. Check the address bar carefully.");
    }
    if (evidence.some((e) => e.category === "URGENCY" || e.category === "THREAT")) {
      recommendations.push("Legitimate institutions give reasonable notice before suspending accounts. Contact them via official app or website.");
    }
    if (!recommendations.length) {
      recommendations.push("Verify sender identity through official customer care channels.");
    }

    return {
      risk_score,
      risk_level,
      evidence,
      recommendations
    };
  }

  function analyzeEmail(sender = "", subject = "", bodyText = "") {
    const evidence = [];
    const senderLower = sender.toLowerCase();
    const fullText = `${sender} ${subject} ${bodyText}`.toLowerCase();

    // 1. Sender Spoofing & Risky TLD
    const emailMatch = sender.match(/<([^>]+)>/) || sender.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
    const address = emailMatch ? emailMatch[1].toLowerCase().trim() : sender.toLowerCase().trim();
    const senderTld = address.split(".").pop();

    if (RISKY_TLDS.has(senderTld)) {
      evidence.push({
        category: "SUSPICIOUS_DOMAIN",
        severity: "HIGH",
        reason: `Sender domain uses high-risk throwaway TLD [.${senderTld}]`
      });
    }

    if (sender.includes("<") && sender.includes(">")) {
      const displayName = sender.split("<")[0].trim().toLowerCase();

      for (const brand of BRANDS) {
        if (displayName.includes(brand.name.toLowerCase())) {
          const senderHost = address.includes("@") ? address.split("@")[1].trim() : address;
          if (!isOfficialHost(senderHost, brand)) {
            evidence.push({
              category: "BRAND_IMPERSONATION",
              severity: "HIGH",
              reason: `Display name claims to be ${brand.name} but email address [${address}] does not belong to verified domains (${brand.domains.join(", ")})`
            });
            break;
          }
        }
      }
    }

    // 2. Urgent / Threatening Extortion
    if (/\b(account\s+suspended|deactivated|blocked\s+today|terminate\s+access|urgent\s+action|legal\s+action|court\s+order)\b/i.test(fullText)) {
      evidence.push({
        category: "URGENCY",
        severity: "HIGH",
        reason: "Message warns of immediate account deactivation or legal penalties"
      });
    }

    // 3. Credential or OTP bait
    if (/\b(share\s+your\s+otp|enter\s+otp|verify\s+kyc|confirm\s+password|update\s+security\s+pin)\b/i.test(fullText)) {
      evidence.push({
        category: "OTP_REQUEST",
        severity: "HIGH",
        reason: "Requests confidential OTP verification or security credentials"
      });
    }

    // 4. Overdue invoice or wire fraud
    if (/\b(invoice\s+(?:#?\d+\s+)?overdue|wire\s+transfer|remit\s+funds|bitcoin\s+wallet|gift\s+card)\b/i.test(fullText)) {
      evidence.push({
        category: "FINANCIAL_FRAUD",
        severity: "HIGH",
        reason: "Contains unexpected invoice debt demand or wire transfer request"
      });
    }

    // 5. Embedded link scanning
    const urlMatches = fullText.match(/https?:\/\/[^\s]+/gi) || [];
    for (const u of urlMatches) {
      const linkEvidence = analyzeUrl(u);
      for (const e of linkEvidence) {
        evidence.push({
          category: e.category,
          severity: e.severity,
          reason: `[Embedded Link] ${e.reason}`
        });
      }
    }

    return evidence;
  }

  // ============================================================================
  // PAYMENT & UPI FRAUD ANALYZERS
  // ============================================================================

  const LEGIT_PSP_HANDLES = new Set([
    "okhdfcbank", "okaxis", "oksbi", "okicici", "paytm", "ybl", "ibl", "axl",
    "postbank", "barodampay", "fbl", "federal", "airtel", "pingpay", "jupiteraxis",
    "aubank", "kotak", "indus", "idfcbank", "dlb", "yesbank", "rbl", "cnrb", "boi", "iob", "pnb"
  ]);

  const PAYMENT_BRANDS = ["paytm", "phonepe", "gpay", "googlepay", "sbi", "hdfc", "icici", "axis", "amazonpay", "bhim"];

  function analyzeUpi(rawVpa) {
    const evidence = [];
    const vpa = (rawVpa || "").trim().toLowerCase();

    if (!vpa || !vpa.includes("@")) {
      return [{
        category: "UPI_SYNTAX",
        severity: "HIGH",
        reason: "Invalid UPI identifier syntax. Standard format is username@bank (e.g., merchant@okhdfcbank)"
      }];
    }

    const parts = vpa.split("@");
    if (parts.length !== 2 || !parts[0] || !parts[1]) {
      return [{
        category: "UPI_SYNTAX",
        severity: "HIGH",
        reason: "Malformed UPI ID structure. Cannot contain multiple @ symbols or empty handles"
      }];
    }

    const [handle, psp] = parts;

    // 1. Deceptive Brand Impersonation in handle
    for (const b of PAYMENT_BRANDS) {
      if (handle.includes(b)) {
        if (/\b(refund|support|care|help|desk|nodal|kyc|verify|verification|claim|reward|official)\b/i.test(handle) ||
            handle.includes("-refund") || handle.includes("care") || handle.includes("support")) {
          evidence.push({
            category: "BRAND_IMPERSONATION",
            severity: "CRITICAL",
            reason: `UPI handle [${vpa}] impersonates an official ${b.toUpperCase()} customer service or refund desk`
          });
          break;
        }
      }
    }

    // 2. Generic financial scam lures in handle
    if (/\b(cashback|lottery|winner|jackpot|freebonus|electricity-bill|billdesk-support)\b/i.test(handle)) {
      evidence.push({
        category: "DECEPTIVE_PAYEE_HANDLE",
        severity: "HIGH",
        reason: `UPI handle [${handle}] contains financial lure or utility pretext keywords`
      });
    }

    // 3. Suspicious domain-like PSP
    if (psp.includes(".") && !psp.startsWith("ok") && !psp.endsWith("bank")) {
      evidence.push({
        category: "SUSPICIOUS_PSP_DOMAIN",
        severity: "HIGH",
        reason: `UPI PSP handle [@${psp}] contains unexpected top-level domain structure`
      });
    }

    return evidence;
  }

  function analyzeQrCode(qrContent) {
    const evidence = [];
    const raw = (qrContent || "").trim();

    if (raw.startsWith("upi://pay") || raw.includes("upi://pay?")) {
      let params;
      try {
        const queryIdx = raw.indexOf("?");
        const queryStr = queryIdx !== -1 ? raw.slice(queryIdx + 1) : raw;
        params = new URLSearchParams(queryStr);
      } catch {
        return [{ category: "MALFORMED_QR", severity: "HIGH", reason: "QR code contains unparseable UPI URI" }];
      }

      const pa = params.get("pa") || "";
      const pn = params.get("pn") || "";
      const am = params.get("am") || "";
      const tn = params.get("tn") || "";

      // CRITICAL FRAUD CHECK: Reverse collect request ("Enter PIN to receive money / claim refund")
      const combinedText = `${tn} ${pn}`.toLowerCase();
      if (/(?:enter|type|input|share|put|provide)\s+(?:your\s+)?(?:(?:\d+[- ]?digit|secret|4|6)\s+)?(?:upi\s+)?(?:pin|code|password)\s+to\s+(?:receive|claim|accept|credit|get|refund)/i.test(combinedText) ||
          /(?:enter|type|input|put).*(?:pin|secret\s*code).*(?:receive|claim|get\s*refund|credit|accept)/i.test(combinedText)) {
        evidence.push({
          category: "REVERSE_COLLECT_FRAUD",
          severity: "CRITICAL",
          reason: "CRITICAL ALERT: QR note instructs entering a UPI PIN to receive money. In UPI architecture, entering your PIN ALWAYS debits funds from your bank account!"
        });
      }

      // Name vs VPA Mismatch: Payee claims official corporate identity but VPA is personal
      if (pn && /(?:support|customer\s*care|refund|official|helpdesk|cashback)/i.test(pn)) {
        if (!pa.includes("merchant") && !pa.includes("corp") && /\d{4,}/.test(pa)) {
          evidence.push({
            category: "PAYEE_MISMATCH",
            severity: "HIGH",
            reason: `Payee name claims to be "${pn}" but UPI VPA [${pa}] is an individual personal identifier`
          });
        }
      }

      // Analyze the embedded VPA
      if (pa) {
        const vpaEvidence = analyzeUpi(pa);
        for (const e of vpaEvidence) {
          evidence.push({
            category: e.category,
            severity: e.severity,
            reason: `[QR Payee VPA] ${e.reason}`
          });
        }
      }
    } else if (raw.startsWith("http://") || raw.startsWith("https://")) {
      // QR contains web payment link
      const urlEvidence = analyzeUrl(raw);
      for (const e of urlEvidence) {
        evidence.push({
          category: e.category,
          severity: e.severity,
          reason: `[QR Payment Link] ${e.reason}`
        });
      }
    } else {
      // Analyze as payment message text
      const msgEvidence = analyzePaymentMessage(raw);
      for (const e of msgEvidence) {
        evidence.push(e);
      }
    }

    return evidence;
  }

  function analyzePaymentMessage(message) {
    const evidence = [];
    const text = (message || "").toLowerCase();

    // 1. Electricity bill disconnection extortion
    if (/(?:electricity|power|bijli)\s+(?:bill\s+)?(?:will\s+be\s+)?(?:disconnected|cut|shut\s*off|disconnected\s+tonight)/i.test(text)) {
      evidence.push({
        category: "UTILITY_EXTORTION",
        severity: "HIGH",
        reason: "Uses immediate electricity disconnection threat to pressure urgent payment"
      });
    }

    // 2. Remote Access Trojan / Screen Sharing trap
    if (/\b(anydesk|teamviewer|rustdesk|quicksupport|airdroid|screenshare|screen\s*share)\b/i.test(text)) {
      evidence.push({
        category: "REMOTE_ACCESS_TOOL",
        severity: "CRITICAL",
        reason: "Coerces victim to install remote desktop software (e.g., AnyDesk/TeamViewer) to hijack banking credentials"
      });
    }

    // 3. Reverse Collect / PIN entry deceit
    if (/(?:enter|type|share|input|put|provide)\s+(?:your\s+)?(?:(?:\d+[- ]?digit|secret|4|6)\s+)?(?:upi\s+)?(?:pin|code|password)\s+to\s+(?:receive|claim|accept|credit|get\s+refund)/i.test(text) ||
        /(?:enter|type|input|put).*(?:pin|secret\s*code).*(?:receive|claim|get\s*refund|credit|accept)/i.test(text)) {
      evidence.push({
        category: "REVERSE_COLLECT_FRAUD",
        severity: "CRITICAL",
        reason: "Urges entering UPI PIN to receive money. PIN entry only authorizes money leaving your account!"
      });
    }

    // 4. Fake Refund or Cashback bait
    if (/(?:refund\s+(?:of\s+)?₹?\s*\d+|cashback\s+(?:of\s+)?₹?\s*\d+|lottery\s+winner|kbc\s+lucky\s+draw)/i.test(text) &&
        /(?:claim|transfer|scan|upi|deposit|processing\s+fee)/i.test(text)) {
      evidence.push({
        category: "ADVANCE_FEE_FRAUD",
        severity: "HIGH",
        reason: "Promises unverified lottery or refund reward in exchange for upfront fee or collect authorization"
      });
    }

    // 5. Embedded UPI handles
    const upiMatches = text.match(/[\w.\-_]{2,60}@[\w.\-_]{2,40}/g) || [];
    for (const upi of upiMatches) {
      const upiEvidence = analyzeUpi(upi);
      for (const e of upiEvidence) {
        evidence.push({
          category: e.category,
          severity: e.severity,
          reason: `[Mentioned UPI] ${e.reason}`
        });
      }
    }

    // 6. Embedded URLs
    const urlMatches = text.match(/https?:\/\/[^\s]+/gi) || [];
    for (const u of urlMatches) {
      const linkEvidence = analyzeUrl(u);
      for (const e of linkEvidence) {
        evidence.push({
          category: e.category,
          severity: e.severity,
          reason: `[Embedded Payment Link] ${e.reason}`
        });
      }
    }

    return evidence;
  }

  function analyzePaymentScreenshot(extractedText) {
    const evidence = [];
    const text = (extractedText || "").toLowerCase();

    // Unverified status reminder for all screenshots
    evidence.push({
      category: "STATUS_DISCLAIMER",
      severity: "INFO",
      reason: "Payment status not independently verified. Screenshots and UTR numbers alone do not guarantee bank settlement."
    });

    if (/(?:payment\s+successful|sent\s+successfully|paid\s+to|transfer\s+complete)/i.test(text)) {
      // Check for missing banking reference / UTR
      if (!/(?:upi\s*ref|utr|rrn|transaction\s*id|txn\s*id|ref\s*no)/i.test(text)) {
        evidence.push({
          category: "SUSPICIOUS_PAYMENT_CONFIRMATION",
          severity: "MEDIUM",
          reason: "Screenshot claims payment success but lacks standard 12-digit UPI UTR / RRN banking reference"
        });
      }
    }

    // Check message heuristics in screenshot text
    const msgEvidence = analyzePaymentMessage(text);
    for (const e of msgEvidence) {
      evidence.push(e);
    }

    return evidence;
  }

  function scanPayment(content, inputType = "upi_id") {
    if (!content || typeof content !== "string" || !content.trim()) {
      return {
        risk_score: 0,
        risk_level: "SAFE",
        evidence: [],
        recommendations: ["No payment details provided."],
        input_type: inputType,
        normalized_payee: null,
        payment_domain: null,
        payment_status: "unverified",
        detection_method: "rules"
      };
    }

    const cleanContent = content.trim();
    let evidence = [];
    let normalizedPayee = null;
    let paymentDomain = null;

    if (inputType === "upi_id") {
      normalizedPayee = cleanContent.toLowerCase();
      evidence = analyzeUpi(cleanContent);
    } else if (inputType === "qr_code" || inputType === "qr") {
      evidence = analyzeQrCode(cleanContent);
      // Attempt to extract payee VPA
      const paMatch = cleanContent.match(/pa=([^&]+)/i);
      if (paMatch) normalizedPayee = decodeURIComponent(paMatch[1]);
    } else if (inputType === "payment_url") {
      evidence = analyzeUrl(cleanContent);
      try {
        const u = new URL(cleanContent.startsWith("http") ? cleanContent : "https://" + cleanContent);
        paymentDomain = u.hostname;
      } catch {
        paymentDomain = cleanContent;
      }
    } else if (inputType === "screenshot") {
      evidence = analyzePaymentScreenshot(cleanContent);
    } else {
      // message or utr
      evidence = analyzePaymentMessage(cleanContent);
    }

    const risk = calculateRisk(evidence);

    return {
      ...risk,
      input_type: inputType,
      normalized_payee: normalizedPayee,
      payment_domain: paymentDomain,
      payment_status: "unverified",
      detection_method: "rules"
    };
  }

  function scanEmail(sender = "", subject = "", body = "") {
    const safeSender = (sender && typeof sender === "string") ? sender.trim() : "";
    const safeSubject = (subject && typeof subject === "string") ? subject.trim() : "";
    const safeBody = (body && typeof body === "string") ? body.trim() : "";
    if (!safeSender && !safeSubject && !safeBody) {
      return {
        risk_score: 0,
        risk_level: "SAFE",
        evidence: [],
        recommendations: ["No email content provided."],
        detection_method: "rules"
      };
    }
    return calculateRisk(analyzeEmail(safeSender, safeSubject, safeBody));
  }

  return {
    analyzeUrl,
    analyzeText,
    analyzeEmail,
    analyzeUpi,
    analyzeQrCode,
    analyzePaymentMessage,
    analyzePaymentScreenshot,
    calculateRisk,
    scanUrl: (url) => calculateRisk(analyzeUrl(url)),
    scanText: (text) => calculateRisk(analyzeText(text)),
    scanEmail,
    scanPayment
  };
});
