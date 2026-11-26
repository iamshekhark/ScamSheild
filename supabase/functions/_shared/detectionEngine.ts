// ScamShield Core Detection Engine (Shared Deno/Node Module)
// Implements explainable deterministic rules, SSRF-safe URL/domain intelligence,
// brand impersonation & typosquatting analysis, and strict hybrid risk scoring.

export type RiskSeverity = "low" | "medium" | "high" | "critical";
export type RiskClassification = "safe" | "caution" | "suspicious" | "high" | "critical" | "inconclusive";

export interface DetectionIndicator {
  indicator_type: string;
  description: string;
  severity: RiskSeverity;
  confidence: number; // 0.0 to 1.0
  evidence?: Record<string, unknown>;
}

export interface DetectionResult {
  risk_score: number; // 0 to 100
  confidence: number; // 0.0 to 1.0
  classification: RiskClassification;
  summary: string;
  threat_types: string[];
  indicators: DetectionIndicator[];
  suspicious_urls: string[];
  sender_analysis?: {
    claimed_identity?: string;
    sender_domain?: string;
    is_spoofed: boolean;
    is_official_match: boolean;
    notes?: string;
  };
  recommended_actions: string[];
  detection_method: "rules" | "ai" | "hybrid";
  limitations?: string[];
  inconclusive?: boolean;
}

// ---------------------------------------------------------------------------
// 1. Brand Intelligence & Lookalike Database
// ---------------------------------------------------------------------------

export interface BrandEntry {
  name: string;
  token: string;
  domains: string[];
  lookalikes?: string[];
}

export const TRUSTED_BRANDS: BrandEntry[] = [
  { name: "Paytm", token: "paytm", domains: ["paytm.com", "paytmbank.com", "paytmpayments.com"], lookalikes: ["paytrn", "pay-tm", "paytmm", "payt-m"] },
  { name: "Amazon", token: "amazon", domains: ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazonaws.com"], lookalikes: ["amaz0n", "amazn", "amazon-security", "amzon"] },
  { name: "PayPal", token: "paypal", domains: ["paypal.com", "paypal.me"], lookalikes: ["paypa1", "pay-pal", "paypai", "paypal-verify"] },
  { name: "State Bank of India", token: "sbi", domains: ["onlinesbi.sbi", "sbi.co.in", "sbi.bank.in"], lookalikes: ["sbi-reward", "onlinesbi-kyc", "sbikyc", "sbi-secure-login"] },
  { name: "HDFC Bank", token: "hdfc", domains: ["hdfcbank.com", "hdfcbank.net"], lookalikes: ["hdfc-update", "hdfc-netbanking", "hdfcbank-kyc"] },
  { name: "ICICI Bank", token: "icici", domains: ["icicibank.com"], lookalikes: ["icici-update", "icicibank-kyc"] },
  { name: "Axis Bank", token: "axis", domains: ["axisbank.com"], lookalikes: ["axis-update", "axisbank-kyc"] },
  { name: "Netflix", token: "netflix", domains: ["netflix.com"], lookalikes: ["netflx", "netflix-login", "netfIix"] },
  { name: "Google", token: "google", domains: ["google.com", "google.co.in", "gmail.com", "youtube.com", "gstatic.com"], lookalikes: ["g00gle", "google-security", "googIe"] },
  { name: "Microsoft", token: "microsoft", domains: ["microsoft.com", "microsoftonline.com", "live.com", "office.com", "outlook.com"], lookalikes: ["micros0ft", "microsoft-verify"] },
  { name: "Apple", token: "apple", domains: ["apple.com", "icloud.com"], lookalikes: ["appl0", "apple-id-verify"] },
  { name: "GitHub", token: "github", domains: ["github.com", "github.io"], lookalikes: ["g1thub", "github-auth"] },
  { name: "India Post", token: "indiapost", domains: ["indiapost.gov.in"], lookalikes: ["indiapost-tracking", "indiapost-parcel", "indiapost-fee"] }
];

export const RISKY_TLDS = new Set([
  "xyz", "top", "click", "buzz", "club", "tk", "ml", "ga", "cf", "gq",
  "icu", "cyou", "site", "online", "shop", "work", "live", "support", "cc", "rest", "surf"
]);

export const SHORTENER_DOMAINS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly",
  "ow.ly", "cutt.ly", "rb.gy", "shorturl.at"
]);

const HOMOGLYPHS: Record<string, string> = { "0": "o", "1": "l", "3": "e", "5": "s", "@": "a", "$": "s", "v": "u" };

export function normalizeDomainString(str: string): string {
  let res = str.toLowerCase();
  for (const [k, v] of Object.entries(HOMOGLYPHS)) {
    res = res.replaceAll(k, v);
  }
  return res.replaceAll("rn", "m").replaceAll("vv", "w");
}

export function editDistance(a: string, b: string): number {
  if (a === b) return 0;
  if (!a.length) return b.length;
  if (!b.length) return a.length;

  const row = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let prev = i;
    for (let j = 1; j <= b.length; j++) {
      const val = a[i - 1] === b[j - 1] ? row[j - 1] : Math.min(row[j - 1] + 1, prev + 1, row[j] + 1);
      row[j - 1] = prev;
      prev = val;
    }
    row[b.length] = prev;
  }
  return row[b.length];
}

// ---------------------------------------------------------------------------
// 2. Strict SSRF Protection for URL Analysis
// ---------------------------------------------------------------------------

export function isPrivateOrReservedHost(host: string): boolean {
  const clean = host.toLowerCase().trim();

  // Loopback / Localhost
  if (clean === "localhost" || clean === "127.0.0.1" || clean === "::1" || clean === "0.0.0.0") {
    return true;
  }

  // IPv4 Private & Reserved Ranges
  const ipv4Match = clean.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4Match) {
    const [_, o1, o2] = ipv4Match.map(Number);
    if (o1 === 10) return true; // 10.0.0.0/8
    if (o1 === 127) return true; // 127.0.0.0/8
    if (o1 === 172 && o2 >= 16 && o2 <= 31) return true; // 172.16.0.0/12
    if (o1 === 192 && o2 === 168) return true; // 192.168.0.0/16
    if (o1 === 169 && o2 === 254) return true; // 169.254.0.0/16 Link-Local & Cloud Metadata
    if (o1 >= 224) return true; // Multicast / Class E reserved
    if (o1 === 0) return true; // 0.0.0.0/8
  }

  // Cloud Metadata Endpoints
  if (clean.includes("metadata.google.internal") || clean.includes("169.254.169.254")) {
    return true;
  }

  // Local / Internal domain suffixes
  if (clean.endsWith(".local") || clean.endsWith(".internal") || clean.endsWith(".lan") || clean.endsWith(".test")) {
    return true;
  }

  return false;
}

// ---------------------------------------------------------------------------
// 3. Deterministic URL Intelligence Analyzer
// ---------------------------------------------------------------------------

export function analyzeUrlIntelligence(rawUrl: string): { indicators: DetectionIndicator[]; normalizedDomain: string; isOfficial: boolean } {
  const indicators: DetectionIndicator[] = [];
  let normalizedDomain = "";
  let isOfficial = false;

  if (!rawUrl || typeof rawUrl !== "string") {
    return { indicators, normalizedDomain, isOfficial };
  }

  const clean = rawUrl.trim();

  // Dangerous execution schemes
  if (/^(?:javascript|data|file|vbscript):/i.test(clean)) {
    indicators.push({
      indicator_type: "UNSAFE_URI_SCHEME",
      description: `URL uses unsafe executable pseudo-scheme (${clean.split(":")[0]}:)`,
      severity: "critical",
      confidence: 1.0,
      evidence: { scheme: clean.split(":")[0] }
    });
    return { indicators, normalizedDomain: "unsafe-scheme", isOfficial: false };
  }

  let u: URL;
  try {
    const urlCandidate = clean.startsWith("http://") || clean.startsWith("https://") ? clean : "https://" + clean;
    u = new URL(urlCandidate);
    normalizedDomain = u.hostname.toLowerCase();
  } catch {
    indicators.push({
      indicator_type: "MALFORMED_URL",
      description: "URL format is invalid or malformed",
      severity: "medium",
      confidence: 0.9
    });
    return { indicators, normalizedDomain: "", isOfficial: false };
  }

  // 1. SSRF & Private Network Check
  if (isPrivateOrReservedHost(normalizedDomain)) {
    indicators.push({
      indicator_type: "PRIVATE_NETWORK_TARGET",
      description: `Target destination points to a private, loopback, or cloud-metadata address [${normalizedDomain}]`,
      severity: "high",
      confidence: 1.0,
      evidence: { destination: normalizedDomain }
    });
  }

  // 2. Userinfo Credential Spoofing (e.g. https://google.com@evil.com)
  if (u.username || u.password || (clean.includes("@") && clean.indexOf("@") < (clean.indexOf("/", 8) > 0 ? clean.indexOf("/", 8) : clean.length))) {
    indicators.push({
      indicator_type: "USERINFO_CREDENTIAL_SPOOFING",
      description: `URL embeds misleading authority before '@'. Actual destination is '${normalizedDomain}'`,
      severity: "critical",
      confidence: 0.95,
      evidence: { actualDestination: normalizedDomain }
    });
  }

  // 3. Official Brand Validation
  for (const b of TRUSTED_BRANDS) {
    if (b.domains.some((d) => normalizedDomain === d || normalizedDomain.endsWith("." + d))) {
      isOfficial = true;
      break;
    }
  }

  if (isOfficial) {
    return { indicators, normalizedDomain, isOfficial: true };
  }

  // 4. Raw IP Address Host
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(normalizedDomain)) {
    indicators.push({
      indicator_type: "RAW_IP_DESTINATION",
      description: `URL points to a numeric IP address [${normalizedDomain}] rather than a legitimate registered domain name`,
      severity: "critical",
      confidence: 0.95,
      evidence: { ip: normalizedDomain }
    });
  }

  // 5. Punycode / Internationalized Homograph Attack (xn--)
  if (normalizedDomain.split(".").some((part) => part.startsWith("xn--"))) {
    indicators.push({
      indicator_type: "PUNYCODE_HOMOGRAPH",
      description: `Uses punycode encoding [${normalizedDomain}] commonly employed in internationalized character spoofing`,
      severity: "critical",
      confidence: 0.9,
      evidence: { domain: normalizedDomain }
    });
  }

  // 6. Known URL Shortener
  if (SHORTENER_DOMAINS.has(normalizedDomain)) {
    const hasSuspiciousParam = /(?:kyc|claim|verify|login|bank|sbi|reward|prize|gift|update)/i.test(clean);
    indicators.push({
      indicator_type: "OBFUSCATED_SHORTENER_URL",
      description: `Uses URL shortener [${normalizedDomain}] to conceal real landing destination${hasSuspiciousParam ? " with suspicious query triggers" : ""}`,
      severity: hasSuspiciousParam ? "high" : "medium",
      confidence: hasSuspiciousParam ? 0.95 : 0.85,
      evidence: { shortener: normalizedDomain }
    });
  }

  // 7. Risky / Throwaway TLD
  const tld = normalizedDomain.split(".").pop() || "";
  if (RISKY_TLDS.has(tld)) {
    indicators.push({
      indicator_type: "RISKY_TLD",
      description: `Domain uses top-level domain '.${tld}' frequently abused in disposable phishing campaigns`,
      severity: "medium",
      confidence: 0.75,
      evidence: { tld }
    });
  }

  // 8. Brand Impersonation & Typosquatting in Domain
  const cleanHost = normalizedDomain.replace(/^www\./, "");
  const hostParts = cleanHost.split(".");
  const mainDomain = hostParts.length >= 2 ? hostParts[hostParts.length - 2] : cleanHost;
  const normalizedMain = normalizeDomainString(mainDomain);

  for (const brand of TRUSTED_BRANDS) {
    // Check known lookalike strings
    if (brand.lookalikes && brand.lookalikes.some((l) => cleanHost.includes(l))) {
      indicators.push({
        indicator_type: "BRAND_TYPOSQUAT",
        description: `Domain mimics legitimate brand ${brand.name} (Official: ${brand.domains[0]})`,
        severity: "critical",
        confidence: 0.95,
        evidence: { brand: brand.name, official: brand.domains[0] }
      });
      break;
    }

    // Subdomain deception: e.g. paypal.com.attacker.com
    if (hostParts.length > 2) {
      const subdomainPart = hostParts.slice(0, -2).join(".");
      if (brand.domains.some((d) => subdomainPart === d || subdomainPart.endsWith("." + d) || subdomainPart.includes(brand.token))) {
        indicators.push({
          indicator_type: "BRAND_SUBDOMAIN_DECEPTION",
          description: `Misleading subdomain claims to be ${brand.name}, but base domain is '${hostParts.slice(-2).join(".")}'`,
          severity: "critical",
          confidence: 0.95,
          evidence: { brand: brand.name, realDomain: hostParts.slice(-2).join(".") }
        });
        break;
      }
    }

    // Levenshtein edit distance check on main domain
    if (brand.token.length >= 4) {
      const dist = editDistance(normalizedMain, brand.token);
      if (dist === 1 && normalizedMain !== brand.token) {
        indicators.push({
          indicator_type: "BRAND_LOOKALIKE_EDIT_DISTANCE",
          description: `Domain '${mainDomain}' is a 1-character typosquat lookalike of ${brand.name}`,
          severity: "critical",
          confidence: 0.9,
          evidence: { brand: brand.name, mainDomain }
        });
        break;
      }
    }
  }

  return { indicators, normalizedDomain, isOfficial: false };
}

// ---------------------------------------------------------------------------
// 4. Deterministic Text, Email & Payment Security Analyzer
// ---------------------------------------------------------------------------

export function analyzeTextAndEmailIntelligence(
  content: string,
  sender?: string,
  subject?: string
): { indicators: DetectionIndicator[]; senderAnalysis: DetectionResult["sender_analysis"] } {
  const indicators: DetectionIndicator[] = [];
  const fullText = `${sender || ""} ${subject || ""} ${content}`.trim();
  const lower = fullText.toLowerCase();

  let senderAnalysis: DetectionResult["sender_analysis"] = {
    is_spoofed: false,
    is_official_match: false
  };

  // 1. Sender Spoofing & Header Analysis
  if (sender && sender.includes("<") && sender.includes(">")) {
    const displayName = sender.split("<")[0].trim();
    const address = sender.split("<")[1].replace(">", "").trim().toLowerCase();
    const senderDomain = address.includes("@") ? address.split("@")[1].trim() : address;

    senderAnalysis.claimed_identity = displayName;
    senderAnalysis.sender_domain = senderDomain;

    const lowerName = displayName.toLowerCase();
    for (const b of TRUSTED_BRANDS) {
      if (lowerName.includes(b.token) || b.domains.some((d) => lowerName.includes(d.split(".")[0]))) {
        const isOfficial = b.domains.some((d) => senderDomain === d || senderDomain.endsWith("." + d));
        senderAnalysis.is_official_match = isOfficial;

        if (!isOfficial) {
          senderAnalysis.is_spoofed = true;
          indicators.push({
            indicator_type: "DISPLAY_NAME_SPOOFING",
            description: `Display name claims to be ${b.name} ('${displayName}'), but email address is hosted on untrusted domain '${senderDomain}'`,
            severity: "critical",
            confidence: 0.95,
            evidence: { claimedBrand: b.name, senderDomain, officialDomains: b.domains }
          });
          break;
        }
      }
    }

    const senderTld = senderDomain.split(".").pop();
    if (senderTld && RISKY_TLDS.has(senderTld) && !senderAnalysis.is_official_match) {
      indicators.push({
        indicator_type: "UNTRUSTED_SENDER_DOMAIN_TLD",
        description: `Sender originates from disposable/risky top-level domain '.${senderTld}'`,
        severity: "high",
        confidence: 0.85,
        evidence: { senderDomain }
      });
    }
  }

  // 2. Negation Check: Ensure educational / security advice is not misclassified
  const hasSecurityNegation = /(do\s+not|never|don't|should\s+not)\s+(share|disclose|give|send|enter)\s+.*(otp|pin|password|credentials)/i.test(lower);

  // 3. Credential & OTP Divulgence
  if (!hasSecurityNegation) {
    if (/(?:share|send|enter|provide|tell|reply\s+with)\b.{0,30}\b(?:otp|one[-\s]time\s+password|verification\s+code|6-digit\s+code|login\s+pin)\b/i.test(lower) ||
        /(?:otp\s+share\s+karo|otp\s+batao|pin\s+daalo|paisa\s+aane\s+ke\s+liye\s+pin|otp\s+bhejo)/i.test(lower)) {
      indicators.push({
        indicator_type: "CREDENTIAL_HARVESTING_OTP",
        description: "Demands disclosure of confidential One-Time Password (OTP) or authentication security PIN",
        severity: "critical",
        confidence: 0.95
      });
    }
  }

  // 4. Reverse Collect UPI Fraud (Enter PIN to receive money)
  if (/(?:enter|type|input|put|share)\s+(?:your\s+)?(?:(?:\d+[- ]?digit|secret|4|6)\s+)?(?:upi\s+)?(?:pin|code)\s+to\s+(?:receive|claim|accept|credit|get|refund)/i.test(lower) ||
      /(?:pin\s+daalo\s+paise?\s+milenge|enter\s+pin\s+to\s+receive)/i.test(lower)) {
    indicators.push({
      indicator_type: "REVERSE_COLLECT_UPI_FRAUD",
      description: "Fraudulent collect request: UPI PIN is ONLY required to send money, never to receive money or refunds",
      severity: "critical",
      confidence: 1.0
    });
  }

  // 5. Digital Arrest / Law Enforcement Extortion
  if (/(?:digital\s+arrest|cbi\s+arrest|police\s+interrogation|customs\s+department\s+narcotics|mha\s+cyber\s+crime\s+notice|arrest\s+warrant\s+issued\s+against\s+you|illegal\s+parcel\s+in\s+your\s+name)/i.test(lower)) {
    indicators.push({
      indicator_type: "DIGITAL_ARREST_EXTORTION",
      description: "Coercive legal impersonation ('Digital Arrest'): Police, CBI, and Customs never conduct arrests or interrogations via video calls",
      severity: "critical",
      confidence: 0.95
    });
  }

  // 6. Fake Jobs / Prepaid Task Scams
  if (/(?:part[- ]time\s+job|youtube\s+(?:like|subscribe)\s+and\s+earn|earn\s+(?:rs\.?|inr|₹)?\s*\d{3,}\s*(?:daily|per\s+day)|telegram\s+(?:task|prepaid\s+task))/i.test(lower)) {
    indicators.push({
      indicator_type: "JOB_TASK_FRAUD",
      description: "Prepaid task or fake part-time work scam requiring initial deposits for promised income",
      severity: "high",
      confidence: 0.9
    });
  }

  // 7. Prize / Advance-Fee / Lottery Scams
  const hasAdvanceFeeNegation =
    /\b(?:no|zero|without|never\s+(?:pay|send|share))\s+(?:advance\s+|processing\s+|convenience\s+)?(?:fee|fees|charges?|deposit|tax)\b/i.test(lower) ||
    /\b(?:how\s+(?:lottery|advance[- ]fee)\s+scams?\s+work|fraudsters?\s+claim\s+you\s+won)\b/i.test(lower);
  const hasContextualPrizeFee =
    /\b(?:won|winner|lottery|lucky\s*draw|jackpot|prize|congratulations)\b.{0,120}\b(?:pay|deposit|send|transfer|remit)\b.{0,60}\b(?:fee|fees|charges?|tax|processing|deposit)\b/i.test(lower) ||
    /\b(?:pay|deposit|send|transfer|remit)\b.{0,60}\b(?:processing|registration|verification|release|advance)?\s*(?:fee|fees|charges?|tax|deposit)\b.{0,80}\b(?:to\s+(?:claim|release|unlock|receive)\b.{0,30}\b(?:prize|lottery|jackpot|reward|winnings|cashback|gift)|prize|lottery|jackpot|winnings)\b/i.test(lower);

  if (!hasAdvanceFeeNegation && (hasContextualPrizeFee ||
      /\byou\s+(?:have\s+)?won\b.{0,30}\b(?:iphone|car|cash|reward|gold|lottery)\b/i.test(lower))) {
    indicators.push({
      indicator_type: "PRIZE_ADVANCE_FEE",
      description: "Advance-fee or lottery scam demanding processing fees to release an unsolicited prize",
      severity: "high",
      confidence: 0.85
    });
  }

  // 8. Fake Invoices / Overdue Payment Extortion & BEC
  if (/(?:banking\s+details\s+(?:have\s+)?changed|new\s+bank\s+account|new\s+offshore\s+account|remit\s+to\s+the\s+new|wire\s+(?:\$[\d,]+|\d+.*)?(?:immediately|to|funds|amount)|overdue\s+invoice|invoice.*overdue|confidential\s+wire|executive\s+board\s+meeting)/i.test(lower)) {
    indicators.push({
      indicator_type: "FINANCIAL_FRAUD_INVOICE",
      description: "Contains unsolicited invoice debt pressure, updated bank details, or executive wire transfer demands",
      severity: "high",
      confidence: 0.85
    });
  }

  // 9. Investment & Cryptocurrency Fraud
  if (/(?:guaranteed\s+(?:\d+%\s+)?profit|bitcoin\s+algorithm|btc\s+wallet|crypto\s+(?:signals|trading|deposit)|vip\s+crypto|transfer\s+[\d.]+\s*btc)/i.test(lower)) {
    indicators.push({
      indicator_type: "INVESTMENT_CRYPTO_FRAUD",
      description: "Prompts high-yield guaranteed crypto investment or demands BTC transfers to private wallets",
      severity: "high",
      confidence: 0.9
    });
  }

  // 10. Tech Support Scam / Remote Access Extortion
  if (/(?:infected\s+with\s+(?:trojan|virus|malware)|zeus\s+(?:trojan|virus)|call\s+(?:microsoft|apple|certified|support|technician)\b.{0,30}helpline|toll-free\s+helpline|\+1-800|remote\s+(?:assistance|access|support)\b.{0,30}toll-free)/i.test(lower)) {
    indicators.push({
      indicator_type: "TECH_SUPPORT_EXTORTION",
      description: "Tech-support pretext warning of malware infection and urging urgent remote assistance calls",
      severity: "high",
      confidence: 0.9
    });
  }

  // 11. Fake Courier / Customs Parcel Detention
  if (/\b(?:parcel|courier|customs|package|shipment|india\s*post)\b/i.test(lower) &&
      /\b(?:held|seized|customs\s*duty|release\s*fee|pay\s*penalty|fine)\b/i.test(lower)) {
    indicators.push({
      indicator_type: "COURIER_CUSTOMS_EXTORTION",
      description: "Courier detention extortion demanding payment to release a detained shipment",
      severity: "high",
      confidence: 0.85
    });
  }

  // 10. KYC / Account Expiration Phishing
  if (/\b(?:kyc|pan|aadhaar|bank\s*account)\b.{0,40}\b(?:expire[sd]?|suspend(?:ed)?|block(?:ed)?|deactivat(?:ed|e))\b/i.test(lower)) {
    const hasPhishLink = /(?:https?:\/\/|bit\.ly|tinyurl|\.xyz|\.top|\.click|\.site)/i.test(lower);
    indicators.push({
      indicator_type: "KYC_ACCOUNT_SUSPENSION_PHISH",
      description: "Threatens immediate account suspension or KYC deactivation over email/SMS",
      severity: hasPhishLink ? "critical" : "high",
      confidence: hasPhishLink ? 0.95 : 0.85
    });
  }

  // 11. Contextual Urgency (Caution Only: NEVER Critical on its own)
  if (!senderAnalysis.is_official_match) {
    if (/\b(within\s+24\s+hours|expires\s+today|final\s+notice|immediate\s+action\s+required|act\s+now)\b/i.test(lower)) {
      indicators.push({
        indicator_type: "PSYCHOLOGICAL_URGENCY",
        description: "Uses artificial time pressure to rush user actions",
        severity: "medium",
        confidence: 0.6
      });
    }
  }

  // 12. Embedded URL extraction & inspection
  const urlMatches = fullText.match(/https?:\/\/[^\s"'<>]+/gi) || [];
  for (const u of urlMatches.slice(0, 5)) {
    const { indicators: urlInds } = analyzeUrlIntelligence(u);
    for (const ind of urlInds) {
      indicators.push({
        ...ind,
        description: `[Embedded URL: ${u.slice(0, 35)}...] ${ind.description}`
      });
    }
  }

  return { indicators, senderAnalysis };
}

// ---------------------------------------------------------------------------
// 5. Unified Risk Scoring & Hybrid Combination Engine
// ---------------------------------------------------------------------------

export function calculateDeterministicScore(indicators: DetectionIndicator[]): { score: number; confidence: number } {
  if (!indicators || indicators.length === 0) {
    return { score: 0, confidence: 0.9 };
  }

  let totalScore = 0;
  let maxWeight = 0;
  let confidenceSum = 0;

  for (const ind of indicators) {
    confidenceSum += ind.confidence;
    switch (ind.severity) {
      case "critical":
        totalScore += 90;
        maxWeight = Math.max(maxWeight, 90);
        break;
      case "high":
        totalScore += 70;
        maxWeight = Math.max(maxWeight, 70);
        break;
      case "medium":
        totalScore += 30;
        maxWeight = Math.max(maxWeight, 30);
        break;
      case "low":
        totalScore += 10;
        maxWeight = Math.max(maxWeight, 10);
        break;
    }
  }

  // Combine: Floor guaranteed by highest severity indicator
  const combined = Math.min(100, Math.max(maxWeight, Math.round(totalScore * 0.75)));
  const avgConfidence = Math.min(1.0, parseFloat((confidenceSum / indicators.length).toFixed(2)));

  return { score: combined, confidence: avgConfidence };
}

export function classifyRisk(score: number): RiskClassification {
  if (score >= 90) return "critical";
  if (score >= 70) return "high";
  if (score >= 40) return "suspicious";
  if (score >= 20) return "caution";
  return "safe";
}

export function combineHybridScore(
  ruleScore: number,
  ruleIndicators: DetectionIndicator[],
  aiResult: {
    risk_score?: number;
    confidence?: number;
    threat_types?: string[];
    indicators?: DetectionIndicator[];
    available?: boolean;
    error?: string;
  } | null
): {
  finalScore: number;
  confidence: number;
  classification: RiskClassification;
  method: "rules" | "ai" | "hybrid";
  limitations: string[];
} {
  const limitations: string[] = [];

  // 1. Determine Deterministic Floor
  // Invariant: Confirmed malicious indicators established by deterministic rules CANNOT be downgraded by AI
  let deterministicFloor = 0;
  for (const ind of ruleIndicators) {
    if (ind.severity === "critical") deterministicFloor = Math.max(deterministicFloor, 90);
    else if (ind.severity === "high") deterministicFloor = Math.max(deterministicFloor, 70);
    else if (ind.severity === "medium") deterministicFloor = Math.max(deterministicFloor, 40);
  }

  // 2. Case A: AI unavailable or errored
  if (!aiResult || aiResult.available === false || typeof aiResult.risk_score !== "number") {
    limitations.push("AI analysis was unavailable or timed out; evaluated strictly via deterministic security rules.");
    const ruleConf = ruleIndicators.length > 0 ? 0.85 : 0.7;
    return {
      finalScore: ruleScore,
      confidence: ruleConf,
      classification: classifyRisk(ruleScore),
      method: "rules",
      limitations
    };
  }

  // 3. Case B: Hybrid Combination
  const aiScore = Math.min(100, Math.max(0, aiResult.risk_score));
  const aiConf = typeof aiResult.confidence === "number" ? Math.min(1.0, Math.max(0, aiResult.confidence)) : 0.8;

  let finalScore: number;

  if (deterministicFloor >= 70) {
    // Strong deterministic threat: AI cannot downgrade
    finalScore = Math.max(deterministicFloor, aiScore);
  } else if (deterministicFloor >= 40) {
    // Suspicious deterministic baseline: AI can confirm or elevate, but not suppress below caution
    finalScore = Math.max(35, Math.round(ruleScore * 0.5 + aiScore * 0.5));
  } else {
    // Low deterministic baseline: AI takes primary weight (e.g., subtle social engineering)
    finalScore = aiScore;
  }

  // Safety floor check
  if (deterministicFloor > 0 && finalScore < deterministicFloor) {
    finalScore = deterministicFloor;
  }

  const combinedConfidence = parseFloat(((0.85 * 0.5) + (aiConf * 0.5)).toFixed(2));

  return {
    finalScore,
    confidence: combinedConfidence,
    classification: classifyRisk(finalScore),
    method: ruleIndicators.length > 0 ? "hybrid" : "ai",
    limitations
  };
}
