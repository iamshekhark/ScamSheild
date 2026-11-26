// ScamShield Background Service Worker (Manifest V3)
// Automatic Real-Time Website Protection + Context Menus + Offline ML Runtime

if (typeof importScripts === "function") {
  importScripts("ml_inference.js", "rules.js", "storage.js", "auth.js", "api.js");
}

const GUARD_CACHE_TTL_MS = 5 * 60 * 1000;
const inFlightTabScans = new Map();
const lastNotifiedTabKey = new Map();

// Preload offline ML models safely if available
async function initML() {
  if (typeof ScamML !== "undefined" && typeof chrome !== "undefined" && chrome.runtime?.getURL) {
    try {
      const urlModelUrl = chrome.runtime.getURL("models/url_classifier.json");
      const textModelUrl = chrome.runtime.getURL("models/text_email_classifier.json");
      const payModelUrl = chrome.runtime.getURL("models/payment_classifier.json");
      const results = await Promise.allSettled([
        ScamML.loadModel("url", urlModelUrl),
        ScamML.loadModel("text_email", textModelUrl),
        ScamML.loadModel("payment", payModelUrl)
      ]);
      const loadedCount = results.filter((r) => r.status === "fulfilled" && r.value === true).length;
      console.log(`[ScamShield] Offline ML models initialized (${loadedCount}/3 loaded).`);
    } catch (e) {
      console.warn("[ScamShield] Local ML models pending load or failed gracefully:", e);
    }
  }
}
initML();

function isInspectableUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== "string") return false;
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return false;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return false;

  const host = parsed.hostname.toLowerCase();
  if (
    host === "chromewebstore.google.com" ||
    (host === "chrome.google.com" && parsed.pathname.startsWith("/webstore")) ||
    ((host === "localhost" || host === "127.0.0.1") && parsed.port === "5173")
  ) {
    return false;
  }
  return true;
}

function normalizeGuardUrl(rawUrl) {
  try {
    const u = new URL(rawUrl);
    u.hash = "";
    return u.toString();
  } catch {
    return String(rawUrl || "");
  }
}

function badgeForRisk(riskLevel) {
  switch (String(riskLevel || "").toUpperCase()) {
    case "CRITICAL": return { text: "!!!", color: "#DC2626" };
    case "HIGH": return { text: "WARN", color: "#EA580C" };
    case "MEDIUM": return { text: "MED", color: "#D97706" };
    case "LOW": return { text: "LOW", color: "#2563EB" };
    case "UNABLE_TO_VERIFY": return { text: "?", color: "#64748B" };
    default: return { text: "SAFE", color: "#16A34A" };
  }
}

function updateTabBadge(tabId, riskLevel) {
  if (!tabId || typeof chrome === "undefined" || !chrome.action) return;
  const { text, color } = badgeForRisk(riskLevel);
  chrome.action.setBadgeText({ tabId, text });
  chrome.action.setBadgeBackgroundColor({ tabId, color });
}

function normalizeIndicator(ind) {
  if (!ind || typeof ind !== "object") return null;
  const type = String(ind.indicator_type || ind.category || "").trim();
  const description = String(ind.description || ind.reason || "").trim();
  const severity = String(ind.severity || "medium").toLowerCase();
  if (!description && (!type || type === "SIGNAL")) return null;
  return {
    ...ind,
    indicator_type: type || "SIGNAL",
    description: description || type,
    severity
  };
}

function hasStrongDeterministicEvidence(indicators) {
  return (indicators || []).some((ind) => {
    const type = String(ind?.indicator_type || ind?.category || "");
    const sev = String(ind?.severity || "").toLowerCase();
    return !type.startsWith("ML_") && (sev === "high" || sev === "critical");
  });
}

function mergeLayeredResults(urlResult, textResult, domSignals, url) {
  const levelRank = { SAFE: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
  const urlScore = Number(urlResult?.risk_score ?? 0);
  const textScore = Number(textResult?.risk_score ?? 0);
  const urlLvl = String(urlResult?.risk_level || "SAFE").toUpperCase();
  const txtLvl = String(textResult?.risk_level || "SAFE").toUpperCase();

  let combinedScore = Math.max(urlScore, textScore);
  let combinedLevel = (levelRank[txtLvl] || 0) > (levelRank[urlLvl] || 0) ? txtLvl : urlLvl;
  const rawIndicators = [
    ...(urlResult?.indicators || urlResult?.evidence || []),
    ...(textResult?.indicators || textResult?.evidence || [])
  ]
    .map(normalizeIndicator)
    .filter(Boolean);

  // Deduplicate correlated cross-modal indicators, keeping highest severity
  const sevRank = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  const dedupMap = new Map();
  for (const ind of rawIndicators) {
    const key = `${ind.indicator_type}:${ind.description}`;
    const existing = dedupMap.get(key);
    if (!existing || (sevRank[ind.severity] || 0) > (sevRank[existing.severity] || 0)) {
      dedupMap.set(key, ind);
    }
  }
  const indicators = Array.from(dedupMap.values());

  let host = "";
  try { host = new URL(url).hostname.toLowerCase(); } catch {}

  const hasStrongBeforeDom = hasStrongDeterministicEvidence(indicators);

  if (domSignals?.hasPasswordInput && (domSignals.externalFormAction || (combinedScore >= 35 && hasStrongBeforeDom))) {
    indicators.push({
      indicator_type: "SUSPICIOUS_LOGIN_FORM",
      description: domSignals.externalFormAction
        ? `Login form submits credentials to external host (${domSignals.externalFormAction})`
        : "Page requests password input alongside suspicious domain or phishing signals",
      severity: "high"
    });
    combinedScore = Math.max(combinedScore, 70);
    if ((levelRank[combinedLevel] || 0) < 3) combinedLevel = "HIGH";
  }

  if (domSignals?.hasPaymentKeywords && domSignals.externalFormAction) {
    indicators.push({
      indicator_type: "EXTERNAL_PAYMENT_FORM",
      description: `Payment/KYC form posts to external domain (${domSignals.externalFormAction})`,
      severity: "critical"
    });
    combinedScore = Math.max(combinedScore, 85);
    combinedLevel = "CRITICAL";
  }

  // Deterministic authority guard: only block when strong (HIGH/CRITICAL) deterministic indicators support CRITICAL >= 75
  const strongDeterministic = hasStrongDeterministicEvidence(indicators);
  if (combinedLevel === "CRITICAL" && !strongDeterministic) {
    const hasAnyDeterministic = indicators.some((ind) => !String(ind.indicator_type || "").startsWith("ML_"));
    combinedLevel = hasAnyDeterministic ? "MEDIUM" : combinedLevel;
  }
  const shouldBlock = combinedLevel === "CRITICAL" && combinedScore >= 75 && strongDeterministic;

  return {
    ...(urlResult || {}),
    normalized_domain: urlResult?.normalized_domain || host,
    risk_score: combinedScore,
    risk_level: combinedLevel,
    indicators,
    evidence: indicators,
    should_block: shouldBlock,
    detection_method: urlResult?.detection_method || "rules",
    explanation: textScore > urlScore && textResult?.explanation
      ? textResult.explanation
      : (urlResult?.explanation || "Evaluated by ScamShield real-time website protection."),
    recommended_actions: (urlResult?.recommended_actions?.length ? urlResult.recommended_actions : textResult?.recommended_actions) ||
      (combinedScore >= 50
        ? ["Do not enter passwords, OTPs, or payment details.", "Leave this website immediately."]
        : ["No significant threats detected."])
  };
}

async function runAutomaticScan(tabId, rawUrl, domSignals = null, options = {}) {
  const { forceRescan = false } = options;
  if (!isInspectableUrl(rawUrl)) return null;

  const prefs = typeof ScamStorage !== "undefined" ? await ScamStorage.getPreferences() : { auto_protect: true };
  if (!forceRescan && prefs.auto_protect === false) {
    if (tabId && typeof chrome !== "undefined" && chrome.action) {
      chrome.action.setBadgeText({ tabId, text: "OFF" });
      chrome.action.setBadgeBackgroundColor({ tabId, color: "#475569" });
    }
    return { status: "disabled", url: rawUrl };
  }

  const normalizedUrl = normalizeGuardUrl(rawUrl);
  let hostname = "";
  try { hostname = new URL(rawUrl).hostname.toLowerCase(); } catch {}

  if (typeof ScamStorage !== "undefined") {
    const allowlist = await ScamStorage.getGuardAllowlist();
    if (!forceRescan && allowlist.includes(hostname)) {
      const allowedRecord = {
        status: "allowlisted",
        risk_score: 0,
        risk_level: "SAFE",
        normalized_domain: hostname,
        explanation: "Domain is in your trusted allowlist.",
        indicators: [],
        content_preview: normalizedUrl.slice(0, 150),
        timestamp: new Date().toLocaleTimeString()
      };
      updateTabBadge(tabId, "SAFE");
      await ScamStorage.setTabScan(tabId, allowedRecord);
      return allowedRecord;
    }

    if (!forceRescan && !domSignals) {
      const cached = await ScamStorage.getCachedUrlScan(normalizedUrl);
      if (cached) {
        updateTabBadge(tabId, cached.risk_level);
        await ScamStorage.setTabScan(tabId, cached);
        return cached;
      }
    }
  }

  const dedupeKey = `${tabId}:${normalizedUrl}:${domSignals ? "dom" : "url"}`;
  if (!forceRescan && inFlightTabScans.has(dedupeKey)) {
    return inFlightTabScans.get(dedupeKey);
  }

  const task = (async () => {
    try {
      if (typeof ScamEngine === "undefined") {
        throw new Error("Detection engine unavailable");
      }

      // Layer 1: Immediate local URL analysis
      const scanOpts = { allowExperimental: prefs.experimental_ml === true };
      const urlResult = ScamEngine.scanUrl(rawUrl, scanOpts);

      // Layer 2: Sanitized DOM / content inspection (when available)
      let textResult = null;
      if (domSignals && (domSignals.title || domSignals.bodyText)) {
        const snippet = `${domSignals.title || ""}\n${domSignals.bodyText || ""}`.trim();
        if (snippet) {
          textResult = ScamEngine.scanText(snippet, { ...scanOpts, context: "webpage" });
        }
      }

      let merged = mergeLayeredResults(urlResult, textResult, domSignals, rawUrl);

      // Layer 3 & 4: Optional async server threat-intel / AI enrichment (URL-only, never private DOM values)
      if (prefs.engine_mode === "server" && typeof ScamApi !== "undefined") {
        try {
          if (typeof ScamAuth !== "undefined" && prefs.supabase_url && prefs.supabase_anon_key) {
            ScamAuth.init(prefs.supabase_url, prefs.supabase_anon_key);
            ScamApi.init(`${prefs.supabase_url.replace(/\/$/, "")}/functions/v1`);
          }
          const serverRes = await Promise.race([
            ScamApi.scan({
              content: normalizedUrl,
              type: "url",
              allowAi: prefs.allow_ai !== false,
              engineMode: "server",
              allowExperimental: prefs.experimental_ml === true
            }),
            new Promise((_, reject) => setTimeout(() => reject(new Error("Server timeout")), 6000))
          ]);
          if (serverRes && !serverRes.is_fallback && typeof serverRes.risk_score === "number") {
            const serverIndicators = (serverRes.indicators || serverRes.evidence || [])
              .map(normalizeIndicator)
              .filter(Boolean);
            if (serverRes.risk_score > merged.risk_score && serverIndicators.length > 0) {
              const nextIndicators = [...merged.indicators, ...serverIndicators];
              const nextLevel = String(serverRes.risk_level || merged.risk_level).toUpperCase();
              const nextScore = serverRes.risk_score;
              merged = {
                ...merged,
                risk_score: nextScore,
                risk_level: nextLevel,
                indicators: nextIndicators,
                evidence: nextIndicators,
                should_block: nextLevel === "CRITICAL" && nextScore >= 75 && hasStrongDeterministicEvidence(nextIndicators),
                explanation: serverRes.explanation || merged.explanation,
                detection_method: serverRes.detection_method || "hybrid"
              };
            }
          }
        } catch {
          // Offline / slow Supabase gracefully preserves Layer 1+2 deterministic verdict
        }
      }

      const overrides = typeof ScamStorage !== "undefined" ? await ScamStorage.getGuardOverrides() : {};
      const isOverridden = Boolean(overrides[hostname]);
      const finalRecord = {
        ...merged,
        status: "scanned",
        input_type: "url",
        label: "Auto Protection",
        content_preview: normalizedUrl.slice(0, 150),
        timestamp: new Date().toLocaleTimeString(),
        overridden: isOverridden
      };

      updateTabBadge(tabId, finalRecord.risk_level);

      if (typeof ScamStorage !== "undefined") {
        await ScamStorage.setTabScan(tabId, finalRecord);
        await ScamStorage.setCachedUrlScan(normalizedUrl, finalRecord, GUARD_CACHE_TTL_MS);
        if (prefs.save_history !== false && (forceRescan || finalRecord.risk_score >= 25)) {
          await ScamStorage.addLocalScan(finalRecord);
        }
      }

      // Proactive warnings & blocking interstitials
      if (tabId && typeof chrome !== "undefined" && chrome.tabs) {
        if ((finalRecord.risk_level === "MEDIUM" || finalRecord.risk_level === "HIGH" || finalRecord.risk_level === "CRITICAL") && !isOverridden) {
          chrome.tabs.sendMessage(tabId, {
            type: "SHOW_GUARD_WARNING",
            payload: {
              block: Boolean(finalRecord.should_block),
              domain: finalRecord.normalized_domain || hostname,
              url: rawUrl,
              riskScore: finalRecord.risk_score,
              riskLevel: finalRecord.risk_level,
              explanation: finalRecord.explanation,
              indicators: finalRecord.indicators,
              recommendedAction: finalRecord.recommended_actions?.[0]
            }
          }, () => { void chrome.runtime.lastError; });

          const notifyKey = `${tabId}:${hostname}:${finalRecord.risk_level}`;
          if ((finalRecord.risk_level === "HIGH" || finalRecord.risk_level === "CRITICAL") &&
              lastNotifiedTabKey.get(tabId) !== notifyKey &&
              chrome.notifications?.create) {
            lastNotifiedTabKey.set(tabId, notifyKey);
            chrome.notifications.create(`ss_warn_${tabId}_${Date.now()}`, {
              type: "basic",
              iconUrl: "icons/icon128.png",
              title: `ScamShield: ${finalRecord.risk_level} Threat (${finalRecord.risk_score}/100)`,
              message: `${hostname}: ${finalRecord.explanation}`
            });
          }
        } else if (finalRecord.risk_level === "SAFE" || finalRecord.risk_level === "LOW") {
          chrome.tabs.sendMessage(tabId, { type: "CLEAR_GUARD_WARNING" }, () => { void chrome.runtime.lastError; });
        }
      }

      return finalRecord;
    } catch (err) {
      const unableRecord = {
        status: "unable_to_verify",
        risk_score: null,
        risk_level: "UNABLE_TO_VERIFY",
        normalized_domain: hostname,
        content_preview: normalizedUrl.slice(0, 150),
        explanation: `Unable to verify website safety: ${err?.message || "scan error"}`,
        indicators: [],
        recommended_actions: ["Exercise caution until verification completes."],
        timestamp: new Date().toLocaleTimeString()
      };
      updateTabBadge(tabId, "UNABLE_TO_VERIFY");
      if (typeof ScamStorage !== "undefined") {
        await ScamStorage.setTabScan(tabId, unableRecord);
      }
      return unableRecord;
    } finally {
      inFlightTabScans.delete(dedupeKey);
    }
  })();

  inFlightTabScans.set(dedupeKey, task);
  return task;
}

// Automatic Navigation Listeners (MV3)
if (typeof chrome !== "undefined" && chrome.webNavigation) {
  chrome.webNavigation.onCommitted.addListener((details) => {
    if (details.frameId === 0 && isInspectableUrl(details.url)) {
      runAutomaticScan(details.tabId, details.url, null);
    }
  });
  chrome.webNavigation.onHistoryStateUpdated.addListener((details) => {
    if (details.frameId === 0 && isInspectableUrl(details.url)) {
      runAutomaticScan(details.tabId, details.url, null);
    }
  });
}

if (typeof chrome !== "undefined" && chrome.tabs?.onUpdated) {
  chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.url && isInspectableUrl(changeInfo.url)) {
      runAutomaticScan(tabId, changeInfo.url, null);
    } else if (changeInfo.status === "complete" && tab?.url && isInspectableUrl(tab.url)) {
      runAutomaticScan(tabId, tab.url, null);
    }
  });
}

// Service-worker message bus
if (typeof chrome !== "undefined" && chrome.runtime?.onMessage) {
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message?.type === "GET_ML_STATUS") {
      const statuses = typeof ScamML !== "undefined" && ScamML.getAllModelStatuses ? ScamML.getAllModelStatuses() : null;
      sendResponse({ success: true, statuses });
      return true;
    }
    if (message?.type === "RELOAD_ML_MODELS") {
      initML().then(() => {
        const statuses = typeof ScamML !== "undefined" && ScamML.getAllModelStatuses ? ScamML.getAllModelStatuses() : null;
        sendResponse({ success: true, statuses });
      });
      return true;
    }
    if (message?.type === "AUTO_INSPECT_DOM" && sender?.tab?.id && message?.signals?.url) {
      runAutomaticScan(sender.tab.id, message.signals.url, message.signals).then((result) => {
        sendResponse({ success: true, result });
      });
      return true;
    }
    if (message?.type === "RECORD_GUARD_OVERRIDE" && message?.domain) {
      if (typeof ScamStorage !== "undefined") {
        ScamStorage.recordGuardOverride(message.domain, message.url, "proceed_unsafe").then(() => {
          sendResponse({ success: true });
        });
        return true;
      }
    }
    if (message?.type === "MANUAL_RESCAN_TAB" && message?.tabId && message?.url) {
      runAutomaticScan(message.tabId, message.url, message.domSignals || null, { forceRescan: true }).then((result) => {
        sendResponse({ success: true, result });
      });
      return true;
    }
    if (message?.type === "SET_AUTO_PROTECT") {
      if (typeof ScamStorage !== "undefined") {
        ScamStorage.getPreferences().then(async (p) => {
          const next = { ...p, auto_protect: Boolean(message.enabled) };
          await ScamStorage.setPreferences(next);
          if (message.tabId && message.url && next.auto_protect) {
            await runAutomaticScan(message.tabId, message.url, null, { forceRescan: true });
          } else if (message.tabId && !next.auto_protect && chrome.action) {
            chrome.action.setBadgeText({ tabId: message.tabId, text: "OFF" });
            chrome.action.setBadgeBackgroundColor({ tabId: message.tabId, color: "#475569" });
          }
          sendResponse({ success: true, preferences: next });
        });
        return true;
      }
    }
  });
}

if (typeof chrome !== "undefined" && chrome.runtime?.onInstalled) {
  chrome.runtime.onInstalled.addListener(() => {
    chrome.contextMenus.create({
      id: "scamshield-scan-selection",
      title: "🛡️ ScamShield: Check selected text",
      contexts: ["selection"]
    });

    chrome.contextMenus.create({
      id: "scamshield-scan-link",
      title: "🛡️ ScamShield: Check this link",
      contexts: ["link"]
    });

    chrome.contextMenus.create({
      id: "scamshield-scan-page",
      title: "🛡️ ScamShield: Check this page URL",
      contexts: ["page"]
    });
  });
}

if (typeof chrome !== "undefined" && chrome.contextMenus?.onClicked) {
  chrome.contextMenus.onClicked.addListener(async (info, tab) => {
    let result = null;
    let inputType = "text";
    let content = "";

    if (info.menuItemId === "scamshield-scan-selection" && info.selectionText) {
      inputType = "text";
      content = info.selectionText;
      result = ScamEngine.scanText(content);
    } else if (info.menuItemId === "scamshield-scan-link" && info.linkUrl) {
      inputType = "url";
      content = info.linkUrl;
      result = ScamEngine.scanUrl(content);
    } else if (info.menuItemId === "scamshield-scan-page" && tab?.url) {
      inputType = "url";
      content = tab.url;
      result = ScamEngine.scanUrl(content);
    }

    if (result) {
      const scanRecord = {
        ...result,
        input_type: inputType,
        content_preview: content.slice(0, 200),
        timestamp: new Date().toLocaleTimeString()
      };
      if (tab?.id && typeof ScamStorage !== "undefined") {
        await ScamStorage.setTabScan(tab.id, scanRecord);
      } else {
        await chrome.storage.local.set({ lastScan: scanRecord });
      }
      updateTabBadge(tab?.id, result.risk_level);
    }
  });
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    isInspectableUrl,
    normalizeGuardUrl,
    badgeForRisk,
    mergeLayeredResults,
    runAutomaticScan
  };
}
