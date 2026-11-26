// ScamShield Automatic Real-Time Website Protection Content Script
// Extracts ONLY sanitized structural signals (never reads input values, passwords, OTPs, or cookies)
// and renders Shadow DOM warning banners or blocking interstitials on threat detection.

(() => {
  if (globalThis.__scamshieldContentGuardLoaded) return;
  globalThis.__scamshieldContentGuardLoaded = true;

  const OVERLAY_ID = "scamshield-guard-overlay";
  let lastReportedUrl = "";

  function getRegistrableDomain(hostname) {
    const parts = String(hostname || "").toLowerCase().split(".").filter(Boolean);
    if (parts.length <= 2) return parts.join(".");
    const twoPartTlds = new Set(["co.in", "co.uk", "org.in", "gov.in", "net.in", "ac.in", "bank.in", "com.au", "co.jp"]);
    const lastTwo = parts.slice(-2).join(".");
    if (twoPartTlds.has(lastTwo) && parts.length >= 3) {
      return parts.slice(-3).join(".");
    }
    return lastTwo;
  }

  function extractSanitizedSignals() {
    const host = (window.location.hostname || "").toLowerCase();
    const hostSite = getRegistrableDomain(host);
    const forms = Array.from(document.querySelectorAll("form"));
    const hasPasswordInput = Boolean(document.querySelector('input[type="password"]'));
    let externalFormAction = "";

    for (const f of forms) {
      const action = f.getAttribute("action") || "";
      if (/^https?:\/\//i.test(action)) {
        try {
          const actionHost = new URL(action).hostname.toLowerCase();
          if (actionHost && getRegistrableDomain(actionHost) !== hostSite) {
            externalFormAction = actionHost;
            break;
          }
        } catch {
          // ignore malformed action URL
        }
      }
    }

    // Collect visible text ONLY (never input values, hidden fields, or cookies)
    const rawText = (document.body?.innerText || "").replace(/\s+/g, " ").trim().slice(0, 1500);
    const title = (document.title || "").trim().slice(0, 160);
    const hasPaymentKeywords = /\b(upi|kyc|otp|cvv|card number|netbanking|verify account|account blocked|pay now|anydesk|teamviewer)\b/i.test(
      `${title} ${rawText}`
    );

    return {
      url: window.location.href,
      title,
      hasPasswordInput,
      hasPaymentKeywords,
      externalFormAction,
      bodyText: rawText
    };
  }

  function removeOverlay() {
    const existing = document.getElementById(OVERLAY_ID);
    if (existing) existing.remove();
  }

  function escapeHtml(str) {
    return String(str || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function renderOverlay(payload) {
    removeOverlay();
    if (!payload || !document.documentElement) return;

    const { block, domain, riskScore, riskLevel, explanation, indicators = [], recommendedAction, url } = payload;
    const hostEl = document.createElement("div");
    hostEl.id = OVERLAY_ID;
    const shadow = hostEl.attachShadow({ mode: "closed" });

    const validIndicators = (Array.isArray(indicators) ? indicators : [])
      .filter((ind) => ind && typeof ind === "object")
      .map((ind) => ({
        type: String(ind.indicator_type || ind.category || "").trim(),
        description: String(ind.description || ind.reason || "").trim()
      }))
      .filter((ind) => ind.description.length > 0 || (ind.type.length > 0 && ind.type !== "SIGNAL"))
      .slice(0, 4);

    const indicatorsHtml = validIndicators.length > 0
      ? validIndicators
          .map((ind) => {
            if (ind.type && ind.description) {
              return `<li><strong>${escapeHtml(ind.type)}:</strong> ${escapeHtml(ind.description)}</li>`;
            }
            if (ind.description) {
              return `<li><strong>SIGNAL:</strong> ${escapeHtml(ind.description)}</li>`;
            }
            return `<li><strong>${escapeHtml(ind.type)}</strong></li>`;
          })
          .join("")
      : "<li>No actionable threat indicators available.</li>";

    if (block) {
      shadow.innerHTML = `
        <style>
          .ss-backdrop { position: fixed; inset: 0; z-index: 2147483647; background: rgba(15, 23, 42, 0.97); color: #f8fafc; font-family: system-ui, -apple-system, sans-serif; display: flex; align-items: center; justify-content: center; padding: 24px; }
          .ss-card { max-width: 560px; width: 100%; background: #1e293b; border: 2px solid #ef4444; border-radius: 14px; padding: 28px; box-shadow: 0 25px 50px rgba(0,0,0,0.6); }
          .ss-badge { display: inline-block; background: #dc2626; color: #fff; font-weight: 800; font-size: 12px; padding: 4px 10px; border-radius: 999px; letter-spacing: 0.04em; }
          h1 { font-size: 22px; margin: 14px 0 8px; color: #fecaca; }
          p { font-size: 14px; line-height: 1.55; color: #cbd5e1; margin: 0 0 12px; }
          ul { margin: 8px 0 16px; padding-left: 18px; font-size: 13px; color: #fca5a5; line-height: 1.5; }
          .ss-actions { display: flex; gap: 12px; flex-wrap: wrap; margin-top: 18px; }
          .ss-btn-back { background: #22c55e; color: #052e16; border: none; border-radius: 8px; padding: 10px 18px; font-weight: 800; cursor: pointer; font-size: 14px; }
          .ss-btn-proceed { background: transparent; color: #94a3b8; border: 1px solid #475569; border-radius: 8px; padding: 10px 14px; font-weight: 600; cursor: pointer; font-size: 12.5px; }
        </style>
        <div class="ss-backdrop" role="dialog" aria-modal="true" aria-label="ScamShield Dangerous Website Warning">
          <div class="ss-card">
            <span class="ss-badge">SCAMSHIELD BLOCKED · ${escapeHtml(riskLevel)} (${escapeHtml(riskScore)}/100)</span>
            <h1>Dangerous Website Detected</h1>
            <p><strong>Domain:</strong> ${escapeHtml(domain)}</p>
            <p>${escapeHtml(explanation || "High-confidence phishing or scam indicators were detected on this site.")}</p>
            ${indicatorsHtml ? `<ul>${indicatorsHtml}</ul>` : ""}
            <p><strong>Recommended Action:</strong> ${escapeHtml(recommendedAction || "Leave this site immediately and do not enter passwords, OTPs, or payment details.")}</p>
            <div class="ss-actions">
              <button class="ss-btn-back" id="ss-back">Go Back to Safety</button>
              <button class="ss-btn-proceed" id="ss-proceed">Proceed Anyway (Unsafe)</button>
            </div>
          </div>
        </div>
      `;
      shadow.getElementById("ss-back")?.addEventListener("click", () => {
        if (window.history.length > 1) {
          window.history.back();
        } else {
          window.location.replace("about:blank");
        }
      });
      shadow.getElementById("ss-proceed")?.addEventListener("click", () => {
        chrome.runtime.sendMessage({ type: "RECORD_GUARD_OVERRIDE", domain, url });
        removeOverlay();
      });
    } else {
      shadow.innerHTML = `
        <style>
          .ss-banner { position: fixed; top: 12px; right: 12px; z-index: 2147483647; max-width: 400px; background: #1e293b; color: #f8fafc; border: 1.5px solid #f59e0b; border-radius: 10px; padding: 14px 16px; font-family: system-ui, -apple-system, sans-serif; box-shadow: 0 12px 30px rgba(0,0,0,0.45); }
          .ss-row { display: flex; justify-content: space-between; align-items: center; gap: 8px; }
          .ss-badge { background: #d97706; color: #fff; font-weight: 800; font-size: 11px; padding: 2px 8px; border-radius: 999px; }
          .ss-close { background: transparent; border: none; color: #94a3b8; cursor: pointer; font-size: 15px; }
          .ss-title { font-weight: 700; font-size: 13.5px; margin: 8px 0 4px; color: #fde68a; }
          p { font-size: 12.5px; color: #cbd5e1; margin: 0 0 6px; line-height: 1.45; }
          ul { margin: 4px 0 6px; padding-left: 16px; font-size: 12px; color: #fcd34d; }
        </style>
        <div class="ss-banner" role="alert">
          <div class="ss-row">
            <span class="ss-badge">SCAMSHIELD · ${escapeHtml(riskLevel)} (${escapeHtml(riskScore)}/100)</span>
            <button class="ss-close" id="ss-dismiss" aria-label="Dismiss warning">✕</button>
          </div>
          <div class="ss-title">Suspicious Activity on ${escapeHtml(domain)}</div>
          <p>${escapeHtml(explanation || "Caution advised before entering credentials or payment details.")}</p>
          ${indicatorsHtml ? `<ul>${indicatorsHtml}</ul>` : ""}
          <p><strong>Advice:</strong> ${escapeHtml(recommendedAction || "Verify this domain independently before proceeding.")}</p>
        </div>
      `;
      shadow.getElementById("ss-dismiss")?.addEventListener("click", removeOverlay);
    }

    document.documentElement.appendChild(hostEl);
  }

  function reportPageSignals(force = false) {
    const href = window.location.href;
    if (!/^https?:/i.test(href)) return;
    if (!force && href === lastReportedUrl) return;
    lastReportedUrl = href;

    const signals = extractSanitizedSignals();
    chrome.runtime.sendMessage({ type: "AUTO_INSPECT_DOM", signals }, () => {
      void chrome.runtime.lastError;
    });
  }

  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg?.type === "SHOW_GUARD_WARNING") {
      renderOverlay(msg.payload);
      sendResponse({ ok: true });
      return true;
    }
    if (msg?.type === "CLEAR_GUARD_WARNING") {
      removeOverlay();
      sendResponse({ ok: true });
      return true;
    }
    if (msg?.type === "EXTRACT_DOM_SIGNALS") {
      sendResponse({ ok: true, signals: extractSanitizedSignals() });
      return true;
    }
  });

  // Initial inspection on load + SPA navigation listeners (never on arbitrary DOM mutations)
  reportPageSignals(true);
  window.addEventListener("popstate", () => reportPageSignals(false));
  window.addEventListener("hashchange", () => reportPageSignals(false));
})();
