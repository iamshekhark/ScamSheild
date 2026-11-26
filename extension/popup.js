// ScamShield Full-Stack Popup Controller
document.addEventListener("DOMContentLoaded", async () => {
  let activeTabUrl = "";
  let activeTabId = null;
  let currentScanId = null;

  // Navigation
  const tabBtns = document.querySelectorAll(".tab-btn");
  const tabPanes = document.querySelectorAll(".tab-pane");
  const subTabBtns = document.querySelectorAll(".sub-tab-btn");
  const subPanes = document.querySelectorAll(".sub-pane");

  // Header
  const engineBadge = document.getElementById("engine-badge");
  const userStatusBtn = document.getElementById("user-status-btn");

  // Scanner elements
  const pageUrlBox = document.getElementById("current-page-url");
  const btnScanCurrent = document.getElementById("btn-scan-current");
  const toggleAutoProtect = document.getElementById("toggle-auto-protect");
  const autoProtectStatus = document.getElementById("auto-protect-status");
  const autoScanStatus = document.getElementById("auto-scan-status");
  const settingAutoProtect = document.getElementById("setting-auto-protect");
  const btnScanUrl = document.getElementById("btn-scan-url");
  const btnScanText = document.getElementById("btn-scan-text");
  const inputUrl = document.getElementById("input-url");
  const inputText = document.getElementById("input-text");
  const inputEmailSender = document.getElementById("input-email-sender");
  const inputEmailSubject = document.getElementById("input-email-subject");
  const inputEmailBody = document.getElementById("input-email-body");
  const btnScanEmail = document.getElementById("btn-scan-email");
  const inputPayment = document.getElementById("input-payment");
  const btnScanPayment = document.getElementById("btn-scan-payment");

  // OCR elements
  const ocrDropzone = document.getElementById("ocr-dropzone");
  const inputOcrFile = document.getElementById("input-ocr-file");
  const ocrPreviewWrap = document.getElementById("ocr-preview-wrap");
  const ocrPreviewImg = document.getElementById("ocr-preview-img");
  const ocrFileName = document.getElementById("ocr-file-name");
  const ocrStatus = document.getElementById("ocr-status");
  const ocrExtractedText = document.getElementById("ocr-extracted-text");
  const btnScanOcr = document.getElementById("btn-scan-ocr");
  let activeOcrFile = null;

  // Result elements
  const resultContainer = document.getElementById("result-container");
  const resType = document.getElementById("res-type");
  const resMethod = document.getElementById("res-method");
  const resConfidence = document.getElementById("res-confidence");
  const resScore = document.getElementById("res-score");
  const resLevel = document.getElementById("res-level");
  const resBar = document.getElementById("res-bar");
  const resExplanation = document.getElementById("res-explanation");
  const resEvidence = document.getElementById("res-evidence");
  const resRecs = document.getElementById("res-recs");
  const btnClear = document.getElementById("btn-clear");

  // Feedback elements
  const feedbackBlock = document.getElementById("feedback-block");
  const fbBtns = document.querySelectorAll(".btn-fb");

  // History elements
  const historyContainer = document.getElementById("history-container");
  const btnRefreshHistory = document.getElementById("btn-refresh-history");

  // Auth elements
  const authForms = document.getElementById("auth-forms");
  const authProfile = document.getElementById("auth-profile");
  const toggleLoginBtn = document.getElementById("toggle-login-btn");
  const toggleRegisterBtn = document.getElementById("toggle-register-btn");
  const fieldNameWrap = document.getElementById("field-displayname-wrap");
  const formAuth = document.getElementById("form-auth");
  const authName = document.getElementById("auth-name");
  const authEmail = document.getElementById("auth-email");
  const authPassword = document.getElementById("auth-password");
  const authError = document.getElementById("auth-error");
  const authSuccess = document.getElementById("auth-success");
  const btnAuthSubmit = document.getElementById("btn-auth-submit");
  const profileName = document.getElementById("profile-name");
  const profileEmail = document.getElementById("profile-email");
  const btnLogout = document.getElementById("btn-logout");
  const btnForgotPasswordLink = document.getElementById("btn-forgot-password-link");
  const authForgotPanel = document.getElementById("auth-forgot-panel");
  const forgotEmail = document.getElementById("forgot-email");
  const forgotCode = document.getElementById("forgot-code");
  const forgotNewPassword = document.getElementById("forgot-new-password");
  const btnSendResetCode = document.getElementById("btn-send-reset-code");
  const forgotError = document.getElementById("forgot-error");
  const forgotSuccess = document.getElementById("forgot-success");
  const btnSubmitForgot = document.getElementById("btn-submit-forgot");
  const btnBackToLogin = document.getElementById("btn-back-to-login");

  // Settings elements
  const settingEngine = document.getElementById("setting-engine");
  const settingSupabaseUrl = document.getElementById("setting-supabase-url");
  const settingSupabaseAnonKey = document.getElementById("setting-supabase-anon-key");
  const settingDashboardUrl = document.getElementById("setting-dashboard-url");
  const settingAllowAi = document.getElementById("setting-allow-ai");
  const settingSaveHistory = document.getElementById("setting-save-history");
  const settingExperimentalMl = document.getElementById("setting-experimental-ml");
  const mlStatusSummary = document.getElementById("ml-status-summary");
  const btnSaveSettings = document.getElementById("btn-save-settings");
  const linkDashProfile = document.getElementById("link-dashboard-profile");
  const linkDashFooter = document.getElementById("link-dashboard-footer");

  let isRegisterMode = false;

  // 1. Initial State Loading
  const prefs = await ScamStorage.getPreferences();
  settingEngine.value = prefs.engine_mode || "offline";
  settingAllowAi.checked = prefs.allow_ai !== false;
  settingSaveHistory.checked = prefs.save_history !== false;
  const isAutoProtectOn = prefs.auto_protect !== false;
  if (toggleAutoProtect) toggleAutoProtect.checked = isAutoProtectOn;
  if (settingAutoProtect) settingAutoProtect.checked = isAutoProtectOn;
  if (autoProtectStatus) autoProtectStatus.textContent = isAutoProtectOn ? "ON" : "OFF";
  if (autoScanStatus) autoScanStatus.textContent = isAutoProtectOn ? "Monitoring" : "Paused";
  if (settingExperimentalMl) {
    settingExperimentalMl.checked = prefs.experimental_ml === true;
  }

  // Preload local ML models for offline inference in popup context
  function updateMLStatusUI(activePrefs) {
    if (typeof ScamML === "undefined" || !ScamML.getAllModelStatuses) return;
    const statuses = ScamML.getAllModelStatuses();
    const isExp = activePrefs?.experimental_ml === true;

    const taskMap = [
      { key: "url", badgeId: "ml-badge-url", verId: "ml-ver-url" },
      { key: "text_email", badgeId: "ml-badge-text", verId: "ml-ver-text" },
      { key: "payment", badgeId: "ml-badge-payment", verId: "ml-ver-payment" }
    ];

    let loadedCount = 0;
    let latestLoadedTime = null;

    taskMap.forEach(({ key, badgeId, verId }) => {
      const info = statuses[key];
      const badge = document.getElementById(badgeId);
      const verEl = document.getElementById(verId);

      if (verEl && info?.model_version) {
        verEl.textContent = info.model_version;
      }

      if (!badge) return;

      badge.className = "ml-status-badge";
      if (!info || !info.loaded) {
        badge.classList.add("badge-error");
        badge.textContent = "Unavailable";
      } else {
        loadedCount++;
        if (info.last_loaded && (!latestLoadedTime || new Date(info.last_loaded) > new Date(latestLoadedTime))) {
          latestLoadedTime = info.last_loaded;
        }

        if (info.is_production_ready && info.activation_status === "enabled") {
          badge.classList.add("badge-success");
          badge.textContent = "Production Active";
        } else if (isExp) {
          badge.classList.add("badge-warning");
          badge.textContent = "Experimental Active";
        } else {
          badge.classList.add("badge-muted");
          badge.textContent = "Gate Locked (Shadow)";
        }
      }
    });

    const modeSummary = document.getElementById("ml-mode-summary");
    if (modeSummary) {
      if (isExp) {
        modeSummary.textContent = "Mode: Experimental Risk Scoring (Analyst Override Active)";
      } else {
        modeSummary.textContent = "Mode: Production Guard (Deterministic Rules Primary)";
      }
    }

    const lastLoadEl = document.getElementById("ml-last-load");
    if (lastLoadEl) {
      const timeStr = latestLoadedTime ? new Date(latestLoadedTime).toLocaleTimeString() : "Pending";
      lastLoadEl.textContent = `Offline: Ready (${loadedCount}/3 Models Loaded) • Last Sync: ${timeStr}`;
    }
  }

  if (typeof ScamML !== "undefined") {
    try {
      const getModelUrl = (relPath) => {
        return (typeof chrome !== "undefined" && chrome.runtime?.getURL) ? chrome.runtime.getURL(relPath) : relPath;
      };
      await Promise.allSettled([
        ScamML.loadModel("url", getModelUrl("models/url_classifier.json")),
        ScamML.loadModel("text_email", getModelUrl("models/text_email_classifier.json")),
        ScamML.loadModel("payment", getModelUrl("models/payment_classifier.json"))
      ]);
    } catch (e) {
      console.warn("Could not load local ML models:", e);
    }
    updateMLStatusUI(prefs);
  }

  if (settingExperimentalMl) {
    settingExperimentalMl.addEventListener("change", () => {
      updateMLStatusUI({ ...prefs, experimental_ml: settingExperimentalMl.checked });
    });
  }

  function isValidDashboardUrl(val) {
    if (!val || typeof val !== "string") return false;
    try {
      const u = new URL(val.trim());
      return u.protocol === "http:" || u.protocol === "https:";
    } catch {
      return false;
    }
  }

  function safeOpenDashboard(e) {
    e.preventDefault();
    const url = e.currentTarget.getAttribute("href") || "";
    if (isValidDashboardUrl(url)) {
      if (typeof chrome !== "undefined" && chrome.tabs?.create) {
        chrome.tabs.create({ url });
      } else {
        window.open(url, "_blank");
      }
    } else {
      alert("Invalid Dashboard URL: Address must start with http:// or https://");
    }
  }

  const rawDashUrl = prefs.dashboard_url || "http://localhost:5173";
  const activeDashUrl = isValidDashboardUrl(rawDashUrl) ? rawDashUrl : "http://localhost:5173";
  if (settingDashboardUrl) settingDashboardUrl.value = activeDashUrl;
  if (linkDashProfile) {
    linkDashProfile.href = activeDashUrl;
    linkDashProfile.addEventListener("click", safeOpenDashboard);
  }
  if (linkDashFooter) {
    linkDashFooter.href = activeDashUrl;
    linkDashFooter.addEventListener("click", safeOpenDashboard);
  }

  const DEFAULT_SUPABASE_URL = "https://twrdubnndhgbqlaeeabl.supabase.co";
  const DEFAULT_SUPABASE_ANON_KEY = "sb_publishable_zY1kd0vajVDqH9McMWYHGg_trMRKeEo";

  const { supabase_url, supabase_anon_key } = await ScamStorage.get(["supabase_url", "supabase_anon_key"]);
  const activeSupabaseUrl = (supabase_url && !supabase_url.includes("your-project")) ? supabase_url : DEFAULT_SUPABASE_URL;
  settingSupabaseUrl.value = activeSupabaseUrl;
  const activeAnonKey = (supabase_anon_key && supabase_anon_key !== "your-anon-key") ? supabase_anon_key : DEFAULT_SUPABASE_ANON_KEY;
  if (settingSupabaseAnonKey) {
    settingSupabaseAnonKey.value = activeAnonKey;
  }
  ScamAuth.init(activeSupabaseUrl, activeAnonKey);
  ScamApi.init(`${activeSupabaseUrl}/functions/v1`);

  updateEngineBadge(prefs.engine_mode || "offline");
  await checkAuthStatus();

  // Load active tab URL
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs && tabs[0]?.url) {
      activeTabUrl = tabs[0].url;
      activeTabId = tabs[0].id ?? null;
      pageUrlBox.textContent = activeTabUrl;
    } else {
      pageUrlBox.textContent = "Unable to read active tab URL.";
      btnScanCurrent.disabled = true;
    }
  } catch {
    pageUrlBox.textContent = "Tab permission unavailable.";
  }

  // Restore active tab's automatic scan result (or lastScan fallback)
  const tabScan = (activeTabId && typeof ScamStorage.getTabScan === "function")
    ? await ScamStorage.getTabScan(activeTabId)
    : null;
  const { lastScan } = await ScamStorage.get("lastScan");
  const initialScan = tabScan || lastScan;
  if (initialScan) {
    if (autoScanStatus) {
      if (initialScan.status === "unable_to_verify" || initialScan.risk_level === "UNABLE_TO_VERIFY") {
        autoScanStatus.textContent = "Unable to verify";
      } else if (initialScan.status === "disabled") {
        autoScanStatus.textContent = "Paused";
      } else {
        autoScanStatus.textContent = `Checked (${initialScan.risk_level || "SAFE"})`;
      }
    }
    if (initialScan.risk_level && initialScan.risk_level !== "UNABLE_TO_VERIFY") {
      renderScanResult(initialScan);
    }
  }

  async function applyAutoProtectToggle(enabled) {
    if (toggleAutoProtect) toggleAutoProtect.checked = enabled;
    if (settingAutoProtect) settingAutoProtect.checked = enabled;
    if (autoProtectStatus) autoProtectStatus.textContent = enabled ? "ON" : "OFF";
    if (autoScanStatus) autoScanStatus.textContent = enabled ? "Scanning…" : "Paused";
    if (typeof chrome !== "undefined" && chrome.runtime?.sendMessage) {
      chrome.runtime.sendMessage(
        { type: "SET_AUTO_PROTECT", enabled, tabId: activeTabId, url: activeTabUrl },
        async () => {
          void chrome.runtime.lastError;
          if (enabled && activeTabId && typeof ScamStorage.getTabScan === "function") {
            const updated = await ScamStorage.getTabScan(activeTabId);
            if (updated && updated.risk_level) {
              if (autoScanStatus) autoScanStatus.textContent = `Checked (${updated.risk_level})`;
              renderScanResult(updated);
            }
          }
        }
      );
    } else {
      const p = await ScamStorage.getPreferences();
      await ScamStorage.setPreferences({ ...p, auto_protect: enabled });
    }
  }

  toggleAutoProtect?.addEventListener("change", () => applyAutoProtectToggle(toggleAutoProtect.checked));
  settingAutoProtect?.addEventListener("change", () => applyAutoProtectToggle(settingAutoProtect.checked));

  // 2. Navigation Tab Switching (with ARIA Accessibility)
  tabBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      tabBtns.forEach((b) => {
        b.classList.remove("active");
        b.setAttribute("aria-selected", "false");
      });
      tabPanes.forEach((p) => p.classList.remove("active"));
      btn.classList.add("active");
      btn.setAttribute("aria-selected", "true");
      const target = document.getElementById(btn.dataset.tab);
      if (target) target.classList.add("active");

      if (btn.dataset.tab === "tab-history") loadScanHistory();
    });
  });

  userStatusBtn.addEventListener("click", () => {
    document.querySelector('[data-tab="tab-account"]')?.click();
  });

  // Scanner Sub-Tabs (with ARIA Accessibility)
  subTabBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      subTabBtns.forEach((b) => {
        b.classList.remove("active");
        b.setAttribute("aria-selected", "false");
      });
      subPanes.forEach((p) => p.classList.remove("active"));
      btn.classList.add("active");
      btn.setAttribute("aria-selected", "true");
      const target = document.getElementById(btn.dataset.sub);
      if (target) target.classList.add("active");
    });
  });

  // Quick Test Chips
  document.querySelectorAll("[data-sample-url]").forEach((chip) => {
    chip.addEventListener("click", () => {
      inputUrl.value = chip.getAttribute("data-sample-url");
      btnScanUrl.click();
    });
  });

  document.querySelectorAll("[data-sample-text]").forEach((chip) => {
    chip.addEventListener("click", () => {
      inputText.value = chip.getAttribute("data-sample-text");
      btnScanText.click();
    });
  });

  document.querySelectorAll("[data-sample-email]").forEach((chip) => {
    chip.addEventListener("click", () => {
      const type = chip.getAttribute("data-sample-email");
      if (type === "paytm") {
        inputEmailSender.value = "Paytm Security <alert-support@paytrn-security.xyz>";
        inputEmailSubject.value = "URGENT: Your KYC is expired. Re-verify OTP to prevent blocking";
        inputEmailBody.value = "Dear Customer, share your OTP immediately at http://paytrn-security.xyz/verify to prevent suspension.";
      } else if (type === "invoice") {
        inputEmailSender.value = "Billing Dept <invoices@cloud-service-billing.top>";
        inputEmailSubject.value = "Invoice #98201 Overdue - Immediate wire transfer required";
        inputEmailBody.value = "Remit $4,200 immediately or services will terminate.";
      } else {
        inputEmailSender.value = "GitHub <notifications@github.com>";
        inputEmailSubject.value = "[GitHub] Security advisory published for repository dependency";
        inputEmailBody.value = "A security advisory has been published for your dependency.";
      }
      btnScanEmail.click();
    });
  });

  document.querySelectorAll("[data-sample-pay]").forEach((chip) => {
    chip.addEventListener("click", () => {
      const type = chip.getAttribute("data-sample-pay");
      if (type === "vpa") {
        inputPayment.value = "paytm-refund-desk@ybl";
      } else if (type === "qr") {
        inputPayment.value = "upi://pay?pa=scammer99@ybl&pn=Refund%20Officer&am=5000&cu=INR&tn=Enter%20your%206-digit%20UPI%20PIN%20to%20receive%20refund";
      } else {
        inputPayment.value = "grocery.store@okhdfcbank";
      }
      btnScanPayment.click();
    });
  });

  // OCR Sample Chips
  document.querySelectorAll("[data-sample-ocr]").forEach((chip) => {
    chip.addEventListener("click", () => {
      const type = chip.getAttribute("data-sample-ocr");
      if (type === "kyc") {
        ocrExtractedText.value = "STATE BANK NOTICE: Your SBI Savings Account KYC verification has expired. Your netbanking access will be blocked within 24 hours. Connect immediately at http://sbi-kyc-update.com/verify to prevent legal action.";
      } else if (type === "swiggy") {
        ocrExtractedText.value = "Payment Successful to Swiggy Bundl Technologies Pvt Ltd.\nAmount: Rs 499.00\nStatus: Success\n(Note: No banking UTR or RRN number present)";
      } else if (type === "qr") {
        ocrExtractedText.value = "upi://pay?pa=refund-nodal@okaxis&pn=Customer%20Support%20Desk&am=1500&tn=Enter%20your%20UPI%20PIN%20to%20claim%20instant%20cashback";
      } else {
        ocrExtractedText.value = "Payment of Rs 1,250.00 to DMart Retail Store Successful.\nUPI Ref / UTR: 426819284712\nTxn ID: T261019284712918\nPaid via PhonePe / HDFC Bank.";
      }
      btnScanOcr.click();
    });
  });

  // OCR Dropzone & File Handling
  if (ocrDropzone && inputOcrFile) {
    ocrDropzone.addEventListener("click", () => inputOcrFile.click());

    ocrDropzone.addEventListener("dragover", (e) => {
      e.preventDefault();
      ocrDropzone.classList.add("dragover");
    });

    ocrDropzone.addEventListener("dragleave", () => {
      ocrDropzone.classList.remove("dragover");
    });

    ocrDropzone.addEventListener("drop", (e) => {
      e.preventDefault();
      ocrDropzone.classList.remove("dragover");
      if (e.dataTransfer.files && e.dataTransfer.files[0]) {
        handleOcrFileSelection(e.dataTransfer.files[0]);
      }
    });

    inputOcrFile.addEventListener("change", (e) => {
      if (e.target.files && e.target.files[0]) {
        handleOcrFileSelection(e.target.files[0]);
      }
    });
  }

  function handleOcrFileSelection(file) {
    if (!file.type.startsWith("image/")) {
      alert("Please upload a valid image file (PNG, JPEG, WebP).");
      return;
    }
    if (file.size > 12 * 1024 * 1024) {
      alert("File exceeds maximum allowed size of 12MB.");
      return;
    }

    activeOcrFile = file;
    ocrFileName.textContent = file.name;
    ocrStatus.textContent = "Image loaded (" + (file.size / 1024).toFixed(1) + " KB)";

    const reader = new FileReader();
    reader.onload = (ev) => {
      ocrPreviewImg.src = ev.target.result;
      ocrPreviewWrap.classList.remove("hidden");
    };
    reader.readAsDataURL(file);
  }

  btnScanOcr?.addEventListener("click", async () => {
    btnScanOcr.disabled = true;
    const originalText = btnScanOcr.textContent;
    btnScanOcr.textContent = "⏳ Scanning...";

    try {
      let result = null;
      if (activeOcrFile && typeof ScamOCR !== "undefined") {
        ocrStatus.textContent = "Extracting text locally...";
        result = await ScamOCR.scanImage(activeOcrFile, {
          onProgress: (p) => {
            if (p.status) ocrStatus.textContent = p.status;
          }
        });
        if (result.extracted_text) {
          ocrExtractedText.value = result.extracted_text;
        } else if (result.qr_code) {
          ocrExtractedText.value = "[Decoded QR URI]: " + result.qr_code;
        }
      } else {
        // Evaluate text directly from textarea
        const val = ocrExtractedText.value.trim();
        if (!val) {
          alert("Please upload an image or enter text to scan.");
          return;
        }

        const currentPrefs = await ScamStorage.getPreferences();
        let threatRes;
        if (val.startsWith("upi://") || val.includes("upi://pay")) {
          threatRes = ScamEngine.scanPayment(val, "qr_code", {
            allowExperimental: currentPrefs.experimental_ml === true
          });
        } else {
          const payRes = ScamEngine.scanPayment(val, "screenshot", {
            allowExperimental: currentPrefs.experimental_ml === true
          });
          const textRes = ScamEngine.scanText(val, {
            allowExperimental: currentPrefs.experimental_ml === true
          });
          threatRes = (payRes.risk_score >= textRes.risk_score) ? payRes : textRes;
        }

        const DISCLAIMER = "PAYMENT UNVERIFIED: Image analysis detects deceptive text and fraud patterns only. ScamShield does NOT verify bank settlement or authenticate payment receipts.";
        result = {
          ...threatRes,
          recommendations: [DISCLAIMER, ...(threatRes.recommendations || []).filter((r) => !r.includes("PAYMENT UNVERIFIED"))],
          extracted_text: val,
          qr_code: val.startsWith("upi://") ? val : null,
          ocr_confidence: 100,
          payment_status: "unverified",
          input_type: "ocr_image",
          detection_method: "local_ocr + rules"
        };
      }

      const scanData = {
        ...result,
        label: "Image / OCR Audit",
        input_type: "ocr_image",
        submitted_content: (result.extracted_text || result.qr_code || "Image Upload").slice(0, 150)
      };

      await ScamStorage.set({ lastScan: scanData });
      renderScanResult(scanData);
      ocrStatus.textContent = "Scan complete (" + result.risk_level + ")";
    } catch (err) {
      alert("OCR Scan Error: " + err.message);
      ocrStatus.textContent = "Error: " + err.message;
    } finally {
      btnScanOcr.disabled = false;
      btnScanOcr.textContent = originalText;
    }
  });

  // 3. Scanner Actions
  btnScanCurrent.addEventListener("click", async () => {
    if (!activeTabUrl) return;

    // 1. Scan active tab URL
    const currentPrefs = await ScamStorage.getPreferences();
    const urlResult = await ScamApi.scan({
      content: activeTabUrl,
      type: "url",
      allowAi: currentPrefs.allow_ai,
      engineMode: currentPrefs.engine_mode,
      allowExperimental: currentPrefs.experimental_ml === true
    });

    let mergedResult = { ...urlResult };

    // 2. Active-tab DOM text extraction (only on http/https/file pages via user-invoked activeTab+scripting)
    if (
      activeTabId &&
      typeof chrome !== "undefined" &&
      chrome.scripting?.executeScript &&
      /^(https?|file):/i.test(activeTabUrl)
    ) {
      try {
        const injection = await chrome.scripting.executeScript({
          target: { tabId: activeTabId },
          func: () => {
            const title = document.title || "";
            const bodyText = (document.body?.innerText || "").replace(/\s+/g, " ").trim().slice(0, 3500);
            const hasPasswordInput = Boolean(document.querySelector('input[type="password"]'));
            return { title, bodyText, hasPasswordInput };
          }
        });
        const pageInfo = injection?.[0]?.result;
        if (pageInfo?.bodyText) {
          const domText = `${pageInfo.title}\n${pageInfo.bodyText}`;
          const textResult = await ScamApi.scan({
            content: domText,
            type: "text",
            allowAi: currentPrefs.allow_ai,
            engineMode: currentPrefs.engine_mode,
            allowExperimental: currentPrefs.experimental_ml === true,
            context: "webpage"
          });

          const combinedScore = Math.max(urlResult.risk_score ?? 0, textResult.risk_score ?? 0);
          const levelRank = { SAFE: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
          const urlLvl = (urlResult.risk_level || "SAFE").toUpperCase();
          const txtLvl = (textResult.risk_level || "SAFE").toUpperCase();
          const combinedLevel = (levelRank[txtLvl] || 0) > (levelRank[urlLvl] || 0) ? txtLvl : urlLvl;
          const combinedIndicators = [
            ...(urlResult.indicators || urlResult.evidence || []),
            ...(textResult.indicators || textResult.evidence || [])
          ];
          if (pageInfo.hasPasswordInput && combinedScore >= 40) {
            combinedIndicators.push({
              indicator_type: "CREDENTIAL_FORM",
              description: "Page requests password/credential input alongside suspicious indicators",
              severity: "high"
            });
          }

          mergedResult = {
            ...urlResult,
            risk_score: combinedScore,
            risk_level: combinedLevel,
            indicators: combinedIndicators,
            evidence: combinedIndicators,
            explanation: (textResult.risk_score ?? 0) > (urlResult.risk_score ?? 0)
              ? textResult.explanation
              : urlResult.explanation
          };
        }
      } catch {
        // Fall back gracefully to URL-only scan if scripting is restricted on the active page
      }
    }

    currentScanId = mergedResult.scan_id || null;
    const scanData = {
      ...mergedResult,
      input_type: "url",
      label: "Active Page",
      content_preview: activeTabUrl.slice(0, 150)
    };
    await ScamStorage.set({ lastScan: scanData });
    if (currentPrefs.save_history !== false && typeof ScamStorage.addLocalScan === "function") {
      await ScamStorage.addLocalScan(scanData);
    }
    renderScanResult(scanData);
  });

  btnScanUrl.addEventListener("click", async () => {
    const url = inputUrl.value.trim();
    if (!url) return;
    await executeScan("url", url, "Link Scan");
  });

  btnScanText.addEventListener("click", async () => {
    const text = inputText.value.trim();
    if (!text) return;
    await executeScan("text", text, "Message Scan");
  });

  btnScanEmail?.addEventListener("click", async () => {
    const sender = inputEmailSender.value.trim();
    const subject = inputEmailSubject.value.trim();
    const body = inputEmailBody.value.trim();
    if (!sender && !subject && !body) return;

    const currentPrefs = await ScamStorage.getPreferences();
    const offline = ScamEngine.scanEmail(sender, subject, body, {
      allowExperimental: currentPrefs.experimental_ml === true
    });
    const scanData = {
      risk_score: offline.risk_score,
      risk_level: offline.risk_level.toLowerCase(),
      detection_method: offline.detection_method || "rules",
      explanation: offline.risk_score >= 50
        ? "Phishing indicators detected in email headers, sender address, or message body."
        : "Standard legitimate email without deceptive indicators.",
      indicators: offline.evidence.map((e) => ({
        indicator_type: e.category,
        description: e.reason,
        severity: e.severity.toLowerCase()
      })),
      recommended_actions: offline.recommendations,
      ml_result: offline.ml_result || null,
      label: "Email Security Audit",
      input_type: "email",
      submitted_content: `${sender}: ${subject}`
    };

    await ScamStorage.set({ lastScan: scanData });
    if (currentPrefs.save_history !== false && typeof ScamStorage.addLocalScan === "function") {
      await ScamStorage.addLocalScan(scanData);
    }
    renderScanResult(scanData);
  });

  btnScanPayment?.addEventListener("click", async () => {
    const val = inputPayment.value.trim();
    if (!val) return;

    let payType = "upi_id";
    if (val.startsWith("upi://") || val.includes("upi://pay")) payType = "qr_code";
    else if (val.startsWith("http://") || val.startsWith("https://")) payType = "payment_url";
    else if (val.includes(" ")) payType = "message";

    const currentPrefs = await ScamStorage.getPreferences();
    const result = await ScamApi.verifyPayment({
      content: val,
      type: payType,
      allowAi: currentPrefs.allow_ai,
      engineMode: currentPrefs.engine_mode,
      allowExperimental: currentPrefs.experimental_ml === true
    });

    const scanData = {
      ...result,
      label: "Payment Scam Check",
      input_type: payType,
      submitted_content: val
    };

    await ScamStorage.set({ lastScan: scanData });
    if (currentPrefs.save_history !== false && typeof ScamStorage.addLocalScan === "function") {
      await ScamStorage.addLocalScan(scanData);
    }
    renderScanResult(scanData);
  });

  btnClear.addEventListener("click", async () => {
    resultContainer.classList.add("hidden");
    inputUrl.value = "";
    inputText.value = "";
    if (inputEmailSender) inputEmailSender.value = "";
    if (inputEmailSubject) inputEmailSubject.value = "";
    if (inputEmailBody) inputEmailBody.value = "";
    if (inputPayment) inputPayment.value = "";
    if (ocrExtractedText) ocrExtractedText.value = "";
    if (inputOcrFile) inputOcrFile.value = "";
    if (ocrPreviewWrap) ocrPreviewWrap.classList.add("hidden");
    activeOcrFile = null;
    await ScamStorage.remove("lastScan");
  });

  async function executeScan(type, content, label) {
    const currentPrefs = await ScamStorage.getPreferences();
    const result = await ScamApi.scan({
      content,
      type,
      allowAi: currentPrefs.allow_ai,
      engineMode: currentPrefs.engine_mode,
      allowExperimental: currentPrefs.experimental_ml === true
    });

    currentScanId = result.scan_id || null;
    const scanData = {
      ...result,
      input_type: type,
      label,
      content_preview: content.slice(0, 150)
    };

    await ScamStorage.set({ lastScan: scanData });
    if (currentPrefs.save_history !== false && typeof ScamStorage.addLocalScan === "function") {
      await ScamStorage.addLocalScan(scanData);
    }
    renderScanResult(scanData);
  }

  function renderScanResult(data) {
    resType.textContent = data.label || (data.input_type === "url" ? "URL Scan" : "Message Scan");
    resMethod.textContent = (data.detection_method || "rules").toUpperCase();
    if (resConfidence) {
      if (typeof data.model_confidence === "number") {
        const lvl = data.confidence_level ? ` (${data.confidence_level})` : "";
        resConfidence.textContent = `Confidence: ${data.model_confidence.toFixed(1)}%${lvl}`;
      } else {
        resConfidence.textContent = "Confidence: Unavailable";
      }
    }
    resScore.textContent = data.risk_score ?? 0;

    const levelStr = (data.risk_level || "low").toUpperCase();
    resLevel.textContent = levelStr;
    resLevel.className = `level-pill level-${data.risk_level || "low"}`;

    resBar.style.width = `${data.risk_score ?? 0}%`;
    const barColors = {
      SAFE: "var(--safe-bar)",
      safe: "var(--safe-bar)",
      LOW: "var(--low-bar)",
      low: "var(--low-bar)",
      MEDIUM: "var(--medium-bar)",
      medium: "var(--medium-bar)",
      HIGH: "var(--high-bar)",
      high: "var(--high-bar)",
      CRITICAL: "var(--critical-bar)",
      critical: "var(--critical-bar)"
    };
    const activeColor = barColors[data.risk_level] || "var(--safe-bar)";
    resBar.style.backgroundColor = activeColor;

    const resultCard = resultContainer.querySelector(".result-card");
    if (resultCard) {
      resultCard.style.borderLeftColor = activeColor;
    }

    const fallbackExp = data.evidence?.length
      ? `${(data.risk_level || "ALERT").toUpperCase()} Risk: Detected ${data.evidence.length} threat indicator(s), including ${data.evidence[0].reason || data.evidence[0].description || "heuristic pattern match"}.`
      : "No suspicious indicators detected.";
    resExplanation.textContent = data.explanation || fallbackExp;

    // Render Evidence
    resEvidence.replaceChildren();
    const evidenceList = (data.indicators || data.evidence || []).filter(
      (ev) => ev && typeof ev === "object" && (String(ev.description || ev.reason || "").trim() || String(ev.indicator_type || ev.category || "").trim())
    );
    const validSeverities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
    if (evidenceList.length > 0) {
      evidenceList.forEach((ev) => {
        const li = document.createElement("li");
        li.className = "evidence-item";
        const rawSev = (ev.severity || "medium").toUpperCase();
        const sev = validSeverities.includes(rawSev) ? rawSev : "MEDIUM";

        const badge = document.createElement("span");
        badge.className = `sev-badge sev-${sev}`;
        badge.textContent = sev;

        const text = document.createElement("span");
        text.textContent = ev.description || ev.reason || "";

        li.appendChild(badge);
        li.appendChild(text);
        resEvidence.appendChild(li);
      });
    } else {
      const li = document.createElement("li");
      li.className = "evidence-item";

      const badge = document.createElement("span");
      badge.className = "sev-badge";
      badge.style.background = "#DCFCE7";
      badge.style.color = "#166534";
      badge.textContent = "CLEAN";

      const text = document.createElement("span");
      text.style.color = "#166534";
      text.textContent = "No scam or phishing signals found. Domain structure and security appear standard.";

      li.appendChild(badge);
      li.appendChild(text);
      resEvidence.appendChild(li);
    }

    // Render Recommendations
    resRecs.replaceChildren();
    const recs = data.recommended_actions || data.recommendations || [];
    if (recs.length > 0) {
      recs.forEach((rec) => {
        const li = document.createElement("li");
        li.textContent = rec;
        resRecs.appendChild(li);
      });
    } else {
      const li = document.createElement("li");
      li.textContent = "Stay alert when entering passwords or payment credentials.";
      resRecs.appendChild(li);
    }

    // Feedback visibility
    feedbackBlock.classList.toggle("hidden", !currentScanId);

    resultContainer.classList.remove("hidden");
  }

  // 4. Feedback Submission
  fbBtns.forEach((btn) => {
    btn.addEventListener("click", async () => {
      if (!currentScanId) return;
      try {
        const type = btn.dataset.fb;
        await ScamApi.submitFeedback(currentScanId, type);
        btn.textContent = "✓ Recorded";
        btn.disabled = true;
      } catch (err) {
        alert(err.message);
      }
    });
  });

  // 5. History Loading
  btnRefreshHistory.addEventListener("click", loadScanHistory);

  async function loadScanHistory() {
    const session = await ScamStorage.getSession();
    const localScans = typeof ScamStorage.getLocalHistory === "function" ? await ScamStorage.getLocalHistory() : [];
    const renderHistoryItems = (items) => {
      historyContainer.replaceChildren();
      const validLevels = ["safe", "low", "medium", "high", "critical"];
      items.forEach((s) => {
        const div = document.createElement("div");
        div.className = "history-item";

        const textWrap = document.createElement("div");
        const titleDiv = document.createElement("div");
        titleDiv.className = "history-content";
        titleDiv.textContent = s.submitted_content || s.normalized_domain || "Scan";

        const subDiv = document.createElement("div");
        subDiv.className = "history-sub";
        const safeType = (s.scan_type || "scan").toUpperCase();
        subDiv.textContent = `${safeType} · ${new Date(s.created_at).toLocaleDateString()}`;

        textWrap.appendChild(titleDiv);
        textWrap.appendChild(subDiv);

        const pill = document.createElement("span");
        const rawLevel = (s.risk_level || "low").toLowerCase();
        const level = validLevels.includes(rawLevel) ? rawLevel : "low";
        pill.className = `level-pill level-${level}`;
        pill.textContent = String(s.risk_score ?? 0);

        div.appendChild(textWrap);
        div.appendChild(pill);

        div.addEventListener("click", () => {
          renderScanResult({
            ...s,
            label: `${safeType} Record`
          });
          document.querySelector('[data-tab="tab-scan"]')?.click();
        });
        historyContainer.appendChild(div);
      });
    };

    if (!session?.access_token) {
      if (localScans.length > 0) {
        renderHistoryItems(localScans);
        return;
      }
      historyContainer.innerHTML = `
        <div class="empty-state">
          <p>Sign in to sync your scan history across devices and the web dashboard.</p>
          <button class="btn btn-ghost mt-2" id="btn-go-auth">Sign In / Register</button>
        </div>
      `;
      document.getElementById("btn-go-auth")?.addEventListener("click", () => {
        document.querySelector('[data-tab="tab-account"]')?.click();
      });
      return;
    }

    historyContainer.replaceChildren();
    const loadingP = document.createElement("p");
    loadingP.className = "empty-state";
    loadingP.textContent = "Loading scans…";
    historyContainer.appendChild(loadingP);

    try {
      const { scans } = await ScamApi.getHistory(20, 0);
      const combined = scans && scans.length > 0 ? scans : localScans;
      if (!combined || combined.length === 0) {
        historyContainer.replaceChildren();
        const emptyP = document.createElement("p");
        emptyP.className = "empty-state";
        emptyP.textContent = "No saved scans yet.";
        historyContainer.appendChild(emptyP);
        return;
      }

      renderHistoryItems(combined);
    } catch (err) {
      if (localScans.length > 0 && !/unauthorized|expired|401|session/i.test(err.message)) {
        renderHistoryItems(localScans);
        return;
      }
      historyContainer.replaceChildren();
      const isAuthErr = /unauthorized|expired|401|session/i.test(err.message);
      const errWrap = document.createElement("div");
      errWrap.className = "empty-state";

      const errP = document.createElement("p");
      errP.className = isAuthErr ? "empty-state" : "empty-state error-text";
      errP.textContent = isAuthErr
        ? "Session expired. Please sign in again to sync your scan history."
        : `Unable to load history (${err.message})`;
      errWrap.appendChild(errP);

      if (isAuthErr) {
        const reAuthBtn = document.createElement("button");
        reAuthBtn.className = "btn btn-ghost mt-2";
        reAuthBtn.textContent = "Sign In Again";
        reAuthBtn.addEventListener("click", () => {
          document.querySelector('[data-tab="tab-account"]')?.click();
        });
        errWrap.appendChild(reAuthBtn);
      }

      historyContainer.appendChild(errWrap);
    }
  }

  // 6. Authentication Handling
  toggleLoginBtn.addEventListener("click", () => {
    isRegisterMode = false;
    toggleLoginBtn.classList.add("active");
    toggleRegisterBtn.classList.remove("active");
    fieldNameWrap.classList.add("hidden");
    btnAuthSubmit.textContent = "Sign In";
    authError.classList.add("hidden");
    authSuccess.classList.add("hidden");
  });

  toggleRegisterBtn.addEventListener("click", () => {
    isRegisterMode = true;
    toggleRegisterBtn.classList.add("active");
    toggleLoginBtn.classList.remove("active");
    fieldNameWrap.classList.remove("hidden");
    btnAuthSubmit.textContent = "Create Account";
    authError.classList.add("hidden");
    authSuccess.classList.add("hidden");
  });

  formAuth.addEventListener("submit", async (e) => {
    e.preventDefault();
    authError.classList.add("hidden");
    authSuccess.classList.add("hidden");
    btnAuthSubmit.disabled = true;

    const email = authEmail.value.trim();
    const password = authPassword.value;
    const name = authName.value.trim();

    try {
      if (isRegisterMode) {
        await ScamAuth.signUp(email, password, name);
        authSuccess.textContent = "Account registered! Check email if verification is required.";
        authSuccess.classList.remove("hidden");
      } else {
        await ScamAuth.signIn(email, password);
      }
      await checkAuthStatus();
    } catch (err) {
      authError.textContent = err.message;
      authError.classList.remove("hidden");
    } finally {
      btnAuthSubmit.disabled = false;
    }
  });

  // Forgot password handlers
  btnForgotPasswordLink?.addEventListener("click", () => {
    formAuth.classList.add("hidden");
    authForgotPanel?.classList.remove("hidden");
    if (authEmail.value && forgotEmail) {
      forgotEmail.value = authEmail.value;
    }
    forgotError?.classList.add("hidden");
    forgotSuccess?.classList.add("hidden");
  });

  btnBackToLogin?.addEventListener("click", () => {
    authForgotPanel?.classList.add("hidden");
    formAuth.classList.remove("hidden");
    forgotError?.classList.add("hidden");
    forgotSuccess?.classList.add("hidden");
  });

  btnSendResetCode?.addEventListener("click", async () => {
    const email = forgotEmail?.value.trim() || "";
    forgotError?.classList.add("hidden");
    forgotSuccess?.classList.add("hidden");
    if (btnSendResetCode) btnSendResetCode.disabled = true;
    try {
      if (!email) throw new Error("Please enter your registered email address.");
      const res = await ScamAuth.requestPasswordReset(email);
      if (forgotSuccess) {
        forgotSuccess.textContent = res?.emailDispatched
          ? "Verification code dispatched to your email inbox."
          : "Verification code generated locally (start mail-service for email delivery).";
        forgotSuccess.classList.remove("hidden");
      }
    } catch (err) {
      if (forgotError) {
        forgotError.textContent = err.message;
        forgotError.classList.remove("hidden");
      }
    } finally {
      if (btnSendResetCode) btnSendResetCode.disabled = false;
    }
  });

  btnSubmitForgot?.addEventListener("click", async () => {
    const email = forgotEmail?.value.trim() || "";
    const code = forgotCode?.value.trim() || "";
    const newPass = forgotNewPassword?.value || "";
    forgotError?.classList.add("hidden");
    forgotSuccess?.classList.add("hidden");
    if (btnSubmitForgot) btnSubmitForgot.disabled = true;

    try {
      if (!email) throw new Error("Please enter your registered email address.");
      if (!/^\d{6}$/.test(code)) throw new Error("Please enter the 6-digit verification code.");
      if (!newPass || newPass.length < 6) throw new Error("New password must be at least 6 characters.");

      await ScamAuth.resetPassword(email, newPass, code);
      if (forgotSuccess) {
        forgotSuccess.textContent = "Password updated successfully! Signing you in…";
        forgotSuccess.classList.remove("hidden");
      }

      setTimeout(async () => {
        authForgotPanel?.classList.add("hidden");
        formAuth.classList.remove("hidden");
        await checkAuthStatus();
      }, 1000);
    } catch (err) {
      if (forgotError) {
        forgotError.textContent = err.message;
        forgotError.classList.remove("hidden");
      }
    } finally {
      if (btnSubmitForgot) btnSubmitForgot.disabled = false;
    }
  });

  btnLogout.addEventListener("click", async () => {
    await ScamAuth.signOut();
    await checkAuthStatus();
  });

  async function checkAuthStatus() {
    const session = typeof ScamAuth.getValidSession === "function"
      ? await ScamAuth.getValidSession()
      : await ScamStorage.getSession();
    if (session?.user) {
      authForms.classList.add("hidden");
      authProfile.classList.remove("hidden");
      profileName.textContent = session.user.user_metadata?.full_name || session.user.email.split("@")[0];
      profileEmail.textContent = session.user.email;
      userStatusBtn.textContent = profileName.textContent;
      userStatusBtn.classList.add("signed-in");
    } else {
      authForms.classList.remove("hidden");
      authProfile.classList.add("hidden");
      userStatusBtn.textContent = "Guest";
      userStatusBtn.classList.remove("signed-in");
    }
  }

  // 7. Settings Handling
  btnSaveSettings.addEventListener("click", async () => {
    const newEngine = settingEngine.value;
    const allowAi = settingAllowAi.checked;
    const saveHist = settingSaveHistory.checked;
    const newUrl = settingSupabaseUrl.value.trim();
    const newAnonKey = settingSupabaseAnonKey ? settingSupabaseAnonKey.value.trim() : "";
    const newDashUrl = settingDashboardUrl ? settingDashboardUrl.value.trim() : "";

    if (newDashUrl && !isValidDashboardUrl(newDashUrl)) {
      alert("Invalid Dashboard URL: Address must start with http:// or https:// (e.g. http://localhost:5173)");
      return;
    }
    const safeDashUrl = newDashUrl || "http://localhost:5173";
    const experimentalMl = settingExperimentalMl ? settingExperimentalMl.checked : false;

    await ScamStorage.setPreferences({
      engine_mode: newEngine,
      allow_ai: allowAi,
      save_history: saveHist,
      experimental_ml: experimentalMl,
      dashboard_url: safeDashUrl
    });

    if (linkDashProfile) linkDashProfile.href = safeDashUrl;
    if (linkDashFooter) linkDashFooter.href = safeDashUrl;

    if (newUrl || newAnonKey) {
      const storageUpdates = {};
      if (newUrl) storageUpdates.supabase_url = newUrl;
      if (newAnonKey) storageUpdates.supabase_anon_key = newAnonKey;
      await ScamStorage.set(storageUpdates);
      ScamAuth.init(newUrl || settingSupabaseUrl.value, newAnonKey || ScamAuth.supabaseAnonKey);
      if (newUrl) ScamApi.init(`${newUrl}/functions/v1`);
    }

    updateEngineBadge(newEngine);
    updateMLStatusUI({ engine_mode: newEngine, allow_ai: allowAi, save_history: saveHist, experimental_ml: experimentalMl });
    alert("Preferences saved successfully!");
  });

  function updateEngineBadge(mode) {
    if (mode === "server") {
      engineBadge.textContent = "🌐 Cloud Hybrid";
      engineBadge.style.color = "#34d399";
      engineBadge.style.background = "rgba(16, 185, 129, 0.15)";
      engineBadge.style.borderColor = "rgba(16, 185, 129, 0.35)";
    } else {
      engineBadge.textContent = "⚡ Local Engine";
      engineBadge.style.color = "#38bdf8";
      engineBadge.style.background = "rgba(6, 182, 212, 0.12)";
      engineBadge.style.borderColor = "rgba(6, 182, 212, 0.3)";
    }
  }

  function escapeHtml(str) {
    return (str || "").replace(/[&<>'"]/g, (tag) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      "'": "&#39;",
      '"': "&quot;"
    }[tag] || tag));
  }
});
