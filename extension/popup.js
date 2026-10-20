// ScamShield Full-Stack Popup Controller
document.addEventListener("DOMContentLoaded", async () => {
  let activeTabUrl = "";
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

  // Result elements
  const resultContainer = document.getElementById("result-container");
  const resType = document.getElementById("res-type");
  const resMethod = document.getElementById("res-method");
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
  const forgotNewPassword = document.getElementById("forgot-new-password");
  const forgotError = document.getElementById("forgot-error");
  const forgotSuccess = document.getElementById("forgot-success");
  const btnSubmitForgot = document.getElementById("btn-submit-forgot");
  const btnBackToLogin = document.getElementById("btn-back-to-login");

  // Settings elements
  const settingEngine = document.getElementById("setting-engine");
  const settingSupabaseUrl = document.getElementById("setting-supabase-url");
  const settingDashboardUrl = document.getElementById("setting-dashboard-url");
  const settingAllowAi = document.getElementById("setting-allow-ai");
  const settingSaveHistory = document.getElementById("setting-save-history");
  const btnSaveSettings = document.getElementById("btn-save-settings");
  const linkDashProfile = document.getElementById("link-dashboard-profile");
  const linkDashFooter = document.getElementById("link-dashboard-footer");

  let isRegisterMode = false;

  // 1. Initial State Loading
  const prefs = await ScamStorage.getPreferences();
  settingEngine.value = prefs.engine_mode || "offline";
  settingAllowAi.checked = prefs.allow_ai !== false;
  settingSaveHistory.checked = prefs.save_history !== false;

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

  const { supabase_url } = await ScamStorage.get("supabase_url");
  const activeSupabaseUrl = supabase_url || "https://twrdubnndhgbqlaeeabl.supabase.co";
  settingSupabaseUrl.value = activeSupabaseUrl;
  const activeAnonKey = ScamAuth.supabaseAnonKey === "your-anon-key"
    ? "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InR3cmR1Ym5uZGhnYnFsYWVlYWJsIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzM2NjM2MzgsImV4cCI6MjA4OTIzOTYzOH0.fEcGaBRyXY1ke8byd74XddM0zmBWQ5FWyH4u8eJgTs0"
    : ScamAuth.supabaseAnonKey;
  ScamAuth.init(activeSupabaseUrl, activeAnonKey);
  ScamApi.init(`${activeSupabaseUrl}/functions/v1`);

  updateEngineBadge(prefs.engine_mode || "offline");
  await checkAuthStatus();

  // Load active tab URL
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs && tabs[0]?.url) {
      activeTabUrl = tabs[0].url;
      pageUrlBox.textContent = activeTabUrl;
    } else {
      pageUrlBox.textContent = "Unable to read active tab URL.";
      btnScanCurrent.disabled = true;
    }
  } catch {
    pageUrlBox.textContent = "Tab permission unavailable.";
  }

  // Restore previous scan if present
  const { lastScan } = await ScamStorage.get("lastScan");
  if (lastScan) renderScanResult(lastScan);

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

  // 3. Scanner Actions
  btnScanCurrent.addEventListener("click", async () => {
    if (!activeTabUrl) return;
    await executeScan("url", activeTabUrl, "Active Page");
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

    const offline = ScamEngine.scanEmail(sender, subject, body);
    const scanData = {
      risk_score: offline.risk_score,
      risk_level: offline.risk_level.toLowerCase(),
      detection_method: "rules",
      explanation: offline.risk_score >= 50
        ? "Phishing indicators detected in email headers, sender address, or message body."
        : "Standard legitimate email without deceptive indicators.",
      indicators: offline.evidence.map((e) => ({
        indicator_type: e.category,
        description: e.reason,
        severity: e.severity.toLowerCase()
      })),
      recommended_actions: offline.recommendations,
      label: "Email Security Audit",
      input_type: "email",
      submitted_content: `${sender}: ${subject}`
    };

    await ScamStorage.set({ lastScan: scanData });
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
      engineMode: currentPrefs.engine_mode
    });

    const scanData = {
      ...result,
      label: "Payment Scam Check",
      input_type: payType,
      submitted_content: val
    };

    await ScamStorage.set({ lastScan: scanData });
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
    await ScamStorage.remove("lastScan");
  });

  async function executeScan(type, content, label) {
    const currentPrefs = await ScamStorage.getPreferences();
    const result = await ScamApi.scan({
      content,
      type,
      allowAi: currentPrefs.allow_ai,
      engineMode: currentPrefs.engine_mode
    });

    currentScanId = result.scan_id || null;
    const scanData = {
      ...result,
      input_type: type,
      label,
      content_preview: content.slice(0, 150)
    };

    await ScamStorage.set({ lastScan: scanData });
    renderScanResult(scanData);
  }

  function renderScanResult(data) {
    resType.textContent = data.label || (data.input_type === "url" ? "URL Scan" : "Message Scan");
    resMethod.textContent = (data.detection_method || "rules").toUpperCase();
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

    resExplanation.textContent = data.explanation || "No suspicious indicators detected.";

    // Render Evidence
    resEvidence.replaceChildren();
    const evidenceList = data.indicators || data.evidence || [];
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
    if (!session?.access_token) {
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
      if (!scans || scans.length === 0) {
        historyContainer.replaceChildren();
        const emptyP = document.createElement("p");
        emptyP.className = "empty-state";
        emptyP.textContent = "No saved scans yet.";
        historyContainer.appendChild(emptyP);
        return;
      }

      historyContainer.replaceChildren();
      const validLevels = ["safe", "low", "medium", "high", "critical"];

      scans.forEach((s) => {
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
    } catch (err) {
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

  btnSubmitForgot?.addEventListener("click", async () => {
    const email = forgotEmail?.value.trim() || "";
    const newPass = forgotNewPassword?.value || "";
    forgotError?.classList.add("hidden");
    forgotSuccess?.classList.add("hidden");
    if (btnSubmitForgot) btnSubmitForgot.disabled = true;

    try {
      if (!email) throw new Error("Please enter your registered email address.");
      if (!newPass || newPass.length < 6) throw new Error("New password must be at least 6 characters.");

      await ScamAuth.resetPassword(email, newPass);
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
    const session = await ScamStorage.getSession();
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
    const newDashUrl = settingDashboardUrl ? settingDashboardUrl.value.trim() : "";

    if (newDashUrl && !isValidDashboardUrl(newDashUrl)) {
      alert("Invalid Dashboard URL: Address must start with http:// or https:// (e.g. http://localhost:5173)");
      return;
    }
    const safeDashUrl = newDashUrl || "http://localhost:5173";

    await ScamStorage.setPreferences({
      engine_mode: newEngine,
      allow_ai: allowAi,
      save_history: saveHist,
      dashboard_url: safeDashUrl
    });

    if (linkDashProfile) linkDashProfile.href = safeDashUrl;
    if (linkDashFooter) linkDashFooter.href = safeDashUrl;

    if (newUrl) {
      await ScamStorage.set({ supabase_url: newUrl });
      ScamAuth.init(newUrl, ScamAuth.supabaseAnonKey);
      ScamApi.init(`${newUrl}/functions/v1`);
    }

    updateEngineBadge(newEngine);
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
