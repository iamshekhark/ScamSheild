// ScamShield Extension API Service Layer
// Bridges between Extension UI, Offline Rules Engine, and Supabase Edge Functions

function getEngine() {
  if (typeof ScamEngine !== "undefined") return ScamEngine;
  if (typeof require === "function") return require("./rules");
  return null;
}

function getStorage() {
  if (typeof ScamStorage !== "undefined") return ScamStorage;
  if (typeof require === "function") return require("./storage");
  return null;
}

function getAuth() {
  if (typeof ScamAuth !== "undefined") return ScamAuth;
  if (typeof require === "function") return require("./auth");
  return null;
}

const ScamApi = {
  functionsBaseUrl: "https://your-supabase-project.supabase.co/functions/v1",

  init(functionsUrl) {
    if (functionsUrl) this.functionsBaseUrl = functionsUrl.replace(/\/$/, "");
  },

  async scan({ content, type = "url", allowAi = true, engineMode = "offline" }) {
    const engine = getEngine();

    // 1. If configured to run offline or network unavailable, use built-in engine
    if (engineMode === "offline" || !engine) {
      const result = type === "url" ? engine?.scanUrl(content) : engine?.scanText(content);
      return {
        ...result,
        detection_method: "rules",
        is_offline: true
      };
    }

    // 2. Server API request
    try {
      const storage = getStorage();
      const auth = getAuth();
      const session = storage ? await storage.getSession() : null;
      const headers = {
        "Content-Type": "application/json",
        "apikey": auth?.supabaseAnonKey || ""
      };
      if (session?.access_token) {
        headers["Authorization"] = `Bearer ${session.access_token}`;
      }

      const res = await fetch(`${this.functionsBaseUrl}/analyze-scam`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          content,
          scan_type: type,
          allow_ai: allowAi
        })
      });

      if (!res.ok) {
        throw new Error(`Server returned status ${res.status}`);
      }

      return await res.json();
    } catch (err) {
      console.warn("Server analysis unavailable, falling back to local engine:", err);
      // Graceful fallback to local engine
      const local = type === "url" ? engine.scanUrl(content) : engine.scanText(content);
      return {
        ...local,
        detection_method: "rules",
        is_fallback: true
      };
    }
  },

  async verifyPayment({ content, type = "upi_id", allowAi = true, engineMode = "offline" }) {
    const engine = getEngine();

    if (engineMode === "offline" || !engine) {
      const result = engine?.scanPayment(content, type);
      return {
        ...result,
        detection_method: "rules",
        is_offline: true
      };
    }

    try {
      const storage = getStorage();
      const auth = getAuth();
      const session = storage ? await storage.getSession() : null;
      const headers = {
        "Content-Type": "application/json",
        "apikey": auth?.supabaseAnonKey || ""
      };
      if (session?.access_token) {
        headers["Authorization"] = `Bearer ${session.access_token}`;
      }

      const res = await fetch(`${this.functionsBaseUrl}/verify-payment-risk`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          content,
          input_type: type,
          allow_ai: allowAi
        })
      });

      if (!res.ok) throw new Error(`Server returned ${res.status}`);
      return await res.json();
    } catch (err) {
      console.warn("Payment verification backend unavailable, falling back to local engine:", err);
      const local = engine.scanPayment(content, type);
      return {
        ...local,
        detection_method: "rules",
        is_fallback: true
      };
    }
  },

  async getHistory(limit = 20, offset = 0, riskLevel = "all") {
    const session = await ScamStorage.getSession();
    if (!session?.access_token) return { scans: [], total: 0 };

    const res = await fetch(
      `${this.functionsBaseUrl}/get-scan-history?limit=${limit}&offset=${offset}&risk_level=${riskLevel}`,
      {
        headers: {
          "Authorization": `Bearer ${session.access_token}`,
          "apikey": ScamAuth.supabaseAnonKey
        }
      }
    );

    if (!res.ok) throw new Error("Failed to fetch scan history");
    return await res.json();
  },

  async submitFeedback(scanId, feedbackType, comment = "") {
    const session = await ScamStorage.getSession();
    if (!session?.access_token) throw new Error("Must be logged in to submit feedback");

    const res = await fetch(`${this.functionsBaseUrl}/submit-feedback`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${session.access_token}`,
        "apikey": ScamAuth.supabaseAnonKey
      },
      body: JSON.stringify({ scan_id: scanId, feedback_type: feedbackType, comment })
    });

    if (!res.ok) throw new Error("Failed to record feedback");
    return await res.json();
  }
};

if (typeof module !== "undefined" && module.exports) {
  module.exports = ScamApi;
}
