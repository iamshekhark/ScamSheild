// ScamShield Secure Local Storage Wrapper
// Safely stores session credentials and local user preferences without exposing passwords.

const ScamStorage = {
  async get(keys) {
    return new Promise((resolve) => {
      chrome.storage.local.get(keys, (result) => resolve(result || {}));
    });
  },

  async set(items) {
    return new Promise((resolve) => {
      chrome.storage.local.set(items, () => resolve());
    });
  },

  async remove(keys) {
    return new Promise((resolve) => {
      chrome.storage.local.remove(keys, () => resolve());
    });
  },

  async clearSession() {
    await this.remove(["session", "user_profile", "lastScan"]);
  },

  async getSession() {
    const { session } = await this.get("session");
    return session || null;
  },

  async setSession(session) {
    await this.set({ session });
  },

  async getPreferences() {
    const { preferences } = await this.get("preferences");
    return preferences || {
      save_history: true,
      allow_ai: true,
      engine_mode: "offline", // 'offline' or 'server'
      dashboard_url: "http://localhost:5173"
    };
  },

  async setPreferences(preferences) {
    await this.set({ preferences });
  }
};

if (typeof module !== "undefined" && module.exports) {
  module.exports = ScamStorage;
}
