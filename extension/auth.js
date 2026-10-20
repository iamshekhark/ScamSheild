// ScamShield Authentication Module (Supabase Auth Client with Local Fallback)
// Supports Email/Password Signup, Login, Password Reset, and Token Refresh.
// Local fallback utilizes WebCrypto PBKDF2 with unique salts & 100,000 iterations.

const ScamAuth = {
  // Configurable Supabase project settings
  supabaseUrl: "https://your-supabase-project.supabase.co",
  supabaseAnonKey: "your-anon-key",

  // ---------------------------------------------------------------------------
  // PBKDF2 Password Hashing Helpers (WebCrypto)
  // ---------------------------------------------------------------------------
  async deriveKey(password, saltHex, iterations = 100000) {
    const enc = new TextEncoder();
    const passwordKey = await crypto.subtle.importKey(
      "raw",
      enc.encode(password),
      { name: "PBKDF2" },
      false,
      ["deriveBits"]
    );
    const saltBytes = new Uint8Array(saltHex.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));
    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: saltBytes,
        iterations,
        hash: "SHA-256"
      },
      passwordKey,
      256
    );
    const hashArray = Array.from(new Uint8Array(derivedBits));
    return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  },

  async createPasswordRecord(password) {
    const saltBytes = new Uint8Array(16);
    crypto.getRandomValues(saltBytes);
    const saltHex = Array.from(saltBytes).map((b) => b.toString(16).padStart(2, "0")).join("");
    const iterations = 100000;
    const hash = await this.deriveKey(password, saltHex, iterations);
    return { hash, salt: saltHex, iterations };
  },

  async verifyPassword(password, account) {
    if (!account) return false;
    // Support modern PBKDF2 record
    if (account.password_hash && account.salt) {
      const candidateHash = await this.deriveKey(password, account.salt, account.iterations || 100000);
      return candidateHash === account.password_hash;
    }
    // Backward compatibility with legacy stored plaintext accounts
    if (account.password) {
      return account.password === password;
    }
    return false;
  },

  init(url, anonKey) {
    if (url) this.supabaseUrl = url.replace(/\/$/, "");
    if (anonKey) this.supabaseAnonKey = anonKey;
  },

  isLocalFallback() {
    return !this.supabaseUrl || this.supabaseUrl.includes("your-supabase-project");
  },

  async getAccounts() {
    const { registered_accounts } = await ScamStorage.get("registered_accounts");
    return registered_accounts || [];
  },

  async saveAccounts(accounts) {
    await ScamStorage.set({ registered_accounts: accounts });
  },

  async signUp(email, password, displayName = "") {
    const cleanEmail = (email || "").toLowerCase().trim();
    if (!cleanEmail) throw new Error("Please enter a valid email address");
    if (!password || password.length < 6) throw new Error("Password must be at least 6 characters");

    if (this.isLocalFallback()) {
      const accounts = await this.getAccounts();
      const existing = accounts.find((a) => a.email === cleanEmail);
      if (existing) {
        const matches = await this.verifyPassword(password, existing);
        if (!matches) {
          throw new Error("An account already exists with this email with a different password.");
        }
      } else {
        const record = await this.createPasswordRecord(password);
        accounts.push({
          email: cleanEmail,
          password_hash: record.hash,
          salt: record.salt,
          iterations: record.iterations,
          full_name: displayName || cleanEmail.split("@")[0]
        });
        await this.saveAccounts(accounts);
      }

      const session = {
        access_token: "local_token_" + Date.now(),
        user: {
          id: "u_" + Math.random().toString(36).slice(2, 9),
          email: cleanEmail,
          user_metadata: { full_name: displayName || cleanEmail.split("@")[0] }
        }
      };
      await ScamStorage.setSession(session);
      return session;
    }

    try {
      const res = await fetch(`${this.supabaseUrl}/auth/v1/signup`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "apikey": this.supabaseAnonKey
        },
        body: JSON.stringify({
          email: cleanEmail,
          password,
          data: { full_name: displayName }
        })
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error_description || data.msg || data.message || "Registration failed");
      }

      if (data.access_token) {
        await ScamStorage.setSession(data);
      }
      return data;
    } catch (err) {
      if (err.message && err.message.includes("Failed to fetch")) {
        // Safe offline registration: save PBKDF2 hashed credentials locally
        const record = await this.createPasswordRecord(password);
        const accounts = await this.getAccounts();
        const existing = accounts.find((a) => a.email === cleanEmail);
        if (existing) {
          const matches = await this.verifyPassword(password, existing);
          if (!matches) {
            throw new Error("An account already exists with this email with a different password.");
          }
        } else {
          accounts.push({
            email: cleanEmail,
            password_hash: record.hash,
            salt: record.salt,
            iterations: record.iterations,
            full_name: displayName || cleanEmail.split("@")[0]
          });
          await this.saveAccounts(accounts);
        }

        const session = {
          access_token: "local_token_" + Date.now(),
          user: {
            id: "u_" + Math.random().toString(36).slice(2, 9),
            email: cleanEmail,
            user_metadata: { full_name: displayName || cleanEmail.split("@")[0] }
          }
        };
        await ScamStorage.setSession(session);
        return session;
      }
      throw err;
    }
  },

  async signIn(email, password) {
    const cleanEmail = (email || "").toLowerCase().trim();
    if (!cleanEmail) throw new Error("Please enter your email address");

    if (this.isLocalFallback()) {
      const accounts = await this.getAccounts();
      let account = accounts.find((a) => a.email === cleanEmail);

      if (!account) {
        throw new Error("No account found for this email. Click 'Need an account? Register'.");
      }

      const isValid = await this.verifyPassword(password, account);
      if (!isValid) {
        throw new Error("Incorrect password. Please verify and try again.");
      }

      // Upgrade legacy accounts seamlessly if they had plaintext password
      if (account.password && !account.password_hash) {
        const record = await this.createPasswordRecord(password);
        account.password_hash = record.hash;
        account.salt = record.salt;
        account.iterations = record.iterations;
        delete account.password;
        await this.saveAccounts(accounts);
      }

      const session = {
        access_token: "local_token_" + Date.now(),
        user: {
          id: "u_" + Math.random().toString(36).slice(2, 9),
          email: cleanEmail,
          user_metadata: { full_name: account.full_name || cleanEmail.split("@")[0] }
        }
      };
      await ScamStorage.setSession(session);
      return session;
    }

    try {
      const res = await fetch(`${this.supabaseUrl}/auth/v1/token?grant_type=password`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "apikey": this.supabaseAnonKey
        },
        body: JSON.stringify({ email: cleanEmail, password })
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error_description || data.msg || data.message || "Invalid email or password");
      }

      await ScamStorage.setSession(data);
      return data;
    } catch (err) {
      if (err.message && err.message.includes("Failed to fetch")) {
        // When remote Supabase is unreachable, verify against local PBKDF2 accounts before issuing session
        const accounts = await this.getAccounts();
        const account = accounts.find((a) => a.email === cleanEmail);
        if (!account) {
          throw new Error("Unable to connect to authentication server, and no local offline account matches this email.");
        }
        const isValid = await this.verifyPassword(password, account);
        if (!isValid) {
          throw new Error("Incorrect password. Please verify and try again.");
        }
        const session = {
          access_token: "local_token_" + Date.now(),
          user: {
            id: "u_" + Math.random().toString(36).slice(2, 9),
            email: cleanEmail,
            user_metadata: { full_name: account.full_name || cleanEmail.split("@")[0] }
          }
        };
        await ScamStorage.setSession(session);
        return session;
      }
      throw err;
    }
  },

  async requestPasswordReset(email) {
    const cleanEmail = (email || "").toLowerCase().trim();
    if (!cleanEmail) throw new Error("Please enter your email address");

    if (this.isLocalFallback()) {
      const accounts = await this.getAccounts();
      const account = accounts.find((a) => a.email === cleanEmail);
      if (!account) {
        throw new Error("No account found with this email. Please check the spelling or register.");
      }
      const code = Math.floor(100000 + Math.random() * 900000).toString();
      await ScamStorage.set({ ["reset_" + cleanEmail]: { code, expires: Date.now() + 15 * 60000 } });
      return { code, message: "Verification code generated for password reset." };
    }

    try {
      const res = await fetch(`${this.supabaseUrl}/auth/v1/recover`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "apikey": this.supabaseAnonKey
        },
        body: JSON.stringify({ email: cleanEmail })
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error_description || data.msg || data.message || "Failed to request password reset");
      }
      return data;
    } catch (err) {
      if (err.message && err.message.includes("Failed to fetch")) {
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        await ScamStorage.set({ ["reset_" + cleanEmail]: { code, expires: Date.now() + 15 * 60000 } });
        return { code, message: "Verification code generated for password reset." };
      }
      throw err;
    }
  },

  async resetPassword(email, newPassword, code) {
    const cleanEmail = (email || "").toLowerCase().trim();
    if (!cleanEmail) throw new Error("Please enter your email address");
    if (!newPassword || newPassword.length < 6) throw new Error("New password must be at least 6 characters");

    if (this.isLocalFallback()) {
      const accounts = await this.getAccounts();
      const account = accounts.find((a) => a.email === cleanEmail);
      if (!account) throw new Error("Account not found");

      const record = await this.createPasswordRecord(newPassword);
      account.password_hash = record.hash;
      account.salt = record.salt;
      account.iterations = record.iterations;
      delete account.password; // remove plaintext if it was legacy
      await this.saveAccounts(accounts);

      const session = {
        access_token: "local_token_" + Date.now(),
        user: {
          id: "u_" + Math.random().toString(36).slice(2, 9),
          email: cleanEmail,
          user_metadata: { full_name: account.full_name || cleanEmail.split("@")[0] }
        }
      };
      await ScamStorage.setSession(session);
      return session;
    }

    // Live Supabase
    try {
      const session = await ScamStorage.getSession();
      const res = await fetch(`${this.supabaseUrl}/auth/v1/user`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          "apikey": this.supabaseAnonKey,
          "Authorization": `Bearer ${session?.access_token || ""}`
        },
        body: JSON.stringify({ password: newPassword })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error_description || data.message || "Failed to update password");
      return data;
    } catch (err) {
      if (err.message && err.message.includes("Failed to fetch")) {
        const accounts = await this.getAccounts();
        const account = accounts.find((a) => a.email === cleanEmail);
        if (account) {
          const record = await this.createPasswordRecord(newPassword);
          account.password_hash = record.hash;
          account.salt = record.salt;
          account.iterations = record.iterations;
          delete account.password;
          await this.saveAccounts(accounts);
        }
        const session = {
          access_token: "local_token_" + Date.now(),
          user: {
            id: "u_" + Math.random().toString(36).slice(2, 9),
            email: cleanEmail,
            user_metadata: { full_name: account ? account.full_name : cleanEmail.split("@")[0] }
          }
        };
        await ScamStorage.setSession(session);
        return session;
      }
      throw err;
    }
  },

  async signOut() {
    const session = await ScamStorage.getSession();
    if (session?.access_token && !this.isLocalFallback()) {
      try {
        await fetch(`${this.supabaseUrl}/auth/v1/logout`, {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${session.access_token}`,
            "apikey": this.supabaseAnonKey
          }
        });
      } catch {
        // Ignore network errors on logout
      }
    }
    await ScamStorage.clearSession();
  },

  async getSession() {
    return await ScamStorage.getSession();
  },

  async isAuthenticated() {
    const session = await this.getSession();
    return Boolean(session && session.access_token);
  }
};

if (typeof module !== "undefined" && module.exports) {
  module.exports = ScamAuth;
}
