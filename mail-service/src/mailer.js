// Nodemailer SMTP Transporter Wrapper with Timeouts, Input Validation, and Resilience

const nodemailer = require("nodemailer");

class MailerService {
  constructor(config = {}) {
    this.host = config.host || process.env.SMTP_HOST || "";
    this.port = parseInt(config.port || process.env.SMTP_PORT || "587", 10);
    this.secure = config.secure ?? (process.env.SMTP_SECURE === "true" || this.port === 465);
    this.user = config.user || process.env.SMTP_USER || "";
    this.pass = config.pass || process.env.SMTP_PASS || "";
    this.from = config.from || process.env.FROM_EMAIL || "ScamShield Security <alerts@scamshield.local>";

    this.connectionTimeout = parseInt(config.connectionTimeout || process.env.SMTP_CONNECTION_TIMEOUT || "10000", 10);
    this.greetingTimeout = parseInt(config.greetingTimeout || process.env.SMTP_GREETING_TIMEOUT || "10000", 10);
    this.socketTimeout = parseInt(config.socketTimeout || process.env.SMTP_SOCKET_TIMEOUT || "15000", 10);

    this.transporter = null;
    this.initTransporter();
  }

  initTransporter() {
    if (!this.host || !this.user) {
      // Unconfigured or testing mode
      this.transporter = null;
      return;
    }

    this.transporter = nodemailer.createTransport({
      host: this.host,
      port: this.port,
      secure: this.secure,
      auth: {
        user: this.user,
        pass: this.pass
      },
      connectionTimeout: this.connectionTimeout,
      greetingTimeout: this.greetingTimeout,
      socketTimeout: this.socketTimeout
    });
  }

  isConfigured() {
    return Boolean(this.transporter);
  }

  async verifyConnection() {
    if (!this.transporter) {
      return { configured: false, status: "SMTP unconfigured (missing host or user)" };
    }
    try {
      await this.transporter.verify();
      return { configured: true, status: "SMTP connection verified" };
    } catch (err) {
      return { configured: true, status: "SMTP verification failed", error: err.message };
    }
  }

  validateEmail(email) {
    if (!email || typeof email !== "string") return false;
    // Standard RFC-5322 permissive email regex
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email.trim());
  }

  async sendMail({ to, subject, html, text }) {
    if (!to || !this.validateEmail(to)) {
      throw new Error(`Invalid destination email address: '${to}'`);
    }

    if (!subject || typeof subject !== "string" || !subject.trim()) {
      throw new Error("Missing email subject");
    }

    if (!html && !text) {
      throw new Error("Email body content (html or text) is required");
    }

    if (!this.transporter) {
      throw new Error("SMTP transporter is not configured on this server");
    }

    const mailOptions = {
      from: this.from,
      to: to.trim(),
      subject: subject.trim(),
      text: text || undefined,
      html: html || undefined
    };

    const info = await this.transporter.sendMail(mailOptions);
    return {
      success: true,
      messageId: info.messageId,
      accepted: info.accepted,
      rejected: info.rejected
    };
  }
}

module.exports = {
  MailerService
};
