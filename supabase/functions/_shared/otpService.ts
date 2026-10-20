// Cryptographically Secure OTP Verification Service
// Never stores plaintext codes; verifies with salted SHA-256 digests.

export const OTP_EXPIRY_MS = 5 * 60 * 1000;      // 5 minutes
export const OTP_COOLDOWN_MS = 60 * 1000;         // 60 seconds resend cooldown
export const OTP_MAX_ATTEMPTS = 5;

export async function hashOtp(code: string, salt: string): Promise<string> {
  const enc = new TextEncoder();
  const data = enc.encode(`${salt}:${code.trim()}`);
  const digest = await crypto.subtle.digest("SHA-256", data);
  const arr = Array.from(new Uint8Array(digest));
  return arr.map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function generateSecureOtp(): string {
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  // Ensure exactly 6 digits (100000 - 999999)
  const code = (buf[0] % 900000) + 100000;
  return code.toString();
}

export function generateSalt(): string {
  const buf = new Uint8Array(16);
  crypto.getRandomValues(buf);
  return Array.from(buf).map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function verifyOtpHash(inputCode: string, salt: string, expectedHash: string): Promise<boolean> {
  const computed = await hashOtp(inputCode, salt);
  if (computed.length !== expectedHash.length) return false;
  
  // Timing-safe constant-time comparison
  let match = 0;
  for (let i = 0; i < computed.length; i++) {
    match |= computed.charCodeAt(i) ^ expectedHash.charCodeAt(i);
  }
  return match === 0;
}
