// Helper module for WebCrypto AES-256-GCM token encryption & decryption
// Provides reusable encryption/decryption utilities without registering any test blocks.

const ENCRYPTION_KEY_RAW = "scamshield_test_master_key_32b_secret!";

async function getCryptoKey(secret = ENCRYPTION_KEY_RAW) {
  const enc = new TextEncoder();
  const hash = await crypto.subtle.digest("SHA-256", enc.encode(secret));
  return crypto.subtle.importKey(
    "raw",
    hash,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptToken(plaintext, secret = ENCRYPTION_KEY_RAW) {
  if (!plaintext) return "";
  const key = await getCryptoKey(secret);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);

  const encryptedBuffer = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoded
  );

  const ivHex = Array.from(iv).map((b) => b.toString(16).padStart(2, "0")).join("");
  const cipherHex = Array.from(new Uint8Array(encryptedBuffer)).map((b) => b.toString(16).padStart(2, "0")).join("");

  return `enc:v1:${ivHex}:${cipherHex}`;
}

async function decryptToken(encryptedString, secret = ENCRYPTION_KEY_RAW) {
  if (!encryptedString) return "";
  if (!encryptedString.startsWith("enc:v1:")) {
    throw new Error("CRITICAL_SECURITY_ERROR: Unencrypted or malformed token rejected. All tokens must be encrypted with AES-256-GCM.");
  }

  const parts = encryptedString.split(":");
  if (parts.length !== 4) throw new Error("Invalid envelope");

  const ivHex = parts[2];
  const cipherHex = parts[3];

  const iv = new Uint8Array(ivHex.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));
  const ciphertext = new Uint8Array(cipherHex.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));

  const key = await getCryptoKey(secret);
  const decryptedBuffer = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    ciphertext
  );

  return new TextDecoder().decode(decryptedBuffer);
}

module.exports = {
  ENCRYPTION_KEY_RAW,
  getCryptoKey,
  encryptToken,
  decryptToken
};
