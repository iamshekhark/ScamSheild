// Cryptographic helpers for Supabase Edge Functions
// Enforces real AES-256-GCM authenticated encryption for OAuth refresh tokens and secrets

function getEncryptionSecret(): string {
  const key = Deno.env.get("TOKEN_ENCRYPTION_KEY") || Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!key) {
    throw new Error("CRITICAL SECURITY ERROR: TOKEN_ENCRYPTION_KEY must be configured in environment. Insecure default keys are forbidden.");
  }
  return key;
}

async function getCryptoKey(secret?: string): Promise<CryptoKey> {
  const rawSecret = secret || getEncryptionSecret();
  const enc = new TextEncoder();
  const hash = await crypto.subtle.digest("SHA-256", enc.encode(rawSecret));
  return crypto.subtle.importKey(
    "raw",
    hash,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );
}

/**
 * Encrypts a plaintext string using AES-256-GCM with a fresh 96-bit random IV per operation.
 * Returns formatted ciphertext: "enc:v1:<iv_hex>:<ciphertext_hex>"
 */
export async function encryptToken(plaintext: string): Promise<string> {
  if (!plaintext) return "";
  const key = await getCryptoKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);

  const encryptedBuffer = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoded
  );

  const ivHex = Array.from(iv)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  const cipherHex = Array.from(new Uint8Array(encryptedBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  return `enc:v1:${ivHex}:${cipherHex}`;
}

/**
 * Decrypts an AES-256-GCM ciphertext created by encryptToken.
 */
export async function decryptToken(encryptedString: string): Promise<string> {
  if (!encryptedString) return "";

  if (!encryptedString.startsWith("enc:v1:")) {
    throw new Error("CRITICAL_SECURITY_ERROR: Unencrypted or malformed token rejected. All tokens must be encrypted with AES-256-GCM.");
  }

  const parts = encryptedString.split(":");
  if (parts.length !== 4) {
    throw new Error("Invalid encrypted token envelope structure");
  }

  const ivHex = parts[2];
  const cipherHex = parts[3];

  const ivMatches = ivHex.match(/.{1,2}/g);
  const cipherMatches = cipherHex.match(/.{1,2}/g);
  if (!ivMatches || !cipherMatches) {
    throw new Error("Malformed hex in encrypted token envelope");
  }

  const iv = new Uint8Array(ivMatches.map((byte) => parseInt(byte, 16)));
  const ciphertext = new Uint8Array(cipherMatches.map((byte) => parseInt(byte, 16)));

  const key = await getCryptoKey();
  const decryptedBuffer = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    ciphertext
  );

  return new TextDecoder().decode(decryptedBuffer);
}
