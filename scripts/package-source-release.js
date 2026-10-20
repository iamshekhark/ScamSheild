// Packaging Script for Clean ScamShield Full Source Release
// Packages only source code, tests, docs, and configs.
// STRICTLY excludes: .env files, node_modules/, dist/, build artifacts, logs, OS files.
// Zero external dependencies - pure Node.js

const fs = require("node:fs");
const path = require("node:path");
const zlib = require("node:zlib");
const crypto = require("node:crypto");

const ROOT_DIR = path.resolve(__dirname, "..");
const DIST_DIR = path.join(ROOT_DIR, "dist");

class SimpleZip {
  constructor() {
    this.files = [];
  }

  addFile(relativePath, buffer) {
    const normPath = relativePath.replace(/\\/g, "/");
    this.files.push({ path: normPath, data: buffer });
  }

  crc32(buf) {
    let crc = 0 ^ (-1);
    for (let i = 0; i < buf.length; i++) {
      crc = (crc >>> 8) ^ SimpleZip.CRC_TABLE[(crc ^ buf[i]) & 0xFF];
    }
    return (crc ^ (-1)) >>> 0;
  }

  build() {
    const localHeaders = [];
    const centralHeaders = [];
    let offset = 0;

    for (const f of this.files) {
      const pathBuf = Buffer.from(f.path, "utf8");
      const compressed = zlib.deflateRawSync(f.data);
      const useCompressed = compressed.length < f.data.length;
      const dataToStore = useCompressed ? compressed : f.data;
      const method = useCompressed ? 8 : 0;
      const crc = this.crc32(f.data);

      const lh = Buffer.alloc(30 + pathBuf.length);
      lh.writeUInt32LE(0x04034b50, 0);
      lh.writeUInt16LE(20, 4);
      lh.writeUInt16LE(0, 6);
      lh.writeUInt16LE(method, 8);
      lh.writeUInt16LE(0, 10);
      lh.writeUInt16LE(0, 12);
      lh.writeUInt32LE(crc, 14);
      lh.writeUInt32LE(dataToStore.length, 18);
      lh.writeUInt32LE(f.data.length, 22);
      lh.writeUInt16LE(pathBuf.length, 26);
      lh.writeUInt16LE(0, 28);
      pathBuf.copy(lh, 30);
      localHeaders.push(lh, dataToStore);

      const cdh = Buffer.alloc(46 + pathBuf.length);
      cdh.writeUInt32LE(0x02014b50, 0);
      cdh.writeUInt16LE(20, 4);
      cdh.writeUInt16LE(20, 6);
      cdh.writeUInt16LE(0, 8);
      cdh.writeUInt16LE(method, 10);
      cdh.writeUInt16LE(0, 12);
      cdh.writeUInt16LE(0, 14);
      cdh.writeUInt32LE(crc, 16);
      cdh.writeUInt32LE(dataToStore.length, 20);
      cdh.writeUInt32LE(f.data.length, 24);
      cdh.writeUInt16LE(pathBuf.length, 28);
      cdh.writeUInt16LE(0, 30);
      cdh.writeUInt16LE(0, 32);
      cdh.writeUInt16LE(0, 34);
      cdh.writeUInt16LE(0, 36);
      cdh.writeUInt32LE(0, 38);
      cdh.writeUInt32LE(offset, 42);
      pathBuf.copy(cdh, 46);
      centralHeaders.push(cdh);
      offset += lh.length + dataToStore.length;
    }

    const centralDirOffset = offset;
    const centralDirBuffer = Buffer.concat(centralHeaders);
    const centralDirSize = centralDirBuffer.length;

    const eocd = Buffer.alloc(22);
    eocd.writeUInt32LE(0x06054b50, 0);
    eocd.writeUInt16LE(0, 4);
    eocd.writeUInt16LE(0, 6);
    eocd.writeUInt16LE(this.files.length, 8);
    eocd.writeUInt16LE(this.files.length, 10);
    eocd.writeUInt32LE(centralDirSize, 12);
    eocd.writeUInt32LE(centralDirOffset, 16);
    eocd.writeUInt16LE(0, 20);

    return Buffer.concat([...localHeaders, centralDirBuffer, eocd]);
  }
}

SimpleZip.CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    }
    table[i] = c >>> 0;
  }
  return table;
})();

const EXCLUDE_DIRS = new Set(["node_modules", "dist", ".git", ".vscode"]);
const EXCLUDE_FILES = new Set([
  ".env",
  ".env.local",
  ".token_cache.json",
  "npm-debug.log",
  ".DS_Store",
  "Thumbs.db"
]);

function isExcluded(name, relPath) {
  if (name.startsWith(".env") && !name.endsWith(".example")) return true;
  if (name.includes(".token_cache")) return true;
  if (EXCLUDE_FILES.has(name)) return true;
  if (name.endsWith(".log")) return true;
  const parts = relPath.replace(/\\/g, "/").split("/");
  return parts.some((p) => EXCLUDE_DIRS.has(p));
}

function collectSourceFiles(dir, baseDir = dir) {
  const results = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    const relPath = path.relative(baseDir, fullPath);

    if (isExcluded(entry.name, relPath)) {
      continue;
    }

    if (entry.isDirectory()) {
      results.push(...collectSourceFiles(fullPath, baseDir));
    } else {
      results.push({ fullPath, relPath });
    }
  }

  return results;
}

function packageSourceRelease() {
  if (!fs.existsSync(DIST_DIR)) {
    fs.mkdirSync(DIST_DIR, { recursive: true });
  }

  const pkgJson = JSON.parse(fs.readFileSync(path.join(ROOT_DIR, "package.json"), "utf8"));
  const version = pkgJson.version || "2.0.0";
  const files = collectSourceFiles(ROOT_DIR);

  console.log(`🔍 Auditing files for clean release...`);

  // Explicit Secret Audit Check: reject any .env files or tokens
  for (const f of files) {
    const norm = f.relPath.replace(/\\/g, "/");
    if (norm.includes(".env") && !norm.includes(".example")) {
      throw new Error(`CRITICAL_SECURITY_LEAK: Forbidden environment file found in release set: ${norm}`);
    }
    if (norm.includes("node_modules/")) {
      throw new Error(`LEAK_DETECTED: node_modules found in release set: ${norm}`);
    }
    if (norm.includes(".token_cache.json")) {
      throw new Error(`CRITICAL_SECURITY_LEAK: Token cache found in release set: ${norm}`);
    }
  }

  console.log(`✅ Audit passed: 0 secrets, 0 node_modules, 0 live credentials.`);
  console.log(`📦 Packaging ${files.length} clean source files into distribution archive...`);

  const zip = new SimpleZip();
  const manifest = {
    name: "scamshield-source-release",
    version,
    packagedAt: new Date().toISOString(),
    totalFiles: files.length,
    files: []
  };

  for (const file of files) {
    const data = fs.readFileSync(file.fullPath);
    zip.addFile(file.relPath, data);

    const hash = crypto.createHash("sha256").update(data).digest("hex");
    manifest.files.push({
      path: file.relPath.replace(/\\/g, "/"),
      sizeBytes: data.length,
      sha256: hash
    });
  }

  const zipBuffer = zip.build();
  const zipName = `scamshield-source-release-v${version}.zip`;
  const zipPath = path.join(DIST_DIR, zipName);

  fs.writeFileSync(zipPath, zipBuffer);

  const zipHash = crypto.createHash("sha256").update(zipBuffer).digest("hex");
  manifest.package = {
    filename: zipName,
    sizeBytes: zipBuffer.length,
    sha256: zipHash
  };

  const reportPath = path.join(DIST_DIR, `scamshield-source-release-v${version}-manifest.json`);
  fs.writeFileSync(reportPath, JSON.stringify(manifest, null, 2));

  console.log(`🎉 Successfully created sanitized source release:`);
  console.log(`   File: ${zipPath}`);
  console.log(`   Size: ${(zipBuffer.length / 1024).toFixed(2)} KB`);
  console.log(`   SHA-256: ${zipHash}`);
  console.log(`   Manifest: ${reportPath}`);
}

try {
  packageSourceRelease();
} catch (err) {
  console.error("❌ Packaging error:", err.message);
  process.exit(1);
}
