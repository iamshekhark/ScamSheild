// Packaging Script for ScamShield Chrome Extension (Manifest V3)
// Performs pre-packaging validation, JS syntax verification, and generates a clean distribution zip archive
// Zero external dependencies - pure Node.js

const fs = require("node:fs");
const path = require("node:path");
const zlib = require("node:zlib");
const crypto = require("node:crypto");
const { execFileSync } = require("node:child_process");

const ROOT_DIR = path.resolve(__dirname, "..");
const EXT_DIR = path.join(ROOT_DIR, "extension");
const DIST_DIR = path.join(ROOT_DIR, "dist");

// Simple, robust in-memory ZIP builder using standard node:zlib
class SimpleZip {
  constructor() {
    this.files = [];
  }

  addFile(relativePath, buffer) {
    const normPath = relativePath.replace(/\\/g, "/");
    this.files.push({ path: normPath, data: buffer });
  }

  // Calculate CRC-32 for zip standard
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
      const method = useCompressed ? 8 : 0; // 8 = deflate, 0 = store
      const crc = this.crc32(f.data);

      // Local Header
      const lh = Buffer.alloc(30 + pathBuf.length);
      lh.writeUInt32LE(0x04034b50, 0); // signature
      lh.writeUInt16LE(20, 4);         // version needed (2.0)
      lh.writeUInt16LE(0, 6);          // flags
      lh.writeUInt16LE(method, 8);     // compression
      lh.writeUInt16LE(0, 10);         // time
      lh.writeUInt16LE(0, 12);         // date
      lh.writeUInt32LE(crc, 14);       // crc32
      lh.writeUInt32LE(dataToStore.length, 18); // compressed size
      lh.writeUInt32LE(f.data.length, 22);      // uncompressed size
      lh.writeUInt16LE(pathBuf.length, 26);     // file name length
      lh.writeUInt16LE(0, 28);                  // extra field length
      pathBuf.copy(lh, 30);

      localHeaders.push(lh, dataToStore);

      // Central Directory Header
      const cdh = Buffer.alloc(46 + pathBuf.length);
      cdh.writeUInt32LE(0x02014b50, 0); // signature
      cdh.writeUInt16LE(20, 4);          // version made by
      cdh.writeUInt16LE(20, 6);          // version needed
      cdh.writeUInt16LE(0, 8);           // flags
      cdh.writeUInt16LE(method, 10);     // compression
      cdh.writeUInt16LE(0, 12);          // time
      cdh.writeUInt16LE(0, 14);          // date
      cdh.writeUInt32LE(crc, 16);        // crc32
      cdh.writeUInt32LE(dataToStore.length, 20); // compressed size
      cdh.writeUInt32LE(f.data.length, 24);      // uncompressed size
      cdh.writeUInt16LE(pathBuf.length, 28);     // file name length
      cdh.writeUInt16LE(0, 30);                  // extra field length
      cdh.writeUInt16LE(0, 32);                  // file comment length
      cdh.writeUInt16LE(0, 34);                  // disk number start
      cdh.writeUInt16LE(0, 36);                  // internal file attr
      cdh.writeUInt32LE(0, 38);                  // external file attr
      cdh.writeUInt32LE(offset, 42);             // relative offset of local header
      pathBuf.copy(cdh, 46);

      centralHeaders.push(cdh);
      offset += lh.length + dataToStore.length;
    }

    const centralDirOffset = offset;
    const centralDirBuffer = Buffer.concat(centralHeaders);
    const centralDirSize = centralDirBuffer.length;

    // End of Central Directory Record (EOCD)
    const eocd = Buffer.alloc(22);
    eocd.writeUInt32LE(0x06054b50, 0);       // signature
    eocd.writeUInt16LE(0, 4);                // disk number
    eocd.writeUInt16LE(0, 6);                // disk with central dir
    eocd.writeUInt16LE(this.files.length, 8); // entries on disk
    eocd.writeUInt16LE(this.files.length, 10); // total entries
    eocd.writeUInt32LE(centralDirSize, 12);  // size of central dir
    eocd.writeUInt32LE(centralDirOffset, 16);// offset of central dir
    eocd.writeUInt16LE(0, 20);               // comment length

    return Buffer.concat([...localHeaders, centralDirBuffer, eocd]);
  }
}

// Generate CRC Table
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

function validateExtension() {
  console.log("🔍 Validating ScamShield Chrome Extension...");

  const manifestPath = path.join(EXT_DIR, "manifest.json");
  if (!fs.existsSync(manifestPath)) {
    throw new Error("Missing manifest.json in " + EXT_DIR);
  }

  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  if (manifest.manifest_version !== 3) {
    throw new Error("Manifest must be Manifest V3, found: " + manifest.manifest_version);
  }

  // Validate referenced icon assets
  if (manifest.icons) {
    for (const [size, iconPath] of Object.entries(manifest.icons)) {
      const fullPath = path.join(EXT_DIR, iconPath);
      if (!fs.existsSync(fullPath)) {
        throw new Error(`Referenced icon size ${size} not found at: ${fullPath}`);
      }
    }
  }

  // Validate background service worker
  if (manifest.background?.service_worker) {
    const swPath = path.join(EXT_DIR, manifest.background.service_worker);
    if (!fs.existsSync(swPath)) {
      throw new Error(`Referenced service worker not found at: ${swPath}`);
    }
  }

  // Validate popup HTML
  if (manifest.action?.default_popup) {
    const popupPath = path.join(EXT_DIR, manifest.action.default_popup);
    if (!fs.existsSync(popupPath)) {
      throw new Error(`Referenced popup html not found at: ${popupPath}`);
    }
  }

  // Verify JS syntax for all JavaScript files
  const jsFiles = fs.readdirSync(EXT_DIR).filter((f) => f.endsWith(".js"));
  for (const jsFile of jsFiles) {
    const jsPath = path.join(EXT_DIR, jsFile);
    try {
      execFileSync(process.execPath, ["--check", jsPath]);
    } catch (err) {
      throw new Error(`Syntax check failed for ${jsFile}: ${err.message}`);
    }
  }

  console.log(`✅ Validation passed: ${manifest.name} v${manifest.version}`);
  return manifest;
}

function collectFiles(dir, baseDir = dir) {
  const results = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    const relPath = path.relative(baseDir, fullPath);

    // Skip OS / temporary files
    if (entry.name.startsWith(".") || entry.name === "Thumbs.db" || entry.name === "node_modules") {
      continue;
    }

    if (entry.isDirectory()) {
      results.push(...collectFiles(fullPath, baseDir));
    } else {
      results.push({ fullPath, relPath });
    }
  }

  return results;
}

function packageExtension() {
  const manifest = validateExtension();

  if (!fs.existsSync(DIST_DIR)) {
    fs.mkdirSync(DIST_DIR, { recursive: true });
  }

  const zip = new SimpleZip();
  const files = collectFiles(EXT_DIR);
  const manifestReport = {
    name: manifest.name,
    version: manifest.version,
    packagedAt: new Date().toISOString(),
    files: []
  };

  console.log(`📦 Packaging ${files.length} extension files into distribution archive...`);

  for (const file of files) {
    const data = fs.readFileSync(file.fullPath);
    zip.addFile(file.relPath, data);

    const hash = crypto.createHash("sha256").update(data).digest("hex");
    manifestReport.files.push({
      path: file.relPath.replace(/\\/g, "/"),
      sizeBytes: data.length,
      sha256: hash
    });
  }

  const zipBuffer = zip.build();
  const zipName = `scamshield-extension-v${manifest.version}.zip`;
  const zipPath = path.join(DIST_DIR, zipName);

  fs.writeFileSync(zipPath, zipBuffer);

  const zipHash = crypto.createHash("sha256").update(zipBuffer).digest("hex");
  manifestReport.package = {
    filename: zipName,
    sizeBytes: zipBuffer.length,
    sha256: zipHash
  };

  const reportPath = path.join(DIST_DIR, `scamshield-extension-v${manifest.version}-manifest.json`);
  fs.writeFileSync(reportPath, JSON.stringify(manifestReport, null, 2));

  console.log(`🎉 Successfully packaged extension:`);
  console.log(`   File: ${zipPath}`);
  console.log(`   Size: ${(zipBuffer.length / 1024).toFixed(2)} KB`);
  console.log(`   SHA-256: ${zipHash}`);
  console.log(`   Manifest report: ${reportPath}`);
}

try {
  packageExtension();
} catch (err) {
  console.error("❌ Packaging error:", err.message);
  process.exit(1);
}
