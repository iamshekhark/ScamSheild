// ScamShield Phase 5: Production Build, CI & Release Packaging Tests
// Tests Manifest V3 compliance, asset integrity, syntax, and release artifact sanitization

const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");

const ROOT_DIR = path.resolve(__dirname, "..");
const EXT_DIR = path.join(ROOT_DIR, "extension");
const DIST_DIR = path.join(ROOT_DIR, "dist");
const DASHBOARD_DIR = path.join(ROOT_DIR, "dashboard");

// ============================================================================
// 1. Manifest V3 & Extension Integrity Verification
// ============================================================================

test("P5-01: Manifest V3 Specification Compliance", () => {
  const manifestPath = path.join(EXT_DIR, "manifest.json");
  assert.ok(fs.existsSync(manifestPath), "manifest.json must exist in extension directory");

  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf-8"));

  // 1. Manifest Version 3
  assert.strictEqual(manifest.manifest_version, 3, "Must strictly target Manifest V3");

  // 2. Prohibit MV2 constructs
  assert.strictEqual("browser_action" in manifest, false, "Must not use MV2 browser_action");
  assert.strictEqual("page_action" in manifest, false, "Must not use MV2 page_action");
  assert.strictEqual("background.scripts" in manifest, false, "Must not use MV2 background.scripts");

  // 3. Service worker background definition
  assert.ok(manifest.background?.service_worker, "Must define background.service_worker");
  assert.ok(
    fs.existsSync(path.join(EXT_DIR, manifest.background.service_worker)),
    `Service worker ${manifest.background.service_worker} must exist on disk`
  );

  // 4. Action & popup
  assert.ok(manifest.action?.default_popup, "Must define action.default_popup");
  assert.ok(
    fs.existsSync(path.join(EXT_DIR, manifest.action.default_popup)),
    `Popup file ${manifest.action.default_popup} must exist on disk`
  );

  // 5. Icons exist
  assert.ok(manifest.icons, "Must specify icons");
  for (const [size, iconRel] of Object.entries(manifest.icons)) {
    const iconPath = path.join(EXT_DIR, iconRel);
    assert.ok(fs.existsSync(iconPath), `Icon ${size} at ${iconRel} must exist`);
  }

  // 6. CSP does not permit unsafe-eval or remote code
  if (manifest.content_security_policy?.extension_pages) {
    const csp = manifest.content_security_policy.extension_pages;
    assert.strictEqual(csp.includes("'unsafe-eval'"), false, "CSP must not allow 'unsafe-eval'");
    assert.strictEqual(csp.includes("http://"), false, "CSP must not allow unencrypted http");
  }
});

test("P5-02: Popup HTML Asset & Script Integrity", () => {
  const popupHtmlPath = path.join(EXT_DIR, "popup.html");
  const html = fs.readFileSync(popupHtmlPath, "utf-8");

  // Chrome Web Store MV3 prohibits external script tags
  const externalScripts = html.match(/<script[^>]+src=["'](https?:\/\/[^"']+)["']/gi);
  assert.strictEqual(
    externalScripts,
    null,
    `popup.html must not load external scripts from CDN: ${externalScripts}`
  );

  // Verify all local script tags point to files that exist
  const scriptMatches = [...html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)];
  for (const match of scriptMatches) {
    const scriptSrc = match[1];
    const scriptPath = path.join(EXT_DIR, scriptSrc);
    assert.ok(fs.existsSync(scriptPath), `Referenced script ${scriptSrc} must exist on disk`);
  }

  // Verify local stylesheets exist
  const cssMatches = [...html.matchAll(/<link[^>]+href=["']([^"']+\.css)["']/gi)];
  for (const match of cssMatches) {
    const cssHref = match[1];
    const cssPath = path.join(EXT_DIR, cssHref);
    assert.ok(fs.existsSync(cssPath), `Referenced stylesheet ${cssHref} must exist on disk`);
  }
});

test("P5-03: Extension JavaScript Syntax Verification", () => {
  const jsFiles = fs.readdirSync(EXT_DIR).filter((f) => f.endsWith(".js"));
  assert.ok(jsFiles.length >= 5, "Extension must contain core JS modules");

  for (const file of jsFiles) {
    const fullPath = path.join(EXT_DIR, file);
    assert.doesNotThrow(() => {
      execFileSync(process.execPath, ["--check", fullPath]);
    }, `Syntax check failed for ${file}`);
  }
});

// ============================================================================
// 2. Linux Rollup & Lockfile Reproducibility
// ============================================================================

test("P5-04: Dashboard Package Lockfile correctly handles Linux Rollup dependency", () => {
  const pkgPath = path.join(DASHBOARD_DIR, "package.json");
  const lockPath = path.join(DASHBOARD_DIR, "package-lock.json");

  assert.ok(fs.existsSync(pkgPath), "dashboard/package.json must exist");
  assert.ok(fs.existsSync(lockPath), "dashboard/package-lock.json must exist");

  const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf-8"));
  const lock = JSON.parse(fs.readFileSync(lockPath, "utf-8"));

  // Verify optionalDependencies includes linux rollup
  assert.ok(
    pkg.optionalDependencies && pkg.optionalDependencies["@rollup/rollup-linux-x64-gnu"],
    "dashboard/package.json must declare @rollup/rollup-linux-x64-gnu in optionalDependencies"
  );

  // Verify lockfile contains @rollup/rollup-linux-x64-gnu with optional: true
  const linuxRollupKey = "node_modules/@rollup/rollup-linux-x64-gnu";
  const linuxRollupPkg = lock.packages[linuxRollupKey];
  assert.ok(linuxRollupPkg, "Lockfile packages must include @rollup/rollup-linux-x64-gnu");
  assert.strictEqual(linuxRollupPkg.optional, true, "Rollup Linux binary must be marked optional");
  assert.deepStrictEqual(linuxRollupPkg.os, ["linux"], "Must be marked os: linux");

  // Verify version alignment between rollup and linux binary
  const rollupKey = "node_modules/rollup";
  if (lock.packages[rollupKey]) {
    assert.strictEqual(
      linuxRollupPkg.version,
      lock.packages[rollupKey].version,
      "Rollup version and Rollup Linux binary version must match in lockfile"
    );
  }
});

// ============================================================================
// 3. Distribution Artifact Sanitization & Secret Scanning
// ============================================================================

test("P5-05: Sanitized Source Release Archive contains zero secrets, .env files, or node_modules", () => {
  const manifestPath = path.join(DIST_DIR, "scamshield-source-release-v2.0.0-manifest.json");
  assert.ok(
    fs.existsSync(manifestPath),
    "Release manifest must exist. Run 'npm run package:source' first."
  );

  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf-8"));
  assert.ok(manifest.files && manifest.files.length > 0, "Manifest must contain packaged files");

  for (const f of manifest.files) {
    const p = f.path;

    // Check 1: No .env files (except .example)
    if (p.includes(".env")) {
      assert.ok(p.endsWith(".example"), `.env file leaked in release: ${p}`);
    }

    // Check 2: No node_modules
    assert.strictEqual(p.includes("node_modules/"), false, `node_modules leaked in release: ${p}`);

    // Check 3: No token caches or logs
    assert.strictEqual(p.includes(".token_cache.json"), false, `Token cache leaked in release: ${p}`);
    assert.strictEqual(p.endsWith(".log"), false, `Log file leaked in release: ${p}`);

    // Check 4: No git directory
    assert.strictEqual(p.startsWith(".git/"), false, `.git leaked in release: ${p}`);
  }

  // Verify release zip file exists and is non-empty
  const zipPath = path.join(DIST_DIR, manifest.package.filename);
  assert.ok(fs.existsSync(zipPath), `Zip file ${zipPath} must exist`);
  const stats = fs.statSync(zipPath);
  assert.ok(stats.size > 50000, "Release zip size must be > 50KB");
  assert.strictEqual(stats.size, manifest.package.sizeBytes, "Zip size must match manifest");
});

test("P5-06: Packaged Extension Archive contains strictly required MV3 distribution files", () => {
  const manifestPath = path.join(DIST_DIR, "scamshield-extension-v2.0.0-manifest.json");
  assert.ok(
    fs.existsSync(manifestPath),
    "Extension manifest report must exist. Run 'npm run package:extension' first."
  );

  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf-8"));
  assert.ok(manifest.files && manifest.files.length >= 10, "Extension manifest must list files");

  const requiredFiles = ["manifest.json", "popup.html", "popup.css", "popup.js", "rules.js", "background.js"];
  const paths = manifest.files.map((f) => f.path);

  for (const req of requiredFiles) {
    assert.ok(paths.includes(req), `Extension package missing required file: ${req}`);
  }

  const zipPath = path.join(DIST_DIR, manifest.package.filename);
  assert.ok(fs.existsSync(zipPath), `Extension zip ${zipPath} must exist`);
  const stats = fs.statSync(zipPath);
  assert.ok(stats.size > 10000, "Extension zip size must be > 10KB");
});
