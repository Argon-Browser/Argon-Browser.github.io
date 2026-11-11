// SPDX-License-Identifier: MIT
/**
 * Argon Browser — Official Website Interactive Controller
 * Works seamlessly across HTTP/HTTPS servers and direct local file:// preview.
 */
(function () {
  "use strict";

  if (typeof window === "undefined" || window.__ARGON_SITE_READY__) return;
  window.__ARGON_SITE_READY__ = true;

  /* =========================================================================
   * 1. DESCRIPTOR-SAFE JSON GATE & STATIC MANIFEST ANALYZER
   * ========================================================================= */
  const MAX_DEPTH = 32;
  const MAX_ARRAY_LENGTH = 4096;
  const OBJECT_TAG = "[object Object]";
  const ARRAY_TAG = "[object Array]";
  const tagOf = (v) => Object.prototype.toString.call(v);

  function convertJsonSafe(value, depth, ancestors) {
    if (depth > MAX_DEPTH) {
      return { ok: false, message: "Manifest data nested deeper than " + MAX_DEPTH + " levels is rejected." };
    }
    if (value === null) return { ok: true, value: null };
    const type = typeof value;
    if (type === "string" || type === "boolean") return { ok: true, value };
    if (type === "number") {
      return Number.isFinite(value)
        ? { ok: true, value }
        : { ok: false, message: "NaN and Infinity are not JSON values." };
    }
    if (type !== "object") {
      return { ok: false, message: type + " values are not JSON data." };
    }
    if (ancestors.has(value)) {
      return { ok: false, message: "Circular references are not JSON data." };
    }
    const kind = tagOf(value);
    if (kind === ARRAY_TAG) {
      if (value.length > MAX_ARRAY_LENGTH) {
        return { ok: false, message: "Arrays longer than " + MAX_ARRAY_LENGTH + " entries are rejected." };
      }
      ancestors.add(value);
      const copy = [];
      for (let i = 0; i < value.length; i += 1) {
        const desc = Object.getOwnPropertyDescriptor(value, i);
        if (!desc) return { ok: false, message: "Array holes are not JSON data." };
        if (desc.get || desc.set) return { ok: false, message: "Accessor properties are not JSON data." };
        const converted = convertJsonSafe(desc.value, depth + 1, ancestors);
        if (!converted.ok) return converted;
        copy.push(converted.value);
      }
      ancestors.delete(value);
      return { ok: true, value: copy };
    }
    if (kind !== OBJECT_TAG) {
      return { ok: false, message: kind.slice(8, -1) + " instances are not JSON data." };
    }
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) {
      return { ok: false, message: "Only plain objects are JSON data." };
    }
    ancestors.add(value);
    const copy = {};
    for (const key of Object.keys(value)) {
      const desc = Object.getOwnPropertyDescriptor(value, key);
      if (desc.get || desc.set) return { ok: false, message: "Accessor properties are not JSON data." };
      const converted = convertJsonSafe(desc.value, depth + 1, ancestors);
      if (!converted.ok) return converted;
      Object.defineProperty(copy, key, {
        value: converted.value,
        enumerable: true,
        writable: true,
        configurable: true
      });
    }
    ancestors.delete(value);
    return { ok: true, value: copy };
  }

  function sanitizeManifest(manifest) {
    const res = convertJsonSafe(manifest, 1, new Set());
    return res.ok ? { ok: true, manifest: res.value } : { ok: false, message: res.message };
  }

  const RECOGNIZED_PERMS = new Set([
    "activeTab", "alarms", "bookmarks", "browserSettings", "browsingData", "captivePortal",
    "clipboardRead", "clipboardWrite", "contextMenus", "contextualIdentities", "cookies",
    "declarativeNetRequest", "declarativeNetRequestFeedback", "declarativeNetRequestWithHostAccess",
    "dns", "downloads", "downloads.open", "find", "geolocation", "history", "identity", "idle",
    "management", "menus", "menus.overrideContext", "nativeMessaging", "notifications", "pkcs11",
    "privacy", "publicSuffix", "proxy", "scripting", "search", "sessions", "storage", "tabGroups",
    "tabHide", "tabs", "theme", "topSites", "unlimitedStorage", "userScripts", "webNavigation",
    "webRequest", "webRequestAuthProvider", "webRequestBlocking", "webRequestFilterResponse",
    "webRequestFilterResponse.serviceWorkerScript"
  ]);
  const CHROME_SPECIFIC_PERMS = new Set([
    "background", "contentSettings", "debugger", "declarativeContent", "desktopCapture",
    "offscreen", "sidePanel", "tabCapture"
  ]);
  const SEMANTICS_REVIEW_PERMS = new Set([
    "proxy", "userScripts", "webRequestBlocking",
    "declarativeNetRequest", "declarativeNetRequestFeedback", "declarativeNetRequestWithHostAccess"
  ]);
  const NO_NAMESPACE_PERMS = new Set(["activeTab", "clipboardRead", "clipboardWrite", "geolocation", "background"]);
  const NAMESPACE_HINTS = new Map([
    ["nativeMessaging", "runtime"], ["unlimitedStorage", "storage"], ["tabHide", "tabs"],
    ["declarativeNetRequestFeedback", "declarativeNetRequest"],
    ["declarativeNetRequestWithHostAccess", "declarativeNetRequest"],
    ["webRequestBlocking", "webRequest"], ["webRequestAuthProvider", "webRequest"],
    ["webRequestFilterResponse", "webRequest"], ["webRequestFilterResponse.serviceWorkerScript", "webRequest"]
  ]);

  function inspectMatchPattern(value, path, add) {
    const entry = { value, path, broad: value === "<all_urls>" };
    if (value !== "<all_urls>") {
      const match = /^([a-z][a-z0-9+.-]*|\*):\/\/([^/]*)(\/.*)$/.exec(value);
      let valid = Boolean(match) && !/[\s\\\u0000-\u001f\u007f]/.test(value);
      if (match) {
        const [, scheme, host, pathname] = match;
        const hostPart = host.replace(/^\*\./, "");
        valid = valid && ((scheme === "file" && host === "") || host === "*" || /^(?:\[[0-9a-fA-F:]+\]|[^*:@?#]+)(?::[0-9]+)?$/.test(hostPart));
        if (valid && host && host !== "*") {
          try { new URL("http://" + hostPart + "/"); } catch { valid = false; }
        }
        entry.broad = host === "*" || scheme === "file";
        if (valid && (!["*", "http", "https", "file"].includes(scheme) || host.includes(":") || pathname.includes("#"))) {
          add("MATCH_PATTERN_REVIEW", "review", path, "Scheme, port, or fragment semantics require browser-specific review. The pattern is not rewritten.");
        }
      }
      if (!valid) add("INVALID_MATCH_PATTERN", "error", path, "Expected a valid match pattern with scheme, host, and slash-prefixed path, or <all_urls>.");
    }
    if (entry.broad) add("BROAD_HOST_PERMISSION", "review", path, "Requests access across all hosts or local files. Review least privilege before installing.");
    return entry;
  }

  function analyzePermissions(manifest, permissions, add) {
    const fields = [
      ["permissions", "required", false],
      ["optional_permissions", "optional", false],
      ["host_permissions", "required", true],
      ["optional_host_permissions", "optional", true]
    ];
    for (const [field, boundary, hostsOnly] of fields) {
      if (!Object.prototype.hasOwnProperty.call(manifest, field)) continue;
      if (hostsOnly && manifest.manifest_version === 2) {
        add("MANIFEST_VERSION_CONFLICT", "error", field, "Dedicated host permission fields require Manifest V3.");
      }
      if (!Array.isArray(manifest[field])) {
        add("INVALID_PERMISSION_LIST", "error", field, "Permission declarations must be arrays of strings.");
        continue;
      }
      manifest[field].forEach((value, index) => {
        const path = field + "[" + index + "]";
        if (typeof value !== "string" || value.length === 0 || /\s/.test(value)) {
          add("INVALID_PERMISSION_VALUE", "error", path, "A permission must be a non-empty string without whitespace.");
          return;
        }
        if (hostsOnly || /[:/<*]/.test(value)) {
          permissions[boundary].hosts.push(inspectMatchPattern(value, path, add));
          if (!hostsOnly && manifest.manifest_version === 3) {
            if (boundary === "required") {
              add("MANIFEST_VERSION_CONFLICT", "error", path, "MV3 required hosts belong in host_permissions.");
            } else {
              add("OPTIONAL_HOST_PLACEMENT", "review", path, "optional_host_permissions is recommended for cross-browser MV3 declarations.");
            }
          }
          return;
        }
        const classification = CHROME_SPECIFIC_PERMS.has(value)
          ? "CHROME_SPECIFIC"
          : RECOGNIZED_PERMS.has(value) ? "RECOGNIZED_PERMISSION" : "UNKNOWN";
        const namespaceHint = classification === "UNKNOWN" || NO_NAMESPACE_PERMS.has(value)
          ? null
          : (NAMESPACE_HINTS.get(value) || value.split(".")[0]);
        permissions[boundary].api.push({ value, path, classification, namespaceHint });
        if (classification === "CHROME_SPECIFIC") {
          add("CHROME_SPECIFIC_PERMISSION", "review", path, "Chromium-specific permission requires Gecko API review; no runtime shim is active in Phase 1.");
        } else if (classification === "UNKNOWN") {
          add("UNKNOWN_PERMISSION", "review", path, "Unrecognized permission requires manual review.");
        }
        if (value === "nativeMessaging") {
          add("NATIVE_MESSAGING_REVIEW", "review", path, "Review native-host trust, allowed extension IDs, and lifecycle.");
        }
        if (SEMANTICS_REVIEW_PERMS.has(value)) {
          add("API_SEMANTICS_REVIEW", "review", path, "API behavior and permission constraints differ across engines; review manually.");
        }
      });
    }
  }

  const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
  const isTxt = (v) => typeof v === "string" && v.trim().length > 0;
  const isStrArr = (v) => Array.isArray(v) && v.every(isTxt);

  const MANIFEST_TYPES = new Map([
    ...["author", "default_locale", "description", "devtools_page", "homepage_url", "name", "options_page",
      "short_name", "version", "version_name", "key", "minimum_chrome_version", "update_url"].map((k) => [k, isTxt]),
    ...["action", "applications", "background", "browser_action", "browser_specific_settings",
      "chrome_settings_overrides", "chrome_url_overrides", "commands", "dark_theme",
      "declarative_net_request", "developer", "dictionaries", "externally_connectable", "icons",
      "oauth2", "omnibox", "options_ui", "page_action", "sandbox", "side_panel", "sidebar_action",
      "storage", "theme", "theme_experiment", "user_scripts"].map((k) => [k, isObj]),
    ...["content_scripts", "permissions", "optional_permissions", "host_permissions",
      "optional_host_permissions", "protocol_handlers", "web_accessible_resources"].map((k) => [k, Array.isArray]),
    ["manifest_version", (v) => [2, 3].includes(v)],
    ["incognito", (v) => ["spanning", "split", "not_allowed"].includes(v)]
  ]);
  const MODELED_KEYS = new Set([
    "manifest_version", "name", "version", "background", "permissions",
    "optional_permissions", "host_permissions", "optional_host_permissions", "description", "author", "short_name"
  ]);
  const CHROME_KEYS = new Set(["key", "minimum_chrome_version", "oauth2", "side_panel", "externally_connectable", "storage", "version_name"]);

  function checkBackground(background, version, add) {
    if (!["scripts", "page", "service_worker"].some((k) => Object.prototype.hasOwnProperty.call(background, k))) {
      add("MISSING_BACKGROUND_CONTEXT", "error", "background", "Background needs scripts, page, or service_worker.");
    }
    const checks = new Map([
      ["scripts", (v) => isStrArr(v) && v.length > 0],
      ["page", isTxt],
      ["service_worker", isTxt],
      ["persistent", (v) => typeof v === "boolean"],
      ["type", (v) => ["classic", "module"].includes(v)],
      ["preferred_environment", (v) => Array.isArray(v) && v.length > 0 && v.every((e) => ["document", "service_worker"].includes(e))]
    ]);
    for (const [key, value] of Object.entries(background)) {
      const path = "background." + key;
      if (!checks.has(key)) add("UNKNOWN_MANIFEST_KEY", "review", path, "Unknown background key requires manual review.");
      else if (!checks.get(key)(value)) add("INVALID_FIELD", "error", path, "Invalid background field value or type.");
    }
    if (Object.prototype.hasOwnProperty.call(background, "page") && Object.prototype.hasOwnProperty.call(background, "scripts")) {
      add("CONFLICTING_BACKGROUND_CONTEXTS", "error", "background", "background.page and background.scripts are mutually exclusive.");
    }
    if (version === 3 && background.persistent === true) {
      add("MANIFEST_VERSION_CONFLICT", "error", "background.persistent", "Manifest V3 cannot declare a persistent background page.");
    }
    if (Object.prototype.hasOwnProperty.call(background, "service_worker")) {
      if (version === 2) add("MANIFEST_VERSION_CONFLICT", "error", "background.service_worker", "Chromium service workers require Manifest V3.");
      add("MV3_SERVICE_WORKER_LIFECYCLE_GAP", "gap", "background.service_worker",
        "Firefox background documents and Chromium service workers differ in lifecycle and state persistence. Argon Phase 1 reports this statically without rewriting.");
    }
  }

  function checkContentScripts(scripts, inventory, add) {
    const checks = new Map([
      ["matches", (v) => isStrArr(v) && v.length > 0],
      ...["exclude_matches", "include_globs", "exclude_globs", "js", "css"].map((k) => [k, isStrArr]),
      ...["all_frames", "match_about_blank", "match_origin_as_fallback"].map((k) => [k, (v) => typeof v === "boolean"]),
      ["run_at", (v) => ["document_start", "document_end", "document_idle"].includes(v)],
      ["world", (v) => ["ISOLATED", "MAIN"].includes(v)]
    ]);
    scripts.forEach((script, index) => {
      const path = "content_scripts[" + index + "]";
      if (!isObj(script)) {
        add("INVALID_FIELD", "error", path, "Each content-script entry must be an object.");
        return;
      }
      inventory.push({ path, declaration: JSON.parse(JSON.stringify(script)) });
      if (!checks.get("matches")(script.matches)) add("INVALID_FIELD", "error", path + ".matches", "Content scripts require a non-empty matches array.");
      if (![script.js, script.css].some((v) => isStrArr(v) && v.length > 0)) {
        add("MISSING_CONTENT_SCRIPT_RESOURCE", "error", path, "Content scripts need at least one JS or CSS resource.");
      }
      for (const [key, value] of Object.entries(script)) {
        const fieldPath = path + "." + key;
        if (!checks.has(key)) add("UNKNOWN_MANIFEST_KEY", "review", fieldPath, "Unknown content-script key.");
        else if (!checks.get(key)(value)) add("INVALID_FIELD", "error", fieldPath, "Invalid content-script value.");
        else if (["matches", "exclude_matches"].includes(key)) {
          value.forEach((p, pIdx) => inspectMatchPattern(p, fieldPath + "[" + pIdx + "]", (code, ...rest) => {
            if (key !== "exclude_matches" || code !== "BROAD_HOST_PERMISSION") add(code, ...rest);
          }));
        }
        if (key === "world" || key === "match_origin_as_fallback") {
          add("CONTENT_SCRIPT_EXECUTION_REVIEW", "review", fieldPath, "Injection world and origin fallback affect isolation; review manually.");
        }
      }
    });
  }

  function analyzeManifestKeys(manifest, contentScripts, add) {
    for (const [key, value] of Object.entries(manifest)) {
      let check = MANIFEST_TYPES.get(key);
      if (key === "content_security_policy") check = manifest.manifest_version === 2 ? isTxt : isObj;
      if (!check) {
        add("UNKNOWN_MANIFEST_KEY", "review", key, "Unknown manifest key requires manual review.");
        continue;
      }
      if (!check(value)) {
        add("INVALID_FIELD", "error", key, "Invalid manifest field type or value.");
        continue;
      }
      if ((key === "action" && manifest.manifest_version === 2) ||
          (key === "browser_action" && manifest.manifest_version === 3) ||
          (key === "user_scripts" && manifest.manifest_version === 3)) {
        add("MANIFEST_VERSION_CONFLICT", "error", key, "Field is not valid for this manifest_version.");
      }
      if (key === "background") checkBackground(value, manifest.manifest_version, add);
      if (key === "content_scripts") checkContentScripts(value, contentScripts, add);
      if (key === "web_accessible_resources") {
        const itemCheck = manifest.manifest_version === 2 ? isTxt : isObj;
        value.forEach((item, idx) => {
          if (!itemCheck(item)) add("INVALID_FIELD", "error", key + "[" + idx + "]", "Invalid web_accessible_resources entry.");
        });
      }
      if (CHROME_KEYS.has(key)) {
        add("CHROME_SPECIFIC_KEY", "review", key, "Chromium-specific manifest key has no direct Firefox equivalent in this rule set.");
      } else if (!MODELED_KEYS.has(key)) {
        add("UNMODELED_MANIFEST_VALUE", "review", key, "Outer type verified; nested semantics require manual review.");
      }
    }
  }

  const VERSION_RE = /^(0|[1-9][0-9]{0,8})(\.(0|[1-9][0-9]{0,8})){0,3}$/;

  function finishReport(report) {
    report.valid = !report.findings.some((f) => f.severity === "error");
    report.requiresManualReview = report.findings.some((f) => f.severity !== "info");
    report.assessment = !report.valid
      ? "INVALID_MANIFEST"
      : report.requiresManualReview ? "MANUAL_REVIEW_REQUIRED" : "NO_KNOWN_STATIC_ISSUES";
    return report;
  }

  function analyzeManifest(manifest) {
    const report = {
      schemaVersion: 1,
      scope: "STATIC_MANIFEST_ONLY",
      runtimeCompatibility: "NOT_TESTED",
      notice: "Static analysis only; extension code is never executed and no permissions are granted.",
      valid: true,
      assessment: "NO_KNOWN_STATIC_ISSUES",
      requiresManualReview: false,
      manifest: { name: null, version: null, manifestVersion: null },
      findings: [],
      permissions: { required: { api: [], hosts: [] }, optional: { api: [], hosts: [] }, contentScripts: [] }
    };
    const add = (code, severity, path, message) => report.findings.push({ code, severity, path, message });
    const gate = sanitizeManifest(manifest);
    if (!gate.ok) {
      add("NON_JSON_INPUT", "error", "$", "Manifest data is not a JSON object graph: " + gate.message);
      return finishReport(report);
    }
    manifest = gate.manifest;
    if (!isObj(manifest)) {
      add("INVALID_ROOT", "error", "$", "The manifest must be a JSON object.");
      return finishReport(report);
    }
    if (![2, 3].includes(manifest.manifest_version)) {
      add("INVALID_MANIFEST_VERSION", "error", "manifest_version", "manifest_version must be 2 or 3.");
    } else {
      report.manifest.manifestVersion = manifest.manifest_version;
    }
    if (!isTxt(manifest.name)) {
      add("INVALID_NAME", "error", "name", "name must be a non-empty string.");
    } else {
      report.manifest.name = manifest.name;
    }
    if (typeof manifest.version !== "string" || !VERSION_RE.test(manifest.version)) {
      add("INVALID_VERSION", "error", "version", "version must contain 1 to 4 dot-separated integers without leading zeros.");
    } else {
      report.manifest.version = manifest.version;
      const parts = manifest.version.split(".").map(Number);
      if (parts.every((p) => p === 0) || parts.some((p) => p > 65535)) {
        add("CHROME_VERSION_RESTRICTION", "review", "version", "Meets Firefox/AMO format but exceeds Chrome Web Store 16-bit integer bounds.");
      }
    }
    analyzePermissions(manifest, report.permissions, add);
    analyzeManifestKeys(manifest, report.permissions.contentScripts, add);
    return finishReport(report);
  }

  function formatCliReport(report) {
    const lines = [
      "Argon static manifest report",
      "----------------------------",
      "Scope:      " + report.scope,
      "Assessment: " + report.assessment,
      "Manifest:   " + (report.manifest.name || "(unnamed)") + " " + (report.manifest.version || "?") + " (MV" + (report.manifest.manifestVersion || "?") + ")",
      ""
    ];
    const req = report.permissions.required;
    lines.push("Required API (" + req.api.length + "): " + (req.api.map((x) => x.value).join(", ") || "none"));
    lines.push("Host patterns (" + req.hosts.length + "): " + (req.hosts.map((x) => x.value).join(", ") || "none"));
    lines.push("");
    if (report.findings.length === 0) {
      lines.push("Findings: none");
    } else {
      lines.push("Findings (" + report.findings.length + "):");
      report.findings.forEach((f) => {
        lines.push("  [" + f.severity.toUpperCase() + "] " + f.code + " (" + f.path + ")");
        lines.push("    " + f.message);
      });
    }
    return lines.join("\n");
  }

  /* =========================================================================
   * 2. DATASETS: SCREENSHOTS, SAMPLES, BENCHMARK, CONFIGS, ASSETS & I18N
   * ========================================================================= */
  const CHROME_STATES = [
    {
      id: "vertical",
      tokenSummary: "48px toolbar · 240px sidebar · dark",
      screenshot: "./assets/chrome-smoke/dark-vertical.png"
    },
    {
      id: "horizontal",
      tokenSummary: "48px toolbar · horizontal tabs · dark",
      screenshot: "./assets/chrome-smoke/dark-horizontal.png"
    },
    {
      id: "light-vertical",
      tokenSummary: "48px toolbar · 240px sidebar · light",
      screenshot: "./assets/chrome-smoke/light-vertical.png"
    },
    {
      id: "light-horizontal",
      tokenSummary: "48px toolbar · horizontal tabs · light",
      screenshot: "./assets/chrome-smoke/light-horizontal.png"
    }
  ];

  const COMPARISON_MODES = {
    VerticalVsHorizontal: {
      darkLeft: "./assets/chrome-smoke/dark-vertical.png",
      darkRight: "./assets/chrome-smoke/dark-horizontal.png",
      lightLeft: "./assets/chrome-smoke/light-vertical.png",
      lightRight: "./assets/chrome-smoke/light-horizontal.png",
      leftPt: "Argon · Abas verticais",
      rightPt: "Argon · Abas horizontais",
      leftEn: "Argon · Vertical tabs",
      rightEn: "Argon · Horizontal tabs"
    },
    DarkVsLight: {
      darkLeft: "./assets/chrome-smoke/dark-vertical.png",
      darkRight: "./assets/chrome-smoke/light-vertical.png",
      lightLeft: "./assets/chrome-smoke/light-vertical.png",
      lightRight: "./assets/chrome-smoke/dark-vertical.png",
      leftPt: "Argon · Tema escuro (vertical)",
      rightPt: "Argon · Tema claro (vertical)",
      leftEn: "Argon · Dark theme (vertical)",
      rightEn: "Argon · Light theme (vertical)"
    },
    HorizontalDarkVsLight: {
      darkLeft: "./assets/chrome-smoke/dark-horizontal.png",
      darkRight: "./assets/chrome-smoke/light-horizontal.png",
      lightLeft: "./assets/chrome-smoke/light-horizontal.png",
      lightRight: "./assets/chrome-smoke/dark-horizontal.png",
      leftPt: "Argon · Horizontal escuro",
      rightPt: "Argon · Horizontal claro",
      leftEn: "Argon · Horizontal dark",
      rightEn: "Argon · Horizontal light"
    }
  };

  const SAMPLE_MANIFESTS = {
    cleanMv3: JSON.stringify({
      manifest_version: 3,
      name: "Argon Tab Pinning Helper",
      version: "1.4.2",
      description: "Minimal tab organizer using standard WebExtensions APIs.",
      permissions: ["storage", "tabs", "activeTab"],
      optional_permissions: ["bookmarks"],
      host_permissions: ["https://example.org/*"]
    }, null, 2),
    mv3ServiceWorker: JSON.stringify({
      manifest_version: 3,
      name: "Chromium Workspace Sync",
      version: "2.1.0",
      permissions: ["storage", "alarms", "scripting"],
      host_permissions: ["<all_urls>"],
      background: {
        service_worker: "background-sw.js",
        type: "module"
      }
    }, null, 2),
    chromeSpecific: JSON.stringify({
      manifest_version: 3,
      name: "Chrome Offscreen Media Utility",
      version: "3.0.1",
      permissions: ["storage", "offscreen", "tabCapture", "nativeMessaging"],
      host_permissions: ["https://*.chromium.org:8443/*"],
      content_scripts: [
        { matches: ["https://example.com/*"], js: ["content.js"], world: "MAIN" }
      ]
    }, null, 2),
    invalidManifest: JSON.stringify({
      manifest_version: 4,
      name: "   ",
      version: "01.2.0-beta",
      permissions: ["storage", 42]
    }, null, 2)
  };

  const BENCHMARK_EXTENSIONS = [
    { id: "ublock-origin", name: "uBlock Origin", category: "content_blockers", url: "https://addons.mozilla.org/en-US/firefox/addon/ublock-origin/" },
    { id: "adblock-plus", name: "Adblock Plus", category: "content_blockers", url: "https://addons.mozilla.org/en-US/firefox/addon/adblock-plus/" },
    { id: "adguard-adblocker", name: "AdGuard AdBlocker", category: "content_blockers", url: "https://addons.mozilla.org/en-US/firefox/addon/adguard-adblocker/" },
    { id: "adblock-for-firefox", name: "AdBlock for Firefox", category: "content_blockers", url: "https://addons.mozilla.org/en-US/firefox/addon/adblock-for-firefox/" },
    { id: "adblocker-ultimate", name: "AdBlocker Ultimate", category: "content_blockers", url: "https://addons.mozilla.org/en-US/firefox/addon/adblocker-ultimate/" },
    { id: "ghostery", name: "Ghostery", category: "content_blockers", url: "https://addons.mozilla.org/en-US/firefox/addon/ghostery/" },
    { id: "sponsorblock", name: "SponsorBlock", category: "content_blockers", url: "https://addons.mozilla.org/en-US/firefox/addon/sponsorblock/" },
    { id: "adblock-for-youtube", name: "AdBlocker for YouTube", category: "content_blockers", url: "https://addons.mozilla.org/en-US/firefox/addon/adblock-for-youtube/" },
    { id: "to-google-translate", name: "To Google Translate", category: "translators", url: "https://addons.mozilla.org/en-US/firefox/addon/to-google-translate/" },
    { id: "traduzir-paginas-web", name: "TWP - Translate Web Pages", category: "translators", url: "https://addons.mozilla.org/en-US/firefox/addon/traduzir-paginas-web/" },
    { id: "simple-translate", name: "Simple Translate", category: "translators", url: "https://addons.mozilla.org/en-US/firefox/addon/simple-translate/" },
    { id: "deepl-translate", name: "DeepL Translator", category: "translators", url: "https://addons.mozilla.org/en-US/firefox/addon/deepl-translate/" },
    { id: "google-translator-for-firefox", name: "Google Translator", category: "translators", url: "https://addons.mozilla.org/en-US/firefox/addon/google-translator-for-firefox/" },
    { id: "immersive-translate", name: "Immersive Translate", category: "translators", url: "https://addons.mozilla.org/en-US/firefox/addon/immersive-translate/" },
    { id: "imtranslator", name: "ImTranslator", category: "translators", url: "https://addons.mozilla.org/en-US/firefox/addon/imtranslator/" },
    { id: "edge_translate", name: "Edge Translate", category: "translators", url: "https://addons.mozilla.org/en-US/firefox/addon/edge_translate/" },
    { id: "bitwarden-password-manager", name: "Bitwarden", category: "password_managers", url: "https://addons.mozilla.org/en-US/firefox/addon/bitwarden-password-manager/" },
    { id: "lastpass-password-manager", name: "LastPass", category: "password_managers", url: "https://addons.mozilla.org/en-US/firefox/addon/lastpass-password-manager/" },
    { id: "1password-x-password-manager", name: "1Password", category: "password_managers", url: "https://addons.mozilla.org/en-US/firefox/addon/1password-x-password-manager/" },
    { id: "proton-pass", name: "Proton Pass", category: "password_managers", url: "https://addons.mozilla.org/en-US/firefox/addon/proton-pass/" },
    { id: "keepassxc-browser", name: "KeePassXC-Browser", category: "password_managers", url: "https://addons.mozilla.org/en-US/firefox/addon/keepassxc-browser/" },
    { id: "norton-password-manager", name: "Norton Password Manager", category: "password_managers", url: "https://addons.mozilla.org/en-US/firefox/addon/norton-password-manager/" },
    { id: "nordpass-password-management", name: "NordPass", category: "password_managers", url: "https://addons.mozilla.org/en-US/firefox/addon/nordpass-password-management/" },
    { id: "dashlane", name: "Dashlane", category: "password_managers", url: "https://addons.mozilla.org/en-US/firefox/addon/dashlane/" },
    { id: "keeper-password-manager", name: "Keeper", category: "password_managers", url: "https://addons.mozilla.org/en-US/firefox/addon/keeper-password-manager/" },
    { id: "react-devtools", name: "React Developer Tools", category: "developer_tools", url: "https://addons.mozilla.org/en-US/firefox/addon/react-devtools/" },
    { id: "web-developer", name: "Web Developer", category: "developer_tools", url: "https://addons.mozilla.org/en-US/firefox/addon/web-developer/" },
    { id: "jsonview", name: "JSONView", category: "developer_tools", url: "https://addons.mozilla.org/en-US/firefox/addon/jsonview/" },
    { id: "json-lite", name: "JSON Lite", category: "developer_tools", url: "https://addons.mozilla.org/en-US/firefox/addon/json-lite/" },
    { id: "cookie-editor", name: "Cookie-Editor", category: "developer_tools", url: "https://addons.mozilla.org/en-US/firefox/addon/cookie-editor/" },
    { id: "styl-us", name: "Stylus", category: "developer_tools", url: "https://addons.mozilla.org/en-US/firefox/addon/styl-us/" },
    { id: "header-editor", name: "Header Editor", category: "developer_tools", url: "https://addons.mozilla.org/en-US/firefox/addon/header-editor/" },
    { id: "axe-devtools", name: "axe DevTools", category: "developer_tools", url: "https://addons.mozilla.org/en-US/firefox/addon/axe-devtools/" },
    { id: "user-agent-string-switcher", name: "User-Agent Switcher", category: "developer_tools", url: "https://addons.mozilla.org/en-US/firefox/addon/user-agent-string-switcher/" },
    { id: "save-page-we", name: "Save Page WE", category: "developer_tools", url: "https://addons.mozilla.org/en-US/firefox/addon/save-page-we/" },
    { id: "multi-account-containers", name: "Multi-Account Containers", category: "productivity", url: "https://addons.mozilla.org/en-US/firefox/addon/multi-account-containers/" },
    { id: "tab-session-manager", name: "Tab Session Manager", category: "productivity", url: "https://addons.mozilla.org/en-US/firefox/addon/tab-session-manager/" },
    { id: "cookie-autodelete", name: "Cookie AutoDelete", category: "productivity", url: "https://addons.mozilla.org/en-US/firefox/addon/cookie-autodelete/" },
    { id: "tree-style-tab", name: "Tree Style Tab", category: "productivity", url: "https://addons.mozilla.org/en-US/firefox/addon/tree-style-tab/" },
    { id: "onetab", name: "OneTab", category: "productivity", url: "https://addons.mozilla.org/en-US/firefox/addon/onetab/" },
    { id: "simple-tab-groups", name: "Simple Tab Groups", category: "productivity", url: "https://addons.mozilla.org/en-US/firefox/addon/simple-tab-groups/" },
    { id: "sidebery", name: "Sidebery", category: "productivity", url: "https://addons.mozilla.org/en-US/firefox/addon/sidebery/" },
    { id: "raindropio", name: "Raindrop.io", category: "productivity", url: "https://addons.mozilla.org/en-US/firefox/addon/raindropio/" },
    { id: "feedbroreader", name: "Feedbro", category: "productivity", url: "https://addons.mozilla.org/en-US/firefox/addon/feedbroreader/" },
    { id: "darkreader", name: "Dark Reader", category: "appearance", url: "https://addons.mozilla.org/en-US/firefox/addon/darkreader/" },
    { id: "adaptive-tab-bar-colour", name: "Adaptive Tab Bar Color", category: "appearance", url: "https://addons.mozilla.org/en-US/firefox/addon/adaptive-tab-bar-colour/" },
    { id: "docsafterdark", name: "DocsAfterDark", category: "appearance", url: "https://addons.mozilla.org/en-US/firefox/addon/docsafterdark/" },
    { id: "turn-off-the-lights", name: "Turn Off the Lights", category: "appearance", url: "https://addons.mozilla.org/en-US/firefox/addon/turn-off-the-lights/" },
    { id: "new-tab-override", name: "New Tab Override", category: "appearance", url: "https://addons.mozilla.org/en-US/firefox/addon/new-tab-override/" },
    { id: "bonjourr-startpage", name: "Bonjourr New Tab", category: "appearance", url: "https://addons.mozilla.org/en-US/firefox/addon/bonjourr-startpage/" }
  ];

  const ARCH_FILES = {
    lock: `// config/firefox.lock.json — Revisão upstream fixada e hashes SHA-256
{
  "schema": 1,
  "upstream": {
    "repository": "https://hg.mozilla.org/mozilla-central",
    "channel": "firefox-esr-pinned",
    "verification": "sha256-strict"
  },
  "assertions": {
    "abortOnDrift": true,
    "preserveMozAppId": true,
    "isolatedProfileRoot": "~/.argon/argon"
  },
  "trackedFiles": [
    "browser/app/profile/firefox.js",
    "browser/base/content/browser.xhtml",
    "browser/themes/shared/browser-shared.css",
    "old-configure.in"
  ]
}`,
    overlay: `// config/overlay.json — Patches declarativos e tokens de geometria
{
  "schema": 1,
  "appName": "argon",
  "vendor": "Argon",
  "bundleId": "org.argon.browser",
  "injections": [
    {
      "target": "browser/app/profile/firefox.js",
      "include": "argon/preferences/argon-prefs.js",
      "mode": "append-verified"
    },
    {
      "target": "browser/themes/shared/browser-shared.css",
      "include": "argon/design-system/tokens.css",
      "tokens": [
        "--argon-toolbar-height: 48px",
        "--argon-sidebar-width: 240px"
      ]
    }
  ]
}`,
    prefs: `// argon/preferences/argon-prefs.js — Privacidade e interface por padrão
pref("argon.telemetry.enabled", false);
pref("datareporting.healthreport.uploadEnabled", false);
pref("toolkit.telemetry.enabled", false);
pref("app.normandy.enabled", false);
pref("app.shield.optoutstudies.enabled", false);

// Geometria e tema padrão do navegador
pref("argon.tabs.layout", "vertical"); // "vertical" (240px) | "horizontal"
pref("argon.theme.mode", "auto");      // "light" | "dark" | "auto"
pref("argon.toolbar.heightPx", 48);`,
    mozconfig: `# config/mozconfig — Identidade isolada do binário Argon
ac_add_options --enable-application=browser
ac_add_options --with-app-name=argon
ac_add_options --with-branding=argon/branding/official
export MOZ_APP_VENDOR="Argon"
export MOZ_APP_PROFILE="argon"
export MOZ_APP_REMOTINGNAME="argon"
export MOZ_TELEMETRY_REPORTING=
export MOZ_CRASHREPORTER=
export MOZ_UPDATER=`
  };

  const DOWNLOADABLE_ASSETS = {
    "mark-primary.svg": `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" role="img" aria-label="Argon Primary Mark">\n  <title>Argon Primary Mark</title>\n  <rect width="128" height="128" rx="20" fill="#1E1E1E"/>\n  <g fill="#FBF8F4">\n    <path d="M16 106 56.4 27.5A8.55 8.55 0 0 1 71.6 27.5L112 106H97L64 41.5 31 106Z"/>\n    <path d="M50.5 78H77.5L82 87H46Z"/>\n  </g>\n</svg>`,
    "mark-inverted.svg": `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" role="img" aria-label="Argon Inverted Mark">\n  <title>Argon Inverted Mark</title>\n  <rect width="128" height="128" rx="20" fill="#FBF8F4"/>\n  <g fill="#1E1E1E">\n    <path d="M16 106 56.4 27.5A8.55 8.55 0 0 1 71.6 27.5L112 106H97L64 41.5 31 106Z"/>\n    <path d="M50.5 78H77.5L82 87H46Z"/>\n  </g>\n</svg>`,
    "mark-private.svg": `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" role="img" aria-label="Argon Private Browsing Mark">\n  <title>Argon Private Browsing Mark</title>\n  <rect width="128" height="128" rx="20" fill="#15171B"/>\n  <g fill="#6478F5">\n    <path d="M16 106 56.4 27.5A8.55 8.55 0 0 1 71.6 27.5L112 106H97L64 41.5 31 106Z"/>\n    <path d="M50.5 78H77.5L82 87H46Z"/>\n  </g>\n</svg>`,
    "construction-grid.svg": `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256" role="img" aria-label="Argon Mark Construction Grid">\n  <rect width="256" height="256" fill="#15171B"/>\n  <g transform="translate(64 64)">\n    <rect width="128" height="128" rx="20" fill="#1E1E1E" stroke="#2F333C" stroke-width="1"/>\n    <g fill="#FBF8F4">\n      <path d="M16 106 56.4 27.5A8.55 8.55 0 0 1 71.6 27.5L112 106H97L64 41.5 31 106Z"/>\n      <path d="M50.5 78H77.5L82 87H46Z"/>\n    </g>\n    <g stroke="#6478F5" stroke-width="0.75" stroke-dasharray="2 2" fill="none">\n      <line x1="64" y1="-20" x2="64" y2="148"/>\n      <line x1="-20" y1="22.85" x2="148" y2="22.85"/>\n      <line x1="-20" y1="41.5" x2="148" y2="41.5"/>\n      <line x1="-20" y1="78" x2="148" y2="78"/>\n      <line x1="-20" y1="87" x2="148" y2="87"/>\n      <line x1="-20" y1="106" x2="148" y2="106"/>\n      <line x1="16" y1="-12" x2="16" y2="140"/>\n      <line x1="112" y1="-12" x2="112" y2="140"/>\n      <circle cx="64" cy="31.4" r="8.55" stroke-dasharray="none"/>\n      <circle cx="20" cy="20" r="20"/>\n    </g>\n  </g>\n</svg>`,
    "brand-tokens.json": JSON.stringify({
      schema: 1,
      brand: { name: "Argon", fullName: "Argon Browser", vendor: "Argon", bundleId: "org.argon.browser" },
      mark: {
        gridUnits: 128,
        cornerRadius: 20,
        cornerRadiusRatio: 0.15625,
        apexCircle: { cx: 64.0, cy: 31.4, r: 8.55, topY: 22.85 },
        innerVertex: { x: 64.0, y: 41.5 },
        baselineY: 106.0,
        leftFootX: [16.0, 31.0],
        rightFootX: [97.0, 112.0],
        crossbar: { topY: 78.0, bottomY: 87.0, topX: [50.5, 77.5], bottomX: [46.0, 82.0], detachedGapUnits: 6.5 }
      },
      colors: {
        brandCore: { obsidian: "#1E1E1E", ivory: "#FBF8F4" },
        accent: { primary: "#6478F5", strong: "#4C62D6" },
        chromeDark: { bg: "#15171B", surface: "#23262D", text: "#F7F8FA" },
        chromeLight: { bg: "#F7F8FA", surface: "#FFFFFF", text: "#15171B" }
      }
    }, null, 2)
  };

  const I18N = {
    pt: {
      navHighlights: "Destaques",
      navExtensions: "Extensões",
      navArch: "Código aberto",
      navCompare: "Comparar",
      navBrand: "Brand kit",
      navDownload: "Baixar",
      themeLight: "Claro",
      themeDark: "Escuro",
      themeAuto: "Auto",
      heroMeta: "Pré-alfa aberta para Linux · Baseado no Firefox e LibreWolf",
      heroHeading: "Navegador focado em privacidade, sem distrações",
      heroLead: "O Argon desativa toda telemetria de fábrica, isola seu perfil e alterna entre abas verticais e horizontais em uma interface plana e silenciosa. Por padrão.",
      heroPrimaryCta: "Baixar para Linux",
      heroSecondaryCta: "Ver código no GitHub",
      hlStep0: "Interface",
      hlStep1: "Privacidade",
      hlStep2: "Extensões",
      hlStep3: "Fluxo",
      hlTitle0: "Simples, na orientação que você preferir",
      hlBody0: "O Argon foi desenhado para sair do seu caminho. Uma barra superior plana de <code>48 px</code> sem bordas tridimensionais nem botões supérfluos.<br><br>Use abas verticais em uma lateral de <code>240 px</code> ou abas horizontais clássicas, com temas Claro, Escuro ou sincronizado ao sistema.<br><br>Toda captura ao lado vem direto do binário real rodando no Linux.",
      hlTitle1: "Construído em torno de privacidade e silêncio",
      hlBody1: "Sem Health Report, sem estudos Normandy ou Shield e sem envios em segundo plano para a Mozilla. Tudo desativado em <code>argon-prefs.js</code> antes do primeiro uso.<br><br>Não é preciso desmarcar nada nas configurações.<br><br>Seu perfil vive isolado em <code>~/.argon/argon</code> e nunca bloqueia nem altera seu Firefox atual.",
      hlTitle2: "Extensões nativas, auditadas antes da instalação",
      hlBody2: "O Argon preserva o <code>MOZ_APP_ID</code> do Gecko para rodar add-ons do Firefox nativamente a partir do <code>addons.mozilla.org</code>.<br><br>Para manifestos Chromium MV2 e MV3, o analisador estático inspeciona permissões e lacunas de Service Worker localmente, sem executar código.",
      hlTitle3: "Feito para o teclado, transparente no roadmap",
      hlBody3: "Barra de endereços centralizada, atalhos diretos e uma curva única de movimento (<code>120–200ms</code>) que zera animações sob <code>prefers-reduced-motion</code>.<br><br>A Fase 1 já é verificada via Gecko Marionette; Paleta de Comandos e Workspaces isolados chegam nas Fases 2 e 3.",
      extTitle: "Inspecione qualquer extensão antes de abrir no perfil",
      extBody: "Além de suportar extensões nativas do Firefox, o Argon inclui um analisador estático para arquivos <code>manifest.json</code> MV2 e MV3. Tudo roda localmente via descritores seguros, sem conceder permissões nem executar scripts.<br><br>Explore os exemplos ao lado ou navegue pelo catálogo de referência com 50 extensões do AMO.",
      extBtnCatalog: "Explorar 50 extensões",
      extBtnCli: "Copiar comando CLI",
      studioTabAnalyzer: "Analisador ao vivo",
      studioTabRegistry: "Catálogo AMO (50)",
      archTitle: "Transparente e código aberto",
      archBody: "Todos os componentes do Argon são abertos sob MIT e MPL 2.0. O desenvolvimento acontece em público, de commits a artefatos de CI.<br><br>Em vez de esconder mudanças em uma árvore monolítica do Firefox, cada ajuste é declarado em <code>config/overlay.json</code> sobre uma revisão fixada por SHA-256.<br><br>Use, audite linha por linha, compile do zero ou contribua.",
      archBtnSource: "Explorar repositório",
      archBtnTests: "Copiar suíte de testes",
      cmpTitle: "A janela mais calma, por padrão",
      cmpBody: "O Argon remove ruídos da moldura do navegador para que você foque apenas no conteúdo da página.<br><br>Arraste o controle deslizante para comparar as capturas nativas do Argon no Linux entre abas verticais, horizontais e temas.",
      cmpConnector: "comparado com",
      cmpOpt1: "Abas horizontais (Escuro)",
      cmpOpt2: "Tema claro (Abas verticais)",
      cmpOpt3: "Horizontal claro vs escuro",
      cmpFlipSurface: "Inverter tema base",
      brandTitle: "Identidade visual aberta e geométrica",
      brandSub: "Desenhada sobre um grid de 128 unidades em Argon Obsidian (#1E1E1E) e Argon Ivory (#FBF8F4), livre para artigos, análises e imprensa.",
      brandGridToggleHide: "Ocultar linhas",
      brandGridToggleShow: "Mostrar linhas",
      tryTitle: "Pronto quando você quiser",
      tryBody: "O Argon usa um perfil próprio em ~/.argon/argon e deixa seu navegador atual intacto. Experimente o pacote Flatpak da Fase 1 no Linux ou compile a partir do código fixado.",
      tryPrimaryBtn: "Baixar Flatpak para Linux",
      trySecondaryBtn: "Ver builds no GitHub",
      cliTitle1: "Artifact mode",
      cliTitle2: "Compilação Flatpak",
      cliTitle3: "Suíte de verificação",
      faqLead: "Ainda mais detalhes sobre o Argon",
      faqQ1: "O Argon coleta algum dado pessoal ou telemetria?",
      faqA1: "Não. Compilações do Argon não definem <code>MOZ_TELEMETRY_REPORTING</code> nem <code>MOZILLA_OFFICIAL</code>, e <code>argon-prefs.js</code> desativa envio de dados à Mozilla, Health Report, experimentos Normandy e estudos Shield de fábrica. Tanto o crash reporter quanto o atualizador em segundo plano vêm desligados.",
      faqQ2: "O Argon altera ou bloqueia meu perfil atual do Firefox?",
      faqA2: "Não. O Argon é compilado com <code>MOZ_APP_PROFILE=argon</code>, <code>MOZ_APP_VENDOR=Argon</code> e canal de janelas próprio (<code>WM_CLASS=argon</code>). Ele cria e usa <code>~/.argon/argon</code> sem jamais tocar em <code>~/.mozilla/firefox</code>.",
      faqQ3: "O Argon suporta extensões do Firefox e do Chrome?",
      faqA3: "Extensões WebExtensions padrão do Firefox funcionam nativamente via <a href=\"https://addons.mozilla.org\" target=\"_blank\" rel=\"noopener noreferrer\">addons.mozilla.org</a> porque o Argon preserva o <code>MOZ_APP_ID</code> do Gecko. Para pacotes Chromium MV2/MV3, o Módulo 1 já entrega auditoria estática de <code>manifest.json</code>; shims de API de runtime estão planejados para a Fase 4.",
      faqQ4: "O que já está verificado hoje versus planejado para as próximas fases?",
      faqA4: "<strong>Verificado hoje (Fase 1 · Milestone 0.1):</strong> barra plana de 48 px, abas verticais de 240 px e horizontais, temas Claro/Escuro/Sistema validados via Marionette, overlay com trava SHA-256, branding Linux Flatpak e analisador estático de manifesto.<br><br><strong>Planejado:</strong> Paleta de Comandos e <code>about:argon</code> (Fase 2), Workspaces isolados e suspensão de abas (Fase 3) e ponte de runtime MV3 com testes nas 50 extensões do catálogo (Fase 4).",
      faqQ5: "Como o Argon acompanha atualizações de segurança do Firefox?",
      faqA5: "Por meio do arquivo <code>config/firefox.lock.json</code>, que fixa a revisão upstream e o hash SHA-256 de cada arquivo tocado pelo Argon. Quando uma nova revisão do Firefox é adotada, <code>npm run apply</code> valida cada hash atomicamente antes de aplicar os patches declarativos.",
      faqQ6: "O Argon é gratuito e 100% código aberto?",
      faqA6: "Sim, em preço e em liberdade. Todo o código próprio do Argon está sob licença <code>MIT</code> e os arquivos derivados do Firefox/Gecko permanecem sob <code>MPL 2.0</code>, sem camadas pagas, sem adware e sem serviços proprietários ocultos.",
      faqQ7: "Onde posso acompanhar o projeto ou relatar problemas?",
      faqA7: "Acompanhe novidades pelo <a href=\"https://x.com/ArgonBrowser\" target=\"_blank\" rel=\"noopener noreferrer\">X (@ArgonBrowser)</a> e confira commits, execuções de CI ou relate problemas diretamente no <a href=\"https://github.com/Argon-Browser/Argon\" target=\"_blank\" rel=\"noopener noreferrer\">GitHub do Argon Browser</a>.",
      footCol1: "Produto",
      footCol2: "Engenharia",
      footCol3: "Comunidade",
      footCmdBtn: "Paleta de comandos (⌘K)"
    },
    en: {
      navHighlights: "Highlights",
      navExtensions: "Extensions",
      navArch: "Open source",
      navCompare: "Compare",
      navBrand: "Brand kit",
      navDownload: "Download",
      themeLight: "Light",
      themeDark: "Dark",
      themeAuto: "Auto",
      heroMeta: "Open pre-alpha for Linux · Built on Firefox & LibreWolf",
      heroHeading: "Privacy-first browser without distractions",
      heroLead: "Argon strips out telemetry, isolates your profile, and lets you switch between vertical and horizontal tabs in a calm, flat interface. By default.",
      heroPrimaryCta: "Download for Linux",
      heroSecondaryCta: "Check out the source",
      hlStep0: "Interface",
      hlStep1: "Privacy",
      hlStep2: "Extensions",
      hlStep3: "Workflow",
      hlTitle0: "Simple, in the orientation you want",
      hlBody0: "Argon is designed to get out of your way. A flat <code>48 px</code> top bar with no 3D bevels or visual clutter.<br><br>Switch between <code>240 px</code> vertical tabs or classic horizontal tabs, paired with Light, Dark, or System themes.<br><br>Every capture on the right comes straight from the native Linux build.",
      hlTitle1: "Built around privacy and silence",
      hlBody1: "No Health Report, no Normandy or Shield studies, and no background Mozilla pings. Everything is disabled in <code>argon-prefs.js</code> out of the box.<br><br>No need to opt out of anything.<br><br>Your profile lives isolated in <code>~/.argon/argon</code> and never touches or locks your existing Firefox installation.",
      hlTitle2: "Native add-ons, audited before install",
      hlBody2: "Argon preserves Gecko's upstream <code>MOZ_APP_ID</code> so standard Firefox add-ons from <code>addons.mozilla.org</code> run natively.<br><br>For Chromium MV2 and MV3 manifests, the static analyzer inspects permissions and Service Worker gaps locally without executing extension code.",
      hlTitle3: "Keyboard-first, honest on the roadmap",
      hlBody3: "Centered address bar, direct shortcuts, and a single motion curve (<code>120–200ms</code>) that drops to zero under <code>prefers-reduced-motion</code>.<br><br>Phase 1 is verified today via Gecko Marionette; Command Palette and isolated Workspaces arrive in Phases 2 and 3.",
      extTitle: "Inspect any extension before it touches your profile",
      extBody: "Alongside native Firefox add-ons, Argon ships a static analyzer for MV2 and MV3 <code>manifest.json</code> files. It runs locally via descriptor-safe JSON checks without granting permissions or executing scripts.<br><br>Try the presets on the right or browse the 50-extension AMO benchmark catalog.",
      extBtnCatalog: "Explore 50 extensions",
      extBtnCli: "Copy CLI command",
      studioTabAnalyzer: "Live analyzer",
      studioTabRegistry: "AMO catalog (50)",
      archTitle: "Transparent and open source",
      archBody: "All Argon components are open source under MIT and MPL 2.0. Development happens in public, from commits to CI artifacts.<br><br>Instead of hiding edits inside a monolithic Firefox tree, every patch is declared in <code>config/overlay.json</code> on top of a SHA-256 pinned revision.<br><br>Use it, inspect it line by line, build it yourself, or contribute.",
      archBtnSource: "Check out the source",
      archBtnTests: "Copy test suite command",
      cmpTitle: "The calmest window, by default",
      cmpBody: "Argon removes chrome noise so you can stay focused on the web page you came for.<br><br>Drag the slider to compare real Linux captures of Argon across vertical tabs, horizontal tabs, and themes.",
      cmpConnector: "compared to",
      cmpOpt1: "Horizontal tabs (Dark)",
      cmpOpt2: "Light theme (Vertical tabs)",
      cmpOpt3: "Horizontal light vs dark",
      cmpFlipSurface: "Flip base theme",
      brandTitle: "Open, geometrically measured brand kit",
      brandSub: "Constructed on a 128-unit coordinate grid in Argon Obsidian (#1E1E1E) and Argon Ivory (#FBF8F4), ready for articles, reviews, and media.",
      brandGridToggleHide: "Hide guides",
      brandGridToggleShow: "Show guides",
      tryTitle: "Ready when you are",
      tryBody: "Argon uses a dedicated profile at ~/.argon/argon and leaves your current browser untouched. Try the Phase 1 Linux Flatpak bundle or build from pinned source.",
      tryPrimaryBtn: "Download Linux Flatpak",
      trySecondaryBtn: "View GitHub builds",
      cliTitle1: "Artifact mode",
      cliTitle2: "Flatpak build",
      cliTitle3: "Verification suite",
      faqLead: "Even more details about Argon",
      faqQ1: "Does Argon collect any personal data or telemetry?",
      faqA1: "No. Argon builds unset <code>MOZ_TELEMETRY_REPORTING</code> and <code>MOZILLA_OFFICIAL</code>, and <code>argon-prefs.js</code> disables Mozilla data submission, Health Report, Normandy experiments, and Shield studies out of the box. Both crash reporter and background updater are disabled.",
      faqQ2: "Will Argon touch or lock my existing Firefox profile?",
      faqA2: "Never. Argon builds with <code>MOZ_APP_PROFILE=argon</code>, <code>MOZ_APP_VENDOR=Argon</code>, and a separate remoting name (<code>WM_CLASS=argon</code>). It stores data in <code>~/.argon/argon</code> without touching <code>~/.mozilla/firefox</code>.",
      faqQ3: "Does Argon support Firefox and Chromium extensions?",
      faqA3: "Standard Firefox WebExtensions install natively from <a href=\"https://addons.mozilla.org\" target=\"_blank\" rel=\"noopener noreferrer\">addons.mozilla.org</a> because Argon preserves Gecko's <code>MOZ_APP_ID</code>. For Chromium MV2/MV3 extensions, Module 1 provides static <code>manifest.json</code> auditing today; runtime shims are planned for Phase 4.",
      faqQ4: "What is verified today versus planned on the roadmap?",
      faqA4: "<strong>Verified today (Phase 1 · Milestone 0.1):</strong> flat 48 px toolbar, 240 px vertical and horizontal tabs, Light/Dark/System themes verified via Marionette, SHA-256 locked overlay tooling, Linux Flatpak packaging, and static manifest analysis.<br><br><strong>Planned:</strong> Command Palette and <code>about:argon</code> (Phase 2), isolated Workspaces and tab unloading (Phase 3), and MV3 runtime bridge testing across the 50-extension catalog (Phase 4).",
      faqQ5: "How does Argon stay updated with Firefox security releases?",
      faqA5: "Through <code>config/firefox.lock.json</code>, which pins the exact upstream Firefox revision and SHA-256 hash of every patched file. Updating upstream validates every hash atomically during <code>npm run apply</code>.",
      faqQ6: "Is Argon free and genuinely open source?",
      faqA6: "Yes, both in price and freedom. Original Argon code is licensed under <code>MIT</code> while modified Firefox/Gecko files remain under <code>MPL 2.0</code>, with no paid tiers, no adware, and no hidden services.",
      faqQ7: "Where can I follow development or report issues?",
      faqA7: "Follow updates on <a href=\"https://x.com/ArgonBrowser\" target=\"_blank\" rel=\"noopener noreferrer\">X (@ArgonBrowser)</a> and track commits, CI runs, or open issues on <a href=\"https://github.com/Argon-Browser/Argon\" target=\"_blank\" rel=\"noopener noreferrer\">GitHub</a>.",
      footCol1: "Product",
      footCol2: "Engineering",
      footCol3: "Community",
      footCmdBtn: "Command palette (⌘K)"
    }
  };

  /* =========================================================================
   * 3. VERTICAL-STRIPE SHIMMER CANVAS (Helium Atmospheric Top Wash)
   * ========================================================================= */
  function mountShimmer(canvas) {
    if (!canvas) return { refreshPalette: function () {} };
    const ctx = canvas.getContext("2d");
    if (!ctx) {
      canvas.classList.add("visible");
      return { refreshPalette: function () {} };
    }

    const scratch = document.createElement("canvas").getContext("2d");
    const reducedMedia = window.matchMedia("(prefers-reduced-motion: reduce)");
    const darkMedia = window.matchMedia("(prefers-color-scheme: dark)");

    let width = 1280;
    let height = 420;
    let dpr = 1;
    let wavePhase = 1.1;
    let secPhase = -0.6;
    let rafId = null;
    let lastAt = null;
    let visible = true;

    function parseRgb(val, fallback) {
      const raw = (val || "").trim();
      if (!raw) return fallback;
      if (scratch) {
        scratch.fillStyle = "#000000";
        scratch.fillStyle = raw;
        const norm = scratch.fillStyle;
        if (norm.startsWith("#") && norm.length === 7) {
          return [
            parseInt(norm.slice(1, 3), 16),
            parseInt(norm.slice(3, 5), 16),
            parseInt(norm.slice(5, 7), 16)
          ];
        }
      }
      return fallback;
    }

    function readPalette() {
      const s = getComputedStyle(document.documentElement);
      return {
        start: parseRgb(s.getPropertyValue("--shimmer-start"), [21, 23, 27]),
        highlight: parseRgb(s.getPropertyValue("--shimmer-highlight"), [100, 120, 245]),
        alpha: parseFloat(s.getPropertyValue("--shimmer-alpha")) || 0.18
      };
    }

    let palette = readPalette();

    function resize() {
      const rect = canvas.getBoundingClientRect();
      dpr = Math.min(window.devicePixelRatio || 1, 1.5);
      width = Math.max(320, Math.round(rect.width || window.innerWidth));
      height = Math.max(200, Math.round(rect.height || 420));
      canvas.width = Math.round(width * dpr);
      canvas.height = Math.round(height * dpr);
      palette = readPalette();
    }

    function render(now) {
      const dt = reducedMedia.matches || lastAt === null ? 0 : Math.min((now - lastAt) / 1000, 0.064);
      lastAt = reducedMedia.matches ? null : now;
      if (!reducedMedia.matches) {
        wavePhase += 0.38 * dt;
        secPhase += 0.22 * dt;
      }

      ctx.save();
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, width, height);

      const count = Math.max(8, Math.min(20, Math.round(width / 96)));
      const stripeW = width / count;
      const [sr, sg, sb] = palette.start;
      const [hr, hg, hb] = palette.highlight;

      for (let i = 0; i < count; i += 1) {
        const x = i * stripeW;
        const w = i === count - 1 ? width - x : Math.ceil(stripeW + 0.5);
        const center = 0.46 + Math.sin(wavePhase - i * 0.72) * 0.18 + Math.sin(secPhase + i * 1.24) * 0.05;
        const grad = ctx.createLinearGradient(x, 0, x + stripeW * 0.35, height);
        grad.addColorStop(0, "rgba(" + sr + "," + sg + "," + sb + ",0.1)");
        grad.addColorStop(Math.max(0.08, center - 0.34), "rgba(" + sr + "," + sg + "," + sb + "," + (palette.alpha * 0.45).toFixed(3) + ")");
        grad.addColorStop(Math.max(0.14, Math.min(0.86, center)), "rgba(" + hr + "," + hg + "," + hb + "," + palette.alpha.toFixed(3) + ")");
        grad.addColorStop(Math.min(0.96, center + 0.36), "rgba(" + sr + "," + sg + "," + sb + "," + (palette.alpha * 0.3).toFixed(3) + ")");
        grad.addColorStop(1, "rgba(" + sr + "," + sg + "," + sb + ",0)");
        ctx.fillStyle = grad;
        ctx.fillRect(x, 0, w, height);
      }

      ctx.restore();
    }

    function loop(now) {
      rafId = null;
      render(now);
      if (!reducedMedia.matches && visible) {
        rafId = window.requestAnimationFrame(loop);
      }
    }

    function start() {
      if (rafId === null && !reducedMedia.matches && visible) {
        rafId = window.requestAnimationFrame(loop);
      }
    }

    function stop() {
      if (rafId !== null) {
        window.cancelAnimationFrame(rafId);
        rafId = null;
      }
    }

    resize();
    render(performance.now());
    canvas.classList.add("visible");
    start();

    window.addEventListener("resize", () => {
      resize();
      render(performance.now());
    });

    if ("IntersectionObserver" in window) {
      const io = new IntersectionObserver((entries) => {
        visible = entries[0]?.isIntersecting ?? true;
        if (!visible) stop();
        else {
          lastAt = null;
          start();
        }
      });
      io.observe(canvas);
    }

    darkMedia.addEventListener("change", () => {
      palette = readPalette();
      render(performance.now());
    });
    reducedMedia.addEventListener("change", () => {
      if (reducedMedia.matches) stop();
      else start();
      render(performance.now());
    });

    return {
      refreshPalette: function () {
        palette = readPalette();
        render(performance.now());
      }
    };
  }

  /* =========================================================================
   * 4. MAIN INTERACTIVE CONTROLLER
   * ========================================================================= */
  function initSite() {
    let currentLang = "pt";
    let currentReportView = "visual";
    let currentExtCat = "all";
    let currentExtQuery = "";
    let currentArchKey = "lock";

    const shimmer = mountShimmer(document.getElementById("hero-shimmer-canvas"));

    // Toast helper
    function showToast(msg) {
      const toast = document.getElementById("copy-toast");
      if (!toast) return;
      toast.textContent = msg;
      toast.classList.add("visible");
      window.clearTimeout(toast.__timer);
      toast.__timer = window.setTimeout(() => toast.classList.remove("visible"), 2200);
    }

    async function copyText(text, label) {
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          await navigator.clipboard.writeText(text);
        } else {
          const ta = document.createElement("textarea");
          ta.value = text;
          document.body.appendChild(ta);
          ta.select();
          document.execCommand("copy");
          ta.remove();
        }
      } catch {
        const ta = document.createElement("textarea");
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand("copy"); } catch {}
        ta.remove();
      }
      showToast(label || (currentLang === "pt" ? "Copiado para a área de transferência" : "Copied to clipboard"));
    }

    function downloadAsset(filename) {
      const content = DOWNLOADABLE_ASSETS[filename];
      if (!content) return;
      const mime = filename.endsWith(".json") ? "application/json" : "image/svg+xml";
      const blob = new Blob([content], { type: mime + ";charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "argon-" + filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      showToast((currentLang === "pt" ? "Baixando " : "Downloading ") + "argon-" + filename);
    }

    // Header Scroll & Responsive Menu
    const header = document.getElementById("site-header");
    const menuToggle = document.getElementById("menu-toggle");
    const linksBox = document.getElementById("links");
    const chevron = menuToggle?.querySelector(".chevron");
    const mobileMedia = window.matchMedia("(max-width: 880px)");

    function syncMenuA11y() {
      if (!linksBox || !header) return;
      const closedMobile = mobileMedia.matches && !header.classList.contains("menuOpen");
      linksBox.inert = closedMobile;
      if (closedMobile) linksBox.setAttribute("aria-hidden", "true");
      else linksBox.removeAttribute("aria-hidden");
    }

    function closeMobileMenu(restoreFocus) {
      if (!header || !menuToggle) return;
      header.classList.remove("menuOpen");
      menuToggle.setAttribute("aria-expanded", "false");
      chevron?.classList.remove("open");
      if (restoreFocus) menuToggle.focus();
      syncMenuA11y();
    }

    const onScroll = () => {
      if (header) header.classList.toggle("scrolled", window.scrollY > 10);
    };
    onScroll();
    syncMenuA11y();
    window.addEventListener("scroll", onScroll, { passive: true });
    mobileMedia.addEventListener("change", () => closeMobileMenu(false));

    if (menuToggle && header) {
      menuToggle.addEventListener("click", () => {
        const open = header.classList.toggle("menuOpen");
        menuToggle.setAttribute("aria-expanded", String(open));
        chevron?.classList.toggle("open", open);
        syncMenuA11y();
      });
    }

    document.addEventListener("click", (e) => {
      if (header?.classList.contains("menuOpen") && !header.contains(e.target)) {
        closeMobileMenu(false);
      }
    });

    linksBox?.querySelectorAll("a").forEach((a) => {
      a.addEventListener("click", () => {
        if (mobileMedia.matches) closeMobileMenu(false);
      });
    });

    // Theme Switcher (Light / Dark / Auto)
    const themeBtns = document.querySelectorAll("[data-theme-mode]");
    function applyTheme(mode) {
      const root = document.documentElement;
      if (mode === "light" || mode === "dark") {
        root.setAttribute("data-argon-color-scheme", mode);
      } else {
        root.removeAttribute("data-argon-color-scheme");
      }
      themeBtns.forEach((btn) => {
        const active = btn.getAttribute("data-theme-mode") === mode;
        btn.classList.toggle("active", active);
        btn.setAttribute("aria-pressed", String(active));
      });
      try { localStorage.setItem("argon-site-theme", mode); } catch {}
      window.requestAnimationFrame(() => shimmer.refreshPalette());
    }

    let initialTheme = "auto";
    try { initialTheme = localStorage.getItem("argon-site-theme") || "auto"; } catch {}
    applyTheme(initialTheme);

    themeBtns.forEach((btn) => {
      btn.addEventListener("click", () => applyTheme(btn.getAttribute("data-theme-mode") || "auto"));
    });

    // Highlight 4-Panel Showcase (Helium Progress-Dot Pill + Step Pills)
    const hlSection = document.getElementById("highlights");
    const hlPanels = Array.from(document.querySelectorAll(".highlight-panel"));
    const hlStages = Array.from(document.querySelectorAll(".highlight-stage"));
    const hlDots = Array.from(document.querySelectorAll(".progress-dot"));
    const hlSteps = Array.from(document.querySelectorAll(".highlight-step-btn"));
    const pauseBtn = document.getElementById("highlight-pause-btn");
    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

    let activeHl = 0;
    let userPaused = reducedMotion.matches;
    let hlInView = true;
    let hlTimer = null;

    function isHlPaused() {
      return userPaused || reducedMotion.matches || !hlInView || document.visibilityState !== "visible";
    }

    function syncHlPlayback() {
      const paused = isHlPaused();
      if (hlSection) hlSection.classList.toggle("playback-paused", paused);
      if (pauseBtn) {
        pauseBtn.classList.toggle("is-paused", paused);
        pauseBtn.setAttribute("aria-pressed", String(paused));
        pauseBtn.setAttribute(
          "aria-label",
          paused
            ? (currentLang === "pt" ? "Retomar progressão dos destaques" : "Resume highlight progression")
            : (currentLang === "pt" ? "Pausar progressão dos destaques" : "Pause highlight progression")
        );
      }
      window.clearTimeout(hlTimer);
      if (!paused && hlPanels.length > 0) {
        hlTimer = window.setTimeout(() => {
          setHighlight((activeHl + 1) % hlPanels.length, false, false);
        }, 9500);
      }
    }

    function setHighlight(index, manual, focusDot) {
      if (hlPanels.length === 0) return;
      activeHl = (index + hlPanels.length) % hlPanels.length;
      if (manual) userPaused = true;

      hlPanels.forEach((p, i) => {
        const active = i === activeHl;
        p.classList.toggle("visible", active);
        p.setAttribute("aria-hidden", String(!active));
      });
      hlStages.forEach((s, i) => {
        const active = i === activeHl;
        s.classList.toggle("visible", active);
        s.setAttribute("aria-hidden", String(!active));
        s.inert = !active;
      });
      hlSteps.forEach((btn, i) => {
        const active = i === activeHl;
        btn.classList.toggle("active", active);
        btn.setAttribute("aria-pressed", String(active));
      });
      hlDots.forEach((dot, i) => {
        const active = i === activeHl;
        dot.classList.toggle("active", active);
        dot.setAttribute("aria-selected", String(active));
        dot.setAttribute("tabindex", active ? "0" : "-1");
        const fill = dot.querySelector(".progress-fill");
        if (fill) {
          fill.classList.remove("animating");
          if (active) {
            void fill.offsetWidth;
            fill.classList.add("animating");
          }
        }
        if (active && focusDot) dot.focus();
      });

      syncHlPlayback();
    }

    hlDots.forEach((dot, i) => {
      dot.addEventListener("click", () => setHighlight(i, true, false));
      dot.addEventListener("keydown", (e) => {
        if (e.key === "ArrowRight") { e.preventDefault(); setHighlight(i + 1, true, true); }
        else if (e.key === "ArrowLeft") { e.preventDefault(); setHighlight(i - 1, true, true); }
        else if (e.key === "Home") { e.preventDefault(); setHighlight(0, true, true); }
        else if (e.key === "End") { e.preventDefault(); setHighlight(hlDots.length - 1, true, true); }
      });
    });

    hlSteps.forEach((btn, i) => {
      btn.addEventListener("click", () => setHighlight(i, true, false));
    });

    if (pauseBtn) {
      pauseBtn.addEventListener("click", () => {
        userPaused = !userPaused;
        syncHlPlayback();
      });
    }

    if (hlSection && "IntersectionObserver" in window) {
      const obs = new IntersectionObserver((entries) => {
        hlInView = entries[0]?.isIntersecting ?? true;
        syncHlPlayback();
      }, { threshold: 0.25 });
      obs.observe(hlSection);
    }

    document.addEventListener("visibilitychange", syncHlPlayback);
    reducedMotion.addEventListener("change", () => {
      if (reducedMotion.matches) userPaused = true;
      syncHlPlayback();
    });

    setHighlight(0, false, false);

    // Stage 0 Live Linux Browser Capture Switcher
    const stageLayoutBtns = document.querySelectorAll("[data-chrome-layout-btn]");
    const stageImg = document.getElementById("stage-chrome-screenshot");
    const stageToken = document.getElementById("stage-token-readout");

    function setChromeCapture(stateId) {
      const st = CHROME_STATES.find((s) => s.id === stateId) || CHROME_STATES[0];
      stageLayoutBtns.forEach((b) => {
        const active = b.getAttribute("data-chrome-layout-btn") === st.id;
        b.classList.toggle("active", active);
        b.setAttribute("aria-pressed", String(active));
      });
      if (stageImg) stageImg.src = st.screenshot;
      if (stageToken) stageToken.textContent = st.tokenSummary;
    }

    stageLayoutBtns.forEach((b) => {
      b.addEventListener("click", () => setChromeCapture(b.getAttribute("data-chrome-layout-btn")));
    });

    // Extension Bridge Studio (Tabs + Analyzer + 50-Extension Registry)
    const studioTabs = document.querySelectorAll("[data-studio-tab]");
    const paneAnalyzer = document.getElementById("studio-pane-analyzer");
    const paneRegistry = document.getElementById("studio-pane-registry");
    const jumpRegistryBtn = document.getElementById("jump-to-registry-btn");

    function switchStudioTab(tab) {
      studioTabs.forEach((btn) => {
        const active = btn.getAttribute("data-studio-tab") === tab;
        btn.classList.toggle("active", active);
        btn.setAttribute("aria-selected", String(active));
      });
      if (paneAnalyzer) paneAnalyzer.classList.toggle("visible", tab === "analyzer");
      if (paneRegistry) paneRegistry.classList.toggle("visible", tab === "registry");
    }

    studioTabs.forEach((btn) => {
      btn.addEventListener("click", () => switchStudioTab(btn.getAttribute("data-studio-tab")));
    });

    if (jumpRegistryBtn) {
      jumpRegistryBtn.addEventListener("click", () => {
        switchStudioTab("registry");
        paneRegistry?.scrollIntoView({ behavior: "smooth", block: "nearest" });
      });
    }

    const manifestInput = document.getElementById("manifest-input");
    const reportBody = document.getElementById("analyzer-report-body");
    const exitBadge = document.getElementById("analyzer-exit-badge");
    const presetBtns = document.querySelectorAll("[data-manifest-preset]");
    const viewBtns = document.querySelectorAll("[data-report-view]");
    const formatBtn = document.getElementById("format-manifest-btn");

    function joinPerms(arr) {
      if (!Array.isArray(arr) || arr.length === 0) return "none";
      return arr.map((x) => typeof x === "string" ? x : (x.value || x.pattern || "")).filter(Boolean).join(", ") || "none";
    }

    function renderManifestAnalysis() {
      if (!manifestInput || !reportBody) return;
      reportBody.textContent = "";

      let parsed;
      try {
        parsed = JSON.parse(manifestInput.value);
      } catch (err) {
        if (exitBadge) {
          exitBadge.textContent = "exit 3";
          exitBadge.className = "quiet-status error";
        }
        const banner = document.createElement("div");
        banner.className = "verdict-banner error";
        banner.textContent = "INPUT_ERROR · Malformed JSON";
        const item = document.createElement("div");
        item.className = "finding-item";
        item.textContent = err instanceof Error ? err.message : "Invalid JSON syntax.";
        reportBody.append(banner, item);
        return;
      }

      const report = analyzeManifest(parsed);
      const exitCode = !report.valid ? 2 : report.requiresManualReview ? 1 : 0;

      if (exitBadge) {
        exitBadge.textContent = "exit " + exitCode;
        exitBadge.className = exitCode === 0 ? "quiet-status ok" : exitCode === 1 ? "quiet-status review" : "quiet-status error";
      }

      if (currentReportView === "cli") {
        const pre = document.createElement("pre");
        pre.className = "cli-raw-pre";
        pre.textContent = formatCliReport(report);
        reportBody.appendChild(pre);
        return;
      }

      if (currentReportView === "json") {
        const pre = document.createElement("pre");
        pre.className = "cli-raw-pre";
        pre.textContent = JSON.stringify(report, null, 2);
        reportBody.appendChild(pre);
        return;
      }

      const banner = document.createElement("div");
      banner.className = "verdict-banner " + (exitCode === 0 ? "ok" : exitCode === 1 ? "review" : "error");
      const sLeft = document.createElement("span");
      sLeft.textContent = report.assessment;
      const sRight = document.createElement("span");
      sRight.textContent = "MV" + (report.manifest.manifestVersion || "?") + " · " + (report.manifest.name || "Unnamed");
      banner.append(sLeft, sRight);
      reportBody.appendChild(banner);

      const permItem = document.createElement("div");
      permItem.className = "finding-item";
      const s1 = document.createElement("strong");
      s1.textContent = "API: ";
      const t1 = document.createTextNode(joinPerms(report.permissions.required.api) + " · ");
      const s2 = document.createElement("strong");
      s2.textContent = "Hosts: ";
      const t2 = document.createTextNode(joinPerms(report.permissions.required.hosts));
      permItem.append(s1, t1, s2, t2);
      reportBody.appendChild(permItem);

      const list = document.createElement("div");
      list.className = "findings-list";
      if (report.findings.length === 0) {
        const okItem = document.createElement("div");
        okItem.className = "finding-item";
        const c = document.createElement("code");
        c.textContent = "NO_KNOWN_STATIC_ISSUES";
        okItem.append(c, document.createTextNode(" — All declared keys, permissions, and match patterns passed static checks."));
        list.appendChild(okItem);
      } else {
        report.findings.slice(0, 6).forEach((f) => {
          const row = document.createElement("div");
          row.className = "finding-item";
          const c = document.createElement("code");
          c.textContent = f.code;
          const p = document.createElement("span");
          p.className = "finding-path";
          p.textContent = f.path ? " (" + f.path + ")" : "";
          row.append(c, p, document.createTextNode(" — " + f.message));
          list.appendChild(row);
        });
      }
      reportBody.appendChild(list);
    }

    function loadManifestPreset(key) {
      const json = SAMPLE_MANIFESTS[key] || SAMPLE_MANIFESTS.mv3ServiceWorker;
      presetBtns.forEach((b) => {
        const active = b.getAttribute("data-manifest-preset") === key;
        b.classList.toggle("active-pill", active);
        b.setAttribute("aria-pressed", String(active));
      });
      if (manifestInput) manifestInput.value = json;
      renderManifestAnalysis();
    }

    presetBtns.forEach((b) => {
      b.addEventListener("click", () => loadManifestPreset(b.getAttribute("data-manifest-preset")));
    });

    viewBtns.forEach((b) => {
      b.addEventListener("click", () => {
        currentReportView = b.getAttribute("data-report-view") || "visual";
        viewBtns.forEach((v) => {
          const active = v.getAttribute("data-report-view") === currentReportView;
          v.classList.toggle("active", active);
          v.setAttribute("aria-pressed", String(active));
        });
        renderManifestAnalysis();
      });
    });

    if (formatBtn && manifestInput) {
      formatBtn.addEventListener("click", () => {
        try {
          manifestInput.value = JSON.stringify(JSON.parse(manifestInput.value), null, 2);
          renderManifestAnalysis();
          showToast(currentLang === "pt" ? "JSON formatado" : "Formatted JSON");
        } catch {
          showToast(currentLang === "pt" ? "JSON inválido para formatar" : "Invalid JSON syntax");
        }
      });
    }

    if (manifestInput) {
      manifestInput.addEventListener("input", () => {
        presetBtns.forEach((b) => {
          b.classList.remove("active-pill");
          b.setAttribute("aria-pressed", "false");
        });
        renderManifestAnalysis();
      });
    }

    loadManifestPreset("mv3ServiceWorker");

    // 50-Extension Benchmark Catalog
    const registryGrid = document.getElementById("registry-grid");
    const registrySearch = document.getElementById("registry-search");
    const catBtns = document.querySelectorAll("[data-ext-cat]");

    const CAT_NAMES_PT = {
      content_blockers: "Bloqueador",
      translators: "Tradutor",
      password_managers: "Senhas",
      developer_tools: "DevTools",
      productivity: "Produtividade",
      appearance: "Aparência"
    };
    const CAT_NAMES_EN = {
      content_blockers: "Blocker",
      translators: "Translator",
      password_managers: "Passwords",
      developer_tools: "DevTools",
      productivity: "Productivity",
      appearance: "Appearance"
    };

    function simulateExt(ext) {
      const templates = {
        content_blockers: { manifest_version: 3, name: ext.name, version: "1.58.0", permissions: ["declarativeNetRequest", "storage", "tabs"], host_permissions: ["<all_urls>"], background: { service_worker: "background.js" } },
        translators: { manifest_version: 3, name: ext.name, version: "2.10.0", permissions: ["activeTab", "contextMenus", "storage", "scripting"], host_permissions: ["https://*/*"] },
        password_managers: { manifest_version: 3, name: ext.name, version: "2026.10.1", permissions: ["storage", "tabs", "contextMenus", "clipboardWrite", "nativeMessaging"], host_permissions: ["https://*/*"] },
        developer_tools: { manifest_version: 3, name: ext.name, version: "5.2.0", devtools_page: "devtools.html", permissions: ["storage", "tabs", "scripting"], host_permissions: ["<all_urls>"] },
        productivity: { manifest_version: 2, name: ext.name, version: "3.9.4", permissions: ["tabs", "sessions", "storage", "contextualIdentities"], background: { scripts: ["background.js"], persistent: false } },
        appearance: { manifest_version: 3, name: ext.name, version: "4.9.88", permissions: ["storage", "activeTab", "theme"], host_permissions: ["https://*/*"] }
      };
      if (manifestInput) {
        manifestInput.value = JSON.stringify(templates[ext.category] || templates.productivity, null, 2);
      }
      switchStudioTab("analyzer");
      renderManifestAnalysis();
      showToast((currentLang === "pt" ? "Manifesto carregado: " : "Loaded manifest: ") + ext.name);
    }

    function renderRegistry() {
      if (!registryGrid) return;
      registryGrid.textContent = "";
      const q = currentExtQuery.trim().toLowerCase();
      const map = currentLang === "pt" ? CAT_NAMES_PT : CAT_NAMES_EN;
      const filtered = BENCHMARK_EXTENSIONS.filter((ext) => {
        const okCat = currentExtCat === "all" || ext.category === currentExtCat;
        const okQ = !q || ext.name.toLowerCase().includes(q) || ext.id.toLowerCase().includes(q);
        return okCat && okQ;
      });

      if (filtered.length === 0) {
        const empty = document.createElement("div");
        empty.className = "finding-item";
        empty.textContent = currentLang === "pt" ? "Nenhuma extensão encontrada." : "No matching extensions.";
        registryGrid.appendChild(empty);
        return;
      }

      filtered.forEach((ext) => {
        const card = document.createElement("div");
        card.className = "ext-card";

        const head = document.createElement("div");
        const title = document.createElement("div");
        title.className = "ext-card-title";
        title.textContent = ext.name;
        const meta = document.createElement("div");
        meta.className = "ext-card-meta";
        const sCat = document.createElement("span");
        sCat.textContent = map[ext.category] || ext.category;
        meta.append(sCat);
        head.append(title, meta);

        const actions = document.createElement("div");
        actions.className = "ext-card-actions";
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "button compact";
        btn.textContent = currentLang === "pt" ? "Simular" : "Simulate";
        btn.addEventListener("click", () => simulateExt(ext));

        const link = document.createElement("a");
        link.href = ext.url;
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        link.style.fontSize = "12px";
        link.style.color = "var(--secondary)";
        link.textContent = "AMO ↗";

        actions.append(btn, link);
        card.append(head, actions);
        registryGrid.appendChild(card);
      });
    }

    catBtns.forEach((b) => {
      b.addEventListener("click", () => {
        currentExtCat = b.getAttribute("data-ext-cat") || "all";
        catBtns.forEach((c) => c.classList.toggle("active-pill", c.getAttribute("data-ext-cat") === currentExtCat));
        renderRegistry();
      });
    });

    if (registrySearch) {
      registrySearch.addEventListener("input", () => {
        currentExtQuery = registrySearch.value;
        renderRegistry();
      });
    }
    renderRegistry();

    // Architecture Overlay Code Reader
    const archPre = document.getElementById("arch-file-viewer");
    const archBtns = document.querySelectorAll("[data-arch-file]");
    const copyArchBtn = document.getElementById("copy-arch-file-btn");

    function setArchFile(key) {
      currentArchKey = ARCH_FILES[key] ? key : "lock";
      if (archPre) archPre.textContent = ARCH_FILES[currentArchKey];
      archBtns.forEach((b) => {
        const active = b.getAttribute("data-arch-file") === currentArchKey;
        b.classList.toggle("active", active);
        b.setAttribute("aria-selected", String(active));
      });
    }

    archBtns.forEach((b) => {
      b.addEventListener("click", () => setArchFile(b.getAttribute("data-arch-file")));
    });

    if (copyArchBtn) {
      copyArchBtn.addEventListener("click", () => {
        copyText(ARCH_FILES[currentArchKey], currentLang === "pt" ? "Arquivo copiado" : "Copied file snippet");
      });
    }
    setArchFile("lock");

    // Split-Screen Comparison Slider (#compare)
    const compareFrame = document.getElementById("comparison-frame");
    const dragHandle = document.getElementById("comparison-drag-handle");
    const compareSelect = document.getElementById("comparison-browser");
    const compareFlipBtn = document.getElementById("comparison-theme-toggle");
    const leftImg = document.getElementById("comparison-argon-img");
    const rightImg = document.getElementById("comparison-other-img");
    const leftTag = document.getElementById("comparison-argon-tag");
    const rightTag = document.getElementById("comparison-other-tag");

    let splitPct = 50;
    let compareLightBase = false;
    let draggingSplit = false;

    function setSplit(val) {
      splitPct = Math.round(Math.max(10, Math.min(90, val)));
      if (compareFrame) {
        compareFrame.style.setProperty("--split-pct", splitPct + "%");
        compareFrame.setAttribute("data-split", String(splitPct));
      }
      if (dragHandle) {
        dragHandle.setAttribute("aria-valuenow", String(splitPct));
      }
    }

    function syncComparison() {
      const key = compareSelect?.value || "VerticalVsHorizontal";
      const cfg = COMPARISON_MODES[key] || COMPARISON_MODES.VerticalVsHorizontal;
      if (leftImg) leftImg.src = compareLightBase ? cfg.lightLeft : cfg.darkLeft;
      if (rightImg) rightImg.src = compareLightBase ? cfg.lightRight : cfg.darkRight;
      if (leftTag) leftTag.textContent = currentLang === "pt" ? cfg.leftPt : cfg.leftEn;
      if (rightTag) rightTag.textContent = currentLang === "pt" ? cfg.rightPt : cfg.rightEn;
      setSplit(splitPct);
    }

    if (compareSelect) {
      compareSelect.addEventListener("change", () => {
        syncComparison();
        setSplit(50);
      });
    }

    if (compareFlipBtn) {
      compareFlipBtn.addEventListener("click", () => {
        compareLightBase = !compareLightBase;
        compareFlipBtn.setAttribute("aria-pressed", String(compareLightBase));
        syncComparison();
      });
    }

    if (compareFrame) {
      const moveFromX = (clientX) => {
        const rect = compareFrame.getBoundingClientRect();
        if (rect.width > 0) setSplit(((clientX - rect.left) / rect.width) * 100);
      };
      compareFrame.addEventListener("pointerdown", (e) => {
        if (e.pointerType === "touch" && e.target !== dragHandle) return;
        draggingSplit = true;
        compareFrame.setPointerCapture?.(e.pointerId);
        moveFromX(e.clientX);
      });
      compareFrame.addEventListener("pointermove", (e) => {
        if (draggingSplit) moveFromX(e.clientX);
      });
      const stopDrag = (e) => {
        if (!draggingSplit) return;
        draggingSplit = false;
        compareFrame.releasePointerCapture?.(e.pointerId);
      };
      compareFrame.addEventListener("pointerup", stopDrag);
      compareFrame.addEventListener("pointercancel", stopDrag);
    }

    if (dragHandle) {
      dragHandle.addEventListener("keydown", (e) => {
        if (e.key === "ArrowLeft") { e.preventDefault(); setSplit(splitPct - 5); }
        else if (e.key === "ArrowRight") { e.preventDefault(); setSplit(splitPct + 5); }
        else if (e.key === "PageDown") { e.preventDefault(); setSplit(splitPct - 15); }
        else if (e.key === "PageUp") { e.preventDefault(); setSplit(splitPct + 15); }
        else if (e.key === "Home") { e.preventDefault(); setSplit(10); }
        else if (e.key === "End") { e.preventDefault(); setSplit(90); }
      });
    }
    syncComparison();

    // Brand Kit 128u Guides Toggle & Downloads
    const toggleGridBtn = document.getElementById("toggle-brand-grid-btn");
    const svgGuides = document.getElementById("brand-svg-guides");
    if (toggleGridBtn && svgGuides) {
      toggleGridBtn.addEventListener("click", () => {
        const hidden = svgGuides.style.display === "none";
        svgGuides.style.display = hidden ? "block" : "none";
        toggleGridBtn.setAttribute("aria-pressed", String(hidden));
        const dict = I18N[currentLang];
        toggleGridBtn.textContent = hidden ? dict.brandGridToggleHide : dict.brandGridToggleShow;
      });
    }

    document.querySelectorAll("[data-download-asset]").forEach((btn) => {
      btn.addEventListener("click", () => downloadAsset(btn.getAttribute("data-download-asset")));
    });

    document.querySelectorAll("[data-copy-text]").forEach((btn) => {
      btn.addEventListener("click", () => {
        copyText(btn.getAttribute("data-copy-text"), btn.getAttribute("data-copy-label"));
      });
    });

    // Bilingual PT / EN Switcher
    function applyLanguage(lang) {
      currentLang = I18N[lang] ? lang : "pt";
      const dict = I18N[currentLang];
      document.documentElement.lang = currentLang === "pt" ? "pt-BR" : "en";

      document.querySelectorAll("[data-lang-btn]").forEach((b) => {
        const active = b.getAttribute("data-lang-btn") === currentLang;
        b.classList.toggle("active", active);
        b.setAttribute("aria-pressed", String(active));
      });

      document.querySelectorAll("[data-i18n]").forEach((el) => {
        const k = el.getAttribute("data-i18n");
        if (dict[k]) el.textContent = dict[k];
      });

      document.querySelectorAll("[data-i18n-html]").forEach((el) => {
        const k = el.getAttribute("data-i18n-html");
        if (dict[k]) el.innerHTML = dict[k];
      });

      if (toggleGridBtn && svgGuides) {
        const shown = svgGuides.style.display !== "none";
        toggleGridBtn.textContent = shown ? dict.brandGridToggleHide : dict.brandGridToggleShow;
      }

      syncComparison();
      renderRegistry();
      syncHlPlayback();
      try { localStorage.setItem("argon-site-lang", currentLang); } catch {}
    }

    let savedLang = "pt";
    try { savedLang = localStorage.getItem("argon-site-lang") || "pt"; } catch {}
    applyLanguage(savedLang);

    document.querySelectorAll("[data-lang-btn]").forEach((b) => {
      b.addEventListener("click", () => applyLanguage(b.getAttribute("data-lang-btn")));
    });

    // Power-user Command Palette (⌘K / Ctrl+K)
    const cmdBackdrop = document.getElementById("cmd-backdrop");
    const cmdInput = document.getElementById("cmd-input");
    const cmdList = document.getElementById("cmd-list");
    const openCmdBtns = document.querySelectorAll("[data-open-cmd]");
    const closeCmdBtn = document.getElementById("close-cmd-btn");

    const COMMANDS = [
      { label: "Alternar para tema escuro", tag: "Tema", run: () => applyTheme("dark") },
      { label: "Alternar para tema claro", tag: "Tema", run: () => applyTheme("light") },
      { label: "Usar tema automático do sistema", tag: "Tema", run: () => applyTheme("auto") },
      { label: "Ver captura: Abas verticais (Escuro)", tag: "Interface", run: () => { location.hash = "#highlights"; setHighlight(0, true, false); setChromeCapture("vertical"); } },
      { label: "Ver captura: Abas horizontais (Escuro)", tag: "Interface", run: () => { location.hash = "#highlights"; setHighlight(0, true, false); setChromeCapture("horizontal"); } },
      { label: "Abrir analisador estático manifest.json", tag: "Extensões", run: () => { location.hash = "#extension-bridge"; switchStudioTab("analyzer"); } },
      { label: "Explorar catálogo de 50 extensões AMO", tag: "Extensões", run: () => { location.hash = "#extension-bridge"; switchStudioTab("registry"); } },
      { label: "Comparar layouts lado a lado", tag: "Comparar", run: () => { location.hash = "#compare"; } },
      { label: "Mudar idioma para English (EN)", tag: "Idioma", run: () => applyLanguage("en") },
      { label: "Mudar idioma para Português (PT)", tag: "Idioma", run: () => applyLanguage("pt") },
      { label: "Abrir perfil oficial no X (@ArgonBrowser)", tag: "Social", run: () => window.open("https://x.com/ArgonBrowser", "_blank", "noopener,noreferrer") },
      { label: "Copiar comando Artifact Mode", tag: "CLI", run: () => copyText("npm run doctor && npm run fetch && npm run apply && npm run build:artifact") }
    ];

    function closeCmd() {
      cmdBackdrop?.classList.remove("open");
    }

    function renderCmds(q) {
      if (!cmdList) return;
      cmdList.textContent = "";
      const query = (q || "").trim().toLowerCase();
      COMMANDS.filter((c) => !query || c.label.toLowerCase().includes(query) || c.tag.toLowerCase().includes(query)).forEach((c) => {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "cmd-item";
        const sLabel = document.createElement("span");
        sLabel.textContent = c.label;
        const sTag = document.createElement("span");
        sTag.className = "quiet-status";
        sTag.textContent = c.tag;
        btn.append(sLabel, sTag);
        btn.addEventListener("click", () => {
          closeCmd();
          c.run();
        });
        cmdList.appendChild(btn);
      });
    }

    function openCmd() {
      if (!cmdBackdrop) return;
      cmdBackdrop.classList.add("open");
      if (cmdInput) {
        cmdInput.value = "";
        renderCmds("");
        cmdInput.focus();
      }
    }

    openCmdBtns.forEach((b) => b.addEventListener("click", openCmd));
    closeCmdBtn?.addEventListener("click", closeCmd);
    cmdBackdrop?.addEventListener("click", (e) => {
      if (e.target === cmdBackdrop) closeCmd();
    });
    cmdInput?.addEventListener("input", () => renderCmds(cmdInput.value));

    document.addEventListener("keydown", (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        openCmd();
      } else if (e.key === "Escape") {
        if (cmdBackdrop?.classList.contains("open")) closeCmd();
        else if (header?.classList.contains("menuOpen")) closeMobileMenu(true);
      }
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initSite);
  } else {
    initSite();
  }
})();
