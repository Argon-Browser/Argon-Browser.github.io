// SPDX-License-Identifier: MPL-2.0

import { analyzePermissions } from './permissions.mjs';
import { analyzeManifestKeys } from './manifest-rules.mjs';
import { sanitizeManifest } from './json-safety.mjs';

const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const isText = (value) => typeof value === 'string' && value.trim().length > 0;
const VERSION = /^(0|[1-9][0-9]{0,8})(\.(0|[1-9][0-9]{0,8})){0,3}$/;

function finish(report) {
  report.valid = !report.findings.some(({ severity }) => severity === 'error');
  report.requiresManualReview = report.findings.some(({ severity }) => severity !== 'info');
  report.assessment = !report.valid ? 'INVALID_MANIFEST'
    : report.requiresManualReview ? 'MANUAL_REVIEW_REQUIRED' : 'NO_KNOWN_STATIC_ISSUES';
  return report;
}

/** Analyze manifest data only; never load any extension resources. */
export function analyzeManifest(manifest) {
  const report = {
    schemaVersion: 1,
    scope: 'STATIC_MANIFEST_ONLY',
    runtimeCompatibility: 'NOT_TESTED',
    notice: 'Static analysis does not establish runtime compatibility or safety. No permissions are granted.',
    valid: true,
    assessment: 'NO_KNOWN_STATIC_ISSUES',
    requiresManualReview: false,
    manifest: { name: null, version: null, manifestVersion: null },
    findings: [],
    permissions: { required: { api: [], hosts: [] }, optional: { api: [], hosts: [] }, contentScripts: [] },
  };
  const add = (code, severity, path, message) => report.findings.push({ code, severity, path, message });
  // Gate first: untrusted data must never execute, so reject anything that is
  // not a plain JSON object graph before any other finding is recorded.
  const gate = sanitizeManifest(manifest);
  if (!gate.ok) {
    add('NON_JSON_INPUT', 'error', '$', `Manifest data is not a JSON object graph: ${gate.message}`);
    return finish(report);
  }
  manifest = gate.manifest;
  if (!isObject(manifest)) {
    add('INVALID_ROOT', 'error', '$', 'The manifest must be a JSON object.');
    return finish(report);
  }
  if (![2, 3].includes(manifest.manifest_version)) {
    add('INVALID_MANIFEST_VERSION', 'error', 'manifest_version', 'manifest_version must be the integer 2 or 3.');
  } else {
    report.manifest.manifestVersion = manifest.manifest_version;
  }
  if (!isText(manifest.name)) {
    add('INVALID_NAME', 'error', 'name', 'name must be a non-empty string.');
  } else {
    report.manifest.name = manifest.name;
  }
  if (typeof manifest.version !== 'string' || !VERSION.test(manifest.version)) {
    add('INVALID_VERSION', 'error', 'version', 'version must contain one to four dot-separated integers, at most nine digits each, without leading zeros. Legacy formats are outside this validation profile.');
  } else {
    report.manifest.version = manifest.version;
    const parts = manifest.version.split('.').map(Number);
    if (parts.every((part) => part === 0) || parts.some((part) => part > 65535)) {
      add('CHROME_VERSION_RESTRICTION', 'review', 'version', 'This version meets the numeric Firefox/AMO format but not Chrome Web Store limits.');
    }
  }
  analyzePermissions(manifest, report.permissions, add);
  analyzeManifestKeys(manifest, report.permissions.contentScripts, add);
  return finish(report);
}
