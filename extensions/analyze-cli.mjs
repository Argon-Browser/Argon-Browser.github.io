#!/usr/bin/env node
// SPDX-License-Identifier: MPL-2.0
/**
 * Argon manifest analyzer CLI.
 *
 * Static analysis only: it reads manifest JSON, never downloads, unpacks, or
 * executes an extension, and never claims runtime compatibility.
 *
 * Exit codes are part of the interface:
 *   0  no known static issues
 *   1  valid manifest that needs manual review
 *   2  invalid manifest
 *   3  input problem (missing file, unreadable file, malformed JSON, no input)
 */

import { readFileSync } from "node:fs";
import process from "node:process";
import { analyzeManifest } from "./manifest-analyzer.mjs";

export const EXIT = {
  CLEAN: 0,
  REVIEW: 1,
  INVALID: 2,
  INPUT: 3,
};

const USAGE = `Usage: analyze-cli.mjs <path/to/manifest.json | -> [--json]

Analyzes a browser extension manifest statically and prints an English report.
Use - to read the manifest from standard input.

Exit codes:
  0  no known static issues
  1  manual review required
  2  invalid manifest
  3  input problem (missing or unreadable file, malformed JSON, no input)`;

function exitFor(report) {
  if (!report.valid) return EXIT.INVALID;
  if (report.requiresManualReview) return EXIT.REVIEW;
  return EXIT.CLEAN;
}

function severityTag(severity) {
  return severity === "error" ? "ERROR" : severity === "review" ? "REVIEW" : "INFO";
}

function formatHuman(report) {
  const lines = [];
  lines.push("Argon static manifest report");
  lines.push("===========================");
  lines.push(`Scope:              ${report.scope}`);
  lines.push(`Runtime compatibility: not tested (static analysis only)`);
  lines.push(`Assessment:         ${report.assessment}`);
  lines.push(
    `Manifest:           ${report.manifest.name ?? "(missing name)"} ` +
      `${report.manifest.version ?? "(missing version)"} ` +
      `(Manifest V${report.manifest.manifestVersion ?? "?"})`,
  );
  lines.push("");
  lines.push(`Notice: ${report.notice}`);
  lines.push("");

  const { required, optional } = report.permissions;
  lines.push(`Required API permissions (${required.api.length}):`);
  if (required.api.length === 0) lines.push("  (none declared)");
  for (const entry of required.api) {
    lines.push(`  - ${entry.value} [${entry.classification}] ${entry.path}`);
  }
  lines.push(`Required host permissions (${required.hosts.length}):`);
  if (required.hosts.length === 0) lines.push("  (none declared)");
  for (const entry of required.hosts) {
    lines.push(`  - ${entry.value}${entry.broad ? " [BROAD]" : ""} ${entry.path}`);
  }
  if (optional.api.length || optional.hosts.length) {
    lines.push(`Optional API permissions (${optional.api.length}):`);
    for (const entry of optional.api) lines.push(`  - ${entry.value} ${entry.path}`);
    lines.push(`Optional host permissions (${optional.hosts.length}):`);
    for (const entry of optional.hosts) lines.push(`  - ${entry.value} ${entry.path}`);
  }
  if (report.permissions.contentScripts.length) {
    lines.push(`Content script blocks: ${report.permissions.contentScripts.length}`);
  }

  lines.push("");
  if (report.findings.length === 0) {
    lines.push("Findings: none");
  } else {
    lines.push(`Findings (${report.findings.length}):`);
    for (const finding of report.findings) {
      lines.push(`  [${severityTag(finding.severity)}] ${finding.code} at ${finding.path}`);
      lines.push(`      ${finding.message}`);
    }
  }
  lines.push("");
  lines.push(
    report.valid
      ? report.requiresManualReview
        ? "Result: manual review required before installation."
        : "Result: no known static issues. This is not a statement of runtime compatibility."
      : "Result: the manifest is invalid and cannot be installed.",
  );
  return lines.join("\n");
}

function readInput(target) {
  if (target === "-") return readFileSync(0, "utf8");
  return readFileSync(target, "utf8");
}

function main(argv) {
  const args = argv.slice(2);
  const json = args.includes("--json");
  const positional = args.filter((arg) => arg !== "--json");

  if (positional.length === 0) {
    process.stderr.write(`${USAGE}\n`);
    return EXIT.INPUT;
  }
  if (positional.length > 1) {
    process.stderr.write(`Only one manifest path is accepted.\n${USAGE}\n`);
    return EXIT.INPUT;
  }

  const target = positional[0];
  let text;
  try {
    text = readInput(target);
  } catch (error) {
    const reason = error?.code === "ENOENT" ? "file does not exist"
      : error?.code === "EACCES" ? "permission denied"
        : error?.message ?? "unknown error";
    process.stderr.write(`Cannot read manifest: ${target} (${reason}).\n`);
    return EXIT.INPUT;
  }

  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    process.stderr.write(`Manifest is not valid JSON: ${error.message}\n`);
    return EXIT.INPUT;
  }

  const report = analyzeManifest(parsed);
  process.stdout.write(json ? `${JSON.stringify(report, null, 2)}\n` : `${formatHuman(report)}\n`);
  return exitFor(report);
}

process.exitCode = main(process.argv);
