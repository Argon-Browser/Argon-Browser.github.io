// SPDX-License-Identifier: MIT
/**
 * Argon Browser — Website Static Data & Presets
 *
 * Pure data module separating sample extension manifests, real Argon window
 * captures, and side-by-side layout comparisons from DOM controller logic.
 *
 * Every screenshot here is a capture of the prebuilt Argon runtime running on
 * Linux, taken from a native window (no Marionette, no automation stripe).
 */

export const GITHUB_REPO_URL = "https://github.com/argon-browser/argon";

export const SAMPLE_MANIFESTS = Object.freeze({
  cleanMv3: {
    label: "Clean MV3 (Exit 0)",
    json: JSON.stringify(
      {
        manifest_version: 3,
        name: "Argon Tab Pinning Helper",
        version: "1.4.2",
        description: "Minimal tab organizer using standard WebExtensions APIs.",
        permissions: ["storage", "tabs", "activeTab"],
        optional_permissions: ["bookmarks"],
        host_permissions: ["https://example.org/*"],
      },
      null,
      2
    ),
  },
  mv3ServiceWorker: {
    label: "MV3 Service Worker (Exit 1)",
    json: JSON.stringify(
      {
        manifest_version: 3,
        name: "Chromium Workspace Sync",
        version: "2.1.0",
        permissions: ["storage", "alarms", "scripting"],
        host_permissions: ["<all_urls>"],
        background: {
          service_worker: "background-sw.js",
          type: "module",
        },
      },
      null,
      2
    ),
  },
  chromeSpecific: {
    label: "Chrome APIs + Host Warning (Exit 1)",
    json: JSON.stringify(
      {
        manifest_version: 3,
        name: "Chrome Offscreen Media Utility",
        version: "3.0.1",
        permissions: [
          "storage",
          "offscreen",
          "tabCapture",
          "nativeMessaging",
        ],
        host_permissions: ["https://*.chromium.org:8443/*"],
        content_scripts: [
          {
            matches: ["https://example.com/*"],
            js: ["content.js"],
            world: "MAIN",
          },
        ],
      },
      null,
      2
    ),
  },
  invalidManifest: {
    label: "Invalid Schema (Exit 2)",
    json: JSON.stringify(
      {
        manifest_version: 4,
        name: "   ",
        version: "01.2.0-beta",
        permissions: ["storage", 42],
      },
      null,
      2
    ),
  },
});

/**
 * Real Argon window captures. Each entry maps a layout switcher button to the
 * capture that represents it; `light` keeps the preview frame in sync with the
 * captured theme.
 */
export const CHROME_LAYOUT_STATES = Object.freeze([
  {
    id: "vertical",
    label: "Dark · Vertical",
    tokenSummary: "--argon-toolbar-height: 48px · --argon-sidebar-width: 240px · dark",
    screenshot: "./assets/chrome-smoke/dark-vertical.png",
    light: false,
  },
  {
    id: "horizontal",
    label: "Dark · Horizontal",
    tokenSummary: "--argon-toolbar-height: 48px · layout: horizontal · dark",
    screenshot: "./assets/chrome-smoke/dark-horizontal.png",
    light: false,
  },
  {
    id: "light-vertical",
    label: "Light · Vertical",
    tokenSummary: "--argon-toolbar-height: 48px · --argon-sidebar-width: 240px · light",
    screenshot: "./assets/chrome-smoke/light-vertical.png",
    light: true,
  },
  {
    id: "light-horizontal",
    label: "Light · Horizontal",
    tokenSummary: "--argon-toolbar-height: 48px · layout: horizontal · light",
    screenshot: "./assets/chrome-smoke/light-horizontal.png",
    light: true,
  },
]);

/**
 * Split-screen comparisons between Argon layouts and themes. Every image is an
 * Argon capture, so the slider compares real product states rather than
 * Argon against another browser.
 */
export const COMPARISON_MODES = Object.freeze({
  VerticalVsHorizontal: {
    label: "Argon vertical tabs vs Argon horizontal tabs",
    argonCaption: "Argon · Vertical tabs (dark)",
    otherCaption: "Argon · Horizontal tabs (dark)",
    darkArgonImg: "./assets/chrome-smoke/dark-vertical.png",
    darkOtherImg: "./assets/chrome-smoke/dark-horizontal.png",
    lightArgonImg: "./assets/chrome-smoke/light-vertical.png",
    lightOtherImg: "./assets/chrome-smoke/light-horizontal.png",
    defaultSplit: 50,
  },
  HorizontalDarkVsLight: {
    label: "Argon horizontal tabs · dark vs light",
    argonCaption: "Argon · Horizontal tabs (dark)",
    otherCaption: "Argon · Horizontal tabs (light)",
    darkArgonImg: "./assets/chrome-smoke/dark-horizontal.png",
    darkOtherImg: "./assets/chrome-smoke/light-horizontal.png",
    lightArgonImg: "./assets/chrome-smoke/light-horizontal.png",
    lightOtherImg: "./assets/chrome-smoke/dark-horizontal.png",
    defaultSplit: 50,
  },
  DarkVsLight: {
    label: "Argon dark vs Argon light (vertical tabs)",
    argonCaption: "Argon · Dark theme (vertical tabs)",
    otherCaption: "Argon · Light theme (vertical tabs)",
    darkArgonImg: "./assets/chrome-smoke/dark-vertical.png",
    darkOtherImg: "./assets/chrome-smoke/light-vertical.png",
    lightArgonImg: "./assets/chrome-smoke/light-vertical.png",
    lightOtherImg: "./assets/chrome-smoke/dark-vertical.png",
    defaultSplit: 50,
  },
});
