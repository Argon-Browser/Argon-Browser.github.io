// SPDX-License-Identifier: MIT
/**
 * Argon Browser — Official Website Interactive Controller
 *
 * Powers the runtime theme switcher,
 * accessible WAI-ARIA highlight tablist, live Extension Bridge manifest.json
 * analyzer, split-screen browser comparison slider, and clipboard actions.
 */

import { analyzeManifest } from "./extensions/manifest-analyzer.mjs";
import {
  GITHUB_REPO_URL,
  SAMPLE_MANIFESTS,
  CHROME_LAYOUT_STATES,
  COMPARISON_MODES,
} from "./data.mjs";

export {
  GITHUB_REPO_URL,
  SAMPLE_MANIFESTS,
  CHROME_LAYOUT_STATES,
  COMPARISON_MODES,
};

export function computeCliExitCode(report) {
  if (!report || !report.valid) return 2;
  if (report.requiresManualReview) return 1;
  return 0;
}

export function formatPermissionEntries(items) {
  if (!Array.isArray(items) || items.length === 0) {
    return "none";
  }
  const values = items
    .map((item) => {
      if (typeof item === "string") return item;
      if (item && typeof item === "object") {
        return String(item.value ?? item.pattern ?? "");
      }
      return "";
    })
    .filter((val) => val.length > 0);
  return values.length > 0 ? values.join(", ") : "none";
}

export function evaluateRawManifestText(rawText) {
  let parsed;
  try {
    parsed = JSON.parse(rawText);
  } catch (err) {
    return {
      exitCode: 3,
      parseError: err instanceof Error ? err.message : "Malformed JSON input.",
      report: null,
    };
  }
  const report = analyzeManifest(parsed);
  return {
    exitCode: computeCliExitCode(report),
    parseError: null,
    report,
  };
}

/**
 * Renders the static manifest analysis report into `container` using only
 * safe DOM creation (`createElement` and `textContent`), preventing any XSS
 * when inspecting untrusted manifest strings.
 */
export function renderAnalyzerReportInto(container, exitBadge, result, doc = document) {
  if (!container) return;
  container.textContent = "";

  if (exitBadge) {
    exitBadge.textContent = `exit ${result.exitCode}`;
    exitBadge.className =
      result.exitCode === 0
        ? "quiet-status ok"
        : result.exitCode === 1
          ? "quiet-status review"
          : "quiet-status error";
  }

  if (result.parseError) {
    const banner = doc.createElement("div");
    banner.className = "verdict-banner error";
    const statusSpan = doc.createElement("span");
    statusSpan.textContent = "INPUT_ERROR · Malformed JSON";
    const codeSpan = doc.createElement("span");
    codeSpan.textContent = "Exit 3";
    banner.append(statusSpan, codeSpan);

    const item = doc.createElement("div");
    item.className = "finding-item";
    const codeEl = doc.createElement("code");
    codeEl.textContent = "JSON_PARSE_ERROR";
    const textNode = doc.createTextNode(`: ${result.parseError}`);
    item.append(codeEl, textNode);

    container.append(banner, item);
    return;
  }

  const report = result.report;
  const bannerClass =
    result.exitCode === 0 ? "ok" : result.exitCode === 1 ? "review" : "error";
  const meta = report.manifest || {};
  const mvLabel = meta.manifestVersion ? `MV${meta.manifestVersion}` : "MV?";
  const nameLabel = meta.name || "Unnamed Extension";
  const versionLabel = meta.version ? ` v${meta.version}` : "";

  const banner = doc.createElement("div");
  banner.className = `verdict-banner ${bannerClass}`;
  const statusSpan = doc.createElement("span");
  statusSpan.textContent = String(report.assessment || "UNKNOWN");
  const metaSpan = doc.createElement("span");
  metaSpan.textContent = `${mvLabel} · ${nameLabel}${versionLabel}`;
  banner.append(statusSpan, metaSpan);
  container.appendChild(banner);

  const perms = report.permissions;
  if (perms && perms.required) {
    const permBox = doc.createElement("div");
    permBox.className = "finding-item";

    const apiStrong = doc.createElement("strong");
    apiStrong.textContent = "Required API: ";
    const apiText = doc.createTextNode(formatPermissionEntries(perms.required.api));

    const br1 = doc.createElement("br");

    const optStrong = doc.createElement("strong");
    optStrong.textContent = "Optional API: ";
    const optText = doc.createTextNode(formatPermissionEntries(perms.optional?.api));

    const br2 = doc.createElement("br");

    const hostStrong = doc.createElement("strong");
    hostStrong.textContent = "Hosts: ";
    const hostText = doc.createTextNode(formatPermissionEntries(perms.required.hosts));

    permBox.append(apiStrong, apiText, br1, optStrong, optText, br2, hostStrong, hostText);
    container.appendChild(permBox);
  }

  const findings = Array.isArray(report.findings) ? report.findings : [];
  const list = doc.createElement("div");
  list.className = "findings-list";

  if (findings.length === 0) {
    const cleanItem = doc.createElement("div");
    cleanItem.className = "finding-item";
    const codeEl = doc.createElement("code");
    codeEl.textContent = "NO_KNOWN_STATIC_ISSUES";
    const msgNode = doc.createTextNode(
      " — All declared manifest keys, permissions, and match patterns pass static validation."
    );
    cleanItem.append(codeEl, msgNode);
    list.appendChild(cleanItem);
  } else {
    for (const finding of findings.slice(0, 6)) {
      const item = doc.createElement("div");
      item.className = "finding-item";

      const codeEl = doc.createElement("code");
      codeEl.textContent = String(finding.code || "FINDING");
      item.appendChild(codeEl);

      if (finding.path) {
        const pathSpan = doc.createElement("span");
        pathSpan.className = "finding-path";
        pathSpan.textContent = ` (${finding.path})`;
        item.appendChild(pathSpan);
      }

      const msgNode = doc.createTextNode(` — ${finding.message || ""}`);
      item.appendChild(msgNode);
      list.appendChild(item);
    }
  }
  container.appendChild(list);

  const notice = doc.createElement("div");
  notice.className = "analyzer-notice";
  notice.textContent = String(
    report.notice ||
      "Static manifest analysis only; runtime extension code was not executed."
  );
  container.appendChild(notice);
}

function updateSplitCssRule(pct) {
  if (typeof document === "undefined" || !document.styleSheets) return;
  for (const sheet of Array.from(document.styleSheets)) {
    let rules;
    try {
      rules = sheet.cssRules;
    } catch {
      continue;
    }
    if (!rules) continue;
    for (const rule of Array.from(rules)) {
      if (rule.selectorText === ".comparison-frame" && rule.style) {
        rule.style.setProperty("--split-pct", `${pct}%`);
        return;
      }
    }
  }
}

function showToast(message) {
  const toast = document.getElementById("copy-toast");
  if (!toast) return;
  toast.textContent = message;
  toast.classList.add("visible");
  window.clearTimeout(toast.__timer);
  toast.__timer = window.setTimeout(() => {
    toast.classList.remove("visible");
  }, 2200);
}

async function copyText(text, label = "Copied to clipboard") {
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      const area = document.createElement("textarea");
      area.value = text;
      document.body.appendChild(area);
      area.select();
      document.execCommand("copy");
      area.remove();
    }
    showToast(label);
  } catch {
    showToast("Copy unavailable in this context");
  }
}

export function initWebsite() {
  if (typeof document === "undefined") return;

  // 2. Fixed Header Scroll & Mobile Menu Toggle with Focus Isolation (inert)
  const header = document.querySelector("header.site-header");
  const menuToggle = document.getElementById("menu-toggle");
  const linksContainer = document.getElementById("links");
  const chevron = menuToggle?.querySelector(".chevron");
  const mobileMenuMedia = window.matchMedia("(max-width: 1279px)");

  const syncMobileMenuA11y = () => {
    if (!linksContainer || !header) return;
    const isMobile = mobileMenuMedia.matches;
    const isOpen = header.classList.contains("menuOpen");
    if (isMobile && !isOpen) {
      linksContainer.inert = true;
      linksContainer.setAttribute("aria-hidden", "true");
    } else {
      linksContainer.inert = false;
      linksContainer.removeAttribute("aria-hidden");
    }
  };

  const updateHeaderScroll = () => {
    if (!header) return;
    header.classList.toggle("scrolled", window.scrollY > 12);
  };
  updateHeaderScroll();
  syncMobileMenuA11y();
  window.addEventListener("scroll", updateHeaderScroll, { passive: true });
  const closeMenu = (restoreFocus = false) => {
    if (!header || !menuToggle) return;
    header.classList.remove("menuOpen");
    menuToggle.setAttribute("aria-expanded", "false");
    chevron?.classList.remove("open");
    if (restoreFocus) menuToggle.focus();
    syncMobileMenuA11y();
  };
  mobileMenuMedia.addEventListener("change", () => closeMenu());
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && header?.classList.contains("menuOpen")) {
      closeMenu(true);
    }
  });
  document.addEventListener("click", (e) => {
    if (header?.classList.contains("menuOpen") && !header.contains(e.target)) {
      closeMenu(header.contains(document.activeElement));
    }
  });
  linksContainer?.querySelectorAll("a").forEach((link) => {
    link.addEventListener("click", () => {
      if (mobileMenuMedia.matches) closeMenu(true);
    });
  });

  if (menuToggle && header) {
    menuToggle.addEventListener("click", () => {
      const open = header.classList.toggle("menuOpen");
      menuToggle.setAttribute("aria-expanded", String(open));
      chevron?.classList.toggle("open", open);
      syncMobileMenuA11y();
    });
  }

  // 3. Runtime Theme Switcher (Light / Dark / System Auto)
  const themeButtons = document.querySelectorAll("[data-theme-mode]");
  const heroScreenshot = document.getElementById("hero-browser-screenshot");
  const darkColorMedia = window.matchMedia("(prefers-color-scheme: dark)");

  const isEffectiveDark = (mode) => {
    if (mode === "dark") return true;
    if (mode === "light") return false;
    return darkColorMedia.matches;
  };

  const applyThemeMode = (mode) => {
    const root = document.documentElement;
    if (mode === "light" || mode === "dark") {
      root.setAttribute("data-argon-color-scheme", mode);
    } else {
      root.removeAttribute("data-argon-color-scheme");
    }
    themeButtons.forEach((btn) => {
      const isSelected = btn.getAttribute("data-theme-mode") === mode;
      btn.classList.toggle("active", isSelected);
      btn.setAttribute("aria-pressed", String(isSelected));
    });
    if (heroScreenshot) {
      heroScreenshot.src = isEffectiveDark(mode)
        ? "./assets/chrome-smoke/dark-vertical.png"
        : "./assets/chrome-smoke/light-vertical.png";
    }
    try {
      localStorage.setItem("argon-site-theme", mode);
    } catch {
      // Ignore storage errors in restricted environments
    }
  };

  let savedTheme = "auto";
  try {
    savedTheme = localStorage.getItem("argon-site-theme") || "auto";
  } catch {
    savedTheme = "auto";
  }
  applyThemeMode(savedTheme);

  darkColorMedia.addEventListener("change", () => {
    const current =
      document.documentElement.getAttribute("data-argon-color-scheme") || "auto";
    if (current === "auto" && heroScreenshot) {
      heroScreenshot.src = darkColorMedia.matches
        ? "./assets/chrome-smoke/dark-vertical.png"
        : "./assets/chrome-smoke/light-vertical.png";
    }
  });

  themeButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      const mode = btn.getAttribute("data-theme-mode") || "auto";
      applyThemeMode(mode);
    });
  });

  // 4. Accessible 4-Panel Highlight Tablist (#highlights)
  const highlightSection = document.getElementById("highlights");
  const panels = Array.from(document.querySelectorAll(".highlight-panel"));
  const stages = Array.from(document.querySelectorAll(".highlight-stage"));
  const tabs = Array.from(document.querySelectorAll(".highlight-tab"));
  const pauseBtn = document.getElementById("highlight-pause-btn");
  const reducedMotionMedia = window.matchMedia("(prefers-reduced-motion: reduce)");
  const durations = [11500, 11000, 11000, 10500];

  let activeHighlight = 0;
  let userPaused = true;
  let inViewport = true;
  let highlightTimer = null;

  const isPlaybackPaused = () =>
    userPaused ||
    reducedMotionMedia.matches ||
    !inViewport ||
    document.visibilityState !== "visible";

  const syncPauseState = () => {
    if (!highlightSection) return;
    const paused = isPlaybackPaused();
    highlightSection.classList.toggle("playback-paused", paused);
    if (pauseBtn) {
      pauseBtn.classList.toggle("is-paused", paused);
      pauseBtn.setAttribute("aria-pressed", String(paused));
      pauseBtn.setAttribute(
        "aria-label",
        paused ? "Resume highlight progression" : "Pause highlight progression"
      );
    }
  };

  const scheduleNextHighlight = () => {
    window.clearTimeout(highlightTimer);
    if (isPlaybackPaused() || panels.length === 0) return;
    const duration = durations[activeHighlight] || 10500;
    highlightTimer = window.setTimeout(() => {
      setHighlight((activeHighlight + 1) % panels.length, false);
    }, duration);
  };

  const setHighlight = (index, manual = true, focusTab = false) => {
    if (panels.length === 0) return;
    activeHighlight = (index + panels.length) % panels.length;
    if (manual) {
      userPaused = true;
    }
    panels.forEach((panel, i) => {
      const active = i === activeHighlight;
      panel.classList.toggle("visible", active);
      panel.hidden = !active;
      panel.setAttribute("aria-hidden", String(!active));
    });
    stages.forEach((stage, i) => {
      const active = i === activeHighlight;
      stage.classList.toggle("visible", active);
      stage.setAttribute("aria-hidden", String(!active));
      stage.inert = !active;
    });
    tabs.forEach((tab, i) => {
      const active = i === activeHighlight;
      tab.classList.toggle("active", active);
      tab.setAttribute("aria-selected", String(active));
      tab.setAttribute("tabindex", active ? "0" : "-1");
      const fill = tab.querySelector(".tab-progress-fill");
      if (fill) {
        fill.classList.remove("animating");
        if (active) {
          void fill.offsetWidth;
          fill.classList.add("animating");
        }
      }
      if (active && focusTab) {
        tab.focus();
      }
    });
    syncPauseState();
    scheduleNextHighlight();
  };

  tabs.forEach((tab, i) => {
    tab.addEventListener("click", () => setHighlight(i, true, false));
    tab.addEventListener("keydown", (e) => {
      if (e.key === "ArrowRight") {
        e.preventDefault();
        setHighlight(i + 1, true, true);
      } else if (e.key === "ArrowLeft") {
        e.preventDefault();
        setHighlight(i - 1, true, true);
      } else if (e.key === "Home") {
        e.preventDefault();
        setHighlight(0, true, true);
      } else if (e.key === "End") {
        e.preventDefault();
        setHighlight(tabs.length - 1, true, true);
      }
    });
  });

  if (pauseBtn) {
    pauseBtn.addEventListener("click", () => {
      userPaused = !userPaused;
      syncPauseState();
      scheduleNextHighlight();
    });
  }

  reducedMotionMedia.addEventListener("change", () => {
    if (reducedMotionMedia.matches) {
      userPaused = true;
    }
    syncPauseState();
    scheduleNextHighlight();
  });

  if (highlightSection) {
    const obs = new IntersectionObserver(
      (entries) => {
        inViewport = entries[0]?.isIntersecting ?? true;
        syncPauseState();
        scheduleNextHighlight();
      },
      { threshold: 0.35 }
    );
    obs.observe(highlightSection);
  }

  document.addEventListener("visibilitychange", () => {
    syncPauseState();
    scheduleNextHighlight();
  });

  setHighlight(0, false, false);

  // Stage 1: Interactive Argon Chrome Layout Switcher inside Highlight 1
  const layoutButtons = document.querySelectorAll("[data-chrome-layout-btn]");
  const mockupWindow = document.getElementById("argon-window-mockup");
  const tokenReadout = document.getElementById("stage-token-readout");
  const mockupImg = document.getElementById("stage-chrome-screenshot");

  const setChromeLayoutPreview = (layoutId) => {
    const state = CHROME_LAYOUT_STATES.find((s) => s.id === layoutId) || CHROME_LAYOUT_STATES[0];
    layoutButtons.forEach((btn) => {
      const isSelected = btn.getAttribute("data-chrome-layout-btn") === state.id;
      btn.classList.toggle("active", isSelected);
      btn.setAttribute("aria-pressed", String(isSelected));
    });
    if (mockupWindow) {
      mockupWindow.setAttribute(
        "data-layout",
        state.id === "light-vertical" ? "vertical" : state.id
      );
      mockupWindow.classList.toggle("light-preview", state.light);
    }
    if (tokenReadout) {
      tokenReadout.textContent = state.tokenSummary;
    }
    if (mockupImg) {
      mockupImg.src = state.screenshot;
    }
  };

  layoutButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      setChromeLayoutPreview(btn.getAttribute("data-chrome-layout-btn"));
    });
  });

  // 5. Live Interactive Extension Manifest Analyzer Studio (Debounced + XSS-Safe)
  const manifestInput = document.getElementById("manifest-input");
  const presetButtons = document.querySelectorAll("[data-manifest-preset]");
  const reportContainer = document.getElementById("analyzer-report-body");
  const exitBadge = document.getElementById("analyzer-exit-badge");
  let analyzeDebounceTimer = null;

  const renderAnalyzerReportNow = () => {
    if (!manifestInput || !reportContainer) return;
    const result = evaluateRawManifestText(manifestInput.value);
    renderAnalyzerReportInto(reportContainer, exitBadge, result, document);
  };

  const selectManifestPreset = (presetKey) => {
    const preset = SAMPLE_MANIFESTS[presetKey] || SAMPLE_MANIFESTS.mv3ServiceWorker;
    presetButtons.forEach((btn) => {
      const isSelected = btn.getAttribute("data-manifest-preset") === presetKey;
      btn.classList.toggle("active", isSelected);
      btn.setAttribute("aria-pressed", String(isSelected));
    });
    if (manifestInput) {
      manifestInput.value = preset.json;
    }
    window.clearTimeout(analyzeDebounceTimer);
    renderAnalyzerReportNow();
  };

  presetButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      selectManifestPreset(btn.getAttribute("data-manifest-preset"));
    });
  });

  if (manifestInput) {
    manifestInput.addEventListener("input", () => {
      presetButtons.forEach((btn) => {
        btn.classList.remove("active");
        btn.setAttribute("aria-pressed", "false");
      });
      window.clearTimeout(analyzeDebounceTimer);
      analyzeDebounceTimer = window.setTimeout(renderAnalyzerReportNow, 300);
    });
  }

  selectManifestPreset("mv3ServiceWorker");

  // 6. Interactive Split-Screen Browser Comparison (#compare)
  const compareFrame = document.getElementById("comparison-frame");
  const dragHandle = document.getElementById("comparison-drag-handle");
  const compareSelect = document.getElementById("comparison-browser");
  const compareThemeBtn = document.getElementById("comparison-theme-toggle");
  const argonImg = document.getElementById("comparison-argon-img");
  const otherImg = document.getElementById("comparison-other-img");
  const argonTag = document.getElementById("comparison-argon-tag");
  const otherTag = document.getElementById("comparison-other-tag");

  let splitPercent = 50;
  let compareLightMode = false;
  let isDraggingSplit = false;

  const setSplitPercent = (value) => {
    splitPercent = Math.round(Math.max(10, Math.min(90, value)));
    updateSplitCssRule(splitPercent);
    if (compareFrame) {
      compareFrame.setAttribute("data-split", String(splitPercent));
    }
    if (dragHandle) {
      const modeKey = compareSelect?.value || "VerticalVsHorizontal";
      const cfg = COMPARISON_MODES[modeKey] || COMPARISON_MODES.VerticalVsHorizontal;
      dragHandle.setAttribute("aria-valuenow", String(splitPercent));
      dragHandle.setAttribute(
        "aria-valuetext",
        `${splitPercent}% ${cfg.argonCaption}, ${100 - splitPercent}% ${cfg.otherCaption}`
      );
    }
  };

  const syncComparisonTarget = () => {
    const modeKey = compareSelect?.value || "VerticalVsHorizontal";
    const cfg = COMPARISON_MODES[modeKey] || COMPARISON_MODES.VerticalVsHorizontal;
    if (argonImg) {
      argonImg.src = compareLightMode ? cfg.lightArgonImg : cfg.darkArgonImg;
    }
    if (otherImg) {
      otherImg.src = compareLightMode ? cfg.lightOtherImg : cfg.darkOtherImg;
    }
    if (argonTag) {
      argonTag.textContent = cfg.argonCaption;
    }
    if (otherTag) {
      otherTag.textContent = cfg.otherCaption;
    }
    if (compareFrame) {
      compareFrame.setAttribute(
        "aria-label",
        `${cfg.label} (${compareLightMode ? "Light" : "Dark"} surface)`
      );
    }
    setSplitPercent(splitPercent);
  };

  if (compareSelect) {
    compareSelect.addEventListener("change", () => {
      const cfg = COMPARISON_MODES[compareSelect.value] || COMPARISON_MODES.VerticalVsHorizontal;
      syncComparisonTarget();
      setSplitPercent(cfg.defaultSplit);
    });
  }

  if (compareThemeBtn) {
    compareThemeBtn.addEventListener("click", () => {
      compareLightMode = !compareLightMode;
      compareThemeBtn.textContent = compareLightMode ? "Surface: Light" : "Surface: Dark";
      compareThemeBtn.setAttribute("aria-pressed", String(compareLightMode));
      syncComparisonTarget();
    });
  }

  if (compareFrame) {
    const updateFromClientX = (clientX) => {
      const rect = compareFrame.getBoundingClientRect();
      if (rect.width <= 0) return;
      const pct = ((clientX - rect.left) / rect.width) * 100;
      setSplitPercent(pct);
    };

    compareFrame.addEventListener("pointerdown", (e) => {
      if (e.pointerType === "touch" && e.target !== dragHandle) {
        return;
      }
      isDraggingSplit = true;
      compareFrame.setPointerCapture?.(e.pointerId);
      updateFromClientX(e.clientX);
    });

    compareFrame.addEventListener("pointermove", (e) => {
      if (!isDraggingSplit) return;
      updateFromClientX(e.clientX);
    });

    const stopDrag = (e) => {
      if (!isDraggingSplit) return;
      isDraggingSplit = false;
      compareFrame.releasePointerCapture?.(e.pointerId);
    };
    compareFrame.addEventListener("pointerup", stopDrag);
    compareFrame.addEventListener("pointercancel", stopDrag);
  }

  if (dragHandle) {
    dragHandle.addEventListener("keydown", (e) => {
      if (e.key === "ArrowLeft") {
        e.preventDefault();
        setSplitPercent(splitPercent - 5);
      } else if (e.key === "ArrowRight") {
        e.preventDefault();
        setSplitPercent(splitPercent + 5);
      } else if (e.key === "PageDown") {
        e.preventDefault();
        setSplitPercent(splitPercent - 15);
      } else if (e.key === "PageUp") {
        e.preventDefault();
        setSplitPercent(splitPercent + 15);
      } else if (e.key === "Home") {
        e.preventDefault();
        setSplitPercent(10);
      } else if (e.key === "End") {
        e.preventDefault();
        setSplitPercent(90);
      }
    });
  }

  syncComparisonTarget();
  setSplitPercent(50);

  // 7. Copy Actions for Brand Swatches and CLI Snippets
  document.querySelectorAll("[data-copy-text]").forEach((el) => {
    el.addEventListener("click", () => {
      const value = el.getAttribute("data-copy-text");
      const label = el.getAttribute("data-copy-label") || `Copied ${value}`;
      if (value) {
        copyText(value, label);
      }
    });
  });
}

if (typeof window !== "undefined" && !window.__ARGON_SITE_READY__) {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initWebsite);
  } else {
    initWebsite();
  }
}
