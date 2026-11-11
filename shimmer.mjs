// SPDX-License-Identifier: MIT
/**
 * Argon Browser — Vertical-Stripe Gradient Shimmer Engine
 *
 * Renders animated vertical gradient bands and film grain using Argon's
 * design tokens (#6478F5 accent, #F7F8FA light chrome, #15171B dark chrome),
 * pausing off-screen and honoring prefers-reduced-motion.
 */

const STRIPE_LIMITS = { min: 64, target: 108, max: 120 };
const BAND_CONFIG = { bandWidth: 0.48, minStop: 0.14, maxStop: 0.96 };
const INTRO_CONFIG = {
  delay: 180,
  revealDuration: 820,
  idleBlendDuration: 480,
  stagger: 42,
  startCenter: 0.94,
  idleCenter: 0.5,
};
const WAVE_CONFIG = {
  speed: 0.44,
  stripePhase: 0.74,
  secondarySpeed: 0.27,
  secondaryStripePhase: 1.28,
  primaryAmplitude: 0.19,
  secondaryAmplitude: 0.055,
};
const EMPHASIS_CONFIG = {
  multiplier: 2.25,
  rampUpDuration: 150,
  waveDuration: 360,
  rampDownDuration: 520,
};

function clamp01(value) {
  return Math.max(0, Math.min(1, value));
}

function easeOutCubic(value) {
  const inv = 1 - clamp01(value);
  return 1 - inv * inv * inv;
}

function easeInOutCubic(value) {
  const t = clamp01(value);
  return t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;
}

function lerp(a, b, t) {
  return a + (b - a) * t;
}

export function computeStripeLayout(width) {
  const safeWidth = Math.max(1, width);
  const minCount = Math.max(1, Math.ceil(safeWidth / STRIPE_LIMITS.max));
  const maxCount = Math.max(1, Math.floor(safeWidth / STRIPE_LIMITS.min));
  const targetCount = Math.max(1, Math.round(safeWidth / STRIPE_LIMITS.target));
  const count = Math.max(minCount, Math.min(maxCount, targetCount));
  const stripeWidth = safeWidth / count;
  const maxIndex = count - 1;
  return {
    count,
    width: stripeWidth,
    maxIndex,
    introCenterIndex: maxIndex / 2,
    introCenterDistance: count % 2 === 0 ? 0.5 : 0,
  };
}

function parseColorRgb(cssValue, scratchCtx) {
  const raw = (cssValue || "").trim();
  if (!raw) return [244, 247, 255];
  if (raw.startsWith("#")) {
    const hex = raw.slice(1);
    const full =
      hex.length === 3
        ? hex
            .split("")
            .map((c) => c + c)
            .join("")
        : hex;
    if (full.length === 6) {
      return [
        Number.parseInt(full.slice(0, 2), 16),
        Number.parseInt(full.slice(2, 4), 16),
        Number.parseInt(full.slice(4, 6), 16),
      ];
    }
  }
  if (scratchCtx) {
    scratchCtx.fillStyle = "#000000";
    scratchCtx.fillStyle = raw;
    const normalized = scratchCtx.fillStyle;
    if (normalized.startsWith("#") && normalized.length === 7) {
      return [
        Number.parseInt(normalized.slice(1, 3), 16),
        Number.parseInt(normalized.slice(3, 5), 16),
        Number.parseInt(normalized.slice(5, 7), 16),
      ];
    }
  }
  return [100, 120, 245];
}

function readShimmerStyle(canvas, scratchCtx) {
  const style = getComputedStyle(canvas);
  const num = (prop, fallback) => {
    const v = Number.parseFloat(style.getPropertyValue(prop).trim());
    return Number.isFinite(v) ? v : fallback;
  };
  const startRgb = parseColorRgb(style.getPropertyValue("--shimmer-start"), scratchCtx);
  const highlightRgb = parseColorRgb(style.getPropertyValue("--shimmer-highlight"), scratchCtx);
  return {
    startRgb,
    highlightRgb,
    alpha: num("--shimmer-alpha", 0.42),
    introAlpha: num("--shimmer-intro-alpha", 0.68),
    grainAlpha: num("--shimmer-grain-alpha", 0.12),
    shineBoost: num("--shimmer-speed-up-shine-boost", 0.28),
  };
}

function gradientHighlightAmount(position, bandStart, center, bandEnd) {
  const eps = 0.0001;
  if (position < bandStart) {
    return 1 - clamp01(position / Math.max(bandStart, eps));
  }
  if (position < center) {
    return clamp01((position - bandStart) / Math.max(center - bandStart, eps));
  }
  if (position < bandEnd) {
    return 1 - clamp01((position - center) / Math.max(bandEnd - center, eps));
  }
  return 0;
}

function createNoisePattern(ctx) {
  const size = 96;
  const patternCanvas = document.createElement("canvas");
  patternCanvas.width = size;
  patternCanvas.height = size;
  const pctx = patternCanvas.getContext("2d");
  if (!pctx) return null;
  const img = pctx.createImageData(size, size);
  const data = img.data;
  let idx = 0;
  for (let y = 0; y < size; y += 1) {
    for (let x = 0; x < size; x += 1) {
      const n = Math.sin(x * 127.1 + y * 311.7) * 43758.5453;
      const frac = n - Math.floor(n);
      const lum = Math.round(180 + (frac - 0.5) * 68);
      data[idx++] = lum;
      data[idx++] = lum;
      data[idx++] = Math.min(255, lum + 8);
      data[idx++] = 22;
    }
  }
  pctx.putImageData(img, 0, 0);
  return ctx.createPattern(patternCanvas, "repeat");
}

export function mountGradientShimmer(canvas, options = {}) {
  if (!canvas || typeof window === "undefined") {
    return { intro() {}, emphasize() {}, destroy() {} };
  }

  const ctx = canvas.getContext("2d");
  if (!ctx) {
    canvas.classList.add("fallback", "visible");
    return { intro() {}, emphasize() {}, destroy() {} };
  }

  const scratchCanvas = document.createElement("canvas");
  const scratchCtx = scratchCanvas.getContext("2d");
  const noisePattern = createNoisePattern(ctx);

  let width = 1;
  let height = 1;
  let dpr = 1;
  let layout = computeStripeLayout(1280);
  let palette = readShimmerStyle(canvas, scratchCtx);

  let wavePhase = Math.random() * Math.PI * 2;
  let secondaryWavePhase = -wavePhase * 0.7;
  let introStartedAt = options.intro !== false ? performance.now() : null;
  let emphasisState = null;
  let rafId = null;
  let lastFrameAt = null;
  let isVisible = true;

  const darkMedia = window.matchMedia("(prefers-color-scheme: dark)");
  const reducedMotionMedia = window.matchMedia("(prefers-reduced-motion: reduce)");

  function updateDimensions() {
    const rect = canvas.getBoundingClientRect();
    dpr = Math.min(window.devicePixelRatio || 1, 1.5);
    width = Math.max(1, Math.round(rect.width || window.innerWidth));
    height = Math.max(1, Math.round(rect.height || 360));
    canvas.width = Math.round(width * dpr);
    canvas.height = Math.round(height * dpr);
    layout = computeStripeLayout(width);
    palette = readShimmerStyle(canvas, scratchCtx);
  }

  function stepEmphasis(now) {
    if (!emphasisState) {
      return { multiplier: 1, shineProgress: 0 };
    }
    if (emphasisState.phase === "ramp-up") {
      const t = clamp01((now - emphasisState.startedAt) / emphasisState.duration);
      const eased = easeOutCubic(t);
      const current = {
        multiplier: lerp(emphasisState.from.multiplier, EMPHASIS_CONFIG.multiplier, eased),
        shineProgress: lerp(emphasisState.from.shineProgress, 1, eased),
      };
      if (t >= 1) {
        emphasisState = { phase: "hold", startedAt: now };
      }
      return current;
    }
    if (emphasisState.phase === "hold") {
      const t = clamp01((now - emphasisState.startedAt) / EMPHASIS_CONFIG.waveDuration);
      if (t >= 1) {
        emphasisState = {
          phase: "ramp-down",
          startedAt: now,
          from: { multiplier: EMPHASIS_CONFIG.multiplier, shineProgress: 1 },
        };
      }
      return { multiplier: EMPHASIS_CONFIG.multiplier, shineProgress: 1 };
    }
    const t = clamp01((now - emphasisState.startedAt) / EMPHASIS_CONFIG.rampDownDuration);
    const eased = easeInOutCubic(t);
    const current = {
      multiplier: lerp(emphasisState.from.multiplier, 1, eased),
      shineProgress: lerp(emphasisState.from.shineProgress, 0, eased),
    };
    if (t >= 1) {
      emphasisState = null;
    }
    return current;
  }

  function renderFrame(now) {
    const reduced = reducedMotionMedia.matches;
    const dt = reduced || lastFrameAt === null ? 0 : Math.min((now - lastFrameAt) / 1000, 0.064);
    lastFrameAt = reduced ? null : now;

    const emp = reduced ? { multiplier: 1, shineProgress: 0 } : stepEmphasis(now);
    if (!reduced) {
      wavePhase += WAVE_CONFIG.speed * emp.multiplier * dt;
      secondaryWavePhase += WAVE_CONFIG.secondarySpeed * emp.multiplier * dt;
    }

    ctx.save();
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, width, height);

    const [sr, sg, sb] = palette.startRgb;
    const [hr, hg, hb] = palette.highlightRgb;

    for (let i = 0; i < layout.count; i += 1) {
      const stripeX = i * layout.width;
      const stripeW = i === layout.maxIndex ? width - stripeX : Math.ceil(layout.width + 0.5);

      let revealProgress = 1;
      let idleProgress = 1;
      if (!reduced && introStartedAt !== null) {
        const dist = Math.max(0, Math.abs(i - layout.introCenterIndex) - layout.introCenterDistance);
        const delay = dist * INTRO_CONFIG.stagger;
        const elapsed = now - introStartedAt - INTRO_CONFIG.delay - delay;
        revealProgress = easeOutCubic(clamp01(elapsed / INTRO_CONFIG.revealDuration));
        idleProgress = easeOutCubic(
          clamp01((elapsed - INTRO_CONFIG.revealDuration) / INTRO_CONFIG.idleBlendDuration)
        );
      }

      const alpha = lerp(palette.introAlpha, palette.alpha, idleProgress);
      const primaryWave = Math.sin(wavePhase - i * WAVE_CONFIG.stripePhase);
      const secondaryWave = Math.sin(secondaryWavePhase + i * WAVE_CONFIG.secondaryStripePhase);
      const idleCenter =
        0.5 +
        primaryWave * WAVE_CONFIG.primaryAmplitude +
        secondaryWave * WAVE_CONFIG.secondaryAmplitude;
      const introCenter = lerp(INTRO_CONFIG.startCenter, INTRO_CONFIG.idleCenter, revealProgress);
      const center = lerp(introCenter, idleCenter, idleProgress);

      const bandStart = Math.max(
        BAND_CONFIG.minStop,
        Math.min(BAND_CONFIG.maxStop, center - BAND_CONFIG.bandWidth)
      );
      const bandEnd = Math.max(
        BAND_CONFIG.minStop,
        Math.min(BAND_CONFIG.maxStop, center + BAND_CONFIG.bandWidth)
      );

      const gradientAlpha =
        clamp01(alpha * (1 + emp.shineProgress * palette.shineBoost)) * revealProgress;
      const outAlpha = gradientAlpha + alpha * (1 - gradientAlpha);
      const highlightStrength = outAlpha > 0.0001 ? gradientAlpha / outAlpha : 0;

      const grad = ctx.createLinearGradient(
        stripeX,
        -height * 0.25,
        stripeX + layout.width * 0.45,
        height * 1.25
      );

      const stops = [0, bandStart, center, bandEnd, 1];
      for (const stop of stops) {
        const amt = gradientHighlightAmount(stop, bandStart, center, bandEnd) * highlightStrength;
        const r = Math.round(lerp(sr, hr, amt));
        const g = Math.round(lerp(sg, hg, amt));
        const b = Math.round(lerp(sb, hb, amt));
        grad.addColorStop(clamp01(stop), `rgba(${r}, ${g}, ${b}, ${outAlpha.toFixed(3)})`);
      }

      ctx.fillStyle = grad;
      ctx.fillRect(stripeX, 0, stripeW, height);
    }

    if (noisePattern && palette.grainAlpha > 0) {
      ctx.globalAlpha = palette.grainAlpha;
      ctx.fillStyle = noisePattern;
      ctx.fillRect(0, 0, width, height);
    }

    ctx.restore();
  }

  function loop(now) {
    rafId = null;
    renderFrame(now);
    if (!reducedMotionMedia.matches && isVisible) {
      rafId = window.requestAnimationFrame(loop);
    }
  }

  function startLoop() {
    if (rafId === null && !reducedMotionMedia.matches && isVisible) {
      rafId = window.requestAnimationFrame(loop);
    }
  }

  function stopLoop() {
    if (rafId !== null) {
      window.cancelAnimationFrame(rafId);
      rafId = null;
    }
  }

  updateDimensions();
  renderFrame(performance.now());
  canvas.classList.add("visible");
  startLoop();

  const resizeObserver = new ResizeObserver(() => {
    updateDimensions();
    renderFrame(performance.now());
  });
  resizeObserver.observe(canvas);

  const intersectionObserver = new IntersectionObserver((entries) => {
    isVisible = entries[0]?.isIntersecting ?? true;
    if (!isVisible) {
      stopLoop();
    } else {
      lastFrameAt = null;
      startLoop();
    }
  });
  intersectionObserver.observe(canvas);

  const mutationObserver = new MutationObserver(() => {
    palette = readShimmerStyle(canvas, scratchCtx);
    renderFrame(performance.now());
  });
  mutationObserver.observe(document.documentElement, {
    attributes: true,
    attributeFilter: ["data-argon-color-scheme", "class"],
  });

  const onMediaChange = () => {
    palette = readShimmerStyle(canvas, scratchCtx);
    if (reducedMotionMedia.matches) {
      stopLoop();
      renderFrame(performance.now());
    } else {
      startLoop();
    }
  };
  darkMedia.addEventListener("change", onMediaChange);
  reducedMotionMedia.addEventListener("change", onMediaChange);

  return {
    intro() {
      if (!reducedMotionMedia.matches) {
        introStartedAt = performance.now();
        startLoop();
      }
    },
    emphasize() {
      if (reducedMotionMedia.matches) return;
      const now = performance.now();
      const current = stepEmphasis(now);
      emphasisState = {
        phase: "ramp-up",
        startedAt: now,
        duration: EMPHASIS_CONFIG.rampUpDuration,
        from: current,
      };
      startLoop();
    },
    refreshPalette() {
      palette = readShimmerStyle(canvas, scratchCtx);
      renderFrame(performance.now());
    },
    destroy() {
      stopLoop();
      resizeObserver.disconnect();
      intersectionObserver.disconnect();
      mutationObserver.disconnect();
      darkMedia.removeEventListener("change", onMediaChange);
      reducedMotionMedia.removeEventListener("change", onMediaChange);
    },
  };
}
