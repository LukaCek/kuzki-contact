// Extra device analytics OFF by default; QR scan counts remain ON.
// Setting this true enables consent UI; it does not bypass consent.
const ENABLE_DEVICE_ANALYTICS = false;

(() => {
  "use strict";

  const SCAN_ORIGIN = "https://qr-pski-skenirano.cekluka.com";
  const SCAN_API = SCAN_ORIGIN + "/scan";
  const POSTER_ID_RE = /^[A-Za-z0-9_-]{4,24}$/;
  const BROWSER_ID_RE = /^[a-f0-9-]{36}$/;
  const PRIVACY_CHOICE = "kuzki_analytics_consent";
  const BROWSER_KEY = "kuzki_browser_id";
  let latestScan = null;

  function sendAnalytics(url, payload) {
    const body = JSON.stringify(payload);
    try {
      if (navigator.sendBeacon && navigator.sendBeacon(url, body)) return;
    } catch (_) { /* fallback below */ }
    try {
      fetch(url, {
        method: "POST", mode: "no-cors", keepalive: true, cache: "no-store",
        headers: {"Content-Type": "text/plain;charset=UTF-8"}, body
      }).catch(() => {});
    } catch (_) { /* tracking must never block contact */ }
  }

  function newRandomId() {
    const c = window.crypto;
    if (c && typeof c.randomUUID === "function") return c.randomUUID();
    if (c && typeof c.getRandomValues === "function") {
      const bytes = c.getRandomValues(new Uint8Array(16));
      bytes[6] = (bytes[6] & 15) | 64;
      bytes[8] = (bytes[8] & 63) | 128;
      const hex = Array.from(bytes, v => v.toString(16).padStart(2, "0")).join("");
      return [hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16),
        hex.slice(16, 20), hex.slice(20)].join("-");
    }
    return Date.now().toString(36) + Math.random().toString(36).slice(2);
  }

  // Retained for future opt-in analytics. Currently disabled by the toggle.
  function consentedBrowserId() {
    if (!ENABLE_DEVICE_ANALYTICS) return null;
    try {
      if (localStorage.getItem(PRIVACY_CHOICE) !== "yes") return null;
      let id = localStorage.getItem(BROWSER_KEY);
      if (!BROWSER_ID_RE.test(id || "")) {
        id = newRandomId();
        if (!BROWSER_ID_RE.test(id || "")) return null;
        localStorage.setItem(BROWSER_KEY, id);
      }
      return id;
    } catch (_) { return null; }
  }

  function allowedDeviceDetails() {
    if (!ENABLE_DEVICE_ANALYTICS) return {};
    let timezone = "";
    try { timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || ""; } catch (_) {}
    const connection = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    return {
      language: navigator.language || "", timezone,
      platform: navigator.platform || "",
      screen: (screen.width || 0) + "x" + (screen.height || 0),
      viewport: window.innerWidth + "x" + window.innerHeight,
      pixel_ratio: window.devicePixelRatio || 1,
      color_depth: screen.colorDepth || 0,
      touch_points: navigator.maxTouchPoints || 0,
      cores: navigator.hardwareConcurrency || 0,
      memory_gb: navigator.deviceMemory || "",
      network_type: connection?.effectiveType || ""
    };
  }

  function consentPayload() {
    if (!ENABLE_DEVICE_ANALYTICS) return {};
    const id = consentedBrowserId();
    return id ? {consent: true, browser_id: id, details: allowedDeviceDetails()} : {};
  }

  function recordPosterScan() {
    const params = new URLSearchParams(window.location.search);
    const posterId = params.get("p");
    if (!posterId) return;
    // Refresh and share must not trigger another QR scan.
    try {
      history.replaceState(null, "", window.location.pathname + window.location.hash);
    } catch (_) {}
    if (!POSTER_ID_RE.test(posterId)) return;
    const scanId = newRandomId();
    latestScan = {posterId, scanId};
    const url = SCAN_API + "?p=" + encodeURIComponent(posterId)
      + "&s=" + encodeURIComponent(scanId);
    sendAnalytics(url, ENABLE_DEVICE_ANALYTICS ? consentPayload() : {});
  }

  function initOptionalPrivacyControls() {
    if (!ENABLE_DEVICE_ANALYTICS) return;

    const footer = document.querySelector(".contact-footer");
    if (!footer) return;
    const section = document.createElement("section");
    section.className = "privacy-options";
    section.setAttribute("aria-label", "Nastavitve zasebnosti");
    const info = document.createElement("p");
    info.textContent = "Dodatna analitika: s tvojo privolitvijo lahko prepoznamo ponovne obiske istega brskalnika. Ni obvezno za uporabo kontaktne strani.";
    const actions = document.createElement("div");
    section.append(info, actions);
    footer.appendChild(section);

    function actionButton(label, callback) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "privacy-choice";
      button.textContent = label;
      button.addEventListener("click", callback);
      actions.appendChild(button);
    }

    function render() {
      actions.replaceChildren();
      if (consentedBrowserId()) {
        actionButton("Prekliči soglasje in izbriši podatke naprave", () => {
          const id = consentedBrowserId();
          if (id) sendAnalytics(SCAN_ORIGIN + "/privacy/forget", {browser_id: id});
          try {
            localStorage.removeItem(BROWSER_KEY);
            localStorage.setItem(PRIVACY_CHOICE, "no");
          } catch (_) {}
          render();
        });
      } else {
        actionButton("Dovoli prepoznavanje ponovnih obiskov", () => {
          try { localStorage.setItem(PRIVACY_CHOICE, "yes"); } catch (_) {}
          const id = consentedBrowserId();
          if (id && latestScan) {
            sendAnalytics(
              SCAN_API + "/enrich?p=" + encodeURIComponent(latestScan.posterId)
                + "&s=" + encodeURIComponent(latestScan.scanId),
              consentPayload()
            );
          }
          render();
        });
        actionButton("Brez dodatne analitike", () => {
          try { localStorage.setItem(PRIVACY_CHOICE, "no"); } catch (_) {}
          render();
        });
      }
    }
    render();
  }

  // Business contact details: keep the existing links intact.
  const PHONE_E164 = "+38670337710";
  function enablePhoneLinks() {
    const normalized = PHONE_E164.trim();
    if (!/^\+[1-9]\d{6,14}$/.test(normalized)) return;
    const digits = normalized.replace(/\D/g, "");
    const hrefs = {
      callBtn: "tel:" + normalized,
      smsBtn: "sms:" + normalized,
      whatsappBtn: "https://wa.me/" + digits + "?text=" + encodeURIComponent("Živjo! Zanima me sprehajanje kužka."),
      viberBtn: "viber://chat?number=" + encodeURIComponent(normalized)
    };
    Object.entries(hrefs).forEach(([id, href]) => {
      const el = document.getElementById(id);
      if (!el) return;
      el.href = href;
      el.classList.remove("disabled");
      el.removeAttribute("aria-disabled");
    });
  }

  function initShare() {
    const button = document.getElementById("shareBtn");
    const status = document.getElementById("shareStatus");
    if (!button || !status) return;
    let clearTimer;
    function feedback(message) {
      status.textContent = message;
      clearTimeout(clearTimer);
      clearTimer = setTimeout(() => { status.textContent = ""; }, 3200);
    }
    button.addEventListener("click", async () => {
      const url = window.location.origin + window.location.pathname;
      const data = {
        title: "Sprehajanje kužkov – kontakt",
        text: "Kontakt za sprehajanje kužkov.",
        url
      };
      try {
        if (navigator.share) await navigator.share(data);
        else if (navigator.clipboard && navigator.clipboard.writeText) {
          await navigator.clipboard.writeText(url);
          feedback("Povezava je kopirana.");
        } else feedback("Kopiranje ni podprto v tem brskalniku.");
      } catch (err) {
        if (err && err.name === "AbortError") return;
        feedback("Povezave ni bilo mogoče deliti.");
      }
    });
  }

  recordPosterScan();
  enablePhoneLinks();
  initShare();
  initOptionalPrivacyControls();
})();
