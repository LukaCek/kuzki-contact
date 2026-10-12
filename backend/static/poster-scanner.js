/* Admin-only QR registration. Never navigate to scanned links. */
(() => {
  "use strict";

  const openButton = document.getElementById("open-flier-scanner");
  const dialog = document.getElementById("flier-scanner-dialog");
  const form = document.getElementById("flier-scanner-form");
  const nameInput = document.getElementById("flier-name");
  const posterIdInput = document.getElementById("flier-poster-id");
  const nextButton = document.getElementById("flier-open-camera");
  const closeButton = document.getElementById("flier-cancel");
  const imageInput = document.getElementById("flier-qr-image");
  const pastedInput = document.getElementById("flier-paste");
  const pasteButton = document.getElementById("flier-use-paste");
  const cameraBox = document.getElementById("flier-reader");
  const message = document.getElementById("flier-scanner-status");

  if (!openButton || !dialog || !form || !nameInput || !posterIdInput) return;

  const QR_LIBRARY = "https://cdnjs.cloudflare.com/ajax/libs/html5-qrcode/2.3.8/html5-qrcode.min.js";
  const VALID_ID = /^[A-Za-z0-9_-]{4,24}$/;
  let loaderPromise = null;
  let scanner = null;
  let operation = 0;
  let saving = false;

  function setStatus(text, isError = false) {
    message.textContent = text;
    message.style.color = isError ? "#a12222" : "#173e2e";
  }

  // Only accept this site's QR URL. Simply decoding never opens the link.
  function posterIdFromQr(raw) {
    let url;
    try { url = new URL(String(raw || "").trim()); }
    catch (_) { return null; }
    if (url.protocol !== "https:" || url.hostname !== "kuski.qd.je"
        || url.port || (url.pathname !== "/" && url.pathname !== "/index.html")
        || url.username || url.password) return null;
    const posterId = url.searchParams.get("p");
    if (!posterId || !VALID_ID.test(posterId)) return null;
    return posterId;
  }

  function validateName() {
    if (!nameInput.value.trim()) {
      nameInput.setCustomValidity("Vpiši ime plakata.");
      nameInput.reportValidity();
      return false;
    }
    nameInput.setCustomValidity("");
    return nameInput.reportValidity();
  }

  async function stopScanner() {
    const current = scanner;
    scanner = null;
    if (!current) return;
    try { await current.stop(); } catch (_) { /* May already be stopped. */ }
    try { current.clear(); } catch (_) {}
  }

  function loadScanner() {
    if (window.Html5Qrcode) return Promise.resolve();
    if (loaderPromise) return loaderPromise;
    loaderPromise = new Promise((resolve, reject) => {
      const script = document.createElement("script");
      script.src = QR_LIBRARY;
      script.async = true;
      script.onload = () => window.Html5Qrcode
        ? resolve()
        : reject(new Error("Knjižnica za QR ni bila naložena."));
      script.onerror = () => reject(new Error("QR knjižnice ni mogoče naložiti."));
      document.head.appendChild(script);
    }).catch(error => {
      loaderPromise = null;
      throw error;
    });
    return loaderPromise;
  }

  async function useDecodedQr(decoded) {
    if (!dialog.open || saving) return;
    const posterId = posterIdFromQr(decoded);
    if (!posterId) {
      setStatus("Ta QR-koda nima veljavnega naslova https://kuski.qd.je/?p=ID. "
        + "Preveri, ali je na letaku prava QR-koda.", true);
      return;
    }
    if (!validateName()) return;
    posterIdInput.value = posterId;
    saving = true;
    const myOperation = ++operation;
    nextButton.disabled = true;
    setStatus("Najdena koda " + posterId + ". Shranjujem ime plakata …");
    await stopScanner();
    if (myOperation !== operation || !dialog.open) return;
    // Only a normal authenticated POST to /stats/posters. No visit to the QR URL.
    if (form.requestSubmit) form.requestSubmit();
    else form.submit();
  }

  async function startCamera() {
    if (saving || !validateName()) return;
    const myOperation = ++operation;
    cameraBox.hidden = false;
    nextButton.disabled = true;
    setStatus("Odpiram kamero … Dovoli dostop do kamere v brskalniku.");
    try {
      await stopScanner();
      await loadScanner();
      if (!dialog.open || myOperation !== operation) return;
      if (!window.isSecureContext) throw new Error("Kamera deluje samo prek HTTPS.");
      scanner = new window.Html5Qrcode("flier-reader");
      await scanner.start(
        { facingMode: "environment" },
        { fps: 10, qrbox: 230 },
        text => { void useDecodedQr(text); },
        () => { /* No code in this frame — keep scanning. */ }
      );
      if (!dialog.open || myOperation !== operation) await stopScanner();
      else setStatus("Usmeri kamero v QR-kodo na fizičnem plakatu.");
    } catch (error) {
      if (myOperation !== operation) return;
      await stopScanner();
      setStatus("Kamere ni bilo mogoče zagnati. Poskusi fotografijo ali "
        + "prilepi povezavo QR-kode. " + String(error && error.message || ""), true);
    } finally {
      if (myOperation === operation) nextButton.disabled = false;
    }
  }

  async function scanImage() {
    if (saving || !validateName()) return;
    const file = imageInput.files && imageInput.files[0];
    if (!file) return;
    const myOperation = ++operation;
    nextButton.disabled = true;
    setStatus("Berem QR-kodo s slike …");
    try {
      await stopScanner();
      await loadScanner();
      if (!dialog.open || myOperation !== operation) return;
      scanner = new window.Html5Qrcode("flier-reader");
      cameraBox.hidden = false;
      const decoded = await scanner.scanFile(file, true);
      if (!dialog.open || myOperation !== operation) return;
      await useDecodedQr(decoded);
    } catch (error) {
      if (myOperation !== operation) return;
      await stopScanner();
      setStatus("Na sliki ni bilo mogoče prebrati QR-kode. Poskusi znova "
        + "ali prilepi povezavo. " + String(error && error.message || ""), true);
    } finally {
      if (myOperation === operation) nextButton.disabled = false;
      imageInput.value = "";
    }
  }

  openButton.addEventListener("click", () => {
    if (typeof dialog.showModal !== "function") {
      alert("Tvoj brskalnik ne podpira tega okenca. Posodobi brskalnik.");
      return;
    }
    form.reset();
    posterIdInput.value = "";
    cameraBox.hidden = true;
    saving = false;
    nextButton.disabled = false;
    message.textContent = "";
    dialog.showModal();
    nameInput.focus();
  });

  nextButton.addEventListener("click", () => { void startCamera(); });
  imageInput.addEventListener("change", () => { void scanImage(); });
  pasteButton.addEventListener("click", () => { void useDecodedQr(pastedInput.value); });
  closeButton.addEventListener("click", () => dialog.close());
  dialog.addEventListener("close", () => {
    ++operation;
    void stopScanner();
    saving = false;
    nextButton.disabled = false;
  });
  nameInput.addEventListener("input", () => nameInput.setCustomValidity(""));
  form.addEventListener("submit", event => {
    if (!VALID_ID.test(posterIdInput.value)) {
      event.preventDefault();
      setStatus("Najprej skeniraj veljavno QR-kodo.", true);
    }
  });
})();
