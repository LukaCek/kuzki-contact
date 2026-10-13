const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const {test} = require("node:test");

const ROOT = path.resolve(__dirname, "..");
const script = fs.readFileSync(path.join(ROOT, "app.js"), "utf8");
const html = fs.readFileSync(path.join(ROOT, "index.html"), "utf8");

function visit(query, opts = {}) {
  const calls = [];
  const links = {};
  for (const id of ["callBtn", "smsBtn", "whatsappBtn", "viberBtn",
                     "shareBtn", "shareStatus"]) {
    links[id] = {
      href: "#", textContent: "",
      listeners: {},
      classList: {remove() {}},
      removeAttribute() {},
      addEventListener(name, callback) {this.listeners[name] = callback;}
    };
  }
  const location = {
    origin: "https://kuski.qd.je", pathname: "/", hash: "", search: query
  };
  const context = {
    window: {location, crypto: {randomUUID: () => "00000000-0000-4000-8000-000000000001"}},
    navigator: {
      sendBeacon(url, body) {
        calls.push({kind: "beacon", url, body});
        return opts.failBeacon ? false : true;
      },
      clipboard: {writeText: async url => calls.push({kind: "clipboard", url})}
    },
    history: {replaceState(a, b, value) {calls.push({kind: "history", value});}},
    document: {
      getElementById(id) {return links[id] || null;},
      querySelector() {throw Error("Opt-in UI should remain disabled");}
    },
    localStorage: {
      getItem() {throw Error("localStorage must not be read");},
      setItem() {throw Error("localStorage must not be written");},
      removeItem() {throw Error("localStorage must not be modified");}
    },
    URLSearchParams,
    Intl,
    encodeURIComponent,
    screen: {},
    setTimeout() {return 1;},
    clearTimeout() {},
    fetch(url, options) {
      calls.push({kind: "fetch", url, options});
      return Promise.resolve({ok: true});
    },
    Math,
    Date,
    Uint8Array
  };
  vm.runInNewContext(script, context, {filename: "app.js"});
  return {calls, links, location};
}

test("master toggle defaults to false and privacy helpers stay in source", () => {
  assert.match(script, /^\/\/[^\n]*\n\/\/[^\n]*\nconst ENABLE_DEVICE_ANALYTICS = false;/);
  for (const functionName of ["consentedBrowserId", "allowedDeviceDetails",
                              "consentPayload", "initOptionalPrivacyControls"]) {
    assert.ok(script.includes("function " + functionName + "("), functionName);
  }
});

test("single QR visit counts once with no fingerprint or localStorage", () => {
  const {calls} = visit("?p=preizkus1");
  const beacon = calls.filter(x => x.kind === "beacon");
  assert.equal(beacon.length, 1);
  assert.match(beacon[0].url, /\/scan\?p=preizkus1&s=00000000-0000-4000-8000-000000000001$/);
  assert.deepEqual(JSON.parse(beacon[0].body), {});
  assert.equal(calls.filter(x => x.kind === "history").length, 1);
});

test("no QR parameter means no request", () => {
  assert.equal(visit("").calls.filter(x => x.kind === "beacon").length, 0);
});

test("invalid poster ID is not counted", () => {
  assert.equal(visit("?p=a!").calls.filter(x => x.kind === "beacon").length, 0);
});

test("beacon failure uses fetch with no-cors", () => {
  const {calls} = visit("?p=abc123", {failBeacon: true});
  const f = calls.find(x => x.kind === "fetch");
  assert.ok(f);
  assert.equal(f.options.method, "POST");
  assert.equal(f.options.mode, "no-cors");
  assert.deepEqual(JSON.parse(f.options.body), {});
});

test("all contact links keep the correct phone number", () => {
  const {links} = visit("");
  assert.equal(links.callBtn.href, "tel:+38670337710");
  assert.equal(links.smsBtn.href, "sms:+38670337710");
  assert.equal(links.whatsappBtn.href, "https://wa.me/38670337710");
  assert.equal(links.viberBtn.href, "viber://chat?number=%2B38670337710");
});

test("share copies clean URL rather than a poster-specific one", async () => {
  const {links, calls} = visit("?p=abc123");
  await links.shareBtn.listeners.click();
  const c = calls.find(x => x.kind === "clipboard");
  assert.equal(c.url, "https://kuski.qd.je/");
});

test("flyer appears above contacts without a redundant top header", () => {
  assert.doesNotMatch(html, /<header class="site-header"|class="brand-logo"|ZA VESELE TAČKE/);
  assert.ok(html.indexOf('class="flyer-panel"') < html.indexOf('class="contact-panel"'));
  assert.match(html, /\\.contact-card\\s*\\{\\s*display: flex; flex-direction: column;/);
  assert.doesNotMatch(html, /flex-direction: column-reverse/);
  assert.match(html, /mateja-flyer\\.png\\?v=6/);
  assert.match(html, /class="brand-mark whatsapp-mark"/);
  assert.match(html, /class="brand-mark viber-mark"/);
  assert.match(html, /mailto:sprehodkuzkov\\.lj@gmail\\.com/);
  assert.match(html, /src="app\\.js\\?v=2" defer/);
  assert.doesNotMatch(html, /privacyControls|privacyActions|Dovoli anonimno prepoznavanje/);
});
