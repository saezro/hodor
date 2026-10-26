// embed.js — hodor embeddable button. Vanilla JS, no deps, no build step.
// Renders a <hodor-button> custom element (Shadow DOM, dark tokens lifted
// from panel.css) that opens/closes a scoped service via the v1 API
// (docs/DESIGN.md Phase 2b). Attributes win over the loading <script>'s
// data-* (so several buttons can share one script tag + custom elements
// with their own data-service/data-key/data-lang).
//
// Usage:
//   <script src="https://hodor.lan/static/embed.js" data-service="jellyfin"
//           data-key="hdr_…" data-lang="es" defer></script>
//   or explicitly: <hodor-button data-service="jellyfin" data-key="hdr_…"></hodor-button>
(function () {
  "use strict";

  // Must run synchronously while this script is still "the current
  // script" (true for classic + defer, false once anything async/dynamic
  // happens) — capture src + data-* now, use later.
  var selfScript = document.currentScript;
  var scriptBase = "";
  var scriptData = {};
  if (selfScript) {
    try {
      scriptBase = new URL(selfScript.getAttribute("src"), location.href).origin;
    } catch (e) { /* no src (inline) — base must come from data-base */ }
    scriptData = {
      base: selfScript.getAttribute("data-base"),
      service: selfScript.getAttribute("data-service"),
      key: selfScript.getAttribute("data-key"),
      lang: selfScript.getAttribute("data-lang")
    };
  }

  var STR = {
    en: {
      open: "Open", close: "Close", opening: "Opening…", closing: "Closing…",
      loading: "Loading…", durationLabel: "Duration",
      errAuth: "Invalid key.", errScope: "Not allowed for this key.",
      errRate: "Too many requests, try again soon.", errNet: "Connection error.",
      errConfig: "Missing data-service or data-key.",
      statusOpen: "Open", statusClosed: "Closed", until: "until"
    },
    es: {
      open: "Abrir", close: "Cerrar", opening: "Abriendo…", closing: "Cerrando…",
      loading: "Cargando…", durationLabel: "Duración",
      errAuth: "Clave inválida.", errScope: "No permitido para esta clave.",
      errRate: "Demasiadas peticiones, prueba en un momento.", errNet: "Error de conexión.",
      errConfig: "Falta data-service o data-key.",
      statusOpen: "Abierto", statusClosed: "Cerrado", until: "hasta"
    }
  };

  function pickLang(v) {
    if (v === "es" || v === "en") return v;
    return (navigator.language || "en").slice(0, 2) === "es" ? "es" : "en";
  }

  var CSS = ""
    + ":host{display:inline-block;font-family:Inter,'Inter Variable',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;}"
    + ".wrap{display:inline-flex;align-items:center;gap:.5rem;background:#1C1B19;"
    + "border:1px solid rgba(242,237,228,.12);border-radius:12px;padding:.45rem .6rem;"
    + "color:#F2EDE4;}"
    + ".dot{width:8px;height:8px;border-radius:999px;flex:none;}"
    + ".dot.open{background:#7bc47f;}"
    + ".dot.closed{background:#e0705e;}"
    + ".dot.pending{background:#a39d91;}"
    + ".state{font-size:.78rem;color:#a39d91;white-space:nowrap;font-variant-numeric:tabular-nums;"
    + "font-family:'JetBrains Mono','Fira Code',ui-monospace,'SF Mono',Menlo,monospace;}"
    + "select{background:#1F1D19;color:#F2EDE4;border:1px solid rgba(242,237,228,.22);"
    + "border-radius:8px;padding:.3rem .4rem;font-size:.78rem;font-family:inherit;}"
    + "select:focus-visible,button:focus-visible{outline:2px solid #F2B766;outline-offset:2px;}"
    + "button{border:0;border-radius:8px;padding:.35rem .75rem;font-size:.82rem;font-weight:650;"
    + "font-family:inherit;cursor:pointer;background:#F2B766;color:#15130F;}"
    + "button:hover:not(:disabled){background:#C97A2E;}"
    + "button:disabled{opacity:.6;cursor:default;}"
    + "button.danger{background:transparent;color:#e0705e;border:1px solid rgba(224,112,94,.4);}"
    + "button.danger:hover:not(:disabled){background:rgba(224,112,94,.12);}"
    + ".err{color:#e0705e;font-size:.78rem;}";

  function fmtCountdown(untilIso) {
    var ms = new Date(untilIso).getTime() - Date.now();
    if (isNaN(ms) || ms <= 0) return "00:00";
    var totalSec = Math.floor(ms / 1000);
    var h = Math.floor(totalSec / 3600);
    var m = Math.floor((totalSec % 3600) / 60);
    var s = totalSec % 60;
    if (h >= 1) return h + "h " + (m < 10 ? "0" : "") + m + "m";
    return (m < 10 ? "0" : "") + m + ":" + (s < 10 ? "0" : "") + s;
  }

  // CSP `default-src 'self'` (no `style-src`, so it inherits default-src)
  // blocks inline <style> content — including one injected into a shadow
  // root — the same as any other inline style. A constructable stylesheet
  // via adoptedStyleSheets is NOT inline styling as far as CSP is
  // concerned (spec carve-out), so it works under a strict CSP with zero
  // extra network request. Only very old browsers lack it; those fall
  // back to loading web/static/embed-button.css (kept in sync with the
  // CSS string above by hand — see comment on that file).
  function applyStyles(root, base) {
    try {
      if ("adoptedStyleSheets" in root && typeof CSSStyleSheet === "function") {
        var sheet = new CSSStyleSheet();
        sheet.replaceSync(CSS);
        root.adoptedStyleSheets = [sheet];
        return;
      }
    } catch (e) { /* fall through to <link> fallback below */ }
    var link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = (base || "") + "/static/embed-button.css";
    root.appendChild(link);
  }

  function define() {
    if (customElements.get("hodor-button")) return;

    class El extends HTMLElement {
      connectedCallback() {
        if (this._init) return;
        this._init = true;
        this._svc = this.getAttribute("data-service") || scriptData.service;
        this._key = this.getAttribute("data-key") || scriptData.key;
        this._lang = pickLang(this.getAttribute("data-lang") || scriptData.lang);
        var baseAttr = this.getAttribute("data-base") || scriptData.base || scriptBase;
        this._base = (baseAttr || "").replace(/\/$/, "");
        this._str = STR[this._lang];
        this._tickTimer = null;
        this._pollTimer = null;
        this._durations = ["1h"];

        var root = this.attachShadow({ mode: "open" });
        applyStyles(root, this._base);
        this._wrap = document.createElement("div");
        this._wrap.className = "wrap";
        this._wrap.setAttribute("role", "group");
        root.appendChild(this._wrap);

        if (!this._svc || !this._key || !this._base) {
          this._renderError(this._str.errConfig);
          return;
        }

        this._load();
        var self = this;
        this._pollTimer = setInterval(function () { self._load(); }, 30000);
        document.addEventListener("visibilitychange", function () {
          if (document.visibilityState === "visible") self._load();
        });
      }

      disconnectedCallback() {
        if (this._pollTimer) clearInterval(this._pollTimer);
        if (this._tickTimer) clearInterval(this._tickTimer);
      }

      _api(path, opts) {
        opts = opts || {};
        return fetch(this._base + path, {
          method: opts.method || "GET",
          headers: Object.assign(
            { Authorization: "Bearer " + this._key },
            opts.body ? { "Content-Type": "application/json" } : {}
          ),
          body: opts.body ? JSON.stringify(opts.body) : undefined
        }).then(function (r) {
          if (r.status === 204) return null;
          if (!r.ok) { var err = new Error("http " + r.status); err.status = r.status; throw err; }
          return r.json();
        });
      }

      _errMessage(err) {
        var s = this._str;
        if (err && err.status === 401) return s.errAuth;
        if (err && err.status === 403) return s.errScope;
        if (err && err.status === 429) return s.errRate;
        return s.errNet;
      }

      _load() {
        var self = this;
        this._api("/api/v1/services/" + encodeURIComponent(this._svc))
          .then(function (data) { self._svcData = data; self._durations = (data.durations && data.durations.length) ? data.durations : self._durations; self._render(); })
          .catch(function (e) { self._renderError(self._errMessage(e)); });
      }

      _renderError(msg) {
        this._wrap.innerHTML = "";
        var dot = document.createElement("span");
        dot.className = "dot pending";
        dot.setAttribute("aria-hidden", "true");
        var txt = document.createElement("span");
        txt.className = "err";
        txt.setAttribute("aria-live", "polite");
        txt.textContent = msg;
        this._wrap.appendChild(dot);
        this._wrap.appendChild(txt);
      }

      _render() {
        var s = this._str;
        var data = this._svcData;
        this._wrap.innerHTML = "";
        this._wrap.setAttribute("aria-label", data.title || data.name || this._svc);

        var dot = document.createElement("span");
        dot.className = "dot " + (data.open ? "open" : "closed");
        dot.setAttribute("aria-hidden", "true");
        this._wrap.appendChild(dot);

        if (data.open) {
          var state = document.createElement("span");
          state.className = "state";
          state.setAttribute("aria-live", "polite");
          this._wrap.appendChild(state);
          this._mountCountdown(state, data.until);

          var closeBtn = document.createElement("button");
          closeBtn.type = "button";
          closeBtn.className = "danger";
          closeBtn.textContent = s.close;
          closeBtn.addEventListener("click", this._onClose.bind(this, closeBtn));
          this._wrap.appendChild(closeBtn);
        } else {
          if (this._tickTimer) { clearInterval(this._tickTimer); this._tickTimer = null; }
          var sel = document.createElement("select");
          sel.setAttribute("aria-label", s.durationLabel);
          this._durations.forEach(function (d) {
            var opt = document.createElement("option");
            opt.value = d; opt.textContent = d;
            sel.appendChild(opt);
          });
          this._wrap.appendChild(sel);

          var openBtn = document.createElement("button");
          openBtn.type = "button";
          openBtn.textContent = s.open;
          openBtn.addEventListener("click", this._onOpen.bind(this, openBtn, sel));
          this._wrap.appendChild(openBtn);
        }
      }

      _mountCountdown(node, untilIso) {
        var self = this;
        if (this._tickTimer) clearInterval(this._tickTimer);
        if (!untilIso) { node.textContent = this._str.statusOpen; return; }
        function tick() { node.textContent = fmtCountdown(untilIso); }
        tick();
        this._tickTimer = setInterval(tick, 1000);
      }

      _onOpen(btn, sel) {
        var self = this;
        var s = this._str;
        btn.disabled = true;
        btn.textContent = s.opening;
        this._api("/api/v1/services/" + encodeURIComponent(this._svc) + "/open", { method: "POST", body: { for: sel.value } })
          .then(function () { self._load(); })
          .catch(function (e) { self._renderError(self._errMessage(e)); });
      }

      _onClose(btn) {
        var self = this;
        var s = this._str;
        btn.disabled = true;
        btn.textContent = s.closing;
        this._api("/api/v1/services/" + encodeURIComponent(this._svc) + "/close", { method: "POST" })
          .then(function () { self._load(); })
          .catch(function (e) { self._renderError(self._errMessage(e)); });
      }
    }

    customElements.define("hodor-button", El);
  }

  define();

  // No explicit <hodor-button> in the markup and the loading <script> has
  // its own data-service/data-key → render one right after the script tag
  // (the documented "drop a <script> and get a button" mode).
  if (selfScript && scriptData.service && scriptData.key && !document.querySelector("hodor-button")) {
    var auto = document.createElement("hodor-button");
    auto.setAttribute("data-service", scriptData.service);
    auto.setAttribute("data-key", scriptData.key);
    if (scriptData.lang) auto.setAttribute("data-lang", scriptData.lang);
    if (scriptData.base) auto.setAttribute("data-base", scriptData.base);
    selfScript.insertAdjacentElement("afterend", auto);
  }
})();
