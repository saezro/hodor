// panel.js — hodor admin panel. Vanilla JS, no build step, no deps.
// Talks to the JSON admin API using the CSRF token from the #hodor-data
// island (see panel.html for why it's not a plain inline <script>).
(function () {
  "use strict";

  var dataEl = document.getElementById("hodor-data");
  var cfg = dataEl ? JSON.parse(dataEl.textContent) : { csrf: "", durations: ["1h", "3h", "6h", "24h"], lang: "en" };
  var CSRF = cfg.csrf;
  var DURATIONS = (cfg.durations && cfg.durations.length) ? cfg.durations : ["1h", "3h", "6h", "24h"];
  var LANG = cfg.lang === "es" ? "es" : "en";

  var STR = {
    en: {
      open: "Open", closed: "Closed", openFor: "Open", close: "Close",
      until: "until", forever: "no timer", by: "by",
      noServices: "No services configured.", noPins: "No pending PINs.",
      noPasses: "No device passes yet.", noEvents: "No events yet.",
      approve: "Approve", revoke: "Revoke", revoked: "revoked",
      opened: "opened", wasClosed: "closed", approved: "approved",
      failed: "Something went wrong.", offline: "offline",
      confirmRevoke: "Revoke this pass? The device will be signed out."
    },
    es: {
      open: "Abierto", closed: "Cerrado", openFor: "Abrir", close: "Cerrar",
      until: "hasta", forever: "sin límite", by: "por",
      noServices: "No hay servicios configurados.", noPins: "No hay PINs pendientes.",
      noPasses: "Aún no hay pases de dispositivo.", noEvents: "Aún no hay eventos.",
      approve: "Aprobar", revoke: "Revocar", revoked: "revocado",
      opened: "abierto", wasClosed: "cerrado", approved: "aprobado",
      failed: "Algo ha ido mal.", offline: "sin conexión",
      confirmRevoke: "¿Revocar este pase? El dispositivo quedará desconectado."
    }
  }[LANG];

  function el(tag, attrs, children) {
    var n = document.createElement(tag);
    for (var k in attrs || {}) {
      if (k === "text") n.textContent = attrs[k];
      else if (k === "html") n.innerHTML = attrs[k];
      else n.setAttribute(k, attrs[k]);
    }
    (children || []).forEach(function (c) { if (c) n.appendChild(c); });
    return n;
  }

  function fmtTime(iso) {
    var d = new Date(iso);
    if (isNaN(d.getTime())) return "";
    return d.toLocaleString(LANG === "es" ? "es-ES" : "en-GB", {
      day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit"
    });
  }

  function toast(msg, isError) {
    var region = document.getElementById("toast-region");
    var t = el("div", { class: "toast" + (isError ? " error" : ""), text: msg });
    region.appendChild(t);
    setTimeout(function () { t.remove(); }, 3500);
  }

  function setOffline(offline) {
    var pill = document.getElementById("conn-status");
    pill.hidden = !offline;
    pill.textContent = STR.offline;
  }

  function api(path, opts) {
    opts = opts || {};
    var headers = opts.headers || {};
    if (opts.method && opts.method !== "GET") headers["X-CSRF-Token"] = CSRF;
    if (opts.body) headers["Content-Type"] = "application/json";
    return fetch(path, {
      method: opts.method || "GET",
      headers: headers,
      body: opts.body ? JSON.stringify(opts.body) : undefined
    }).then(function (r) {
      setOffline(false);
      if (!r.ok) {
        return r.json().catch(function () { return {}; }).then(function (b) {
          throw new Error(b.error || (r.status + " " + r.statusText));
        });
      }
      if (r.status === 204) return null;
      return r.json();
    }).catch(function (err) {
      if (err instanceof TypeError) setOffline(true);
      throw err;
    });
  }

  // ---- Services -----------------------------------------------------

  function renderServices(services) {
    var list = document.getElementById("services-list");
    list.setAttribute("aria-busy", "false");
    list.innerHTML = "";
    if (!services.length) {
      list.appendChild(el("div", { class: "empty", text: STR.noServices }));
      return;
    }
    services.forEach(function (svc) {
      var meta = svc.open
        ? (svc.until ? STR.until + " " + fmtTime(svc.until) : STR.forever) + (svc.opened_by ? " · " + STR.by + " " + svc.opened_by : "")
        : (svc.group ? "group: " + svc.group : svc.mode);

      var durSelect = el("select", { "aria-label": "Duration" }, DURATIONS.map(function (d) {
        return el("option", { value: d, text: d });
      }));

      var openBtn = el("button", { class: "primary", type: "button" }, [document.createTextNode(STR.openFor)]);
      openBtn.addEventListener("click", function () {
        openBtn.disabled = true;
        api("/api/services/" + encodeURIComponent(svc.name) + "/open", { method: "POST", body: { for: durSelect.value } })
          .then(function () { toast(svc.title + " — " + STR.opened); loadServices(); })
          .catch(function (e) { toast(e.message || STR.failed, true); })
          .finally(function () { openBtn.disabled = false; });
      });

      var closeBtn = el("button", { class: "danger", type: "button", text: STR.close });
      closeBtn.addEventListener("click", function () {
        closeBtn.disabled = true;
        api("/api/services/" + encodeURIComponent(svc.name) + "/close", { method: "POST" })
          .then(function () { toast(svc.title + " — " + STR.wasClosed); loadServices(); })
          .catch(function (e) { toast(e.message || STR.failed, true); })
          .finally(function () { closeBtn.disabled = false; });
      });

      var actions = el("div", { class: "actions" }, svc.open ? [closeBtn] : [durSelect, openBtn]);

      var row = el("div", { class: "row" }, [
        el("div", { class: "row-main" }, [
          el("span", { class: "name", text: svc.title || svc.name }),
          el("span", { class: "meta", text: meta })
        ]),
        el("span", { class: "badge " + (svc.open ? "open" : "closed"), text: svc.open ? STR.open : STR.closed }),
        actions
      ]);
      list.appendChild(row);
    });
  }

  function loadServices() {
    return api("/api/services").then(renderServices).catch(function (e) { toast(e.message || STR.failed, true); });
  }

  // ---- PINs -----------------------------------------------------------

  function renderPins(pins) {
    var list = document.getElementById("pins-list");
    list.setAttribute("aria-busy", "false");
    list.innerHTML = "";
    document.getElementById("pins-count").hidden = pins.length === 0;
    document.getElementById("pins-count").textContent = String(pins.length);
    if (!pins.length) {
      list.appendChild(el("div", { class: "empty", text: STR.noPins }));
      return;
    }
    pins.forEach(function (p) {
      // The pending-PIN list never carries the raw 6-digit code (it would
      // defeat the point of a PIN); the admin reads it off the TV screen
      // and types it here to approve that specific pairing.
      var codeInput = el("input", {
        type: "text", inputmode: "numeric", pattern: "[0-9]{6}", maxlength: "6",
        placeholder: "••••••", class: "pin-code", "aria-label": "PIN code"
      });
      var approveBtn = el("button", { class: "primary", type: "button", text: STR.approve });
      approveBtn.addEventListener("click", function () {
        var code = codeInput.value.trim();
        if (!/^\d{6}$/.test(code)) { toast(STR.failed, true); return; }
        approveBtn.disabled = true;
        api("/api/pins", { method: "POST", body: { code: code } })
          .then(function () { toast(p.service + " — " + STR.approved); loadPins(); })
          .catch(function (e) { toast(e.message || STR.failed, true); })
          .finally(function () { approveBtn.disabled = false; });
      });
      var row = el("div", { class: "row" }, [
        el("div", { class: "row-main" }, [
          el("span", { class: "name", text: p.service }),
          el("span", { class: "meta", text: "created " + fmtTime(p.created_at) + " · expires " + fmtTime(p.expires_at) })
        ]),
        el("div", { class: "actions" }, [codeInput, approveBtn])
      ]);
      list.appendChild(row);
    });
  }

  function loadPins() {
    return api("/api/pins").then(renderPins).catch(function (e) { toast(e.message || STR.failed, true); });
  }

  // ---- Passes -----------------------------------------------------------

  function renderPasses(passes) {
    var list = document.getElementById("passes-list");
    list.setAttribute("aria-busy", "false");
    list.innerHTML = "";
    if (!passes.length) {
      list.appendChild(el("div", { class: "empty", text: STR.noPasses }));
      return;
    }
    passes.forEach(function (p) {
      var revokeBtn = el("button", { class: "danger", type: "button", text: STR.revoke, disabled: p.revoked ? "disabled" : null });
      if (!p.revoked) {
        revokeBtn.addEventListener("click", function () {
          if (!window.confirm(STR.confirmRevoke)) return;
          revokeBtn.disabled = true;
          api("/api/passes/" + encodeURIComponent(p.id), { method: "DELETE" })
            .then(function () { toast(p.label || p.service); loadPasses(); })
            .catch(function (e) { toast(e.message || STR.failed, true); revokeBtn.disabled = false; });
        });
      }
      var row = el("div", { class: "row" }, [
        el("div", { class: "row-main" }, [
          el("span", { class: "name", text: p.label || p.service }),
          el("span", { class: "meta", text: p.service + " · since " + fmtTime(p.created_at) })
        ]),
        el("span", { class: "badge " + (p.revoked ? "revoked" : "open"), text: p.revoked ? STR.revoked : STR.open }),
        el("div", { class: "actions" }, [revokeBtn])
      ]);
      list.appendChild(row);
    });
  }

  function loadPasses() {
    return api("/api/passes").then(renderPasses).catch(function (e) { toast(e.message || STR.failed, true); });
  }

  // ---- Events -----------------------------------------------------------

  function renderEvents(events) {
    var list = document.getElementById("events-list");
    list.setAttribute("aria-busy", "false");
    list.innerHTML = "";
    if (!events || !events.length) {
      list.appendChild(el("div", { class: "empty", text: STR.noEvents }));
      return;
    }
    events.slice().reverse().forEach(function (e) {
      var row = el("div", { class: "row event-row" }, [
        el("span", { class: "event-time", text: fmtTime(e.time) }),
        el("span", { class: "event-msg", text: e.message })
      ]);
      list.appendChild(row);
    });
  }

  function loadEvents() {
    return api("/api/events").then(renderEvents).catch(function () {
      // /api/events may be absent on older servers; degrade quietly.
      document.getElementById("events-list").innerHTML = "";
      document.getElementById("events-list").appendChild(el("div", { class: "empty", text: STR.noEvents }));
    });
  }

  function loadAll() {
    loadServices();
    loadPins();
    loadPasses();
    loadEvents();
  }

  loadAll();
  setInterval(loadAll, 5000);
})();
