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
      until: "until", forever: "no timer", by: "by", group: "group",
      noServices: "No services configured.", noPins: "No pending PINs.",
      noPasses: "No device passes yet.", noEvents: "No events yet.",
      approve: "Approve", revoke: "Revoke", revoked: "revoked",
      opened: "opened", wasClosed: "closed", expired: "closed (expired)", approved: "approved",
      failed: "Something went wrong.", offline: "offline",
      confirmRevoke: "Revoke this pass? The device will be signed out.",
      pinCodeLabel: "PIN code", durationLabel: "Duration",
      created: "created", expires: "expires", since: "since",
      // Settings tab (services/durations/keys/reload) — see render in
      // panel.js below; kept out of the Go template/i18n.go on purpose.
      base: "base", overlay: "overlay",
      svcHeading: "Services", svcAdd: "Add service", svcEdit: "Edit", svcDelete: "Delete",
      svcAddTitle: "Add service", svcEditTitle: "Edit service",
      svcName: "Name (lowercase, letters/digits/-)", svcTitleLabel: "Title",
      svcHosts: "Hosts (comma-separated)", svcMode: "Mode", svcUpstream: "Upstream URL",
      svcGroup: "Group (optional)", svcAccent: "Accent color (optional)",
      svcMessage: "Closed-page message (optional)",
      svcBypass: "Skip the closed page while this is the only closed service",
      svcSave: "Save", svcCancel: "Cancel",
      svcDeleteConfirm: "Delete this service from the overlay?",
      svcSaved: "service saved", svcDeleted: "service deleted",
      durHeading: "Open-for durations", durSave: "Save", durSaved: "durations saved",
      keysHeading: "API keys", keyAdd: "New key", keyAddTitle: "New API key",
      noKeys: "No API keys yet.",
      keyName: "Name", keyServices: "Services (comma-separated, or *)",
      keyActionsLegend: "Allowed actions", keyOrigins: "Allowed origins (comma-separated, optional)",
      keySave: "Create", keyCancel: "Cancel", keyRevoke: "Revoke",
      keyRevokeConfirm: "Revoke this key? Anything using it stops working right away.",
      keyRevoked: "key revoked",
      keyResultTitle: "Key created", keyResultWarning: "Copy it now — it will not be shown again.",
      keyResultValueLabel: "API key", keyResultSnippetLabel: "Embeddable snippet (script or iframe)",
      copy: "Copy", copied: "Copied", closeBtn: "Close",
      reloadHeading: "Reload configuration", reloadBtn: "Reload config",
      reloadDone: "config reloaded", reloadWarnings: "Reloaded with warnings:"
    },
    es: {
      open: "Abierto", closed: "Cerrado", openFor: "Abrir", close: "Cerrar",
      until: "hasta", forever: "sin límite", by: "por", group: "grupo",
      noServices: "No hay servicios configurados.", noPins: "No hay PINs pendientes.",
      noPasses: "Aún no hay pases de dispositivo.", noEvents: "Aún no hay eventos.",
      approve: "Aprobar", revoke: "Revocar", revoked: "revocado",
      opened: "abierto", wasClosed: "cerrado", expired: "cerrado (caducado)", approved: "aprobado",
      failed: "Algo ha ido mal.", offline: "sin conexión",
      confirmRevoke: "¿Revocar este pase? El dispositivo quedará desconectado.",
      pinCodeLabel: "Código PIN", durationLabel: "Duración",
      created: "creado", expires: "caduca", since: "desde",
      base: "base", overlay: "overlay",
      svcHeading: "Servicios", svcAdd: "Añadir servicio", svcEdit: "Editar", svcDelete: "Eliminar",
      svcAddTitle: "Añadir servicio", svcEditTitle: "Editar servicio",
      svcName: "Nombre (minúsculas, letras/dígitos/-)", svcTitleLabel: "Título",
      svcHosts: "Hosts (separados por coma)", svcMode: "Modo", svcUpstream: "URL de destino",
      svcGroup: "Grupo (opcional)", svcAccent: "Color de acento (opcional)",
      svcMessage: "Mensaje de página cerrada (opcional)",
      svcBypass: "Saltar la página cerrada mientras este sea el único servicio cerrado",
      svcSave: "Guardar", svcCancel: "Cancelar",
      svcDeleteConfirm: "¿Eliminar este servicio del overlay?",
      svcSaved: "servicio guardado", svcDeleted: "servicio eliminado",
      durHeading: "Duraciones de apertura", durSave: "Guardar", durSaved: "duraciones guardadas",
      keysHeading: "Claves de API", keyAdd: "Nueva clave", keyAddTitle: "Nueva clave de API",
      noKeys: "Aún no hay claves de API.",
      keyName: "Nombre", keyServices: "Servicios (separados por coma, o *)",
      keyActionsLegend: "Acciones permitidas", keyOrigins: "Orígenes permitidos (separados por coma, opcional)",
      keySave: "Crear", keyCancel: "Cancelar", keyRevoke: "Revocar",
      keyRevokeConfirm: "¿Revocar esta clave? Lo que la use deja de funcionar enseguida.",
      keyRevoked: "clave revocada",
      keyResultTitle: "Clave creada", keyResultWarning: "Cópiala ahora — no volverá a mostrarse.",
      keyResultValueLabel: "Clave de API", keyResultSnippetLabel: "Fragmento insertable (script o iframe)",
      copy: "Copiar", copied: "Copiado", closeBtn: "Cerrar",
      reloadHeading: "Recargar configuración", reloadBtn: "Recargar config",
      reloadDone: "config recargada", reloadWarnings: "Recargada con avisos:"
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
          // body kept on the error so settings forms can show the
          // per-field message from a 400 {"errors":{field:msg}} instead
          // of the generic "400 Bad Request" (see formError below).
          var err = new Error(b.error || (r.status + " " + r.statusText));
          err.body = b;
          throw err;
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
        : (svc.group ? STR.group + ": " + svc.group : svc.mode);

      var durSelect = el("select", { "aria-label": STR.durationLabel }, DURATIONS.map(function (d) {
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
        placeholder: "000000", class: "pin-code", "aria-label": STR.pinCodeLabel
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
          el("span", { class: "meta", text: STR.created + " " + fmtTime(p.created_at) + " · " + STR.expires + " " + fmtTime(p.expires_at) })
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
          el("span", { class: "meta", text: p.service + " · " + STR.since + " " + fmtTime(p.created_at) })
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

  // The server logs events as a stable "type:service[:extra]" key (see
  // internal/state/state.go appendEventLocked callers) so this is the only
  // place that needs to know how to phrase them per language. Anything not
  // matching the known types (e.g. a message persisted by an older build)
  // is shown as-is rather than dropped.
  function formatEvent(message) {
    var parts = (message || "").split(":");
    var svc = parts[1];
    switch (parts[0]) {
      case "opened":
        var by = parts.slice(2).join(":");
        return svc + " — " + STR.opened + (by ? " " + STR.by + " " + by : "");
      case "closed":
        return svc + " — " + STR.wasClosed;
      case "expired":
        return svc + " — " + STR.expired;
      default:
        return message;
    }
  }

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
        el("span", { class: "event-msg", text: formatEvent(e.message) })
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

  // ---- Settings: services CRUD (base read-only), durations editor,
  // API keys (create shows the raw key once + copy + snippet, revoke),
  // reload-config button. Loaded lazily (see showTab below) since it is
  // the one tab not worth polling every 5s like the rest of loadAll.
  // All its labels/buttons are built here from STR, same convention as
  // the services/pins/passes/events rows above, so panel.html only
  // needs empty containers + the <dialog>s.

  function formError(err) {
    if (err && err.body && err.body.errors) {
      var k = Object.keys(err.body.errors)[0];
      return k + ": " + err.body.errors[k];
    }
    return (err && err.message) || STR.failed;
  }

  function splitList(s) {
    return (s || "").split(",").map(function (v) { return v.trim(); }).filter(Boolean);
  }

  function copyText(text, btn) {
    var done = function () {
      var orig = btn.textContent;
      btn.textContent = STR.copied;
      setTimeout(function () { btn.textContent = orig; }, 1500);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done).catch(function () { toast(STR.failed, true); });
    } else {
      toast(STR.failed, true);
    }
  }

  // Static chrome (headings/buttons/labels) for the settings tab: set
  // once here instead of in panel.html, consistent with how pins/passes
  // rows get their button text from STR rather than the template.
  function initSettingsChrome() {
    document.getElementById("settings-services-h").textContent = STR.svcHeading;
    document.getElementById("service-add-btn").textContent = STR.svcAdd;
    document.getElementById("settings-durations-h").textContent = STR.durHeading;
    document.getElementById("durations-save-btn").textContent = STR.durSave;
    document.getElementById("settings-keys-h").textContent = STR.keysHeading;
    document.getElementById("key-add-btn").textContent = STR.keyAdd;
    document.getElementById("settings-reload-h").textContent = STR.reloadHeading;
    document.getElementById("reload-btn").textContent = STR.reloadBtn;

    document.getElementById("svc-name-label").textContent = STR.svcName;
    document.getElementById("svc-title-label").textContent = STR.svcTitleLabel;
    document.getElementById("svc-hosts-label").textContent = STR.svcHosts;
    document.getElementById("svc-mode-label").textContent = STR.svcMode;
    document.getElementById("svc-upstream-label").textContent = STR.svcUpstream;
    document.getElementById("svc-group-label").textContent = STR.svcGroup;
    document.getElementById("svc-accent-label").textContent = STR.svcAccent;
    document.getElementById("svc-message-label").textContent = STR.svcMessage;
    document.getElementById("svc-bypass-label").textContent = STR.svcBypass;
    document.getElementById("service-cancel-btn").textContent = STR.svcCancel;
    document.getElementById("service-save-btn").textContent = STR.svcSave;

    document.getElementById("key-name-label").textContent = STR.keyName;
    document.getElementById("key-services-label").textContent = STR.keyServices;
    document.getElementById("key-actions-legend").textContent = STR.keyActionsLegend;
    document.getElementById("key-origins-label").textContent = STR.keyOrigins;
    document.getElementById("key-cancel-btn").textContent = STR.keyCancel;
    document.getElementById("key-save-btn").textContent = STR.keySave;
    document.getElementById("key-dialog-title").textContent = STR.keyAddTitle;

    document.getElementById("key-result-title").textContent = STR.keyResultTitle;
    document.getElementById("key-result-warning").textContent = STR.keyResultWarning;
    document.getElementById("key-result-value-label").textContent = STR.keyResultValueLabel;
    document.getElementById("key-result-snippet-label").textContent = STR.keyResultSnippetLabel;
    document.getElementById("key-result-copy-btn").textContent = STR.copy;
    document.getElementById("key-result-snippet-copy-btn").textContent = STR.copy;
    document.getElementById("key-result-close-btn").textContent = STR.closeBtn;
  }

  var serviceDialog = document.getElementById("service-dialog");
  var serviceForm = document.getElementById("service-form");
  var serviceFormError = document.getElementById("service-form-error");
  var svcUpstreamField = document.getElementById("svc-upstream-field");
  var editingServiceName = null; // null = creating a new overlay service

  document.getElementById("svc-mode").addEventListener("change", function () {
    svcUpstreamField.hidden = this.value !== "proxy";
  });

  function openServiceDialog(svc) {
    serviceFormError.hidden = true;
    editingServiceName = svc ? svc.name : null;
    document.getElementById("service-dialog-title").textContent = svc ? STR.svcEditTitle : STR.svcAddTitle;
    document.getElementById("svc-name").value = svc ? svc.name : "";
    document.getElementById("svc-name").disabled = !!svc;
    document.getElementById("svc-title").value = svc ? svc.title || "" : "";
    document.getElementById("svc-hosts").value = svc ? (svc.hosts || []).join(", ") : "";
    document.getElementById("svc-mode").value = svc ? svc.mode || "proxy" : "proxy";
    document.getElementById("svc-upstream").value = svc ? svc.upstream || "" : "";
    svcUpstreamField.hidden = (svc ? svc.mode : "proxy") !== "proxy";
    document.getElementById("svc-group").value = svc ? svc.group || "" : "";
    document.getElementById("svc-accent").value = svc ? svc.accent_color || "" : "";
    document.getElementById("svc-message").value = svc ? svc.message || "" : "";
    document.getElementById("svc-bypass").checked = !!(svc && svc.pass_bypasses_closed);
    serviceDialog.showModal();
  }

  document.getElementById("service-add-btn").addEventListener("click", function () { openServiceDialog(null); });
  document.getElementById("service-cancel-btn").addEventListener("click", function () { serviceDialog.close(); });

  serviceForm.addEventListener("submit", function (ev) {
    ev.preventDefault();
    var name = editingServiceName || document.getElementById("svc-name").value.trim();
    var hosts = splitList(document.getElementById("svc-hosts").value);
    if (!name || !hosts.length) { serviceFormError.textContent = STR.failed; serviceFormError.hidden = false; return; }

    var body = {
      title: document.getElementById("svc-title").value.trim(),
      hosts: hosts,
      mode: document.getElementById("svc-mode").value,
      upstream: document.getElementById("svc-upstream").value.trim(),
      group: document.getElementById("svc-group").value.trim(),
      accent_color: document.getElementById("svc-accent").value.trim(),
      message: document.getElementById("svc-message").value.trim()
    };
    // Omitted unless checked: the field is *bool server-side and an
    // explicit false would override the base default, not just leave it
    // alone, so "unchecked" here means "don't set it" rather than "off".
    if (document.getElementById("svc-bypass").checked) body.pass_bypasses_closed = true;

    var saveBtn = document.getElementById("service-save-btn");
    saveBtn.disabled = true;
    api("/api/config/services/" + encodeURIComponent(name), { method: "PUT", body: body })
      .then(function () {
        serviceDialog.close();
        toast(STR.svcSaved);
        loadSettings();
        loadServices();
      })
      .catch(function (e) { serviceFormError.textContent = formError(e); serviceFormError.hidden = false; })
      .finally(function () { saveBtn.disabled = false; });
  });

  function renderSettingsServices(services) {
    var list = document.getElementById("settings-services-list");
    list.setAttribute("aria-busy", "false");
    list.innerHTML = "";
    if (!services.length) {
      list.appendChild(el("div", { class: "empty", text: STR.noServices }));
      return;
    }
    services.forEach(function (svc) {
      var meta = (svc.hosts || []).join(", ") + " · " + svc.mode + (svc.group ? " · " + STR.group + ": " + svc.group : "");
      var isBase = svc.source === "base";
      var badge = el("span", { class: "badge " + (isBase ? "base" : "open"), text: isBase ? STR.base : STR.overlay });
      var actions;
      if (isBase) {
        actions = el("div", { class: "actions" }, []);
      } else {
        var editBtn = el("button", { type: "button", text: STR.svcEdit });
        editBtn.addEventListener("click", function () { openServiceDialog(svc); });
        var delBtn = el("button", { class: "danger", type: "button", text: STR.svcDelete });
        delBtn.addEventListener("click", function () {
          if (!window.confirm(STR.svcDeleteConfirm)) return;
          delBtn.disabled = true;
          api("/api/config/services/" + encodeURIComponent(svc.name), { method: "DELETE" })
            .then(function () { toast(STR.svcDeleted); loadSettings(); loadServices(); })
            .catch(function (e) { toast(formError(e), true); delBtn.disabled = false; });
        });
        actions = el("div", { class: "actions" }, [editBtn, delBtn]);
      }
      list.appendChild(el("div", { class: "row settings-row" }, [
        el("div", { class: "row-main" }, [
          el("span", { class: "name", text: svc.title || svc.name }),
          el("span", { class: "meta", text: meta })
        ]),
        badge,
        actions
      ]));
    });
  }

  var durationsForm = document.getElementById("durations-form");
  var durationsInput = document.getElementById("durations-input");
  durationsForm.addEventListener("submit", function (ev) {
    ev.preventDefault();
    var durations = splitList(durationsInput.value);
    var btn = document.getElementById("durations-save-btn");
    btn.disabled = true;
    api("/api/config/durations", { method: "PUT", body: { durations: durations } })
      .then(function () { DURATIONS = durations.length ? durations : DURATIONS; toast(STR.durSaved); })
      .catch(function (e) { toast(formError(e), true); })
      .finally(function () { btn.disabled = false; });
  });

  var keyDialog = document.getElementById("key-dialog");
  var keyForm = document.getElementById("key-form");
  var keyFormError = document.getElementById("key-form-error");
  var keyResultDialog = document.getElementById("key-result-dialog");

  document.getElementById("key-add-btn").addEventListener("click", function () {
    keyFormError.hidden = true;
    keyForm.reset();
    keyDialog.showModal();
  });
  document.getElementById("key-cancel-btn").addEventListener("click", function () { keyDialog.close(); });

  keyForm.addEventListener("submit", function (ev) {
    ev.preventDefault();
    var name = document.getElementById("key-name").value.trim();
    var services = splitList(document.getElementById("key-services").value);
    var actions = [];
    ["open", "close", "status"].forEach(function (a) {
      if (document.getElementById("key-action-" + a).checked) actions.push(a);
    });
    var origins = splitList(document.getElementById("key-origins").value);
    if (!name || !services.length || !actions.length) {
      keyFormError.textContent = STR.failed;
      keyFormError.hidden = false;
      return;
    }
    var saveBtn = document.getElementById("key-save-btn");
    saveBtn.disabled = true;
    api("/api/config/keys", {
      method: "POST",
      body: { name: name, services: services, actions: actions, allow_origins: origins }
    }).then(function (res) {
      keyDialog.close();
      loadSettings();
      showKeyResult(res, services);
    }).catch(function (e) {
      keyFormError.textContent = formError(e);
      keyFormError.hidden = false;
    }).finally(function () { saveBtn.disabled = false; });
  });

  function showKeyResult(res, services) {
    document.getElementById("key-result-value").textContent = res.key;
    var svc = services[0] || "SERVICE";
    var note = services.length > 1 ? "\n# services: " + services.join(", ") : "";
    var snippet = '<script src="' + location.origin + '/embed.js" data-service="' + svc +
      '" data-key="' + res.key + '" defer><\/script>\n\n<iframe src="' + location.origin +
      "/embed/" + encodeURIComponent(svc) + "?k=" + res.key + '"></iframe>' + note;
    document.getElementById("key-result-snippet").value = snippet;
    document.getElementById("key-result-copy-btn").onclick = function () { copyText(res.key, this); };
    document.getElementById("key-result-snippet-copy-btn").onclick = function () { copyText(snippet, this); };
    document.getElementById("key-result-close-btn").onclick = function () { keyResultDialog.close(); };
    keyResultDialog.showModal();
  }

  function renderSettingsKeys(keys) {
    var list = document.getElementById("settings-keys-list");
    list.setAttribute("aria-busy", "false");
    list.innerHTML = "";
    if (!keys.length) {
      list.appendChild(el("div", { class: "empty", text: STR.noKeys }));
      return;
    }
    keys.forEach(function (k) {
      var isBase = k.source === "base";
      var meta = (k.services || []).join(", ") + " · " + (k.actions || []).join("/") +
        (k.allow_origins && k.allow_origins.length ? " · " + k.allow_origins.join(", ") : "");
      var badge = el("span", { class: "badge " + (isBase ? "base" : "open"), text: isBase ? STR.base : STR.overlay });
      var actions;
      if (isBase) {
        actions = el("div", { class: "actions" }, []);
      } else {
        var revokeBtn = el("button", { class: "danger", type: "button", text: STR.keyRevoke });
        revokeBtn.addEventListener("click", function () {
          if (!window.confirm(STR.keyRevokeConfirm)) return;
          revokeBtn.disabled = true;
          api("/api/config/keys/" + encodeURIComponent(k.id), { method: "DELETE" })
            .then(function () { toast(STR.keyRevoked); loadSettings(); })
            .catch(function (e) { toast(formError(e), true); revokeBtn.disabled = false; });
        });
        actions = el("div", { class: "actions" }, [revokeBtn]);
      }
      list.appendChild(el("div", { class: "row settings-row" }, [
        el("div", { class: "row-main" }, [
          el("span", { class: "name", text: k.name }),
          el("span", { class: "meta", text: meta })
        ]),
        badge,
        actions
      ]));
    });
  }

  document.getElementById("reload-btn").addEventListener("click", function () {
    var btn = this;
    var warnEl = document.getElementById("reload-warnings");
    btn.disabled = true;
    api("/api/config/reload", { method: "POST" })
      .then(function (res) {
        warnEl.innerHTML = "";
        if (res.warnings && res.warnings.length) {
          warnEl.hidden = false;
          res.warnings.forEach(function (w) { warnEl.appendChild(el("li", { text: w })); });
          toast(STR.reloadWarnings);
        } else {
          warnEl.hidden = true;
          toast(STR.reloadDone);
        }
      })
      .catch(function (e) { toast(formError(e), true); })
      .finally(function () { btn.disabled = false; });
  });

  var settingsChromeReady = false;
  function loadSettings() {
    if (!settingsChromeReady) { initSettingsChrome(); settingsChromeReady = true; }
    return api("/api/config").then(function (cfg) {
      durationsInput.value = (cfg.durations || []).join(", ");
      renderSettingsServices(cfg.services || []);
      renderSettingsKeys(cfg.api_keys || []);
    }).catch(function (e) { toast(formError(e), true); });
  }

  // ---- Tabs: show one .panel-section at a time, driven by the tab
  // links' hash so it's bookmarkable/back-button-friendly. No tab
  // framework, just toggling `hidden` + the active link class.

  var TAB_IDS = ["services", "pins", "passes", "events", "settings"];

  function showTab(id) {
    if (TAB_IDS.indexOf(id) === -1) id = TAB_IDS[0];
    TAB_IDS.forEach(function (tid) {
      document.getElementById(tid).hidden = tid !== id;
    });
    document.querySelectorAll(".tab-link").forEach(function (link) {
      var active = link.getAttribute("data-tab") === id;
      link.classList.toggle("is-active", active);
      if (active) link.setAttribute("aria-current", "true");
      else link.removeAttribute("aria-current");
    });
    if (id === "settings") loadSettings();
  }

  document.querySelectorAll(".tab-link").forEach(function (link) {
    link.addEventListener("click", function (ev) {
      ev.preventDefault();
      var id = link.getAttribute("data-tab");
      showTab(id);
      history.replaceState(null, "", "#" + id);
    });
  });

  showTab((location.hash || "").slice(1));

  loadAll();
  setInterval(loadAll, 5000);
})();
