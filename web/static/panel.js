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
  // Declared up front (not just where loadSettings used to set it) so
  // openServiceDialog/key-add-btn can also lazily init the settings
  // chrome if opened before the Settings tab was ever visited.
  var settingsChromeReady = false;

  var STR = {
    en: {
      open: "Open", closed: "Closed", openFor: "Open", close: "Close",
      until: "until", forever: "no timer", by: "by", group: "group",
      noServices: "No services configured.",
      noServicesEmpty: "No services yet — add the first one.", noPins: "No pending PINs.",
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
      svcBypass: "Devices with a pass get in even while closed",
      svcNameHint: "Internal identifier (also used for this service's pass cookie); can't be changed after creating it.",
      svcTitleHint: "Name shown in the panel and the closed page; falls back to the name if left blank.",
      svcHostsHint: "Domains that route to this service — hodor matches the request's Host header against this list.",
      svcModeHint: "Proxy: hodor forwards requests straight to Upstream. forwardAuth: your own reverse proxy (Caddy, Traefik, nginx…) asks hodor at /auth and serves the request itself.",
      svcUpstreamHint: "Where hodor forwards requests in proxy mode, e.g. http://127.0.0.1:5000. Not used in forwardAuth mode.",
      svcGroupHint: "Services sharing a group open and close together as one switch. Leave blank to control this service on its own.",
      svcAccentHint: "Accent color for this service's closed page, as a hex code like #C97A2E.",
      svcMessageHint: "Custom text shown on this service's closed page instead of the default message.",
      svcBypassHint: "A device that already got a pass (e.g. the TV) keeps working after the service closes again for everyone else.",
      svcSave: "Save", svcCancel: "Cancel",
      svcDeleteConfirm: "Delete this service from the overlay?",
      svcSaved: "service saved", svcDeleted: "service deleted",
      durSaved: "durations saved",
      genDurationsLabel: "Open-for durations (comma-separated)",
      settingsGeneralDesc: "Webhook, pass duration and the quick open-for presets.",
      settingsServicesDesc: "Edit or remove the services you added here; services from the base config are read-only and managed in the config file.",
      settingsKeysDesc: "Scoped keys to open or close services from outside the panel.",
      settingsAdvancedHeading: "Advanced",
      settingsAdvancedDesc: "Panel access, trusted proxies and the admin token. Changing these can lock you out of the panel.",
      advSaved: "advanced settings saved",
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
      reloadBtn: "Reload config",
      reloadDone: "config reloaded", reloadWarnings: "Reloaded with warnings:",
      // General settings block (see render in panel.js below).
      genHeading: "General", genSave: "Save", genSaved: "general settings saved",
      genLocked: "locked by file/env",
      genLangLabel: "Language", genAdminPublicUrlLabel: "Public admin URL",
      genAdminAllowCidrsLabel: "Allowed admin IPs/CIDRs (one per line)",
      genOnChangeLabel: "Webhook on change", genPassTtlLabel: "Pass duration",
      genAdminTokenLabel: "Admin token", genAdminTokenConfigured: "configured",
      genAdminTokenNotConfigured: "not configured",
      genAdminTokenSet: "Set", genAdminTokenClear: "Remove",
      genAdminTokenSetOk: "admin token set", genAdminTokenClearedOk: "admin token removed",
      genAdminTokenEmpty: "Type a new token first.",
      genAdminTrustedProxiesLabel: "Admin trusted proxies (one per line)",
      genAdminTrustedHeaderLabel: "Admin trusted header",
      genPublicTrustedProxiesLabel: "Public trusted proxies (one per line)",
      genPublicCookieSecureLabel: "Secure cookie",
      genFixedNote: "Ports, secret and data folder are changed with environment variables and require a restart.",
      genLockoutError: "This change would lock you out of the panel: your IP wouldn't be in the allowed list.",
      genNothingChanged: "Nothing to save.",
      loginTitle: "Admin access required", loginDesc: "This panel needs the admin token to continue.",
      loginSetupDesc: "First access: enter the setup code shown in the container logs.",
      loginLabel: "Admin token", loginSubmit: "Enter",
      loginError: "Incorrect token.", loginFailed: "Could not check the token.",
      logoutBtn: "Log out",
      setupBannerText: "Set an admin token in Settings → General; the setup code changes on every restart.",
      setupBannerLink: "Go to Settings"
    },
    es: {
      open: "Abierto", closed: "Cerrado", openFor: "Abrir", close: "Cerrar",
      until: "hasta", forever: "sin límite", by: "por", group: "grupo",
      noServices: "No hay servicios configurados.",
      noServicesEmpty: "Aún no hay servicios — añade el primero.", noPins: "No hay PINs pendientes.",
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
      svcBypass: "Los dispositivos con pase entran aunque esté cerrado",
      svcNameHint: "Identificador interno (también nombra la cookie de pase); no se puede cambiar después de crearlo.", svcTitleHint: "Nombre que se ve en el panel y en la página de cerrado; si se deja vacío, se usa el identificador.", svcHostsHint: "Dominios que llevan a este servicio: hodor compara la cabecera Host de cada petición con esta lista.", svcModeHint: "Proxy: hodor reenvía las peticiones directamente a la URL de destino. forwardAuth: tu propio proxy (Caddy, Traefik, nginx…) pregunta a hodor en /auth y sirve él la petición.", svcUpstreamHint: "Adónde reenvía hodor en modo proxy, p. ej. http://127.0.0.1:5000. No se usa en modo forwardAuth.", svcGroupHint: "Los servicios del mismo grupo se abren y cierran juntos con un solo interruptor. Vacío = este servicio va por su cuenta.", svcAccentHint: "Color de la página de cerrado de este servicio, en hexadecimal, p. ej. #C97A2E.", svcMessageHint: "Texto propio que se muestra en la página de cerrado en lugar del mensaje por defecto.", svcBypassHint: "Un dispositivo que ya tiene pase (p. ej. la tele) sigue entrando cuando el servicio se vuelve a cerrar para los demás.",
      svcSave: "Guardar", svcCancel: "Cancelar",
      svcDeleteConfirm: "¿Eliminar este servicio del overlay?",
      svcSaved: "servicio guardado", svcDeleted: "servicio eliminado",
      durSaved: "duraciones guardadas",
      genDurationsLabel: "Duraciones de apertura (separadas por coma)",
      settingsGeneralDesc: "Webhook, duración del pase y las duraciones rápidas de apertura.",
      settingsServicesDesc: "Edita o elimina los servicios que has añadido aquí; los de la configuración base son de solo lectura y se gestionan en el archivo de configuración.",
      settingsKeysDesc: "Claves con permisos concretos para abrir o cerrar servicios desde fuera del panel.",
      settingsAdvancedHeading: "Avanzado",
      settingsAdvancedDesc: "Acceso al panel, proxies de confianza y el token de administrador. Cambiarlos puede dejarte sin acceso al panel.",
      advSaved: "ajustes avanzados guardados",
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
      reloadBtn: "Recargar config",
      reloadDone: "config recargada", reloadWarnings: "Recargada con avisos:",
      genHeading: "General", genSave: "Guardar", genSaved: "configuración general guardada",
      genLocked: "fijado por archivo/entorno",
      genLangLabel: "Idioma", genAdminPublicUrlLabel: "URL pública del panel",
      genAdminAllowCidrsLabel: "IPs/CIDRs permitidas para el panel (una por línea)",
      genOnChangeLabel: "Webhook al cambiar", genPassTtlLabel: "Duración del pase",
      genAdminTokenLabel: "Token de administración", genAdminTokenConfigured: "configurado",
      genAdminTokenNotConfigured: "no configurado",
      genAdminTokenSet: "Establecer", genAdminTokenClear: "Quitar",
      genAdminTokenSetOk: "token de admin establecido", genAdminTokenClearedOk: "token de admin quitado",
      genAdminTokenEmpty: "Escribe primero un token nuevo.",
      genAdminTrustedProxiesLabel: "Proxies de confianza del panel (una por línea)",
      genAdminTrustedHeaderLabel: "Cabecera de confianza del panel",
      genPublicTrustedProxiesLabel: "Proxies de confianza públicos (una por línea)",
      genPublicCookieSecureLabel: "Cookie segura",
      genFixedNote: "Puertos, secreto y carpeta de datos se cambian con variables de entorno y requieren reinicio.",
      genLockoutError: "Ese cambio te dejaría sin acceso al panel: tu IP no estaría en la lista permitida.",
      genNothingChanged: "No hay nada que guardar.",
      loginTitle: "Acceso de administrador requerido", loginDesc: "Este panel necesita el token de administrador para continuar.",
      loginSetupDesc: "Primer acceso: introduce el código de setup que aparece en los logs del contenedor.",
      loginLabel: "Token de administrador", loginSubmit: "Entrar",
      loginError: "Token incorrecto.", loginFailed: "No se pudo comprobar el token.",
      logoutBtn: "Cerrar sesión",
      setupBannerText: "Fija un admin token en Configuración → General; el código de setup cambia en cada reinicio.",
      setupBannerLink: "Ir a Configuración"
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

  // ---- Setup banner --------------------------------------------------
  // Persistent (non-modal) nudge shown while admin.token is still unset
  // (setup mode: see applyLoginDialogMode below for the login side of
  // this). Driven by general.admin_token_set from GET /api/config(/general),
  // refreshed on load and every time renderGeneral() re-renders (i.e.
  // after visiting Settings or changing the token there).
  var setupBanner = document.getElementById("setup-banner");
  var setupBannerLinkBtn = document.getElementById("setup-banner-link");

  function updateSetupBanner(tokenSet) {
    if (!setupBanner) return;
    setupBanner.hidden = !!tokenSet;
  }

  if (setupBanner) {
    document.getElementById("setup-banner-text").textContent = STR.setupBannerText;
    setupBannerLinkBtn.textContent = STR.setupBannerLink;
    setupBannerLinkBtn.addEventListener("click", function () {
      showTab("settings");
      history.replaceState(null, "", "#settings");
      var advanced = document.getElementById("settings-advanced");
      if (advanced) advanced.open = true;
      document.getElementById("gen-admin-token").focus();
    });
  }

  // ---- Admin token (sessionStorage) ----------------------------------
  // The admin listener requires `Authorization: Bearer <admin.token>` on
  // every /api/* call once admin.token is configured (see
  // internal/admin/middleware.go csrfAndAuth). The panel itself has no
  // other way to carry that token, so it's kept in sessionStorage (never
  // persisted to disk/localStorage) and attached by api() below. Wrapped
  // in try/catch: sessionStorage can throw in locked-down contexts
  // (private browsing, disabled storage).
  var ADMIN_TOKEN_KEY = "hodor.adminToken";

  function getAdminToken() {
    try { return sessionStorage.getItem(ADMIN_TOKEN_KEY) || ""; } catch (e) { return ""; }
  }

  function setAdminToken(tok) {
    try {
      if (tok) sessionStorage.setItem(ADMIN_TOKEN_KEY, tok);
      else sessionStorage.removeItem(ADMIN_TOKEN_KEY);
    } catch (e) { /* storage unavailable, nothing we can do */ }
  }

  var loginDialog = document.getElementById("login-dialog");
  var loginForm = document.getElementById("login-form");
  var loginError = document.getElementById("login-form-error");
  var loginInput = document.getElementById("login-token");
  var loginSubmitBtn = document.getElementById("login-submit-btn");

  var loginDialogDesc = document.getElementById("login-dialog-desc");
  var loginSetupBlock = document.getElementById("login-setup-block");
  var loginSetupCopyBtn = document.getElementById("login-setup-copy-btn");

  // Setup mode: no admin.token configured yet, server hands out a
  // one-off setup token printed in its logs instead. Any 401 carries
  // `X-Hodor-Setup: 1` while that's the case (see api() below), which
  // flips the login dialog's copy so the first run tells people where
  // to find the code instead of implying they already have one.
  function applyLoginDialogMode(setup) {
    if (!loginDialog) return;
    loginDialogDesc.textContent = setup ? STR.loginSetupDesc : STR.loginDesc;
    loginSetupBlock.hidden = !setup;
  }

  function showLoginDialog(setup) {
    if (!loginDialog || loginDialog.open) return;
    applyLoginDialogMode(!!setup);
    loginError.hidden = true;
    loginInput.value = "";
    loginDialog.showModal();
    loginInput.focus();
  }

  if (loginDialog) {
    document.getElementById("login-dialog-title").textContent = STR.loginTitle;
    document.getElementById("login-token-label").textContent = STR.loginLabel;
    loginSubmitBtn.textContent = STR.loginSubmit;
    loginSetupCopyBtn.textContent = STR.copy;
    loginSetupCopyBtn.addEventListener("click", function () {
      copyText(document.getElementById("login-setup-cmd").textContent, loginSetupCopyBtn);
    });
    applyLoginDialogMode(false);
  }

  if (loginForm) {
    loginForm.addEventListener("submit", function (ev) {
      ev.preventDefault();
      var value = loginInput.value.trim();
      loginError.hidden = true;
      if (!value) return;
      loginSubmitBtn.disabled = true;
      fetch("/api/services", { headers: { "Authorization": "Bearer " + value } })
        .then(function (r) {
          if (r.status === 401) {
            applyLoginDialogMode(r.headers.get("X-Hodor-Setup") === "1");
            loginError.textContent = STR.loginError;
            loginError.hidden = false;
            return;
          }
          if (!r.ok) {
            loginError.textContent = STR.loginFailed;
            loginError.hidden = false;
            return;
          }
          setAdminToken(value);
          location.reload();
        })
        .catch(function () {
          loginError.textContent = STR.loginFailed;
          loginError.hidden = false;
        })
        .finally(function () { loginSubmitBtn.disabled = false; });
    });
  }

  function api(path, opts, _isCsrfRetry) {
    opts = opts || {};
    var headers = opts.headers || {};
    if (opts.method && opts.method !== "GET") headers["X-CSRF-Token"] = CSRF;
    if (opts.body) headers["Content-Type"] = "application/json";
    var token = getAdminToken();
    if (token) headers["Authorization"] = "Bearer " + token;
    return fetch(path, {
      method: opts.method || "GET",
      headers: headers,
      body: opts.body ? JSON.stringify(opts.body) : undefined
    }).then(function (r) {
      setOffline(false);
      if (!r.ok) {
        if (r.status === 401) showLoginDialog(r.headers.get("X-Hodor-Setup") === "1");
        // A 403 on a mutating request most likely means this tab's CSRF
        // token (embedded in the page when it loaded) went stale because
        // hodor restarted meanwhile: the CSRF secret is per-process (see
        // Server.csrfToken/csrfAndAuth in internal/admin/middleware.go),
        // so every tab left open across a restart would otherwise be
        // stuck failing until manually reloaded. Fetch a fresh token from
        // GET /api/csrf (needs auth but no CSRF token itself) and retry
        // this request exactly once before giving up.
        if (r.status === 403 && !_isCsrfRetry && opts.method && opts.method !== "GET") {
          return api("/api/csrf", { method: "GET" }).then(function (b) {
            if (b && b.token) CSRF = b.token;
            return api(path, opts, true);
          }).catch(function () {
            return Promise.reject(new Error(r.status + " " + r.statusText));
          });
        }
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

  function emptyServicesState() {
    var addBtn = el("button", { class: "primary", type: "button", text: STR.svcAdd });
    addBtn.addEventListener("click", function () { openServiceDialog(null); });
    return el("div", { class: "empty-state" }, [
      el("div", { class: "empty", text: STR.noServicesEmpty }),
      addBtn
    ]);
  }

  function renderServices(services) {
    var list = document.getElementById("services-list");
    list.setAttribute("aria-busy", "false");
    list.innerHTML = "";
    if (!services.length) {
      list.appendChild(emptyServicesState());
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

  function splitLines(s) {
    return (s || "").split("\n").map(function (v) { return v.trim(); }).filter(Boolean);
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
    document.getElementById("settings-general-h").textContent = STR.genHeading;
    document.getElementById("settings-general-desc").textContent = STR.settingsGeneralDesc;
    document.getElementById("gen-on-change-label").textContent = STR.genOnChangeLabel;
    document.getElementById("gen-pass-ttl-label").textContent = STR.genPassTtlLabel;
    document.getElementById("gen-durations-label").textContent = STR.genDurationsLabel;
    document.getElementById("general-save-btn").textContent = STR.genSave;

    document.getElementById("settings-services-h").textContent = STR.svcHeading;
    document.getElementById("settings-services-desc").textContent = STR.settingsServicesDesc;

    document.getElementById("settings-keys-h").textContent = STR.keysHeading;
    document.getElementById("settings-keys-desc").textContent = STR.settingsKeysDesc;
    document.getElementById("key-add-btn").textContent = STR.keyAdd;

    document.getElementById("settings-advanced-h").textContent = STR.settingsAdvancedHeading;
    document.getElementById("settings-advanced-desc").textContent = STR.settingsAdvancedDesc;
    document.getElementById("gen-lang-label").textContent = STR.genLangLabel;
    document.getElementById("gen-admin-public-url-label").textContent = STR.genAdminPublicUrlLabel;
    document.getElementById("gen-admin-allow-cidrs-label").textContent = STR.genAdminAllowCidrsLabel;
    document.getElementById("gen-admin-token-label").textContent = STR.genAdminTokenLabel;
    document.getElementById("gen-admin-token-set-btn").textContent = STR.genAdminTokenSet;
    document.getElementById("gen-admin-token-clear-btn").textContent = STR.genAdminTokenClear;
    document.getElementById("gen-admin-trusted-proxies-label").textContent = STR.genAdminTrustedProxiesLabel;
    document.getElementById("gen-admin-trusted-header-label").textContent = STR.genAdminTrustedHeaderLabel;
    document.getElementById("gen-public-trusted-proxies-label").textContent = STR.genPublicTrustedProxiesLabel;
    document.getElementById("gen-public-cookie-secure-label").textContent = STR.genPublicCookieSecureLabel;
    document.getElementById("gen-fixed-note").textContent = STR.genFixedNote;
    document.getElementById("advanced-save-btn").textContent = STR.genSave;
    [].forEach.call(document.querySelectorAll("#advanced-form .badge.base"), function (b) {
      b.textContent = STR.genLocked;
    });
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
    document.getElementById("svc-name-hint").textContent = STR.svcNameHint;
    document.getElementById("svc-title-hint").textContent = STR.svcTitleHint;
    document.getElementById("svc-hosts-hint").textContent = STR.svcHostsHint;
    document.getElementById("svc-mode-hint").textContent = STR.svcModeHint;
    document.getElementById("svc-upstream-hint").textContent = STR.svcUpstreamHint;
    document.getElementById("svc-group-hint").textContent = STR.svcGroupHint;
    document.getElementById("svc-accent-hint").textContent = STR.svcAccentHint;
    document.getElementById("svc-message-hint").textContent = STR.svcMessageHint;
    document.getElementById("svc-bypass-hint").textContent = STR.svcBypassHint;
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
    // Reachable from the Services tab's own add button (see below),
    // which can fire before Settings/initSettingsChrome ever ran — the
    // labels/button text for this dialog are set there, not here.
    if (!settingsChromeReady) { initSettingsChrome(); settingsChromeReady = true; }
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
    document.getElementById("svc-bypass").checked = !svc || svc.pass_bypasses_closed !== false;
    serviceDialog.showModal();
  }

  // The only "add service" trigger left in the UI (Settings used to have
  // its own duplicate button — Cas: "quiero ahí mismo el botón de añadir
  // servicio", 2026-10-27): header of the Services tab, next to the hint,
  // reusing this same dialog/flow. Its text is set here instead of lazily
  // in initSettingsChrome since Services is the default tab.
  document.getElementById("services-add-btn").textContent = STR.svcAdd;
  document.getElementById("services-add-btn").addEventListener("click", function () { openServiceDialog(null); });
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
    body.pass_bypasses_closed = document.getElementById("svc-bypass").checked;

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
    // Only overlay (panel-managed) services: base ones have no action
    // here (edit/delete are 409s against the base config) and listing
    // them was just the same data already shown, with no buttons, in
    // the Services tab (Cas: "la config es terrible" / duplicate list,
    // 2026-10-27).
    var overlayServices = (services || []).filter(function (svc) { return svc.source !== "base"; });
    var list = document.getElementById("settings-services-list");
    list.setAttribute("aria-busy", "false");
    list.innerHTML = "";
    if (!overlayServices.length) {
      list.appendChild(emptyServicesState());
      return;
    }
    overlayServices.forEach(function (svc) {
      var meta = (svc.hosts || []).join(", ") + " · " + svc.mode + (svc.group ? " · " + STR.group + ": " + svc.group : "");
      var badge = el("span", { class: "badge open", text: STR.overlay });
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
      var actions = el("div", { class: "actions" }, [editBtn, delBtn]);
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

  // Durations now live as one more field inside the General form/Save
  // (see generalForm submit below) instead of their own block + Save
  // button (Cas: several scattered Save buttons, 2026-10-27).
  var durationsInput = document.getElementById("gen-durations");

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

  // ---- General settings (GET/PUT /api/config/general): lang, admin
  // public URL, allowed admin CIDRs, webhook, pass TTL, plus an
  // <details> "advanced" group for the admin token (set/remove, never
  // shown) and the trusted-proxy/cookie knobs. originalGeneral holds the
  // last value loaded from the server so the PUT only carries fields the
  // admin actually changed (the API treats an absent field as "leave
  // alone", see internal/admin/panel.go) and never a locked one.
  var generalForm = document.getElementById("general-form");
  var generalFormError = document.getElementById("general-form-error");
  var advancedForm = document.getElementById("advanced-form");
  var advancedFormError = document.getElementById("advanced-form-error");
  var originalGeneral = null;
  var generalLocked = {};

  // admin_trusted_proxies and admin_trusted_header are read-only here on
  // purpose (security decision, 2026-10-26): the backend strips them from
  // the PUT body, so the panel only ever displays whatever value is
  // already configured (see renderGeneral below) instead of pretending
  // they are editable. Split 2026-10-27 between the General card (webhook,
  // pass duration, open-for durations — one Save) and the discreet
  // Advanced section (panel access/token — its own Save), still the same
  // PUT /api/config/general endpoint underneath, just two field subsets.
  var GENERAL_FIELD_IDS = {
    lang: "gen-lang",
    admin_public_url: "gen-admin-public-url",
    admin_allow_cidrs: "gen-admin-allow-cidrs",
    public_trusted_proxies: "gen-public-trusted-proxies",
    public_cookie_secure: "gen-public-cookie-secure",
    pass_ttl: "gen-pass-ttl",
    on_change: "gen-on-change",
    durations: "gen-durations"
  };

  function clearFieldErrors(genericEl) {
    genericEl.hidden = true;
    Object.keys(GENERAL_FIELD_IDS).forEach(function (field) {
      var fe = document.getElementById(GENERAL_FIELD_IDS[field] + "-error");
      if (fe) { fe.hidden = true; fe.textContent = ""; }
    });
    document.getElementById("gen-admin-token-error").hidden = true;
  }

  function showFieldErrors(err, genericEl) {
    clearFieldErrors(genericEl);
    if (err && err.body && err.body.error === "would lock you out") {
      genericEl.textContent = STR.genLockoutError;
      genericEl.hidden = false;
      return;
    }
    if (err && err.body && err.body.errors) {
      var any = false;
      Object.keys(err.body.errors).forEach(function (field) {
        var inputId = GENERAL_FIELD_IDS[field];
        var fe = inputId ? document.getElementById(inputId + "-error") : null;
        if (fe) { fe.textContent = err.body.errors[field]; fe.hidden = false; any = true; }
      });
      if (any) return;
    }
    genericEl.textContent = formError(err);
    genericEl.hidden = false;
  }

  function setGeneralFieldLocked(field, inputEl) {
    var locked = !!generalLocked[field];
    inputEl.disabled = locked;
    var badge = document.getElementById(GENERAL_FIELD_IDS[field] + "-badge");
    if (badge) badge.hidden = !locked;
  }

  function renderAdminTokenStatus(tokenSet) {
    var statusEl = document.getElementById("gen-admin-token-status");
    statusEl.textContent = tokenSet ? STR.genAdminTokenConfigured : STR.genAdminTokenNotConfigured;
    var tokenLocked = !!generalLocked.admin_token;
    document.getElementById("gen-admin-token").disabled = tokenLocked;
    document.getElementById("gen-admin-token-set-btn").disabled = tokenLocked;
    document.getElementById("gen-admin-token-clear-btn").disabled = tokenLocked || !tokenSet;
    var badge = document.getElementById("gen-admin-token-badge");
    if (badge) badge.hidden = !tokenLocked;
    var logoutBtnEl = document.getElementById("gen-admin-token-logout-btn");
    if (logoutBtnEl) logoutBtnEl.hidden = !tokenSet;
  }

  function renderGeneral(general) {
    originalGeneral = general || {};
    generalLocked = {};
    (originalGeneral.locked || []).forEach(function (f) { generalLocked[f] = true; });

    var langEl = document.getElementById("gen-lang");
    langEl.value = originalGeneral.lang === "en" ? "en" : "es";
    setGeneralFieldLocked("lang", langEl);

    var urlEl = document.getElementById("gen-admin-public-url");
    urlEl.value = originalGeneral.admin_public_url || "";
    setGeneralFieldLocked("admin_public_url", urlEl);

    var cidrsEl = document.getElementById("gen-admin-allow-cidrs");
    cidrsEl.value = (originalGeneral.admin_allow_cidrs || []).join("\n");
    setGeneralFieldLocked("admin_allow_cidrs", cidrsEl);

    var onChangeEl = document.getElementById("gen-on-change");
    onChangeEl.value = originalGeneral.on_change || "";
    setGeneralFieldLocked("on_change", onChangeEl);

    var ttlEl = document.getElementById("gen-pass-ttl");
    ttlEl.value = originalGeneral.pass_ttl || "";
    setGeneralFieldLocked("pass_ttl", ttlEl);

    var adminProxies = originalGeneral.admin_trusted_proxies || [];
    document.getElementById("gen-admin-trusted-proxies-field").hidden = adminProxies.length === 0;
    document.getElementById("gen-admin-trusted-proxies-value").textContent = adminProxies.join("\n");

    var adminHeader = originalGeneral.admin_trusted_header || "";
    document.getElementById("gen-admin-trusted-header-field").hidden = !adminHeader;
    document.getElementById("gen-admin-trusted-header-value").textContent = adminHeader;

    var publicProxiesEl = document.getElementById("gen-public-trusted-proxies");
    publicProxiesEl.value = (originalGeneral.public_trusted_proxies || []).join("\n");
    setGeneralFieldLocked("public_trusted_proxies", publicProxiesEl);

    var cookieEl = document.getElementById("gen-public-cookie-secure");
    cookieEl.checked = !!originalGeneral.public_cookie_secure;
    setGeneralFieldLocked("public_cookie_secure", cookieEl);

    document.getElementById("gen-admin-token").value = "";
    renderAdminTokenStatus(!!originalGeneral.admin_token_set);
    updateSetupBanner(!!originalGeneral.admin_token_set);
  }

  // General Save: webhook + pass duration (both PUT /api/config/general)
  // plus the open-for durations (PUT /api/config/durations, a different
  // endpoint — not merged backend-side to avoid an API change) behind one
  // button and one toast (Cas: several scattered Saves, 2026-10-27).
  generalForm.addEventListener("submit", function (ev) {
    ev.preventDefault();
    clearFieldErrors(generalFormError);
    if (!originalGeneral) return;

    var body = {};
    function maybeSet(field, val) {
      if (generalLocked[field]) return;
      if (JSON.stringify(originalGeneral[field] || null) !== JSON.stringify(val || null)) body[field] = val;
    }
    maybeSet("on_change", document.getElementById("gen-on-change").value.trim());
    maybeSet("pass_ttl", document.getElementById("gen-pass-ttl").value.trim());

    var durations = splitList(durationsInput.value);
    var durationsChanged = JSON.stringify(durations) !== JSON.stringify(DURATIONS);

    if (!Object.keys(body).length && !durationsChanged) { toast(STR.genNothingChanged); return; }

    var btn = document.getElementById("general-save-btn");
    btn.disabled = true;
    var p = Object.keys(body).length ? api("/api/config/general", { method: "PUT", body: body }) : Promise.resolve();
    p.then(function () {
        if (!durationsChanged) return;
        return api("/api/config/durations", { method: "PUT", body: { durations: durations } })
          .then(function () { DURATIONS = durations.length ? durations : DURATIONS; });
      })
      .then(function () { toast(STR.genSaved); loadSettings(); })
      .catch(function (e) { showFieldErrors(e, generalFormError); })
      .finally(function () { btn.disabled = false; });
  });

  // Advanced Save: lang, admin public URL/CIDRs, public trusted proxies
  // and cookie-secure — all PUT /api/config/general, separate from the
  // General card's own Save since this is the risk-of-lockout group
  // (lang reloads the page; URL/CIDRs can shut the admin's own IP out).
  advancedForm.addEventListener("submit", function (ev) {
    ev.preventDefault();
    clearFieldErrors(advancedFormError);
    if (!originalGeneral) return;

    var body = {};
    function maybeSet(field, val) {
      if (generalLocked[field]) return;
      if (JSON.stringify(originalGeneral[field] || null) !== JSON.stringify(val || null)) body[field] = val;
    }
    maybeSet("lang", document.getElementById("gen-lang").value);
    maybeSet("admin_public_url", document.getElementById("gen-admin-public-url").value.trim());
    maybeSet("admin_allow_cidrs", splitLines(document.getElementById("gen-admin-allow-cidrs").value));
    maybeSet("public_trusted_proxies", splitLines(document.getElementById("gen-public-trusted-proxies").value));
    maybeSet("public_cookie_secure", document.getElementById("gen-public-cookie-secure").checked);

    if (!Object.keys(body).length) { toast(STR.genNothingChanged); return; }

    var langChanged = "lang" in body;
    var btn = document.getElementById("advanced-save-btn");
    btn.disabled = true;
    api("/api/config/general", { method: "PUT", body: body })
      .then(function () {
        toast(STR.advSaved);
        if (langChanged) { location.reload(); return; }
        loadSettings();
      })
      .catch(function (e) { showFieldErrors(e, advancedFormError); })
      .finally(function () { btn.disabled = false; });
  });

  document.getElementById("gen-admin-token-set-btn").addEventListener("click", function () {
    clearFieldErrors(advancedFormError);
    var input = document.getElementById("gen-admin-token");
    var value = input.value.trim();
    var errEl = document.getElementById("gen-admin-token-error");
    if (!value) { errEl.textContent = STR.genAdminTokenEmpty; errEl.hidden = false; return; }
    var btn = this;
    btn.disabled = true;
    api("/api/config/general", { method: "PUT", body: { admin_token: value } })
      .then(function () {
        // Store it BEFORE the next api() call (loadSettings): once set
        // server-side, admin.token != "" means every /api/* needs the
        // bearer, including the panel's own GET /api/config — without
        // this the panel would lock itself out right after setting it.
        setAdminToken(value);
        toast(STR.genAdminTokenSetOk);
        input.value = "";
        loadSettings();
      })
      .catch(function (e) { errEl.textContent = formError(e); errEl.hidden = false; })
      .finally(function () { btn.disabled = false; });
  });

  document.getElementById("gen-admin-token-clear-btn").addEventListener("click", function () {
    clearFieldErrors(advancedFormError);
    var btn = this;
    btn.disabled = true;
    api("/api/config/general", { method: "PUT", body: { admin_token: "" } })
      .then(function () {
        setAdminToken("");
        toast(STR.genAdminTokenClearedOk);
        document.getElementById("gen-admin-token").value = "";
        loadSettings();
      })
      .catch(function (e) { document.getElementById("gen-admin-token-error").textContent = formError(e); document.getElementById("gen-admin-token-error").hidden = false; })
      .finally(function () { btn.disabled = false; });
  });

  var logoutBtn = document.getElementById("gen-admin-token-logout-btn");
  if (logoutBtn) {
    logoutBtn.textContent = STR.logoutBtn;
    logoutBtn.addEventListener("click", function () {
      setAdminToken("");
      location.reload();
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

  function loadSettings() {
    if (!settingsChromeReady) { initSettingsChrome(); settingsChromeReady = true; }
    return api("/api/config").then(function (cfg) {
      durationsInput.value = (cfg.durations || []).join(", ");
      renderGeneral(cfg.general || {});
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

  // Initial tab: an explicit #hash wins; otherwise land on Settings when
  // there are no services yet, since Services would just show the empty
  // state's "add the first one" CTA with nothing else to do there.
  var initialHash = (location.hash || "").slice(1);
  if (initialHash) {
    showTab(initialHash);
  } else {
    api("/api/services").then(function (services) {
      showTab(services.length ? "services" : "settings");
    }).catch(function () { showTab("services"); });
  }

  loadAll();
  setInterval(loadAll, 5000);

  // Prime the setup banner even if the user never opens Settings: a
  // fresh login in setup mode should see the nudge right away, not
  // only after clicking into the General tab. Quiet failure (e.g. still
  // logged out): the login dialog already covers that case.
  api("/api/config").then(function (cfg) {
    updateSetupBanner(!!(cfg.general && cfg.general.admin_token_set));
  }).catch(function () {});
})();
