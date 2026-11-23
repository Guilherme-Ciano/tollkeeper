(() => {
  "use strict";

  const VIEW_TITLES = {
    overview: "Overview",
    policy: "Policy Editor",
    pins: "Tool Pinning",
    simulator: "Call Simulator",
    audit: "Audit Explorer",
  };

  const state = {
    view: "overview",
    token: sessionStorage.getItem("tk_admin_token") || "",
    autoRefresh: true,
    overview: null,
    upstreams: [],
    policy: { default: "deny", rules: [], tenants: {} },
    policyScope: "__global__",
    expandedRules: new Set([0]),
    pinsReport: { mode: "off", tools: [] },
    pinFilter: "all",
    selectedPin: null,
    auditEvents: [],
    selectedAuditIdx: -1,
    inspectorTab: "details",
    paletteIdx: 0,
    paletteItems: [],
    refreshTimer: null,
  };

  const $ = (id) => document.getElementById(id);

  function esc(str) {
    return String(str ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function ico(name, extra) {
    return '<svg class="ico' + (extra ? " " + extra : "") + '"><use href="#ic-' + name + '"></use></svg>';
  }

  function toast(msg) {
    const el = $("toast");
    el.innerHTML = ico("check", "ico-sm") + "<span>" + esc(msg) + "</span>";
    el.classList.remove("hidden");
    clearTimeout(toast._t);
    toast._t = setTimeout(() => el.classList.add("hidden"), 2400);
  }

  function showGlobalError(msg) {
    const el = $("global-error");
    if (!msg) {
      el.classList.add("hidden");
      el.innerHTML = "";
      return;
    }
    el.innerHTML = ico("alert", "ico-sm") + "<span>" + esc(msg) + "</span>";
    el.classList.remove("hidden");
  }

  async function apiFetch(path, opts = {}) {
    const headers = Object.assign({ Accept: "application/json" }, opts.headers || {});
    if (state.token) {
      headers.Authorization = "Bearer " + state.token;
    }
    const resp = await fetch(path, Object.assign({}, opts, { headers }));
    if (resp.status === 401) {
      openAuthModal();
      throw new Error("Admin report token required (HTTP 401)");
    }
    if (!resp.ok) {
      const txt = await resp.text();
      throw new Error("HTTP " + resp.status + ": " + (txt.trim() || resp.statusText));
    }
    return resp.json();
  }

  async function copyText(text, label) {
    try {
      await navigator.clipboard.writeText(text);
      toast(label || "Copied to clipboard");
    } catch {
      toast("Clipboard unavailable");
    }
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("tk_theme", theme);
    $("btn-theme-light").classList.toggle("active", theme !== "dark");
    $("btn-theme-dark").classList.toggle("active", theme === "dark");
  }

  function initTheme() {
    const saved = localStorage.getItem("tk_theme");
    const initial = saved || (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    applyTheme(initial);
    $("btn-theme-light").addEventListener("click", () => applyTheme("light"));
    $("btn-theme-dark").addEventListener("click", () => applyTheme("dark"));
  }

  function toggleTheme() {
    const cur = document.documentElement.getAttribute("data-theme");
    applyTheme(cur === "dark" ? "light" : "dark");
  }

  function initLiveToggle() {
    const btn = $("btn-auto-refresh");
    btn.addEventListener("click", () => {
      state.autoRefresh = !state.autoRefresh;
      btn.classList.toggle("on", state.autoRefresh);
      btn.setAttribute("aria-pressed", String(state.autoRefresh));
      $("live-dot").className = "dot" + (state.autoRefresh ? " dot-ok" : "");
    });
  }

  function openAuthModal() {
    $("auth-token-input").value = state.token;
    $("auth-modal").classList.remove("hidden");
    $("auth-token-input").focus();
  }

  function closeAuthModal() {
    $("auth-modal").classList.add("hidden");
  }

  function initAuthModal() {
    $("btn-auth").addEventListener("click", openAuthModal);
    $("btn-auth-cancel").addEventListener("click", closeAuthModal);
    $("auth-modal").addEventListener("click", (e) => {
      if (e.target === $("auth-modal")) closeAuthModal();
    });
    $("btn-auth-clear").addEventListener("click", () => {
      state.token = "";
      sessionStorage.removeItem("tk_admin_token");
      closeAuthModal();
      toast("Token cleared");
      refreshActiveView();
    });
    $("auth-modal-form").addEventListener("submit", (e) => {
      e.preventDefault();
      state.token = $("auth-token-input").value.trim();
      if (state.token) {
        sessionStorage.setItem("tk_admin_token", state.token);
      } else {
        sessionStorage.removeItem("tk_admin_token");
      }
      closeAuthModal();
      toast("Token saved");
      refreshActiveView();
    });
  }

  /* Command Palette */
  function buildPaletteItems(query) {
    const q = (query || "").trim().toLowerCase();
    const base = [
      { icon: "activity", label: "Overview & Upstreams", hint: "View", run: () => switchView("overview") },
      { icon: "shield", label: "Policy Editor", hint: "View", run: () => switchView("policy") },
      { icon: "lock", label: "Tool Pinning Diffs", hint: "View", run: () => switchView("pins") },
      { icon: "play", label: "Call Simulator", hint: "View", run: () => switchView("simulator") },
      { icon: "scroll", label: "Audit Explorer", hint: "View", run: () => switchView("audit") },
      { icon: "sun", label: "Switch Light / Dark Theme", hint: "Action", run: () => { toggleTheme(); toast("Theme updated"); } },
      { icon: "refresh", label: "Refresh Live Telemetry", hint: "Action", run: () => refreshActiveView() },
      { icon: "key", label: "Configure Bearer Report Token", hint: "Auth", run: () => openAuthModal() },
    ];
    const toolItems = (state.pinsReport.tools || []).slice(0, 30).map((t) => ({
      icon: "lock",
      label: "Inspect pin: " + t.name,
      hint: t.status,
      run: () => {
        state.selectedPin = t.name;
        switchView("pins");
      },
    }));
    const all = base.concat(toolItems);
    return q ? all.filter((item) => item.label.toLowerCase().includes(q) || item.hint.toLowerCase().includes(q)) : all;
  }

  function renderPalette() {
    const items = buildPaletteItems($("palette-input").value);
    state.paletteItems = items;
    if (state.paletteIdx >= items.length) state.paletteIdx = 0;
    const list = $("palette-list");
    if (!items.length) {
      list.innerHTML = '<div class="empty-state">No matching commands or tools.</div>';
      return;
    }
    list.innerHTML = items
      .map(
        (it, i) =>
          '<button class="palette-item' + (i === state.paletteIdx ? " active" : "") + '" data-pidx="' + i + '" type="button">' +
          '<span class="palette-item-left">' + ico(it.icon, "ico-sm") + "<span>" + esc(it.label) + "</span></span>" +
          '<span class="palette-hint">' + esc(it.hint) + "</span>" +
          "</button>"
      )
      .join("");
  }

  function openPalette() {
    $("palette-input").value = "";
    state.paletteIdx = 0;
    renderPalette();
    $("palette-modal").classList.remove("hidden");
    $("palette-input").focus();
  }

  function closePalette() {
    $("palette-modal").classList.add("hidden");
  }

  function initPalette() {
    $("btn-palette").addEventListener("click", openPalette);
    $("palette-modal").addEventListener("click", (e) => {
      if (e.target === $("palette-modal")) closePalette();
    });
    $("palette-input").addEventListener("input", () => {
      state.paletteIdx = 0;
      renderPalette();
    });
    $("palette-input").addEventListener("keydown", (e) => {
      if (e.key === "ArrowDown") {
        e.preventDefault();
        state.paletteIdx = (state.paletteIdx + 1) % Math.max(1, state.paletteItems.length);
        renderPalette();
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        state.paletteIdx = (state.paletteIdx - 1 + state.paletteItems.length) % Math.max(1, state.paletteItems.length);
        renderPalette();
      } else if (e.key === "Enter" && state.paletteItems[state.paletteIdx]) {
        e.preventDefault();
        const item = state.paletteItems[state.paletteIdx];
        closePalette();
        item.run();
      }
    });
    $("palette-list").addEventListener("click", (e) => {
      const btn = e.target.closest("button[data-pidx]");
      if (!btn) return;
      const item = state.paletteItems[Number(btn.dataset.pidx)];
      closePalette();
      if (item) item.run();
    });
    document.addEventListener("keydown", (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        if ($("palette-modal").classList.contains("hidden")) openPalette();
        else closePalette();
      } else if (e.key === "Escape") {
        closePalette();
        closeAuthModal();
      }
    });
  }

  function switchView(view) {
    if (!VIEW_TITLES[view]) view = "overview";
    state.view = view;
    document.querySelectorAll(".nav-item").forEach((b) => {
      b.classList.toggle("active", b.dataset.view === view);
    });
    document.querySelectorAll(".view").forEach((v) => {
      v.classList.toggle("active", v.id === "view-" + view);
    });
    $("view-title").textContent = VIEW_TITLES[view];
    if (window.location.hash !== "#" + view) {
      history.replaceState(null, "", "#" + view);
    }
    refreshActiveView();
  }

  /* VIEW 1: OVERVIEW & UPSTREAMS */
  function meterSVG(segments) {
    let x = 0;
    const total = segments.reduce((acc, s) => acc + Math.max(0, s.val), 0);
    if (total <= 0) {
      return '<svg class="meter-svg" viewBox="0 0 100 4" preserveAspectRatio="none"></svg>';
    }
    const rects = segments
      .filter((s) => s.val > 0)
      .map((s) => {
        const w = (s.val / total) * 100;
        const rect = '<rect x="' + x.toFixed(2) + '" y="0" width="' + w.toFixed(2) + '" height="4" class="svg-' + s.cls + '"/>';
        x += w;
        return rect;
      })
      .join("");
    return '<svg class="meter-svg" viewBox="0 0 100 4" preserveAspectRatio="none">' + rects + "</svg>";
  }

  function latencySVG(p50, p95, maxMs) {
    const cap = Math.max(maxMs, 10);
    const w95 = p95 > 0 ? Math.min(52, Math.max(3, (p95 / cap) * 52)) : 0;
    const w50 = p50 > 0 ? Math.min(52, Math.max(2, (p50 / cap) * 52)) : 0;
    return (
      '<svg class="lat-svg" viewBox="0 0 52 5">' +
      (w95 > 0 ? '<rect x="0" y="0" width="' + w95.toFixed(1) + '" height="5" rx="2.5" class="svg-info-soft"/>' : "") +
      (w50 > 0 ? '<rect x="0" y="0" width="' + w50.toFixed(1) + '" height="5" rx="2.5" class="svg-info"/>' : "") +
      "</svg>"
    );
  }

  async function refreshOverview() {
    const [ov, up] = await Promise.all([apiFetch("/api/overview"), apiFetch("/upstreams")]);
    state.overview = ov;
    state.upstreams = up.upstreams || [];
    showGlobalError("");

    $("sidebar-version").textContent = ov.version || "dev";
    $("meta-chain").textContent = (ov.audit && ov.audit.chain_id) || "local";
    $("meta-digest").textContent = ov.config_digest ? ov.config_digest.slice(0, 12) : "—";

    $("global-status-dot").className = "dot " + (ov.ready ? "dot-ok" : "dot-warn");
    $("global-status-text").textContent = ov.ready ? "Ready" : "Starting";

    const pendingPins = (ov.pinning.new || 0) + (ov.pinning.changed || 0);
    const badge = $("nav-pin-badge");
    badge.textContent = String(pendingPins);
    badge.classList.toggle("hidden", pendingPins === 0);

    renderPostureMeta(ov);
    renderOverviewKPIs(ov);
    renderUpstreamsTable();
    renderWatchdogBanner(ov.audit);
  }

  function renderPostureMeta(ov) {
    const sinks = [];
    if (ov.audit.enabled) sinks.push("Local Chain");
    if (ov.audit.postgres_enabled) sinks.push("Postgres");
    if (ov.audit.siem_enabled) sinks.push("SIEM:" + (ov.audit.siem_format || "json"));
    if (ov.audit.otlp_enabled) sinks.push("OTLP");
    if (ov.audit.anchor_enabled) sinks.push("Rekor");

    $("posture-meta").innerHTML =
      '<span class="meta-chip"><code>' + esc(ov.public_url || "—") + "</code></span>" +
      '<span class="meta-sep">·</span>' +
      '<span class="meta-chip">Auth <strong>' + esc((ov.auth.mode || "jwt").toUpperCase()) + "</strong> · DPoP <strong>" + esc(ov.auth.dpop_mode || "off") + "</strong></span>" +
      '<span class="meta-sep">·</span>' +
      '<span class="meta-chip">Rate Limit <strong>' + esc(ov.rate_limits.store || "memory") + "</strong> (" + esc(ov.rate_limits.rules || 0) + ")</span>" +
      (sinks.length ? '<span class="meta-sep">·</span><span class="meta-chip">' + esc(sinks.join(", ")) + "</span>" : "");
  }

  function renderOverviewKPIs(ov) {
    const wd = (ov.audit && ov.audit.watchdog) || {};
    let wdTitle = "Disabled";
    let wdDot = "";
    let wdFoot = ov.audit.enabled ? "Watchdog off · args " + (ov.audit.record_args || "hash") : "Audit logging disabled";
    if (wd.enabled) {
      if (!wd.checked) {
        wdTitle = "Pending";
        wdDot = "dot-warn";
        wdFoot = "Awaiting first chain verification";
      } else if (wd.healthy) {
        wdTitle = "Verified";
        wdDot = "dot-ok";
        wdFoot = (wd.records ?? 0) + " records · " + (wd.checkpoints ?? 0) + " checkpoints · tail " + (wd.unsigned_tail ?? 0);
      } else {
        wdTitle = "Broken";
        wdDot = "dot-err";
        wdFoot = wd.error || "Chain verification failed";
      }
    }

    const pinMeter = meterSVG([
      { val: ov.pinning.approved || 0, cls: "ok" },
      { val: ov.pinning.new || 0, cls: "warn" },
      { val: ov.pinning.changed || 0, cls: "err" },
    ]);

    $("overview-kpis").innerHTML =
      '<div class="metric-cell">' +
      '<div class="metric-head"><span>Upstreams Synced</span>' + ico("server", "ico-sm") + "</div>" +
      '<div class="metric-main"><span class="metric-val">' + esc(ov.upstreams.synced || 0) + '</span><span class="metric-den">/ ' + esc(ov.upstreams.total || 0) + "</span></div>" +
      '<div class="metric-sub"><span>' + esc(ov.catalog.tools || 0) + " tools</span><span>" + esc(ov.catalog.prompts || 0) + " prompts</span><span>" + esc(ov.catalog.resources || 0) + " resources</span></div>" +
      "</div>" +
      '<div class="metric-cell">' +
      '<div class="metric-head"><span>Policy Engine</span>' + ico("shield", "ico-sm") + "</div>" +
      '<div class="metric-main"><span class="metric-val">' + esc(ov.policy.rules || 0) + '</span><span class="metric-den">' + (ov.policy.rules === 1 ? "rule" : "rules") + "</span></div>" +
      '<div class="metric-sub"><span>Default <code>' + esc(ov.policy.default || "deny") + "</code></span><span>" + esc(ov.policy.tenants || 0) + " tenant scopes</span></div>" +
      "</div>" +
      '<div class="metric-cell">' +
      '<div class="metric-head"><span>Tool Pinning · ' + esc(ov.pinning.mode || "off") + "</span>" + ico("lock", "ico-sm") + "</div>" +
      '<div class="metric-main"><span class="metric-val">' + esc(ov.pinning.approved || 0) + '</span><span class="metric-den">/ ' + esc(ov.pinning.total || 0) + " approved</span></div>" +
      pinMeter +
      '<div class="metric-sub"><span class="status-inline status-inline-muted"><span class="dot dot-err"></span>' + esc(ov.pinning.changed || 0) + ' changed</span><span class="status-inline status-inline-muted"><span class="dot dot-warn"></span>' + esc(ov.pinning.new || 0) + " new</span></div>" +
      "</div>" +
      '<div class="metric-cell">' +
      '<div class="metric-head"><span>Audit Integrity</span>' + ico("shield-check", "ico-sm") + "</div>" +
      '<div class="metric-main"><span class="dot ' + wdDot + '"></span><span class="metric-val">' + esc(wdTitle) + "</span></div>" +
      '<div class="metric-sub"><span>' + esc(wdFoot) + "</span></div>" +
      "</div>";
  }

  function renderUpstreamsTable() {
    const q = ($("upstreams-search").value || "").trim().toLowerCase();
    const list = state.upstreams.filter((u) => !q || u.id.toLowerCase().includes(q) || (u.transport || "").toLowerCase().includes(q));
    $("upstreams-count").textContent = list.length + (list.length === 1 ? " upstream" : " upstreams");
    const tbody = $("upstreams-tbody");
    if (!list.length) {
      tbody.innerHTML = '<tr><td colspan="10"><div class="empty-state">' + ico("server") + "<span>No matching upstreams.</span></div></td></tr>";
      return;
    }
    const maxLat = Math.max(10, ...list.map((u) => Number(u.latency_p95_ms || 0)));
    tbody.innerHTML = list
      .map((u) => {
        const health = u.up
          ? '<span class="status-inline"><span class="dot dot-ok"></span>Healthy</span>'
          : '<span class="status-inline"><span class="dot dot-err"></span>Down</span>';
        const brkState = u.breaker_state || "closed";
        const brkHTML = brkState === "closed"
          ? '<span class="mono status-inline-muted">closed</span>'
          : '<span class="badge badge-mono ' + (brkState === "open" ? "badge-err" : "badge-warn") + '">' + esc(brkState) + "</span>";
        const sync = u.synced
          ? '<span class="status-inline status-inline-muted">' + ico("check", "ico-sm") + "Synced</span>"
          : '<span class="badge badge-warn">Pending</span>';
        const p50 = Number(u.latency_p50_ms || 0);
        const p95 = Number(u.latency_p95_ms || 0);
        return (
          "<tr>" +
          '<td class="mono"><strong>' + esc(u.id) + "</strong></td>" +
          '<td class="mono status-inline-muted">' + esc(u.transport) + "</td>" +
          "<td>" + health + "</td>" +
          "<td>" + brkHTML + "</td>" +
          "<td>" + sync + "</td>" +
          '<td class="num">' + esc(u.tools ?? 0) + "</td>" +
          '<td class="num">' + esc(u.in_flight ?? 0) + "</td>" +
          '<td class="num"><span class="lat-cell">' + latencySVG(p50, p95, maxLat) + "<span>" + p50.toFixed(1) + " / " + p95.toFixed(1) + " ms</span></span></td>" +
          '<td class="num">' + esc(u.calls_failed ?? 0) + "</td>" +
          '<td class="mono status-inline-muted">' + esc(u.last_error || "—") + "</td>" +
          "</tr>"
        );
      })
      .join("");
  }

  function renderWatchdogBanner(audit) {
    const el = $("audit-watchdog-banner");
    if (!audit || !audit.watchdog || !audit.watchdog.enabled) {
      el.classList.add("hidden");
      return;
    }
    const wd = audit.watchdog;
    el.classList.remove("hidden", "banner-ok", "banner-warn", "banner-error");
    if (!wd.checked) {
      el.classList.add("banner-warn");
      el.innerHTML = ico("alert", "ico-sm") + "<span>Continuous audit watchdog enabled — awaiting initial verification pass.</span>";
      return;
    }
    if (wd.healthy) {
      el.classList.add("banner-ok");
      el.innerHTML =
        ico("shield-check", "ico-sm") +
        "<span><strong>Chain integrity verified</strong> · " +
        esc(wd.records ?? 0) + " records · " + esc(wd.checkpoints ?? 0) + " checkpoints · unsigned tail " +
        esc(wd.unsigned_tail ?? 0) + " · last check " + esc(wd.verified_at) + "</span>";
      return;
    }
    el.classList.add("banner-error");
    el.innerHTML = ico("alert", "ico-sm") + "<span><strong>Watchdog verification failed:</strong> " + esc(wd.error || "chain broken") + "</span>";
  }

  /* VIEW 2: POLICY EDITOR */
  function splitCSV(val) {
    return String(val || "")
      .split(/[,\s]+/)
      .map((s) => s.trim())
      .filter(Boolean);
  }

  function activePolicyScopeObj() {
    if (state.policyScope === "__global__") return state.policy;
    if (!state.policy.tenants) state.policy.tenants = {};
    if (!state.policy.tenants[state.policyScope]) {
      state.policy.tenants[state.policyScope] = { default: "deny", rules: [] };
    }
    return state.policy.tenants[state.policyScope];
  }

  function normalizePolicyObject(p) {
    return {
      default: (p && p.default) || "deny",
      rules: Array.isArray(p && p.rules) ? p.rules : [],
      tenants: (p && p.tenants) ? p.tenants : {},
    };
  }

  function updateYAMLGutter() {
    const ta = $("policy-yaml-editor");
    const lines = Math.max(1, (ta.value || "").split("\n").length);
    const nums = [];
    for (let i = 1; i <= lines; i++) nums.push(String(i));
    $("policy-yaml-gutter").textContent = nums.join("\n");
    $("policy-yaml-meta").textContent = "YAML · " + lines + (lines === 1 ? " line" : " lines");
  }

  async function loadPolicy() {
    const data = await apiFetch("/api/policy");
    state.policy = normalizePolicyObject(data.policy);
    state.policyScope = "__global__";
    state.expandedRules = new Set([0]);
    $("policy-yaml-editor").value = data.yaml || "";
    updateYAMLGutter();
    renderPolicyScopeTabs();
    renderPolicyRules();
    hidePolicyBanner();
  }

  function renderPolicyScopeTabs() {
    const tenants = Object.keys(state.policy.tenants || {}).sort();
    const globalCount = (state.policy.rules || []).length;
    const tabs = [
      '<button class="pill-tab' + (state.policyScope === "__global__" ? " active" : "") + '" data-scope="__global__" type="button">Global <span class="pill-count">' + globalCount + "</span></button>",
    ].concat(
      tenants.map((t) => {
        const n = ((state.policy.tenants[t] && state.policy.tenants[t].rules) || []).length;
        return (
          '<button class="pill-tab' + (state.policyScope === t ? " active" : "") + '" data-scope="' + esc(t) + '" type="button">' +
          esc(t) + ' <span class="pill-count">' + n + "</span></button>"
        );
      })
    );
    $("policy-scope-tabs").innerHTML = tabs.join("");
    $("policy-default").value = activePolicyScopeObj().default || "deny";
  }

  function renderPolicyRules() {
    const sc = activePolicyScopeObj();
    const rules = sc.rules || [];
    $("policy-rule-count").textContent = rules.length + (rules.length === 1 ? " rule" : " rules");
    const container = $("policy-rules-list");
    if (!rules.length) {
      container.innerHTML = '<div class="empty-state">' + ico("shield") + "<span>No rules in this scope. Click <strong>Add Rule</strong> to create one.</span></div>";
      return;
    }
    container.innerHTML = rules
      .map((r, idx) => {
        const sub = r.subjects || {};
        const od = r.on_deny || {};
        const open = state.expandedRules.has(idx);
        const effCls = r.effect === "allow" ? "badge-ok" : "badge-err";
        const globs = (r.tools || []).concat(r.prompts || [], r.resources || []).join(", ") || "—";
        const hasStepUp = (od.step_up_scopes && od.step_up_scopes.length) || (od.acr_values && od.acr_values.length) || od.max_age || od.require_dpop;
        return (
          '<div class="rule-card' + (open ? "" : " collapsed") + '" data-rule-idx="' + idx + '">' +
          '<div class="rule-card-head" data-toggle-rule="' + idx + '">' +
          '<div class="rule-head-left">' +
          ico("chevron-down", "ico-sm rule-chevron") +
          '<span class="rule-idx">' + (idx + 1) + "</span>" +
          '<span class="rule-title">' + esc(r.name || "unnamed") + "</span>" +
          '<span class="badge ' + effCls + '">' + esc(r.effect || "deny") + "</span>" +
          (r.mode === "shadow" ? '<span class="badge badge-info">shadow</span>' : "") +
          (r.when ? '<span class="badge badge-mono">CEL</span>' : "") +
          (hasStepUp ? '<span class="badge badge-warn">step-up</span>' : "") +
          '<span class="rule-summary-globs">' + esc(globs) + "</span>" +
          "</div>" +
          '<div class="toolbar-group">' +
          '<button class="btn btn-ghost btn-icon" data-act="up" type="button" title="Move up">' + ico("arrow-up", "ico-sm") + "</button>" +
          '<button class="btn btn-ghost btn-icon" data-act="down" type="button" title="Move down">' + ico("arrow-down", "ico-sm") + "</button>" +
          '<button class="btn btn-danger btn-icon" data-act="del" type="button" title="Delete rule">' + ico("trash", "ico-sm") + "</button>" +
          "</div></div>" +
          '<div class="rule-body"><div class="rule-grid">' +
          '<label class="field"><span>Rule Name</span><input class="input input-sm mono" data-k="name" value="' + esc(r.name || "") + '"></label>' +
          '<label class="field"><span>Effect &amp; Mode</span><div class="field-pair-eq">' +
          '<select class="input input-sm" data-k="effect"><option value="allow"' + (r.effect === "allow" ? " selected" : "") + '>allow</option><option value="deny"' + (r.effect === "deny" ? " selected" : "") + ">deny</option></select>" +
          '<select class="input input-sm" data-k="mode"><option value=""' + (!r.mode || r.mode === "enforce" ? " selected" : "") + '>enforce</option><option value="shadow"' + (r.mode === "shadow" ? " selected" : "") + ">shadow</option></select>" +
          "</div></label>" +
          '<label class="field"><span>Tools (globs)</span><input class="input input-sm mono" data-k="tools" value="' + esc((r.tools || []).join(", ")) + '" placeholder="notes__*, files__read_*"></label>' +
          '<label class="field"><span>Scopes Any</span><input class="input input-sm mono" data-k="scopes_any" value="' + esc((sub.scopes_any || []).join(", ")) + '" placeholder="mcp:tools"></label>' +
          '<label class="field"><span>Roles Any</span><input class="input input-sm" data-k="roles_any" value="' + esc((sub.roles_any || []).join(", ")) + '" placeholder="admin, analyst"></label>' +
          '<label class="field"><span>Tenants</span><input class="input input-sm" data-k="tenants" value="' + esc((sub.tenants || []).join(", ")) + '" placeholder="acme"></label>' +
          '<label class="field field-full"><span>CEL when condition</span><input class="input input-sm mono" data-k="when" value="' + esc(r.when || "") + '" placeholder="tool.annotations.readOnlyHint == true"></label>' +
          '<label class="field"><span>RFC 6750 Step-Up Scopes</span><input class="input input-sm mono" data-k="step_up_scopes" value="' + esc((od.step_up_scopes || []).join(", ")) + '" placeholder="files:write"></label>' +
          '<label class="field"><span>RFC 9470 ACR &amp; Max Age</span><div class="field-pair">' +
          '<input class="input input-sm mono" data-k="acr_values" value="' + esc((od.acr_values || []).join(", ")) + '" placeholder="phr">' +
          '<input class="input input-sm mono" data-k="max_age" value="' + esc(od.max_age || "") + '" placeholder="5m">' +
          "</div></label>" +
          "</div></div></div>"
        );
      })
      .join("");
  }

  function hidePolicyBanner() {
    const el = $("policy-validation-result");
    el.classList.add("hidden");
    el.innerHTML = "";
  }

  function showPolicyBanner(ok, msg) {
    const el = $("policy-validation-result");
    el.classList.remove("hidden", "banner-ok", "banner-error");
    el.classList.add(ok ? "banner-ok" : "banner-error");
    el.innerHTML = ico(ok ? "check" : "alert", "ico-sm") + "<span>" + esc(msg) + "</span>";
  }

  async function validatePolicy(source) {
    const payload = source === "visual"
      ? { policy: state.policy }
      : { yaml: $("policy-yaml-editor").value };
    const res = await apiFetch("/api/policy/validate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (res.valid) {
      state.policy = normalizePolicyObject(res.policy);
      $("policy-yaml-editor").value = res.normalized_yaml || "";
      updateYAMLGutter();
      renderPolicyScopeTabs();
      renderPolicyRules();
      showPolicyBanner(true, "CEL compiled & validated cleanly — " + res.rules + " global rules, " + res.tenants + " tenant scopes.");
    } else {
      showPolicyBanner(false, "Validation error: " + (res.errors || ["unknown error"]).join(" · "));
    }
    return res;
  }

  function initPolicyEditor() {
    $("policy-scope-tabs").addEventListener("click", (e) => {
      const btn = e.target.closest("button[data-scope]");
      if (!btn) return;
      state.policyScope = btn.dataset.scope;
      state.expandedRules = new Set([0]);
      renderPolicyScopeTabs();
      renderPolicyRules();
    });
    $("policy-default").addEventListener("change", (e) => {
      activePolicyScopeObj().default = e.target.value;
      validatePolicy("visual").catch((err) => showPolicyBanner(false, err.message));
    });
    $("btn-add-tenant").addEventListener("click", () => {
      const id = window.prompt("New tenant scope ID (e.g. acme):");
      if (!id || !id.trim()) return;
      const clean = id.trim();
      if (!state.policy.tenants) state.policy.tenants = {};
      if (!state.policy.tenants[clean]) {
        state.policy.tenants[clean] = { default: "deny", rules: [] };
      }
      state.policyScope = clean;
      state.expandedRules = new Set([0]);
      renderPolicyScopeTabs();
      renderPolicyRules();
    });
    $("btn-add-rule").addEventListener("click", () => {
      const sc = activePolicyScopeObj();
      sc.rules = sc.rules || [];
      const newIdx = sc.rules.length;
      sc.rules.push({
        name: "rule-" + (newIdx + 1),
        tools: ["*"],
        effect: "allow",
        subjects: {},
        on_deny: {},
      });
      state.expandedRules.add(newIdx);
      renderPolicyScopeTabs();
      renderPolicyRules();
    });
    $("policy-rules-list").addEventListener("click", (e) => {
      const btn = e.target.closest("button[data-act]");
      if (btn) {
        e.stopPropagation();
        const card = btn.closest(".rule-card");
        const idx = Number(card.dataset.ruleIdx);
        const rules = activePolicyScopeObj().rules;
        if (btn.dataset.act === "del") {
          rules.splice(idx, 1);
          state.expandedRules.delete(idx);
        } else if (btn.dataset.act === "up" && idx > 0) {
          [rules[idx - 1], rules[idx]] = [rules[idx], rules[idx - 1]];
        } else if (btn.dataset.act === "down" && idx < rules.length - 1) {
          [rules[idx + 1], rules[idx]] = [rules[idx], rules[idx + 1]];
        }
        renderPolicyScopeTabs();
        renderPolicyRules();
        validatePolicy("visual").catch((err) => showPolicyBanner(false, err.message));
        return;
      }
      const head = e.target.closest("[data-toggle-rule]");
      if (head) {
        const idx = Number(head.dataset.toggleRule);
        if (state.expandedRules.has(idx)) state.expandedRules.delete(idx);
        else state.expandedRules.add(idx);
        renderPolicyRules();
      }
    });
    $("policy-rules-list").addEventListener("change", (e) => {
      const card = e.target.closest(".rule-card");
      if (!card) return;
      const idx = Number(card.dataset.ruleIdx);
      const r = activePolicyScopeObj().rules[idx];
      if (!r) return;
      if (!r.subjects) r.subjects = {};
      if (!r.on_deny) r.on_deny = {};
      const k = e.target.dataset.k;
      const v = e.target.value;
      if (k === "name") r.name = v.trim();
      else if (k === "effect") r.effect = v;
      else if (k === "mode") r.mode = v;
      else if (k === "tools") r.tools = splitCSV(v);
      else if (k === "when") r.when = v;
      else if (k === "scopes_any") r.subjects.scopes_any = splitCSV(v);
      else if (k === "roles_any") r.subjects.roles_any = splitCSV(v);
      else if (k === "tenants") r.subjects.tenants = splitCSV(v);
      else if (k === "step_up_scopes") r.on_deny.step_up_scopes = splitCSV(v);
      else if (k === "acr_values") r.on_deny.acr_values = splitCSV(v);
      else if (k === "max_age") r.on_deny.max_age = v.trim();
      validatePolicy("visual").catch((err) => showPolicyBanner(false, err.message));
    });
    const editor = $("policy-yaml-editor");
    editor.addEventListener("input", updateYAMLGutter);
    editor.addEventListener("scroll", () => {
      $("policy-yaml-gutter").scrollTop = editor.scrollTop;
    });
    editor.addEventListener("keydown", (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
        e.preventDefault();
        validatePolicy("yaml").catch((err) => showPolicyBanner(false, err.message));
      }
    });
    $("btn-validate-policy").addEventListener("click", () => {
      validatePolicy("yaml").catch((err) => showPolicyBanner(false, err.message));
    });
    $("btn-sync-from-yaml").addEventListener("click", () => {
      validatePolicy("yaml").catch((err) => showPolicyBanner(false, err.message));
    });
    $("btn-reload-policy").addEventListener("click", () => {
      loadPolicy().then(() => toast("Reset to live policy")).catch((err) => showGlobalError(err.message));
    });
    $("btn-copy-yaml").addEventListener("click", () => copyText($("policy-yaml-editor").value, "Policy YAML copied"));
    $("btn-download-yaml").addEventListener("click", () => {
      const blob = new Blob([$("policy-yaml-editor").value], { type: "text/yaml;charset=utf-8" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "tollkeeper-policy.yaml";
      a.click();
      URL.revokeObjectURL(a.href);
    });
    $("btn-send-to-sim").addEventListener("click", () => {
      $("sim-use-draft").checked = true;
      switchView("simulator");
      toast("Simulator using draft YAML");
    });
  }

  /* VIEW 3: TOOL PINNING DIFFS */
  async function loadPins() {
    const rep = await apiFetch("/api/pins");
    state.pinsReport = rep || { mode: "off", tools: [] };
    const tools = state.pinsReport.tools || [];
    $("pins-mode-badge").textContent = "mode: " + (state.pinsReport.mode || "off");
    $("pf-all").textContent = String(tools.length);
    $("pf-changed").textContent = String(tools.filter((t) => t.status === "changed").length);
    $("pf-new").textContent = String(tools.filter((t) => t.status === "new").length);
    $("pf-approved").textContent = String(tools.filter((t) => t.status === "approved").length);

    $("catalog-tools-datalist").innerHTML = tools.map((t) => '<option value="' + esc(t.name) + '">').join("");

    if (!state.selectedPin && tools.length) {
      const firstInteresting = tools.find((t) => t.status === "changed") || tools.find((t) => t.status === "new") || tools[0];
      state.selectedPin = firstInteresting.name;
    }
    renderPinsList();
  }

  function renderPinsList() {
    const q = ($("pins-search").value || "").trim().toLowerCase();
    const list = (state.pinsReport.tools || []).filter((t) => {
      if (state.pinFilter !== "all" && t.status !== state.pinFilter) return false;
      if (q && !t.name.toLowerCase().includes(q) && !t.upstream.toLowerCase().includes(q)) return false;
      return true;
    });
    $("pins-count").textContent = String(list.length);
    const el = $("pins-list");
    if (!list.length) {
      el.innerHTML = '<div class="empty-state">' + ico("lock") + "<span>No tools match this filter.</span></div>";
      return;
    }
    el.innerHTML = list
      .map((t) => {
        const dotCls = t.status === "approved" ? "dot-ok" : t.status === "changed" ? "dot-err" : "dot-warn";
        const badgeCls = t.status === "approved" ? "badge-ok" : t.status === "changed" ? "badge-err" : "badge-warn";
        const active = state.selectedPin === t.name ? " active" : "";
        return (
          '<button class="pin-row' + active + '" data-tool="' + esc(t.name) + '" type="button">' +
          '<div class="pin-row-left"><span class="dot ' + dotCls + '"></span><div><div class="pin-name">' + esc(t.name) + '</div><div class="pin-up">' + esc(t.upstream) + "</div></div></div>" +
          '<span class="badge ' + badgeCls + '">' + esc(t.status) + "</span>" +
          "</button>"
        );
      })
      .join("");
    if (state.selectedPin) {
      const found = (state.pinsReport.tools || []).find((t) => t.name === state.selectedPin);
      if (found) renderPinDetail(found);
    }
  }

  function prettyJSON(raw) {
    if (!raw) return "";
    try {
      const parsed = typeof raw === "string" ? JSON.parse(raw) : raw;
      return JSON.stringify(parsed, null, 2);
    } catch {
      return String(raw);
    }
  }

  function hasHiddenControlChars(text) {
    return /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/.test(text);
  }

  function diffLines(oldText, newText) {
    const a = oldText ? oldText.split("\n") : [];
    const b = newText ? newText.split("\n") : [];
    const m = a.length;
    const n = b.length;
    if (m * n > 250000) {
      return a.map((l, i) => ({ t: "del", l, o: i + 1, n: "" })).concat(b.map((l, j) => ({ t: "add", l, o: "", n: j + 1 })));
    }
    const dp = Array.from({ length: m + 1 }, () => new Uint16Array(n + 1));
    for (let i = m - 1; i >= 0; i--) {
      for (let j = n - 1; j >= 0; j--) {
        dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
      }
    }
    const out = [];
    let i = 0;
    let j = 0;
    while (i < m && j < n) {
      if (a[i] === b[j]) {
        out.push({ t: "ctx", l: a[i], o: i + 1, n: j + 1 });
        i++;
        j++;
      } else if (dp[i + 1][j] >= dp[i][j + 1]) {
        out.push({ t: "del", l: a[i], o: i + 1, n: "" });
        i++;
      } else {
        out.push({ t: "add", l: b[j], o: "", n: j + 1 });
        j++;
      }
    }
    while (i < m) {
      out.push({ t: "del", l: a[i], o: i + 1, n: "" });
      i++;
    }
    while (j < n) {
      out.push({ t: "add", l: b[j], o: "", n: j + 1 });
      j++;
    }
    return out;
  }

  function renderPinDetail(t) {
    state.selectedPin = t.name;
    $("pin-detail-title").textContent = t.name;
    $("pin-detail-sub").textContent = "Upstream " + t.upstream + " · original " + t.original + " · status " + t.status;
    const cmd = "tollkeeper pin approve " + t.name;
    const copyBtn = $("btn-copy-approve");
    copyBtn.classList.remove("hidden");
    copyBtn.dataset.cmd = cmd;

    const curText = prettyJSON(t.definition);
    const prevText = prettyJSON(t.approved_definition);
    const hiddenWarn = hasHiddenControlChars(curText)
      ? '<div class="banner banner-error">' + ico("alert", "ico-sm") + "<span><strong>Hidden Unicode / control characters detected</strong> in the current tool definition — review for tool poisoning before approving.</span></div>"
      : "";

    const diff = diffLines(prevText, curText);
    const adds = diff.filter((d) => d.t === "add").length;
    const dels = diff.filter((d) => d.t === "del").length;
    const rowsHTML = diff
      .map((d) => {
        const sign = d.t === "add" ? "+" : d.t === "del" ? "−" : " ";
        return (
          '<tr class="diff-row-' + d.t + '">' +
          '<td class="diff-ln">' + esc(d.o) + "</td>" +
          '<td class="diff-ln">' + esc(d.n) + "</td>" +
          '<td class="diff-sign">' + sign + "</td>" +
          '<td class="diff-code">' + esc(d.l) + "</td>" +
          "</tr>"
        );
      })
      .join("");

    const cliBox = t.status !== "approved"
      ? '<div class="cli-snippet"><span>' + ico("terminal", "ico-sm") + " <code>" + esc(cmd) + '</code></span><button class="btn btn-sm" data-copy="' + esc(cmd) + '" type="button">' + ico("copy", "ico-sm") + "<span>Copy</span></button></div>"
      : "";

    $("pin-detail-body").innerHTML =
      hiddenWarn +
      '<div class="hash-grid">' +
      '<div class="hash-box"><div class="hash-box-head"><span>Approved SHA-256</span>' +
      (t.approved_pin ? '<button class="btn btn-ghost btn-icon" data-copy="' + esc(t.approved_pin) + '" type="button" title="Copy hash">' + ico("copy", "ico-sm") + "</button>" : "") +
      "</div><code>" + esc(t.approved_pin || "not yet approved in lockfile") + "</code></div>" +
      '<div class="hash-box"><div class="hash-box-head"><span>Live SHA-256</span>' +
      '<button class="btn btn-ghost btn-icon" data-copy="' + esc(t.pin || "") + '" type="button" title="Copy hash">' + ico("copy", "ico-sm") + "</button>" +
      "</div><code>" + esc(t.pin || "—") + "</code></div>" +
      "</div>" +
      cliBox +
      '<div class="diff-frame">' +
      '<div class="diff-header"><span>' + esc(t.approved_definition ? "approved_definition.json → current_definition.json" : "new_tool_definition.json") + '</span><span class="diff-stats"><span class="diff-stat-add">+' + adds + '</span><span class="diff-stat-del">−' + dels + "</span></span></div>" +
      '<div class="diff-scroll"><table class="diff-table"><tbody>' + rowsHTML + "</tbody></table></div>" +
      "</div>";
  }

  function initPinsView() {
    $("pins-filter").addEventListener("click", (e) => {
      const btn = e.target.closest("button[data-filter]");
      if (!btn) return;
      state.pinFilter = btn.dataset.filter;
      $("pins-filter").querySelectorAll(".pill-tab").forEach((s) => s.classList.toggle("active", s === btn));
      renderPinsList();
    });
    $("pins-search").addEventListener("input", renderPinsList);
    $("pins-list").addEventListener("click", (e) => {
      const row = e.target.closest(".pin-row");
      if (!row) return;
      const tool = (state.pinsReport.tools || []).find((t) => t.name === row.dataset.tool);
      if (tool) {
        renderPinDetail(tool);
        renderPinsList();
      }
    });
    $("pin-detail-body").addEventListener("click", (e) => {
      const btn = e.target.closest("button[data-copy]");
      if (btn) copyText(btn.dataset.copy, "Copied");
    });
    $("btn-copy-approve").addEventListener("click", (e) => {
      copyText(e.currentTarget.dataset.cmd || "", "Approve command copied");
    });
  }

  /* VIEW 4: CALL SIMULATOR */
  function applySimPreset(preset) {
    if (preset === "reader") {
      $("sim-sub").value = "alice";
      $("sim-tenant").value = "acme";
      $("sim-actor").value = "";
      $("sim-scopes").value = "mcp:tools";
      $("sim-roles").value = "viewer";
      $("sim-acr").value = "";
      $("sim-auth-age").value = "60";
      $("sim-dpop").checked = false;
      $("sim-ann-readonly").checked = true;
      $("sim-ann-destructive").checked = false;
    } else if (preset === "writer") {
      $("sim-sub").value = "bob";
      $("sim-tenant").value = "acme";
      $("sim-actor").value = "";
      $("sim-scopes").value = "mcp:tools files:write notes:write billing:approve";
      $("sim-roles").value = "admin";
      $("sim-acr").value = "phr";
      $("sim-auth-age").value = "45";
      $("sim-dpop").checked = true;
      $("sim-ann-readonly").checked = false;
      $("sim-ann-destructive").checked = true;
    } else if (preset === "stepup") {
      $("sim-sub").value = "alice";
      $("sim-tenant").value = "";
      $("sim-actor").value = "";
      $("sim-scopes").value = "mcp:tools";
      $("sim-roles").value = "operator";
      $("sim-acr").value = "pwd";
      $("sim-auth-age").value = "3600";
      $("sim-dpop").checked = false;
      $("sim-ann-readonly").checked = false;
      $("sim-ann-destructive").checked = true;
    } else if (preset === "delegated") {
      $("sim-sub").value = "alice";
      $("sim-tenant").value = "acme";
      $("sim-actor").value = "coding-agent-v1";
      $("sim-scopes").value = "mcp:tools";
      $("sim-roles").value = "analyst";
      $("sim-acr").value = "phr";
      $("sim-auth-age").value = "120";
      $("sim-dpop").checked = true;
      $("sim-ann-readonly").checked = false;
      $("sim-ann-destructive").checked = false;
    }
    toast("Loaded preset: " + preset);
  }

  async function runSimulation() {
    let parsedArgs = {};
    const rawArgs = $("sim-args").value.trim();
    if (rawArgs) {
      try {
        parsedArgs = JSON.parse(rawArgs);
      } catch (err) {
        $("sim-result").innerHTML = '<div class="banner banner-error">' + ico("alert", "ico-sm") + "<span>Invalid arguments JSON: " + esc(err.message) + "</span></div>";
        return;
      }
    }
    const authAgeStr = $("sim-auth-age").value.trim();
    const body = {
      kind: $("sim-kind").value,
      name: $("sim-name").value.trim(),
      principal: {
        sub: $("sim-sub").value.trim(),
        client_id: $("sim-client-id").value.trim(),
        tenant: $("sim-tenant").value.trim(),
        actor: $("sim-actor").value.trim(),
        scopes: splitCSV($("sim-scopes").value),
        roles: splitCSV($("sim-roles").value),
        groups: splitCSV($("sim-groups").value),
        acr: $("sim-acr").value.trim(),
        dpop: $("sim-dpop").checked,
      },
      args: parsedArgs,
    };
    if (authAgeStr !== "") {
      body.principal.auth_age_seconds = Number(authAgeStr);
    }
    if ($("sim-ann-readonly").checked || $("sim-ann-destructive").checked) {
      body.annotations = {
        readOnlyHint: $("sim-ann-readonly").checked,
        destructiveHint: $("sim-ann-destructive").checked,
      };
    }
    if ($("sim-use-draft").checked) {
      body.policy_yaml = $("policy-yaml-editor").value;
    }

    const res = await apiFetch("/api/simulate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    renderSimResult(res);
  }

  function renderSimResult(res) {
    const heroCls = res.decision === "allow" ? "decision-hero-ok" : res.decision === "step_up" ? "decision-hero-warn" : "decision-hero-err";
    const heroIco = res.decision === "allow" ? "check" : res.decision === "step_up" ? "alert" : "x";

    let challengeHTML = "";
    if (res.step_up) {
      const attrs = [];
      const isAuth = (res.step_up.acr_values && res.step_up.acr_values.length) || res.step_up.max_age || res.step_up.require_dpop;
      attrs.push('error="' + (isAuth ? "insufficient_user_authentication" : "insufficient_scope") + '"');
      if (res.step_up.scopes && res.step_up.scopes.length) attrs.push('scope="' + res.step_up.scopes.join(" ") + '"');
      if (res.step_up.acr_values && res.step_up.acr_values.length) attrs.push('acr_values="' + res.step_up.acr_values.join(" ") + '"');
      if (res.step_up.max_age) attrs.push('max_age="' + res.step_up.max_age + '"');
      const scheme = res.step_up.require_dpop ? "DPoP" : "Bearer";
      challengeHTML =
        '<div class="challenge-box">' +
        '<div class="challenge-head"><span>RFC 9470 / 6750 Step-Up Challenge</span><span>HTTP 401</span></div>' +
        "<code>WWW-Authenticate: " + esc(scheme + " " + attrs.join(", ")) + "</code>" +
        "</div>";
    }

    const shadowHTML = res.shadow
      ? '<div class="banner">' + ico("shield", "ico-sm") + '<span>Shadow rule <code>' + esc(res.shadow.rule) + "</code> would decide <code>" + esc(res.shadow.effect) + "</code></span></div>"
      : "";

    const timelineHTML = (res.steps || [])
      .map((s) => {
        const out = String(s.outcome || "");
        let dotCls = "";
        if (out.includes("allow")) dotCls = "tl-dot-ok";
        else if (out.includes("step-up")) dotCls = "tl-dot-warn";
        else if (out.includes("deny")) dotCls = "tl-dot-err";
        return (
          '<div class="tl-item">' +
          '<span class="tl-dot ' + dotCls + '"></span>' +
          '<div><code class="mono">' + esc(s.rule) + "</code>" + (s.shadow ? ' <span class="badge badge-info">shadow</span>' : "") + "</div>" +
          '<span class="muted">' + esc(out) + "</span>" +
          "</div>"
        );
      })
      .join("");

    const pinDot = res.pin_blocked ? "dot-err" : res.pin_status === "approved" || res.pin_status === "off" ? "dot-ok" : "dot-warn";

    $("sim-result").innerHTML =
      '<div class="decision-hero ' + heroCls + '">' +
      "<div>" +
      '<div class="decision-title">' + ico(heroIco) + "<span>" + esc(res.decision) + "</span></div>" +
      '<div class="decision-sub">Rule <code>' + esc(res.rule) + "</code> — " + esc(res.reason) + "</div>" +
      "</div>" +
      '<span class="badge badge-mono">' + ($("sim-use-draft").checked ? "Draft YAML" : "Live Engine") + "</span>" +
      "</div>" +
      '<div class="attr-strip">' +
      '<div class="attr-cell"><div class="attr-k">List Visibility</div><div class="attr-v"><span class="status-inline"><span class="dot ' + (res.visible ? "dot-ok" : "dot-err") + '"></span>' + (res.visible ? "Visible" : "Hidden") + "</span></div></div>" +
      '<div class="attr-cell"><div class="attr-k">Tool Pin Guard</div><div class="attr-v"><span class="status-inline"><span class="dot ' + pinDot + '"></span>' + esc(res.pin_status) + (res.pin_blocked ? " · blocked" : "") + "</span></div></div>" +
      '<div class="attr-cell"><div class="attr-k">Catalog Lookup</div><div class="attr-v">' + (res.catalog_matched ? "Matched" : "Synthetic") + "</div></div>" +
      "</div>" +
      challengeHTML +
      shadowHTML +
      '<div><div class="section-label">Rule Evaluation Trace</div><div class="timeline">' + (timelineHTML || '<div class="empty-state">No rules evaluated.</div>') + "</div></div>";
  }

  function initSimulator() {
    document.querySelectorAll("button[data-preset]").forEach((b) => {
      b.addEventListener("click", () => applySimPreset(b.dataset.preset));
    });
    $("btn-run-sim").addEventListener("click", () => {
      runSimulation().catch((err) => {
        $("sim-result").innerHTML = '<div class="banner banner-error">' + ico("alert", "ico-sm") + "<span>" + esc(err.message) + "</span></div>";
      });
    });
    $("sim-form").addEventListener("submit", (e) => {
      e.preventDefault();
      runSimulation().catch((err) => {
        $("sim-result").innerHTML = '<div class="banner banner-error">' + ico("alert", "ico-sm") + "<span>" + esc(err.message) + "</span></div>";
      });
    });
  }

  /* VIEW 5: AUDIT EXPLORER */
  async function loadAuditEvents() {
    const params = new URLSearchParams();
    for (const [key, id] of [
      ["decision", "af-decision"],
      ["phase", "af-phase"],
      ["kind", "af-kind"],
      ["tenant", "af-tenant"],
      ["sub", "af-sub"],
      ["tool", "af-tool"],
      ["q", "af-q"],
      ["limit", "af-limit"],
    ]) {
      const val = $(id).value.trim();
      if (val) params.set(key, val);
    }
    const data = await apiFetch("/api/audit/events?" + params.toString());
    state.auditEvents = data.events || [];
    $("audit-count").textContent = state.auditEvents.length + " shown · " + (data.total_scanned || 0) + " scanned";
    $("audit-source-meta").textContent = data.enabled ? "Source: " + (data.path || "audit.jsonl") : "Local file audit is disabled.";
    renderAuditTable();
  }

  function renderAuditTable() {
    const tbody = $("audit-tbody");
    if (!state.auditEvents.length) {
      tbody.innerHTML = '<tr><td colspan="9"><div class="empty-state">' + ico("scroll") + "<span>No audit records match the active filters.</span></div></td></tr>";
      return;
    }
    tbody.innerHTML = state.auditEvents
      .map((item, idx) => {
        const ev = item.event || {};
        const dec = ev.decision || item.kind;
        const decCls =
          dec === "allow" || item.kind === "checkpoint" || item.kind === "anchor"
            ? "badge-ok"
            : dec === "step_up" || dec === "rate_limited"
            ? "badge-warn"
            : dec === "deny" || dec === "rejected"
            ? "badge-err"
            : "badge-info";
        const subj = ev.sub ? (ev.tenant ? ev.sub + " @" + ev.tenant : ev.sub) : "—";
        const target = ev.tool || ev.method || item.summary || "—";
        const lat = ev.latency_us ? (ev.latency_us / 1000).toFixed(2) + " ms" : "—";
        const selCls = idx === state.selectedAuditIdx ? " row-selected" : "";
        const tsShort = item.ts.includes("T") ? item.ts.split("T")[1].replace("Z", "").slice(0, 12) : item.ts;
        return (
          '<tr class="clickable' + selCls + '" data-audit-idx="' + idx + '">' +
          '<td class="num">' + esc(item.seq) + "</td>" +
          '<td class="mono tabular audit-ts" title="' + esc(item.ts) + '">' + esc(tsShort) + "</td>" +
          '<td class="mono status-inline-muted">' + esc(ev.phase || item.kind) + "</td>" +
          '<td><span class="badge ' + decCls + '">' + esc(dec) + "</span></td>" +
          "<td>" + esc(subj) + "</td>" +
          '<td class="mono audit-target" title="' + esc(target) + '">' + esc(target) + "</td>" +
          '<td class="mono status-inline-muted col-hide-split">' + esc(ev.rule || "—") + "</td>" +
          '<td class="num col-hide-split">' + esc(lat) + "</td>" +
          '<td class="mono status-inline-muted col-hide-split">' + esc((item.hash || "").slice(0, 10)) + "</td>" +
          "</tr>"
        );
      })
      .join("");
  }

  function renderAuditInspector() {
    const item = state.auditEvents[state.selectedAuditIdx];
    if (!item) return;
    $("audit-drawer-title").textContent = "Record #" + item.seq + " · " + item.kind;
    $("audit-drawer-sub").textContent = item.ts + " · " + item.chain_id;
    $("btn-copy-audit").dataset.json = prettyJSON(item.raw);

    $("inspector-tabs").querySelectorAll(".insp-tab").forEach((b) => {
      b.classList.toggle("active", b.dataset.itab === state.inspectorTab);
    });

    if (state.inspectorTab === "raw") {
      $("audit-inspector-body").innerHTML = '<pre class="code-block">' + esc(prettyJSON(item.raw)) + "</pre>";
      return;
    }

    const ev = item.event || {};
    const fields = [
      ["Decision", ev.decision || item.kind],
      ["Phase", ev.phase || "—"],
      ["Subject", ev.sub || "—"],
      ["Tenant", ev.tenant || "—"],
      ["Actor (act)", ev.act || "—"],
      ["Target", ev.tool || ev.method || item.summary || "—"],
      ["Rule", ev.rule || "—"],
      ["Reason", ev.reason || "—"],
      ["Latency", ev.latency_us ? (ev.latency_us / 1000).toFixed(2) + " ms" : "—"],
    ];
    const kvHTML = fields
      .map(([k, v]) => '<div class="kv-k">' + esc(k) + '</div><div class="kv-v">' + esc(v) + "</div>")
      .join("");

    $("audit-inspector-body").innerHTML =
      '<div class="chain-link">' +
      '<div class="section-label">Hash Chain Link</div>' +
      "<div><strong>prev</strong> <code>" + esc(item.prev) + "</code></div>" +
      "<div><strong>hash</strong> <code>" + esc(item.hash) + "</code></div>" +
      "</div>" +
      '<div class="kv-list">' + kvHTML + "</div>";
  }

  function openAuditInspector(idx) {
    if (!state.auditEvents[idx]) return;
    state.selectedAuditIdx = idx;
    renderAuditTable();
    $("audit-split").classList.add("has-inspector");
    $("audit-drawer").classList.remove("hidden");
    renderAuditInspector();
  }

  function closeAuditInspector() {
    state.selectedAuditIdx = -1;
    $("audit-split").classList.remove("has-inspector");
    $("audit-drawer").classList.add("hidden");
    renderAuditTable();
  }

  function initAuditExplorer() {
    $("audit-filter-form").addEventListener("submit", (e) => {
      e.preventDefault();
      loadAuditEvents().catch((err) => showGlobalError(err.message));
    });
    $("btn-audit-clear").addEventListener("click", () => {
      for (const id of ["af-decision", "af-phase", "af-kind", "af-tenant", "af-sub", "af-tool", "af-q"]) {
        $(id).value = "";
      }
      loadAuditEvents().catch((err) => showGlobalError(err.message));
    });
    $("audit-tbody").addEventListener("click", (e) => {
      const row = e.target.closest("tr[data-audit-idx]");
      if (row) openAuditInspector(Number(row.dataset.auditIdx));
    });
    $("inspector-tabs").addEventListener("click", (e) => {
      const btn = e.target.closest("button[data-itab]");
      if (!btn) return;
      state.inspectorTab = btn.dataset.itab;
      renderAuditInspector();
    });
    $("btn-close-drawer").addEventListener("click", closeAuditInspector);
    $("btn-copy-audit").addEventListener("click", (e) => {
      copyText(e.currentTarget.dataset.json || "", "Audit record JSON copied");
    });
  }

  async function refreshActiveView() {
    try {
      await refreshOverview();
      if (state.view === "policy" && !$("policy-yaml-editor").value) {
        await loadPolicy();
      } else if (state.view === "pins") {
        await loadPins();
      } else if (state.view === "simulator") {
        await loadPins();
        if (!$("policy-yaml-editor").value) {
          await loadPolicy();
        }
        if (!$("sim-name").value && state.pinsReport.tools && state.pinsReport.tools.length) {
          $("sim-name").value = state.pinsReport.tools[0].name;
        }
      } else if (state.view === "audit") {
        await loadAuditEvents();
      }
    } catch (err) {
      showGlobalError(err.message);
    }
  }

  function startAutoRefresh() {
    clearInterval(state.refreshTimer);
    state.refreshTimer = setInterval(() => {
      if (!state.autoRefresh) return;
      if (state.view === "overview" || state.view === "audit" || state.view === "pins") {
        refreshActiveView();
      }
    }, 10000);
  }

  function boot() {
    initTheme();
    initLiveToggle();
    initAuthModal();
    initPalette();
    initPolicyEditor();
    initPinsView();
    initSimulator();
    initAuditExplorer();

    $("upstreams-search").addEventListener("input", renderUpstreamsTable);
    document.querySelectorAll(".nav-item").forEach((btn) => {
      btn.addEventListener("click", () => switchView(btn.dataset.view));
    });
    $("btn-refresh").addEventListener("click", refreshActiveView);

    const hashView = window.location.hash.replace(/^#/, "");
    switchView(VIEW_TITLES[hashView] ? hashView : "overview");
    startAutoRefresh();
  }

  document.addEventListener("DOMContentLoaded", boot);
})();
