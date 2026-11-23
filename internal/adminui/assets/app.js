(() => {
  "use strict";

  const VIEW_TITLES = {
    overview: "Overview & Upstreams",
    policy: "Policy Editor",
    pins: "Tool Pinning Diffs",
    simulator: "MCP Call Simulator",
    audit: "Audit Event Explorer",
  };

  const state = {
    view: "overview",
    token: sessionStorage.getItem("tk_admin_token") || "",
    overview: null,
    policy: { default: "deny", rules: [], tenants: {} },
    policyScope: "__global__",
    pinsReport: { mode: "off", tools: [] },
    pinFilter: "all",
    selectedPin: null,
    auditEvents: [],
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

  function toast(msg) {
    const el = $("toast");
    el.textContent = msg;
    el.classList.remove("hidden");
    clearTimeout(toast._t);
    toast._t = setTimeout(() => el.classList.add("hidden"), 2400);
  }

  function showGlobalError(msg) {
    const el = $("global-error");
    if (!msg) {
      el.classList.add("hidden");
      el.textContent = "";
      return;
    }
    el.textContent = msg;
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

  function initTheme() {
    const saved = localStorage.getItem("tk_theme");
    if (saved === "dark" || (!saved && window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches)) {
      document.documentElement.setAttribute("data-theme", "dark");
    }
    $("btn-theme").addEventListener("click", () => {
      const next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      localStorage.setItem("tk_theme", next);
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
      toast("Token updated");
      refreshActiveView();
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

  async function refreshOverview() {
    const [ov, up] = await Promise.all([apiFetch("/api/overview"), apiFetch("/upstreams")]);
    state.overview = ov;
    showGlobalError("");

    $("sidebar-version").textContent = ov.version || "dev";
    $("meta-chain").textContent = (ov.audit && ov.audit.chain_id) || "local";
    $("meta-digest").textContent = ov.config_digest ? ov.config_digest.slice(0, 12) : "—";

    const pill = $("global-status");
    pill.textContent = ov.ready ? "READY" : "NOT READY";
    pill.className = "status-pill " + (ov.ready ? "status-ok" : "status-warn");

    const pendingPins = (ov.pinning.new || 0) + (ov.pinning.changed || 0);
    const badge = $("nav-pin-badge");
    badge.textContent = String(pendingPins);
    badge.classList.toggle("hidden", pendingPins === 0);

    renderOverviewKPIs(ov);
    renderUpstreamsTable(up.upstreams || []);
    renderWatchdogBanner(ov.audit);
  }

  function renderOverviewKPIs(ov) {
    const wd = (ov.audit && ov.audit.watchdog) || {};
    let wdLabel = "Disabled";
    if (wd.enabled) {
      wdLabel = !wd.checked ? "Pending" : wd.healthy ? "Verified OK" : "FAILED";
    }
    const exporters = [];
    if (ov.audit.otlp_enabled) exporters.push("OTLP");
    if (ov.audit.siem_enabled) exporters.push("SIEM:" + (ov.audit.siem_format || "json"));
    if (ov.audit.postgres_enabled) exporters.push("Postgres");
    if (ov.audit.anchor_enabled) exporters.push("Rekor");

    const cards = [
      {
        label: "Catalog & Upstreams",
        value: ov.catalog.tools + " tools",
        sub: ov.upstreams.synced + "/" + ov.upstreams.total + " upstreams synced · " + ov.catalog.prompts + " prompts · " + ov.catalog.resources + " resources",
      },
      {
        label: "Auth & Policy",
        value: (ov.auth.mode || "jwt").toUpperCase(),
        sub: "DPoP: " + (ov.auth.dpop_mode || "off") + " · " + ov.policy.rules + " rules · " + ov.policy.tenants + " tenants · default " + (ov.policy.default || "deny"),
      },
      {
        label: "Tool Pinning",
        value: (ov.pinning.mode || "off").toUpperCase(),
        sub: ov.pinning.approved + " approved · " + ov.pinning.new + " new · " + ov.pinning.changed + " changed",
      },
      {
        label: "Audit Watchdog",
        value: wdLabel,
        sub: ov.audit.enabled ? (exporters.length ? exporters.join(" · ") : "Local hash chain") : "Audit disabled",
      },
    ];

    $("overview-kpis").innerHTML = cards
      .map(
        (c) =>
          '<div class="kpi-card">' +
          '<div class="kpi-label">' + esc(c.label) + "</div>" +
          '<div class="kpi-value">' + esc(c.value) + "</div>" +
          '<div class="kpi-sub">' + esc(c.sub) + "</div>" +
          "</div>"
      )
      .join("");
  }

  function renderUpstreamsTable(list) {
    $("upstreams-count").textContent = list.length + (list.length === 1 ? " upstream" : " upstreams");
    const tbody = $("upstreams-tbody");
    if (!list.length) {
      tbody.innerHTML = '<tr><td colspan="10" class="empty">No upstreams configured.</td></tr>';
      return;
    }
    tbody.innerHTML = list
      .map((u) => {
        const upBadge = u.up
          ? '<span class="badge badge-ok">up</span>'
          : '<span class="badge badge-err">down</span>';
        const brkClass = u.breaker_state === "closed" ? "badge-ok" : u.breaker_state === "open" ? "badge-err" : "badge-warn";
        const syncBadge = u.synced
          ? '<span class="badge badge-ok">yes</span>'
          : '<span class="badge badge-warn">no</span>';
        const lat = (Number(u.latency_p50_ms || 0).toFixed(1)) + " / " + (Number(u.latency_p95_ms || 0).toFixed(1)) + " ms";
        return (
          "<tr>" +
          "<td><code>" + esc(u.id) + "</code></td>" +
          "<td>" + esc(u.transport) + "</td>" +
          "<td>" + upBadge + "</td>" +
          '<td><span class="badge ' + brkClass + '">' + esc(u.breaker_state || "closed") + "</span></td>" +
          "<td>" + syncBadge + "</td>" +
          '<td class="num">' + esc(u.tools ?? 0) + "</td>" +
          '<td class="num">' + esc(u.in_flight ?? 0) + "</td>" +
          '<td class="num">' + esc(lat) + "</td>" +
          '<td class="num">' + esc(u.calls_failed ?? 0) + "</td>" +
          "<td><code>" + esc(u.last_error || "—") + "</code></td>" +
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
      el.textContent = "Audit watchdog enabled — waiting for first verification pass.";
      return;
    }
    if (wd.healthy) {
      el.classList.add("banner-ok");
      el.textContent =
        "Watchdog verified chain OK · records=" + wd.records +
        " · checkpoints=" + wd.checkpoints +
        " · unsigned_tail=" + wd.unsigned_tail +
        " · checked " + wd.verified_at;
      return;
    }
    el.classList.add("banner-error");
    el.textContent = "Audit watchdog ALERT: " + (wd.error || "chain verification failed");
  }

  function splitCSV(val) {
    return String(val || "")
      .split(/[,\s]+/)
      .map((s) => s.trim())
      .filter(Boolean);
  }

  function activePolicyScopeObj() {
    if (state.policyScope === "__global__") {
      return state.policy;
    }
    if (!state.policy.tenants) state.policy.tenants = {};
    if (!state.policy.tenants[state.policyScope]) {
      state.policy.tenants[state.policyScope] = { default: "deny", rules: [] };
    }
    return state.policy.tenants[state.policyScope];
  }

  async function loadPolicy() {
    const data = await apiFetch("/api/policy");
    state.policy = normalizePolicyObject(data.policy);
    state.policyScope = "__global__";
    $("policy-yaml-editor").value = data.yaml || "";
    renderPolicyScopeOptions();
    renderPolicyRules();
    hidePolicyBanner();
  }

  function normalizePolicyObject(p) {
    const out = {
      default: (p && p.default) || "deny",
      rules: Array.isArray(p && p.rules) ? p.rules : [],
      tenants: (p && p.tenants) ? p.tenants : {},
    };
    return out;
  }

  function renderPolicyScopeOptions() {
    const sel = $("policy-scope");
    const tenants = Object.keys(state.policy.tenants || {}).sort();
    const opts = ['<option value="__global__">Global (policy.rules)</option>'].concat(
      tenants.map((t) => '<option value="' + esc(t) + '">Tenant: ' + esc(t) + "</option>")
    );
    sel.innerHTML = opts.join("");
    sel.value = state.policyScope;
    const sc = activePolicyScopeObj();
    $("policy-default").value = sc.default || "deny";
  }

  function renderPolicyRules() {
    const sc = activePolicyScopeObj();
    const rules = sc.rules || [];
    $("policy-rule-count").textContent = rules.length + (rules.length === 1 ? " rule" : " rules");
    const container = $("policy-rules-list");
    if (!rules.length) {
      container.innerHTML = '<p class="empty">No rules in this scope yet. Click <strong>+ Add Rule</strong>.</p>';
      return;
    }
    container.innerHTML = rules
      .map((r, idx) => {
        const sub = r.subjects || {};
        const od = r.on_deny || {};
        return (
          '<div class="rule-card" data-rule-idx="' + idx + '">' +
          '<div class="rule-card-head">' +
          '<strong>#' + (idx + 1) + " " + esc(r.name || "unnamed") + "</strong>" +
          '<div class="toolbar-group">' +
          '<button class="btn btn-ghost btn-sm" data-act="up" type="button">&uarr;</button>' +
          '<button class="btn btn-ghost btn-sm" data-act="down" type="button">&darr;</button>' +
          '<button class="btn btn-danger btn-sm" data-act="del" type="button">Delete</button>' +
          "</div></div>" +
          '<div class="rule-grid">' +
          '<label class="field"><span>Name</span><input class="input input-sm" data-k="name" value="' + esc(r.name || "") + '"></label>' +
          '<label class="field"><span>Effect / Mode</span><div class="toolbar-group">' +
          '<select class="input input-sm" data-k="effect"><option value="allow"' + (r.effect === "allow" ? " selected" : "") + '>allow</option><option value="deny"' + (r.effect === "deny" ? " selected" : "") + ">deny</option></select>" +
          '<select class="input input-sm" data-k="mode"><option value=""' + (!r.mode || r.mode === "enforce" ? " selected" : "") + '>enforce</option><option value="shadow"' + (r.mode === "shadow" ? " selected" : "") + ">shadow</option></select>" +
          "</div></label>" +
          '<label class="field"><span>Tools (globs)</span><input class="input input-sm" data-k="tools" value="' + esc((r.tools || []).join(", ")) + '" placeholder="notes__*, files__read_*"></label>' +
          '<label class="field"><span>Scopes Any</span><input class="input input-sm" data-k="scopes_any" value="' + esc((sub.scopes_any || []).join(", ")) + '" placeholder="mcp:tools"></label>' +
          '<label class="field"><span>Roles Any</span><input class="input input-sm" data-k="roles_any" value="' + esc((sub.roles_any || []).join(", ")) + '" placeholder="admin, analyst"></label>' +
          '<label class="field"><span>Tenants</span><input class="input input-sm" data-k="tenants" value="' + esc((sub.tenants || []).join(", ")) + '" placeholder="acme"></label>' +
          '<label class="field field-full"><span>CEL when expression</span><input class="input input-sm" data-k="when" value="' + esc(r.when || "") + '" placeholder="tool.annotations.readOnlyHint == true"></label>' +
          '<label class="field"><span>Step-Up Scopes</span><input class="input input-sm" data-k="step_up_scopes" value="' + esc((od.step_up_scopes || []).join(", ")) + '" placeholder="files:write"></label>' +
          '<label class="field"><span>Step-Up ACR / Max Age</span><div class="toolbar-group">' +
          '<input class="input input-sm" data-k="acr_values" value="' + esc((od.acr_values || []).join(", ")) + '" placeholder="phr">' +
          '<input class="input input-sm" data-k="max_age" value="' + esc(od.max_age || "") + '" placeholder="5m">' +
          "</div></label>" +
          "</div></div>"
        );
      })
      .join("");
  }

  function hidePolicyBanner() {
    const el = $("policy-validation-result");
    el.classList.add("hidden");
    el.textContent = "";
  }

  function showPolicyBanner(ok, msg) {
    const el = $("policy-validation-result");
    el.classList.remove("hidden", "banner-ok", "banner-error");
    el.classList.add(ok ? "banner-ok" : "banner-error");
    el.textContent = msg;
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
      renderPolicyScopeOptions();
      renderPolicyRules();
      showPolicyBanner(true, "Policy valid & CEL compiled cleanly (" + res.rules + " global rules, " + res.tenants + " tenant scopes).");
    } else {
      showPolicyBanner(false, "Validation failed: " + (res.errors || ["unknown error"]).join(" | "));
    }
    return res;
  }

  function initPolicyEditor() {
    $("policy-scope").addEventListener("change", (e) => {
      state.policyScope = e.target.value;
      renderPolicyScopeOptions();
      renderPolicyRules();
    });
    $("policy-default").addEventListener("change", (e) => {
      activePolicyScopeObj().default = e.target.value;
      validatePolicy("visual").catch((err) => showPolicyBanner(false, err.message));
    });
    $("btn-add-tenant").addEventListener("click", () => {
      const id = window.prompt("New tenant ID (e.g. acme):");
      if (!id || !id.trim()) return;
      const clean = id.trim();
      if (!state.policy.tenants) state.policy.tenants = {};
      if (!state.policy.tenants[clean]) {
        state.policy.tenants[clean] = { default: "deny", rules: [] };
      }
      state.policyScope = clean;
      renderPolicyScopeOptions();
      renderPolicyRules();
    });
    $("btn-add-rule").addEventListener("click", () => {
      const sc = activePolicyScopeObj();
      sc.rules = sc.rules || [];
      sc.rules.push({
        name: "rule-" + (sc.rules.length + 1),
        tools: ["*"],
        effect: "allow",
        subjects: {},
        on_deny: {},
      });
      renderPolicyRules();
    });
    $("policy-rules-list").addEventListener("click", (e) => {
      const btn = e.target.closest("button[data-act]");
      if (!btn) return;
      const card = btn.closest(".rule-card");
      const idx = Number(card.dataset.ruleIdx);
      const rules = activePolicyScopeObj().rules;
      if (btn.dataset.act === "del") {
        rules.splice(idx, 1);
      } else if (btn.dataset.act === "up" && idx > 0) {
        [rules[idx - 1], rules[idx]] = [rules[idx], rules[idx - 1]];
      } else if (btn.dataset.act === "down" && idx < rules.length - 1) {
        [rules[idx + 1], rules[idx]] = [rules[idx], rules[idx + 1]];
      }
      renderPolicyRules();
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
    $("btn-validate-policy").addEventListener("click", () => {
      validatePolicy("yaml").catch((err) => showPolicyBanner(false, err.message));
    });
    $("btn-sync-from-yaml").addEventListener("click", () => {
      validatePolicy("yaml").catch((err) => showPolicyBanner(false, err.message));
    });
    $("btn-reload-policy").addEventListener("click", () => {
      loadPolicy().then(() => toast("Reset to live policy")).catch((err) => showGlobalError(err.message));
    });
    $("btn-copy-yaml").addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText($("policy-yaml-editor").value);
        toast("Policy YAML copied");
      } catch {
        toast("Copy failed — select from YAML pane");
      }
    });
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
      toast("Simulator configured to test draft YAML");
    });
  }

  async function loadPins() {
    const rep = await apiFetch("/api/pins");
    state.pinsReport = rep || { mode: "off", tools: [] };
    $("pins-mode-badge").textContent = "mode: " + (state.pinsReport.mode || "off");
    updateSimulatorDatalist(state.pinsReport.tools || []);
    renderPinsList();
  }

  function updateSimulatorDatalist(tools) {
    const dl = $("catalog-tools-datalist");
    dl.innerHTML = tools.map((t) => '<option value="' + esc(t.name) + '">').join("");
  }

  function renderPinsList() {
    const q = ($("pins-search").value || "").trim().toLowerCase();
    const list = (state.pinsReport.tools || []).filter((t) => {
      if (state.pinFilter === "pending" && t.status === "approved") return false;
      if (state.pinFilter !== "all" && state.pinFilter !== "pending" && t.status !== state.pinFilter) return false;
      if (q && !t.name.toLowerCase().includes(q) && !t.upstream.toLowerCase().includes(q)) return false;
      return true;
    });
    $("pins-count").textContent = String(list.length);
    const el = $("pins-list");
    if (!list.length) {
      el.innerHTML = '<p class="empty">No tools match this filter.</p>';
      return;
    }
    el.innerHTML = list
      .map((t) => {
        const cls = t.status === "approved" ? "badge-ok" : t.status === "changed" ? "badge-err" : "badge-warn";
        const active = state.selectedPin === t.name ? " active" : "";
        return (
          '<button class="pin-row' + active + '" data-tool="' + esc(t.name) + '" type="button">' +
          '<div><div class="pin-name">' + esc(t.name) + '</div><div class="pin-up">' + esc(t.upstream) + "</div></div>" +
          '<span class="badge ' + cls + '">' + esc(t.status) + "</span>" +
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
      return a.map((l) => ({ t: "del", l })).concat(b.map((l) => ({ t: "add", l })));
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
        out.push({ t: "ctx", l: a[i++] });
        j++;
      } else if (dp[i + 1][j] >= dp[i][j + 1]) {
        out.push({ t: "del", l: a[i++] });
      } else {
        out.push({ t: "add", l: b[j++] });
      }
    }
    while (i < m) out.push({ t: "del", l: a[i++] });
    while (j < n) out.push({ t: "add", l: b[j++] });
    return out;
  }

  function renderPinDetail(t) {
    state.selectedPin = t.name;
    $("pin-detail-title").textContent = t.name;
    $("pin-detail-sub").textContent = "Upstream: " + t.upstream + " · Original: " + t.original + " · Status: " + t.status;
    const copyBtn = $("btn-copy-approve");
    copyBtn.classList.remove("hidden");
    copyBtn.dataset.cmd = "tollkeeper pin approve " + t.name;

    const curText = prettyJSON(t.definition);
    const prevText = prettyJSON(t.approved_definition);
    const hiddenWarn = hasHiddenControlChars(curText)
      ? '<div class="banner banner-error">Warning: current definition contains hidden Unicode/bidi or control characters (possible tool poisoning).</div>'
      : "";

    const diff = diffLines(prevText, curText);
    const diffHTML = diff
      .map((d) => {
        const prefix = d.t === "add" ? "+ " : d.t === "del" ? "- " : "  ";
        return '<div class="diff-line diff-' + d.t + '">' + esc(prefix + d.l) + "</div>";
      })
      .join("");

    $("pin-detail-body").innerHTML =
      hiddenWarn +
      '<div class="hash-grid">' +
      '<div class="hash-box"><div class="kpi-label">Approved SHA-256 Pin</div><code>' + esc(t.approved_pin || "not yet approved") + "</code></div>" +
      '<div class="hash-box"><div class="kpi-label">Current SHA-256 Pin</div><code>' + esc(t.pin || "—") + "</code></div>" +
      "</div>" +
      '<div><div class="kpi-label">Definition Diff (approved vs current)</div><div class="diff-view">' + diffHTML + "</div></div>";
  }

  function initPinsView() {
    $("pins-filter").addEventListener("click", (e) => {
      const btn = e.target.closest("button[data-filter]");
      if (!btn) return;
      state.pinFilter = btn.dataset.filter;
      $("pins-filter").querySelectorAll(".seg").forEach((s) => s.classList.toggle("active", s === btn));
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
    $("btn-copy-approve").addEventListener("click", async (e) => {
      const cmd = e.target.dataset.cmd || "";
      try {
        await navigator.clipboard.writeText(cmd);
        toast("Copied: " + cmd);
      } catch {
        toast(cmd);
      }
    });
  }

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
      $("sim-scopes").value = "mcp:tools files:write billing:approve";
      $("sim-roles").value = "admin";
      $("sim-acr").value = "phr";
      $("sim-auth-age").value = "45";
      $("sim-dpop").checked = true;
      $("sim-ann-readonly").checked = false;
      $("sim-ann-destructive").checked = true;
    } else if (preset === "stepup") {
      $("sim-sub").value = "alice";
      $("sim-tenant").value = "acme";
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
      $("sim-roles").value = "developer";
      $("sim-acr").value = "phr";
      $("sim-auth-age").value = "120";
      $("sim-dpop").checked = true;
      $("sim-ann-readonly").checked = false;
      $("sim-ann-destructive").checked = false;
    }
    toast("Preset loaded: " + preset);
  }

  async function runSimulation() {
    let parsedArgs = {};
    const rawArgs = $("sim-args").value.trim();
    if (rawArgs) {
      try {
        parsedArgs = JSON.parse(rawArgs);
      } catch (err) {
        $("sim-result").innerHTML = '<div class="banner banner-error">Invalid arguments JSON: ' + esc(err.message) + "</div>";
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
    const decClass = res.decision === "allow" ? "badge-ok" : res.decision === "step_up" ? "badge-warn" : "badge-err";
    const visBadge = res.visible ? '<span class="badge badge-ok">visible in list</span>' : '<span class="badge badge-err">hidden in list</span>';
    const pinCls = res.pin_blocked ? "badge-err" : res.pin_status === "approved" || res.pin_status === "off" ? "badge-ok" : "badge-warn";

    let stepUpHTML = "";
    if (res.step_up) {
      const parts = [];
      if (res.step_up.scopes && res.step_up.scopes.length) parts.push("scopes=" + res.step_up.scopes.join(" "));
      if (res.step_up.acr_values && res.step_up.acr_values.length) parts.push("acr_values=" + res.step_up.acr_values.join(" "));
      if (res.step_up.max_age) parts.push("max_age=" + res.step_up.max_age);
      if (res.step_up.require_dpop) parts.push("require_dpop=true");
      stepUpHTML = '<div class="banner banner-warn"><strong>RFC 9470 / 6750 Step-Up Challenge:</strong> <code>' + esc(parts.join(" · ")) + "</code></div>";
    }

    let shadowHTML = "";
    if (res.shadow) {
      shadowHTML = '<div class="banner"><strong>Shadow hit:</strong> rule <code>' + esc(res.shadow.rule) + "</code> would decide <code>" + esc(res.shadow.effect) + "</code></div>";
    }

    const stepsHTML = (res.steps || [])
      .map(
        (s) =>
          '<div class="step-item">' +
          "<div><code>" + esc(s.rule) + "</code>" + (s.shadow ? ' <span class="badge badge-info">shadow</span>' : "") + "</div>" +
          '<span class="muted">' + esc(s.outcome) + "</span>" +
          "</div>"
      )
      .join("");

    $("sim-result").innerHTML =
      '<div class="sim-summary">' +
      '<span class="decision-big ' + decClass + '">' + esc(res.decision) + "</span>" +
      visBadge +
      '<span class="badge ' + pinCls + '">pin: ' + esc(res.pin_status) + (res.pin_blocked ? " (blocked)" : "") + "</span>" +
      (res.catalog_matched ? '<span class="badge badge-info">catalog matched</span>' : '<span class="badge">synthetic target</span>') +
      "</div>" +
      '<div><strong>Winning rule:</strong> <code>' + esc(res.rule) + "</code> — " + esc(res.reason) + "</div>" +
      stepUpHTML +
      shadowHTML +
      '<div><div class="kpi-label">Rule-by-Rule Evaluation Trace</div><div class="step-list">' + (stepsHTML || '<p class="empty">No rules evaluated.</p>') + "</div></div>";
  }

  function initSimulator() {
    document.querySelectorAll("button[data-preset]").forEach((b) => {
      b.addEventListener("click", () => applySimPreset(b.dataset.preset));
    });
    $("btn-run-sim").addEventListener("click", () => {
      runSimulation().catch((err) => {
        $("sim-result").innerHTML = '<div class="banner banner-error">' + esc(err.message) + "</div>";
      });
    });
    $("sim-form").addEventListener("submit", (e) => {
      e.preventDefault();
      runSimulation().catch((err) => {
        $("sim-result").innerHTML = '<div class="banner banner-error">' + esc(err.message) + "</div>";
      });
    });
  }

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
    $("audit-count").textContent = state.auditEvents.length + " shown (" + (data.total_scanned || 0) + " scanned)";
    $("audit-source-meta").textContent = data.enabled ? "Source: " + (data.path || "audit.jsonl") : "Local file audit is disabled.";
    renderAuditTable();
  }

  function renderAuditTable() {
    const tbody = $("audit-tbody");
    if (!state.auditEvents.length) {
      tbody.innerHTML = '<tr><td colspan="9" class="empty">No audit records match the current filters.</td></tr>';
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
        return (
          '<tr class="clickable" data-audit-idx="' + idx + '">' +
          '<td class="num">' + esc(item.seq) + "</td>" +
          "<td><code>" + esc(item.ts.replace("T", " ").replace("Z", "")) + "</code></td>" +
          "<td><code>" + esc(item.kind + (ev.phase ? "/" + ev.phase : "")) + "</code></td>" +
          '<td><span class="badge ' + decCls + '">' + esc(dec) + "</span></td>" +
          "<td>" + esc(subj) + "</td>" +
          "<td><code>" + esc(target) + "</code></td>" +
          "<td><code>" + esc(ev.rule || "—") + "</code></td>" +
          '<td class="num">' + esc(lat) + "</td>" +
          "<td><code>" + esc((item.hash || "").slice(0, 10)) + "</code></td>" +
          "</tr>"
        );
      })
      .join("");
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
      if (!row) return;
      const item = state.auditEvents[Number(row.dataset.auditIdx)];
      if (!item) return;
      $("audit-drawer-title").textContent = "Record #" + item.seq + " (" + item.kind + ") · hash " + item.hash;
      $("audit-drawer-json").textContent = prettyJSON(item.raw);
      $("audit-drawer").classList.remove("hidden");
    });
    $("btn-close-drawer").addEventListener("click", () => {
      $("audit-drawer").classList.add("hidden");
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
      if (!$("auto-refresh").checked) return;
      if (state.view === "overview" || state.view === "audit" || state.view === "pins") {
        refreshActiveView();
      }
    }, 10000);
  }

  function boot() {
    initTheme();
    initAuthModal();
    initPolicyEditor();
    initPinsView();
    initSimulator();
    initAuditExplorer();

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
