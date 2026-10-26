/* ConfigSentry web app. Plain JavaScript, no external libraries. */
(() => {
  "use strict";

  const $ = (sel) => document.querySelector(sel);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const SEV = { high: "High", medium: "Medium", low: "Low", info: "Info" };
  const SEV_COLOR = { high: "#C93838", medium: "#B7650B", low: "#2F6DB5", pass: "#1F8A5B" };

  const state = {
    meta: null,
    platform: "auto",
    file: null,          // { name, bytes: ArrayBuffer }
    lastBody: null,      // what was audited (for report downloads)
    lastName: null,
    lastPlatform: null,
    result: null,
    mask: true,
    tab: "findings",
    sev: new Set(["high", "medium", "low"]),
    rules: null,
    ruleFilter: "all",
  };

  // ----------------------------------------------------------------- //
  // Routing
  // ----------------------------------------------------------------- //
  function route() {
    const page = (location.hash.replace(/^#\/?/, "") || "audit").split("?")[0];
    const name = ["audit", "rules", "privacy"].includes(page) ? page : "audit";
    for (const p of ["audit", "rules", "privacy"]) $(`#page-${p}`).hidden = p !== name;
    document.querySelectorAll("nav a").forEach((a) => a.classList.toggle("on", a.dataset.nav === name));
    if (name === "rules") loadRules();
    document.title = name === "audit" ? "ConfigSentry" : `${name[0].toUpperCase() + name.slice(1)} - ConfigSentry`;
  }
  window.addEventListener("hashchange", () => { route(); window.scrollTo(0, 0); });

  // ----------------------------------------------------------------- //
  // Meta: platforms and facts
  // ----------------------------------------------------------------- //
  async function loadMeta() {
    const res = await fetch("/api/meta");
    state.meta = await res.json();
    $("#ver").textContent = state.meta.version;
    const total = state.meta.platforms.reduce((n, p) => n + p.rules, 0);
    $("#facts").innerHTML =
      `<li><b>${state.meta.platforms.length}</b> platforms</li>` +
      `<li><b>${total}</b> security checks</li>` +
      `<li>Works offline, nothing leaves this computer</li>`;
    renderTiles();
  }

  function renderTiles() {
    const groups = [
      ["Switches and routers", state.meta.platforms.filter((p) => p.kind !== "Firewall")],
      ["Firewalls", state.meta.platforms.filter((p) => p.kind === "Firewall")],
    ];
    let html = `<button type="button" class="tile auto" role="radio" data-p="auto">
        <b>Detect automatically</b><small id="detHint">Recommended. ConfigSentry reads the file and picks the platform.</small></button>`;
    for (const [label, list] of groups) {
      html += `<div class="grp">${esc(label)}</div>`;
      for (const p of list) {
        html += `<button type="button" class="tile" role="radio" data-p="${esc(p.key)}" title="${esc(p.command)}">
          <b>${esc(cleanName(p.name))}</b>
          <small>${esc(HINT[p.key] || p.command)}</small></button>`;
      }
    }
    $("#tiles").innerHTML = html;
    $("#tiles").addEventListener("click", (e) => {
      const t = e.target.closest(".tile");
      if (t) selectPlatform(t.dataset.p);
    });
    selectPlatform("auto");
  }

  const HINT = {
    cisco_ios: "show running-config",
    cisco_nxos: "show running-config",
    huawei_vrp: "display current-configuration",
    junos: "show configuration | display set",
    mikrotik: "/export",
    cisco_asa: "show running-config",
    fortigate: "show full-configuration",
    paloalto: "XML export or set format",
    checkpoint_gaia: "clish show configuration",
    sophos: "Entities.xml or backup .tar (beta)",
  };
  const cleanName = (n) => n.replace(/\s*-\s*beta$/i, "").replace(/\s*\(.*\)$/, "");

  function selectPlatform(key) {
    state.platform = key;
    document.querySelectorAll(".tile").forEach((t) => t.setAttribute("aria-checked", String(t.dataset.p === key)));
    hideNotice();
  }

  // ----------------------------------------------------------------- //
  // Input: drop zone, file, paste
  // ----------------------------------------------------------------- //
  const drop = $("#drop");
  const fileInput = $("#file");
  const paste = $("#paste");

  function fmtSize(n) {
    return n < 1024 ? `${n} bytes` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`;
  }

  async function setFile(f) {
    if (!f) return;
    if (f.size > 25 * 1024 * 1024) { showNotice("That file is larger than 25 MB. Export a smaller configuration and try again.", true); return; }
    state.file = { name: f.name, bytes: await f.arrayBuffer() };
    $("#fname").textContent = f.name;
    $("#fsize").textContent = fmtSize(f.size);
    drop.hidden = true;
    $("#filechip").hidden = false;
    paste.hidden = true;
    $("#pasteToggle").hidden = true;
    hideNotice();
    updateRun();
  }

  function clearFile() {
    state.file = null;
    fileInput.value = "";
    drop.hidden = false;
    $("#filechip").hidden = true;
    $("#pasteToggle").hidden = false;
    updateRun();
  }

  drop.addEventListener("click", () => fileInput.click());
  drop.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); fileInput.click(); } });
  fileInput.addEventListener("change", () => setFile(fileInput.files[0]));
  ["dragenter", "dragover"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("over"); }));
  ["dragleave", "drop"].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("over"); }));
  drop.addEventListener("drop", (e) => setFile(e.dataTransfer.files[0]));
  // Also accept a file dropped anywhere on the audit page.
  document.addEventListener("dragover", (e) => e.preventDefault());
  document.addEventListener("drop", (e) => { e.preventDefault(); if (e.dataTransfer.files[0] && !$("#page-audit").hidden) setFile(e.dataTransfer.files[0]); });

  $("#fclear").addEventListener("click", clearFile);
  $("#pasteToggle").addEventListener("click", () => {
    const show = paste.hidden;
    paste.hidden = !show;
    $("#pasteToggle").textContent = show ? "Upload a file instead" : "Paste text instead";
    $("#pasteToggle").setAttribute("aria-expanded", String(show));
    drop.hidden = show;
    if (show) paste.focus(); else paste.value = "";
    updateRun();
  });
  paste.addEventListener("input", updateRun);

  function currentInput() {
    if (state.file) return { body: state.file.bytes, name: state.file.name };
    if (!paste.hidden && paste.value.trim()) return { body: new TextEncoder().encode(paste.value), name: "pasted configuration" };
    return null;
  }

  function updateRun() {
    const ok = !!currentInput();
    $("#run").disabled = !ok;
    $("#runHint").textContent = ok ? "Runs in a second or two. Nothing leaves this computer." : "Add a configuration to start.";
  }

  // ----------------------------------------------------------------- //
  // Notices
  // ----------------------------------------------------------------- //
  function showNotice(html, isErr = false, actions = []) {
    const n = $("#notice");
    n.className = "notice" + (isErr ? " err" : "");
    n.innerHTML = `<div>${html}</div>` + (actions.length ? `<div class="acts"></div>` : "");
    actions.forEach(([label, primary, fn]) => {
      const b = document.createElement("button");
      b.type = "button"; b.className = "btn" + (primary ? " primary" : ""); b.textContent = label;
      b.addEventListener("click", fn);
      n.querySelector(".acts").appendChild(b);
    });
    n.hidden = false;
  }
  function hideNotice() { $("#notice").hidden = true; }
  const pname = (key) => (state.meta.platforms.find((p) => p.key === key) || { name: key }).name;

  // ----------------------------------------------------------------- //
  // Audit
  // ----------------------------------------------------------------- //
  async function runAudit(platform = state.platform, force = false) {
    const input = currentInput();
    if (!input) return;
    const btn = $("#run");
    btn.classList.add("busy"); btn.disabled = true;
    hideNotice();
    try {
      const q = new URLSearchParams({ platform, name: input.name });
      if (force) q.set("force", "1");
      const res = await fetch(`/api/audit?${q}`, { method: "POST", body: input.body });
      const data = await res.json();
      if (data.status === "ok") {
        state.result = data.result;
        state.lastBody = input.body; state.lastName = input.name; state.lastPlatform = data.result.platform_key;
        state.tab = "findings";
        state.sev = new Set(["high", "medium", "low"]);
        if (platform === "auto") $("#detHint").innerHTML = `Detected <span class="det">${esc(pname(data.result.platform_key))}</span>.`;
        renderResults(true);
      } else if (data.status === "mismatch") {
        showNotice(
          `This looks like a <b>${esc(pname(data.detected))}</b> configuration, but <b>${esc(pname(data.selected))}</b> is selected. Which rules should be used?`,
          false,
          [[`Audit as ${pname(data.detected)}`, true, () => { selectPlatform(data.detected); runAudit(data.detected); }],
           [`Use ${pname(data.selected)} anyway`, false, () => runAudit(data.selected, true)]]);
      } else if (data.status === "choose") {
        showNotice(esc(data.message), false);
        $("#tiles").scrollIntoView({ behavior: "smooth", block: "center" });
      } else {
        showNotice(esc(data.message || "The audit could not run."), true);
      }
    } catch (err) {
      showNotice("ConfigSentry is not running. Start it again with start.bat, then reload this page.", true);
    } finally {
      btn.classList.remove("busy");
      updateRun();
    }
  }
  $("#run").addEventListener("click", () => runAudit());

  // ----------------------------------------------------------------- //
  // Results
  // ----------------------------------------------------------------- //
  function dial(score, grade) {
    const color = score >= 75 ? SEV_COLOR.pass : score >= 40 ? SEV_COLOR.medium : SEV_COLOR.high;
    const circ = 2 * Math.PI * 64;
    const arc = score > 0
      ? `<circle cx="80" cy="80" r="64" fill="none" stroke="${color}" stroke-width="10" stroke-linecap="round" stroke-dasharray="${(circ * score / 100).toFixed(1)} ${circ.toFixed(1)}" transform="rotate(-90 80 80)"/>`
      : "";
    return `<svg class="dial" viewBox="0 0 160 160" role="img" aria-label="Security score ${score} out of 100, grade ${grade}">
      <circle cx="80" cy="80" r="64" fill="none" stroke="#EEF0F3" stroke-width="10"/>${arc}
      <text x="80" y="86" text-anchor="middle" font-size="38" font-weight="700" fill="#1C2330" font-family="Segoe UI, system-ui, sans-serif">${score}</text>
      <text x="80" y="108" text-anchor="middle" font-size="11" fill="#667085" font-family="Segoe UI, system-ui, sans-serif">Grade ${esc(grade)}</text></svg>`;
  }

  function verdict(s) {
    const failed = s.high + s.medium + s.low;
    if (!failed) return ["No issues found", "Every applicable check passed for this rule set."];
    if (s.high) return [`${s.high} high-risk ${s.high === 1 ? "issue" : "issues"} to fix first`,
      "High findings expose credentials or management access. Start with those, then work through the rest."];
    if (s.medium) return [`${s.medium} medium-risk ${s.medium === 1 ? "issue" : "issues"}`,
      "No high-risk settings were found. The medium findings are the next hardening steps."];
    return ["Only low-risk findings", "The core controls are in place. The remaining items are good-practice hardening."];
  }

  const ORDER = { high: 0, medium: 1, low: 2, info: 3 };

  function renderResults(scroll = false) {
    const r = state.result;
    const box = $("#results");
    const s = r.summary;
    const failed = r.results.filter((x) => x.status === "FAIL").sort((a, b) => ORDER[a.severity] - ORDER[b.severity] || a.id.localeCompare(b.id));
    const passed = r.results.filter((x) => x.status === "PASS");
    const na = r.results.filter((x) => x.status === "N/A");
    const total = s.high + s.medium + s.low + s.passed || 1;
    const parts = [["high", s.high, "High"], ["medium", s.medium, "Medium"], ["low", s.low, "Low"], ["pass", s.passed, "Passed"]];
    const [vt, vs] = verdict(s);

    let html = `
      <div class="res-h"><h2>${esc(r.hostname || "Audit result")}</h2>
        <div class="res-meta">${esc(r.platform_name)} rules, from ${esc(r.source)}</div></div>
      <div class="score"><div>${dial(r.score, r.grade)}</div><div>
        <p class="verdict">${esc(vt)}</p><p class="verdict-sub">${esc(vs)}</p>
        <div class="bar" role="img" aria-label="Breakdown of results">${parts.filter((p) => p[1]).map((p) =>
          `<span style="width:${(100 * p[1] / total).toFixed(2)}%;background:${SEV_COLOR[p[0]]}" title="${p[2]}: ${p[1]}"></span>`).join("")}</div>
        <div class="legend">${parts.map((p) => `<div><b>${p[1]}</b><span class="dot" style="background:${SEV_COLOR[p[0]]}"></span>${p[2]}</div>`).join("")}</div>
      </div></div>
      <div class="toolbar">
        <div class="left">
          <button type="button" class="btn" data-dl="html">Download HTML report</button>
          <button type="button" class="btn" data-dl="json">Download JSON</button>
        </div>
        <label class="switch"><input type="checkbox" id="maskSw" ${state.mask ? "checked" : ""}><span class="trk"></span>Mask secrets</label>
      </div>
      ${state.mask ? "" : `<div class="maskwarn"><b>Secret masking is off.</b> Hashes, keys and SNMP communities are shown in full, and type 7 values can be decoded instantly. Do not share screenshots or reports while masking is off.</div>`}
      <div class="tabs" role="tablist">
        ${[["findings", "Findings", failed.length], ["passed", "Passed", passed.length], ["na", "Not applicable", na.length]].map(([k, l, n]) =>
          `<button type="button" role="tab" data-tab="${k}" aria-selected="${state.tab === k}">${l}<span class="n">${n}</span></button>`).join("")}
      </div>`;

    if (state.tab === "findings") {
      if (!failed.length) {
        html += `<div class="empty">No issues found by the current rule set.</div>`;
      } else {
        const sevs = ["high", "medium", "low"].filter((k) => s[k]);
        html += `<div class="chips" id="sevChips">${sevs.map((k) =>
          `<button type="button" class="chip" data-sev="${k}" aria-pressed="${state.sev.has(k)}">${SEV[k]} (${s[k]})</button>`).join("")}</div>`;
        const shown = failed.filter((f) => state.sev.has(f.severity));
        html += shown.length ? shown.map(finding).join("") : `<div class="empty">Select a severity to see its findings.</div>`;
      }
    } else if (state.tab === "passed") {
      html += passed.length
        ? `<ul class="list">${passed.map((p) => `<li><span class="rid">${esc(p.id)}</span><span>${esc(p.title)}<small>Not found in this configuration</small></span></li>`).join("")}</ul>`
        : `<div class="empty">No checks passed.</div>`;
    } else {
      html += na.length
        ? `<ul class="list">${na.map((p) => `<li><span class="rid">${esc(p.id)}</span><span>${esc(p.title)}<small>${esc(p.evidence.join("; "))}</small></span></li>`).join("")}</ul>`
        : `<div class="empty">Every check applied to this configuration.</div>`;
    }

    box.innerHTML = html;
    box.hidden = false;
    if (scroll) box.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function finding(f) {
    const ev = state.mask ? f.evidence_masked : f.evidence;
    return `<details class="f"><summary>
        <span class="sev s-${esc(f.severity)}">${SEV[f.severity] || esc(f.severity)}</span>
        <span class="rid">${esc(f.id)}</span><span class="ft">${esc(f.title)}</span><span class="cat">${esc(f.category)}</span></summary>
      <div class="fb"><div class="desc">${esc(f.description)}</div>
        ${ev.length ? `<div class="lbl">Evidence</div><div class="code ev">${esc(ev.join("\n"))}</div>` : ""}
        <div class="lbl">Recommended fix</div><div class="code fix">${esc(f.remediation)}</div>
        ${f.references.length ? `<div class="ref">References: ${esc(f.references.join(", "))}</div>` : ""}</div></details>`;
  }

  $("#results").addEventListener("click", (e) => {
    const tab = e.target.closest("[data-tab]");
    if (tab) { state.tab = tab.dataset.tab; renderResults(); return; }
    const chip = e.target.closest("[data-sev]");
    if (chip) {
      const k = chip.dataset.sev;
      state.sev.has(k) ? state.sev.delete(k) : state.sev.add(k);
      renderResults(); return;
    }
    const dl = e.target.closest("[data-dl]");
    if (dl) download(dl.dataset.dl, dl);
  });
  $("#results").addEventListener("change", (e) => {
    if (e.target.id === "maskSw") { state.mask = e.target.checked; renderResults(); $("#maskSw").focus(); }
  });

  async function download(fmt, btn) {
    btn.classList.add("busy");
    try {
      const q = new URLSearchParams({ platform: state.lastPlatform, name: state.lastName, format: fmt, mask: state.mask ? "1" : "0", force: "1" });
      const res = await fetch(`/api/report?${q}`, { method: "POST", body: state.lastBody });
      if (!res.ok) throw new Error();
      const blob = await res.blob();
      const host = (state.result.hostname || "device").replace(/\s+/g, "_");
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `configsentry_${host}.${fmt}`;
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(a.href), 2000);
    } catch {
      showNotice("The report could not be created. Run the audit again and retry.", true);
    } finally {
      btn.classList.remove("busy");
    }
  }

  // ----------------------------------------------------------------- //
  // Rules page
  // ----------------------------------------------------------------- //
  async function loadRules() {
    if (!state.rules) {
      state.rules = await (await fetch("/api/rules")).json();
      const keys = Object.keys(state.rules);
      const total = keys.reduce((n, k) => n + state.rules[k].rules.length, 0);
      $("#rulesIntro").textContent = `All ${total} checks ConfigSentry runs, across ${keys.length} platforms.`;
      $("#ruleChips").innerHTML = `<button type="button" class="chip" data-rp="all" aria-pressed="true">All</button>` +
        keys.map((k) => `<button type="button" class="chip" data-rp="${esc(k)}" aria-pressed="false">${esc(cleanName(state.rules[k].name))}</button>`).join("");
      $("#ruleChips").addEventListener("click", (e) => {
        const c = e.target.closest("[data-rp]");
        if (!c) return;
        state.ruleFilter = c.dataset.rp;
        document.querySelectorAll("#ruleChips .chip").forEach((x) => x.setAttribute("aria-pressed", String(x === c)));
        renderRules();
      });
      $("#ruleSearch").addEventListener("input", renderRules);
    }
    renderRules();
  }

  function renderRules() {
    const q = $("#ruleSearch").value.trim().toLowerCase();
    let html = "";
    for (const [key, g] of Object.entries(state.rules)) {
      if (state.ruleFilter !== "all" && state.ruleFilter !== key) continue;
      const rows = g.rules.filter((r) => !q || [r.id, r.title, r.category, r.description].join(" ").toLowerCase().includes(q));
      if (!rows.length) continue;
      html += `<div class="rgroup"><h3>${esc(g.name)}</h3><p class="sub">${esc(g.kind)}, ${g.rules.length} checks</p>` +
        rows.map((r) => `<div class="rrow"><span class="rid">${esc(r.id)}</span><span class="sev s-${esc(r.severity)}">${SEV[r.severity]}</span>
          <span>${esc(r.title)}</span><span class="cat">${esc(r.category)}</span></div>`).join("") + `</div>`;
    }
    $("#rulesList").innerHTML = html || `<div class="empty">No rules match "${esc(q)}".</div>`;
  }

  // ----------------------------------------------------------------- //
  route();
  loadMeta().catch(() => showNotice("ConfigSentry is not running. Start it again with start.bat, then reload this page.", true));
})();
