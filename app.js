/* SOC 2 Incident Response Checklist. Static app, browser localStorage only. */

const STORE_KEY = "soc2incident";

/* ---------- Readiness checklist (Prepare tab) ---------- */
const PREPARE_ITEMS = [
  { id: "prep-plan", title: "Incident response plan is documented, approved, and reviewed at least annually",
    why: "An auditor testing CC7.4 starts here: a plan that only lives in someone's head does not count.",
    crit: "CC7.4" },
  { id: "prep-roles", title: "Incident roles are assigned: commander, communications lead, legal liaison",
    why: "Decision speed during an incident depends on knowing who calls the shots before the pressure hits.",
    crit: "CC7.4" },
  { id: "prep-contacts", title: "Contact list is current: internal team, outside counsel, key vendors, regulators",
    why: "Stale contacts are the classic tabletop failure. Review the list quarterly.",
    crit: "CC7.4" },
  { id: "prep-tabletop", title: "Tabletop exercise completed in the last 12 months",
    why: "A plan you have never practiced is a draft, not a control. Document the exercise and the fixes it produced.",
    crit: "CC7.4" },
  { id: "prep-logging", title: "Logging and monitoring are in place with alerting on security anomalies",
    why: "You cannot triage what you cannot see. CC7.2 and CC7.3 depend on real detection capability.",
    crit: "CC7.2, CC7.3" },
  { id: "prep-notify", title: "Breach notification procedure is documented: who decides, who is notified, on what timeline",
    why: "P6.6 expects an established process for notifying data subjects, regulators, and others. Build it calmly, not mid-incident.",
    crit: "P6.6" },
  { id: "prep-vendor", title: "Vendor contracts require vendors to notify you of suspected breaches",
    why: "Your vendors are part of your attack surface. P6.5 expects their notification commitments in writing.",
    crit: "P6.5" }
];

/* ---------- Incident phase tasks (Active incident tab) ---------- */
const PHASES = [
  { id: "detect", name: "1. Detect and triage", crit: "CC7.3", tasks: [
    { id: "d1", text: "Confirm the event is real: triage the alert, not the rumor." },
    { id: "d2", text: "Classify severity and record the initial facts." },
    { id: "d3", text: "Assign an incident commander." },
    { id: "d4", text: "Preserve evidence: secure logs before they rotate." }
  ]},
  { id: "contain", name: "2. Contain", crit: "CC7.4", tasks: [
    { id: "c1", text: "Isolate affected systems from the network." },
    { id: "c2", text: "Block malicious access: revoke sessions, rotate exposed credentials." },
    { id: "c3", text: "Confirm containment: verify the attacker cannot move laterally." }
  ]},
  { id: "eradicate", name: "3. Eradicate", crit: "CC7.4", tasks: [
    { id: "e1", text: "Remove the root cause: malware, rogue accounts, misconfigurations." },
    { id: "e2", text: "Patch or fix the exploited vulnerability." },
    { id: "e3", text: "Reset every credential that may have been exposed." }
  ]},
  { id: "recover", name: "4. Recover", crit: "CC7.4", tasks: [
    { id: "r1", text: "Restore systems from known-clean backups." },
    { id: "r2", text: "Verify system integrity before returning to production." },
    { id: "r3", text: "Bring systems back online in priority order and monitor closely." }
  ]},
  { id: "notify", name: "5. Notify", crit: "P6.6", tasks: [
    { id: "n1", text: "Determine notification obligations: contracts, customer SLAs, state breach laws." },
    { id: "n2", text: "Draft notifications for data subjects and regulators with counsel." },
    { id: "n3", text: "Deliver notifications and keep proof of delivery." },
    { id: "n4", text: "Notify customers and partners per your commitments." }
  ]},
  { id: "learn", name: "6. Lessons learned", crit: "CC7.5", tasks: [
    { id: "l1", text: "Hold a post-incident review within 5 business days." },
    { id: "l2", text: "Update the IR plan with what you learned." },
    { id: "l3", text: "Close the incident and archive the record." }
  ]}
];

/* Fallback summaries in case data/tsc.json cannot be fetched (file:// use, offline). */
const TSC_FALLBACK = {
  "CC7.3": { title: "Security event triage and evaluation", summary: "Anomalies get triaged: the company evaluates whether something is a real security event and how bad it is." },
  "CC7.4": { title: "Incident response", summary: "When a security event becomes an incident, the response plan kicks in: contain, eradicate, recover, learn." },
  "P6.5": { title: "Vendor breach notification commitments", summary: "Vendors commit to notify you of actual or suspected unauthorized disclosures, and those notifications reach the right people fast." },
  "P6.6": { title: "Breach notification to data subjects and regulators", summary: "Breaches and incidents are notified to affected people, regulators, and others as required, through an established process." }
};

/* ---------- Pure helpers (testable in node) ---------- */
function fmtElapsed(ms) {
  if (ms < 0) ms = 0;
  const totalMin = Math.floor(ms / 60000);
  const d = Math.floor(totalMin / 1440);
  const h = Math.floor((totalMin % 1440) / 60);
  const m = totalMin % 60;
  if (d > 0) return d + "d " + h + "h " + m + "m";
  if (h > 0) return h + "h " + m + "m";
  return m + "m";
}

function fmtDateTime(iso) {
  if (!iso) return "n/a";
  const d = new Date(iso);
  return isNaN(d.getTime()) ? "n/a" : d.toLocaleString();
}

function emptyState() {
  return { prepare: {}, incidents: [], activeIncidentId: null };
}

function loadState() {
  try {
    const raw = localStorage.getItem(STORE_KEY);
    if (!raw) return emptyState();
    const s = JSON.parse(raw);
    if (!s || typeof s !== "object") return emptyState();
    s.prepare = s.prepare || {};
    s.incidents = Array.isArray(s.incidents) ? s.incidents : [];
    return s;
  } catch (e) { return emptyState(); }
}

function saveState(s) {
  localStorage.setItem(STORE_KEY, JSON.stringify(s));
}

function newIncident(name, notes) {
  return {
    id: "inc-" + Date.now().toString(36) + "-" + Math.floor(Math.random() * 1e6).toString(36),
    name: name, notes: notes || "",
    detectedAt: new Date().toISOString(),
    closedAt: null, deadlineHours: null,
    tasks: {}, log: []
  };
}

function taskState(inc, taskId) {
  return inc.tasks && inc.tasks[taskId] ? inc.tasks[taskId] : { done: false, at: null };
}

function phaseProgress(inc, phase) {
  const done = phase.tasks.filter(t => taskState(inc, t.id).done).length;
  return { done: done, total: phase.tasks.length };
}

function incidentProgress(inc) {
  let done = 0, total = 0;
  PHASES.forEach(p => p.tasks.forEach(t => { total++; if (taskState(inc, t.id).done) done++; }));
  return { done: done, total: total };
}

/* Markdown export for one incident. */
function buildMarkdown(state, inc, nowIso) {
  const lines = [];
  const now = nowIso || new Date().toISOString();
  lines.push("# Incident record: " + inc.name);
  lines.push("");
  lines.push("- Detected: " + fmtDateTime(inc.detectedAt));
  lines.push("- Status: " + (inc.closedAt ? "Closed (" + fmtDateTime(inc.closedAt) + ")" : "Open"));
  if (inc.notes) lines.push("- Description: " + inc.notes);
  lines.push("- Exported: " + fmtDateTime(now));
  lines.push("");
  const elapsed = new Date(now).getTime() - new Date(inc.detectedAt).getTime();
  lines.push("## Notification deadline tracker");
  lines.push("");
  lines.push("- Elapsed since detection: " + fmtElapsed(elapsed));
  lines.push("- Earliest deadline tracked: " + (inc.deadlineHours != null && inc.deadlineHours !== "" ? inc.deadlineHours + " hours from detection" : "not set"));
  lines.push("");
  lines.push("Notification windows vary by contract and regulation. P6.6 requires notification to affected");
  lines.push("data subjects and regulators per the entity's objectives; contracts and state breach laws set");
  lines.push("specific windows. This record tracks elapsed time only. Not legal advice.");
  lines.push("");
  lines.push("## Task checklist by phase");
  lines.push("");
  const prog = incidentProgress(inc);
  lines.push("Tasks complete: " + prog.done + " of " + prog.total);
  lines.push("");
  PHASES.forEach(p => {
    lines.push("### " + p.name + " (" + p.crit + ")");
    lines.push("");
    p.tasks.forEach(t => {
      const st = taskState(inc, t.id);
      lines.push("- [" + (st.done ? "x" : " ") + "] " + t.text + (st.done && st.at ? " (completed " + fmtDateTime(st.at) + ")" : ""));
    });
    lines.push("");
  });
  lines.push("## Incident log");
  lines.push("");
  if (inc.log.length === 0) lines.push("No log entries recorded.");
  else inc.log.forEach(e => lines.push("- " + fmtDateTime(e.at) + ": " + e.text));
  lines.push("");
  lines.push("## Readiness snapshot");
  lines.push("");
  const ready = PREPARE_ITEMS.filter(i => state.prepare[i.id]).length;
  lines.push("Readiness items complete: " + ready + " of " + PREPARE_ITEMS.length);
  PREPARE_ITEMS.forEach(i => lines.push("- [" + (state.prepare[i.id] ? "x" : " ") + "] " + i.title));
  lines.push("");
  lines.push("---");
  lines.push("Readiness aid only. Not legal advice. Consult counsel on breach notification obligations.");
  lines.push("Generated by the AI Tech Pros SOC 2 Incident Response Checklist.");
  return lines.join("\n");
}

function buildPrepMarkdown(state) {
  const lines = ["# SOC 2 incident readiness checklist", ""];
  const ready = PREPARE_ITEMS.filter(i => state.prepare[i.id]).length;
  lines.push("Complete: " + ready + " of " + PREPARE_ITEMS.length);
  lines.push("");
  PREPARE_ITEMS.forEach(i => {
    lines.push("- [" + (state.prepare[i.id] ? "x" : " ") + "] " + i.title + " [" + i.crit + "]");
    lines.push("  " + i.why);
  });
  lines.push("");
  lines.push("Readiness aid only. Not legal advice.");
  return lines.join("\n");
}

/* node exports for verification */
if (typeof module !== "undefined" && module.exports) {
  module.exports = { fmtElapsed, fmtDateTime, buildMarkdown, buildPrepMarkdown, newIncident,
    incidentProgress, phaseProgress, taskState, PREPARE_ITEMS, PHASES, STORE_KEY };
}

/* ---------- Browser UI ---------- */
if (typeof window !== "undefined") {
  let state = loadState();
  let tscById = Object.assign({}, TSC_FALLBACK);
  let timerId = null;

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  }

  function download(filename, text) {
    const blob = new Blob([text], { type: "text/markdown;charset=utf-8" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    document.body.appendChild(a); a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500);
  }

  /* ---- tabs ---- */
  document.querySelectorAll(".tab").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach(b => b.classList.remove("on"));
      document.querySelectorAll(".tabpane").forEach(p => p.classList.add("hidden"));
      btn.classList.add("on");
      document.getElementById("tab-" + btn.dataset.tab).classList.remove("hidden");
      if (btn.dataset.tab === "incident") renderIncidentTab();
      if (btn.dataset.tab === "log") renderLogTab();
    });
  });

  /* ---- prepare tab ---- */
  function renderPrepare() {
    const list = document.getElementById("prepList");
    list.innerHTML = "";
    PREPARE_ITEMS.forEach(item => {
      const done = !!state.prepare[item.id];
      const div = document.createElement("div");
      div.className = "check" + (done ? " done" : "");
      div.innerHTML = '<input type="checkbox"' + (done ? " checked" : "") + ' aria-label="' + esc(item.title) + '">' +
        '<span class="lbl"><strong>' + esc(item.title) + ' <span class="crit">' + esc(item.crit) + '</span></strong>' +
        '<span class="why">' + esc(item.why) + '</span></span>';
      div.querySelector("input").addEventListener("change", e => {
        state.prepare[item.id] = e.target.checked;
        saveState(state);
        renderPrepare();
      });
      list.appendChild(div);
    });
    const ready = PREPARE_ITEMS.filter(i => state.prepare[i.id]).length;
    document.getElementById("prepFill").style.width = (ready / PREPARE_ITEMS.length * 100) + "%";
    document.getElementById("prepText").textContent = ready + " of " + PREPARE_ITEMS.length + " ready";

    const refs = document.getElementById("tscRefs");
    refs.innerHTML = "";
    ["CC7.3", "CC7.4", "P6.5", "P6.6"].forEach(id => {
      const r = tscById[id] || TSC_FALLBACK[id];
      const d = document.createElement("div");
      d.className = "ref";
      d.innerHTML = '<div class="rid">' + esc(id) + '</div><h3>' + esc(r.title) + '</h3><p>' + esc(r.summary) + '</p>';
      refs.appendChild(d);
    });
  }

  document.getElementById("exportPrep").addEventListener("click", () => {
    download("soc2-incident-readiness.md", buildPrepMarkdown(state));
  });
  document.getElementById("resetPrep").addEventListener("click", () => {
    if (confirm("Clear all readiness answers?")) { state.prepare = {}; saveState(state); renderPrepare(); }
  });

  /* ---- incident tab ---- */
  function activeIncident() {
    return state.incidents.find(i => i.id === state.activeIncidentId) || null;
  }

  function refreshSelects() {
    ["incidentSelect", "logIncidentSelect"].forEach(selId => {
      const sel = document.getElementById(selId);
      sel.innerHTML = "";
      if (state.incidents.length === 0) {
        const o = document.createElement("option"); o.value = ""; o.textContent = "No incidents yet";
        sel.appendChild(o); sel.value = "";
      } else {
        state.incidents.forEach(i => {
          const o = document.createElement("option");
          o.value = i.id;
          o.textContent = i.name + (i.closedAt ? " (closed)" : " (open)");
          sel.appendChild(o);
        });
        sel.value = state.activeIncidentId || state.incidents[0].id;
      }
    });
  }

  document.getElementById("startIncident").addEventListener("click", () => {
    const nameEl = document.getElementById("newName");
    const name = nameEl.value.trim();
    if (!name) { alert("Give the incident a name first."); nameEl.focus(); return; }
    const inc = newIncident(name, document.getElementById("newNotes").value.trim());
    inc.log.push({ at: new Date().toISOString(), text: "Incident opened. Detection clock started." });
    state.incidents.unshift(inc);
    state.activeIncidentId = inc.id;
    nameEl.value = ""; document.getElementById("newNotes").value = "";
    saveState(state); refreshSelects(); renderIncidentTab();
  });

  document.getElementById("incidentSelect").addEventListener("change", e => {
    state.activeIncidentId = e.target.value || null;
    saveState(state); renderIncidentTab();
  });
  document.getElementById("logIncidentSelect").addEventListener("change", e => {
    state.activeIncidentId = e.target.value || null;
    saveState(state); renderLogTab(); refreshSelects();
  });

  document.getElementById("closeIncident").addEventListener("click", () => {
    const inc = activeIncident();
    if (!inc) return;
    if (inc.closedAt) { alert("This incident is already closed."); return; }
    inc.closedAt = new Date().toISOString();
    inc.log.push({ at: inc.closedAt, text: "Incident closed." });
    saveState(state); refreshSelects(); renderIncidentTab();
  });

  document.getElementById("deleteIncident").addEventListener("click", () => {
    const inc = activeIncident();
    if (!inc) return;
    if (!confirm("Delete incident \"" + inc.name + "\" and its log? This cannot be undone.")) return;
    state.incidents = state.incidents.filter(i => i.id !== inc.id);
    state.activeIncidentId = state.incidents.length ? state.incidents[0].id : null;
    saveState(state); refreshSelects(); renderIncidentTab(); renderLogTab();
  });

  function renderIncidentTab() {
    refreshSelects();
    const detail = document.getElementById("incidentDetail");
    const inc = activeIncident();
    if (!inc) { detail.innerHTML = '<p class="muted">No incident selected. Start one above to begin tracking.</p>'; return; }
    const prog = incidentProgress(inc);
    let html = '<h2>' + esc(inc.name) + ' <span class="' + (inc.closedAt ? "status-closed" : "status-open") + '">' +
      (inc.closedAt ? "CLOSED" : "OPEN") + '</span></h2>' +
      '<p class="inc-meta">Detected: ' + esc(fmtDateTime(inc.detectedAt)) +
      (inc.closedAt ? ' &middot; Closed: ' + esc(fmtDateTime(inc.closedAt)) : '') +
      (inc.notes ? '<br>' + esc(inc.notes) : '') + '</p>' +
      '<div class="timer"><div class="elapsed" id="elapsedClock">' + esc(fmtElapsed(Date.now() - new Date(inc.detectedAt).getTime())) + '</div>' +
      '<div class="meta">elapsed since detection</div>' +
      '<div class="dbar"><i id="dbarFill"></i></div>' +
      '<div class="deadline-row"><label for="deadlineHours">My earliest notification deadline (hours from detection):</label>' +
      '<input id="deadlineHours" type="text" inputmode="numeric" value="' + esc(inc.deadlineHours == null ? "" : inc.deadlineHours) + '" placeholder="e.g. 72">' +
      '<button id="saveDeadline" class="btn">Set</button></div>' +
      '<p class="note">Notification windows vary by contract and regulation. P6.6 requires notification to affected data subjects and regulators per the entity\'s objectives; your contracts and state breach laws set specific windows. This tracker counts elapsed time only. Not legal advice.</p></div>' +
      '<div class="progress"><div class="progress-fill" id="incFill" style="width:' + (prog.total ? (prog.done / prog.total * 100) : 0) + '%"></div></div>' +
      '<p class="muted small" id="incText">' + prog.done + ' of ' + prog.total + ' tasks complete</p>';
    PHASES.forEach(p => {
      const pp = phaseProgress(inc, p);
      html += '<div class="phase"><h3>' + esc(p.name) + ' <span class="crit">' + esc(p.crit) + '</span> <span class="pcount">' + pp.done + '/' + pp.total + '</span></h3>';
      p.tasks.forEach(t => {
        const st = taskState(inc, t.id);
        html += '<div class="check' + (st.done ? " done" : "") + '" data-task="' + t.id + '">' +
          '<input type="checkbox"' + (st.done ? " checked" : "") + ' aria-label="' + esc(t.text) + '">' +
          '<span class="lbl">' + esc(t.text) + '</span>' +
          (st.done && st.at ? '<span class="ts">' + esc(fmtDateTime(st.at)) + '</span>' : '') + '</div>';
      });
      html += '</div>';
    });
    detail.innerHTML = html;

    detail.querySelectorAll(".check").forEach(div => {
      div.querySelector("input").addEventListener("change", e => {
        const tid = div.dataset.task;
        if (e.target.checked) inc.tasks[tid] = { done: true, at: new Date().toISOString() };
        else delete inc.tasks[tid];
        saveState(state); renderIncidentTab();
      });
    });
    document.getElementById("saveDeadline").addEventListener("click", () => {
      const v = document.getElementById("deadlineHours").value.trim();
      if (v === "") inc.deadlineHours = null;
      else {
        const n = parseFloat(v);
        if (isNaN(n) || n <= 0) { alert("Enter a positive number of hours, or leave blank."); return; }
        inc.deadlineHours = n;
      }
      saveState(state); updateDeadline(inc);
    });
    startTimer(inc);
    updateDeadline(inc);
  }

  function updateDeadline(inc) {
    const fill = document.getElementById("dbarFill");
    if (!fill) return;
    if (inc.deadlineHours == null || inc.deadlineHours === "") {
      fill.style.width = "0%"; fill.className = ""; return;
    }
    const elapsedH = (Date.now() - new Date(inc.detectedAt).getTime()) / 3600000;
    const pct = Math.min(100, elapsedH / inc.deadlineHours * 100);
    fill.style.width = pct + "%";
    fill.className = elapsedH >= inc.deadlineHours ? "over" : (pct >= 75 ? "warn" : "");
  }

  function startTimer(inc) {
    if (timerId) clearInterval(timerId);
    timerId = setInterval(() => {
      const clock = document.getElementById("elapsedClock");
      if (!clock) { clearInterval(timerId); timerId = null; return; }
      clock.textContent = fmtElapsed(Date.now() - new Date(inc.detectedAt).getTime());
      updateDeadline(inc);
    }, 1000);
  }

  /* ---- log tab ---- */
  function renderLogTab() {
    refreshSelects();
    const inc = activeIncident();
    const box = document.getElementById("logEntries");
    box.innerHTML = "";
    if (!inc) { box.innerHTML = '<p class="muted">No incident selected.</p>'; return; }
    if (inc.log.length === 0) box.innerHTML = '<p class="muted">No log entries yet.</p>';
    inc.log.slice().reverse().forEach(e => {
      const d = document.createElement("div");
      d.className = "logentry";
      d.innerHTML = '<span class="lt">' + esc(fmtDateTime(e.at)) + '</span><span class="lx">' + esc(e.text) + '</span>';
      box.appendChild(d);
    });
  }

  document.getElementById("addLog").addEventListener("click", () => {
    const inc = activeIncident();
    if (!inc) { alert("Start an incident first."); return; }
    const ta = document.getElementById("logText");
    const text = ta.value.trim();
    if (!text) { alert("Write the log entry first."); ta.focus(); return; }
    inc.log.push({ at: new Date().toISOString(), text: text });
    ta.value = "";
    saveState(state); renderLogTab();
  });

  document.getElementById("exportMd").addEventListener("click", () => {
    const inc = activeIncident();
    if (!inc) { alert("Start an incident first."); return; }
    const safe = inc.name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "incident";
    download("soc2-incident-" + safe + ".md", buildMarkdown(state, inc));
  });

  /* ---- init ---- */
  fetch("data/tsc.json").then(r => r.json()).then(d => {
    (d.criteria || []).forEach(c => { tscById[c.id] = { title: c.title, summary: c.summary }; });
    renderPrepare();
  }).catch(() => renderPrepare());

  if (!state.activeIncidentId && state.incidents.length) state.activeIncidentId = state.incidents[0].id;
  renderPrepare();
  refreshSelects();
}
