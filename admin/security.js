const STORAGE_KEY = "aethra_security_admin_key";

const adminKeyInput = document.getElementById("adminKey");
const saveKeyBtn = document.getElementById("saveKeyBtn");
const refreshBtn = document.getElementById("refreshBtn");
const statusLine = document.getElementById("statusLine");

const modeValue = document.getElementById("modeValue");
const containmentValue = document.getElementById("containmentValue");
const threatPressureValue = document.getElementById("threatPressureValue");
const threatPressureBar = document.getElementById("threatPressureBar");
const healthBadge = document.getElementById("healthBadge");

const flagsBox = document.getElementById("flagsBox");
const counterList = document.getElementById("counterList");

const warningCount = document.getElementById("warningCount");
const criticalCount = document.getElementById("criticalCount");
const unauthCount = document.getElementById("unauthCount");
const containmentCount = document.getElementById("containmentCount");
const actionBreakdown = document.getElementById("actionBreakdown");

const eventsList = document.getElementById("eventsList");

function safeText(value, fallback = "--") {
  const text = String(value ?? "").trim();
  return text || fallback;
}

function safeNumber(value, fallback = 0) {
  const num = Number(value);
  return Number.isFinite(num) ? num : fallback;
}

function getSavedAdminKey() {
  try {
    return localStorage.getItem(STORAGE_KEY) || "";
  } catch {
    return "";
  }
}

function saveAdminKey(value) {
  try {
    localStorage.setItem(STORAGE_KEY, value || "");
  } catch {
    // ignore
  }
}

function setStatus(message, isError = false) {
  statusLine.textContent = message;
  statusLine.style.color = isError ? "#ff8fa4" : "";
}

function formatTimestamp(value) {
  if (!value) return "--";

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "--";

  return date.toLocaleString();
}

function badgeClassForHealth(health) {
  const normalized = safeText(health, "").toLowerCase();

  if (normalized === "good") return "badge good";
  if (normalized === "guarded" || normalized === "stressed") return "badge warn";
  if (normalized === "critical") return "badge danger";
  return "badge";
}

function createFlagPill(label, active) {
  const pill = document.createElement("div");
  pill.className = `flag-pill${active ? " active" : ""}`;
  pill.textContent = active ? `${label}: ON` : `${label}: OFF`;
  return pill;
}

function createKvRow(label, value) {
  const row = document.createElement("div");
  row.className = "kv-row";

  const left = document.createElement("span");
  left.textContent = label;

  const right = document.createElement("span");
  right.textContent = String(value);

  row.appendChild(left);
  row.appendChild(right);

  return row;
}

function renderStatus(status) {
  modeValue.textContent = safeText(status?.mode);
  containmentValue.textContent = safeText(status?.containment?.mode, "normal");

  const pressure = Math.max(0, Math.min(100, safeNumber(status?.threatPressure, 0)));
  threatPressureValue.textContent = String(pressure);
  threatPressureBar.style.width = `${pressure}%`;

  const health = safeText(status?.systemHealth, "unknown");
  healthBadge.className = badgeClassForHealth(health);
  healthBadge.textContent = health;

  flagsBox.innerHTML = "";
  const flags = [
    ["Freeze registrations", status?.containment?.freezeRegistrations === true],
    ["Disable profile edits", status?.containment?.disableProfileEdits === true],
    ["Lock admin writes", status?.containment?.lockAdminWrites === true],
    ["Disable uploads", status?.containment?.disableUploads === true],
    ["Force captcha", status?.containment?.forceCaptcha === true],
    ["Read only", status?.containment?.readOnlyMode === true],
    ["Lockdown", status?.containment?.lockdown === true]
  ];

  for (const [label, active] of flags) {
    flagsBox.appendChild(createFlagPill(label, active));
  }

  counterList.innerHTML = "";
  const counters = status?.counters || {};
  const counterItems = [
    ["Total signals", safeNumber(counters.totalSignals, 0)],
    ["Critical signals", safeNumber(counters.criticalSignals, 0)],
    ["Block signals", safeNumber(counters.blockSignals, 0)],
    ["Challenge signals", safeNumber(counters.challengeSignals, 0)],
    ["Repeated offenders", safeNumber(counters.repeatedOffenderSignals, 0)],
    ["Lockdown triggers", safeNumber(counters.lockdownTriggers, 0)],
    ["High-risk state signals", safeNumber(counters.highRiskStateSignals, 0)],
    ["Route pressure signals", safeNumber(counters.routePressureSignals, 0)]
  ];

  for (const [label, value] of counterItems) {
    counterList.appendChild(createKvRow(label, value));
  }
}

function renderMetrics(metrics) {
  warningCount.textContent = String(
    safeNumber(metrics?.eventCounts?.bySeverity?.warning, 0)
  );
  criticalCount.textContent = String(
    safeNumber(metrics?.eventCounts?.bySeverity?.critical, 0)
  );
  unauthCount.textContent = String(
    safeNumber(metrics?.highlights?.unauthorizedAdminAttempts, 0)
  );
  containmentCount.textContent = String(
    safeNumber(metrics?.highlights?.containmentEventCount, 0)
  );

  actionBreakdown.innerHTML = "";
  const actions = metrics?.eventCounts?.byAction || {};
  const rows = [
    ["Allow", safeNumber(actions.allow, 0)],
    ["Challenge", safeNumber(actions.challenge, 0)],
    ["Throttle", safeNumber(actions.throttle, 0)],
    ["Block", safeNumber(actions.block, 0)],
    ["Contain", safeNumber(actions.contain, 0)],
    ["Observe", safeNumber(actions.observe, 0)]
  ];

  for (const [label, value] of rows) {
    actionBreakdown.appendChild(createKvRow(label, value));
  }
}

function createEventChip(text, className = "") {
  const chip = document.createElement("span");
  chip.className = `chip ${className}`.trim();
  chip.textContent = text;
  return chip;
}

function renderEvents(events) {
  eventsList.innerHTML = "";

  if (!Array.isArray(events) || events.length === 0) {
    const empty = document.createElement("div");
    empty.className = "empty";
    empty.textContent = "No security events found.";
    eventsList.appendChild(empty);
    return;
  }

  for (const event of events) {
    const card = document.createElement("div");
    card.className = "event";

    const top = document.createElement("div");
    top.className = "event-top";

    const type = document.createElement("div");
    type.className = "event-type";
    type.textContent = safeText(event?.type, "unknown_event");

    const time = document.createElement("div");
    time.className = "event-time";
    time.textContent = formatTimestamp(event?.timestamp);

    top.appendChild(type);
    top.appendChild(time);

    const meta = document.createElement("div");
    meta.className = "event-meta";
    meta.appendChild(createEventChip(`severity: ${safeText(event?.severity, "info")}`, safeText(event?.severity, "").toLowerCase()));
    meta.appendChild(createEventChip(`action: ${safeText(event?.action, "observe")}`));

    if (event?.mode) {
      meta.appendChild(createEventChip(`mode: ${safeText(event.mode)}`));
    }

    if (event?.route) {
      meta.appendChild(createEventChip(`route: ${safeText(event.route)}`));
    }

    const message = document.createElement("div");
    message.className = "event-message";
    message.textContent = safeText(event?.message, "No message");

    const reason = document.createElement("div");
    reason.className = "event-reason";
    reason.textContent = `Reason: ${safeText(event?.reason, "n/a")}`;

    card.appendChild(top);
    card.appendChild(meta);
    card.appendChild(message);
    card.appendChild(reason);

    eventsList.appendChild(card);
  }
}

async function fetchProtectedJson(path, adminKey) {
  const response = await fetch(path, {
    method: "GET",
    headers: {
      "x-security-admin-key": adminKey
    }
  });

  let data = null;
  try {
    data = await response.json();
  } catch {
    data = null;
  }

  if (!response.ok) {
    throw new Error(data?.error || `Request failed for ${path}`);
  }

  return data;
}

async function loadDashboard() {
  const adminKey = adminKeyInput.value.trim();

  if (!adminKey) {
    setStatus("Enter the security admin key first.", true);
    return;
  }

  setStatus("Loading dashboard data...");

  refreshBtn.disabled = true;
  saveKeyBtn.disabled = true;

  try {
    const [status, eventsData, metrics] = await Promise.all([
      fetchProtectedJson("/api/security-status", adminKey),
      fetchProtectedJson("/api/security-events?limit=50", adminKey),
      fetchProtectedJson("/api/security-metrics?limit=100", adminKey)
    ]);

    renderStatus(status);
    renderMetrics(metrics);
    renderEvents(eventsData?.events || []);

    setStatus(
      `Dashboard updated successfully. Last refresh: ${new Date().toLocaleTimeString()}`
    );
  } catch (error) {
    console.error(error);
    setStatus(`Failed to load dashboard: ${error.message || "unknown_error"}`, true);
  } finally {
    refreshBtn.disabled = false;
    saveKeyBtn.disabled = false;
  }
}

function init() {
  const savedKey = getSavedAdminKey();
  if (savedKey) {
    adminKeyInput.value = savedKey;
  }

  saveKeyBtn.addEventListener("click", () => {
    const key = adminKeyInput.value.trim();
    saveAdminKey(key);
    setStatus(key ? "Admin key saved locally in this browser." : "Admin key cleared.");
  });

  refreshBtn.addEventListener("click", () => {
    loadDashboard();
  });

  adminKeyInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      loadDashboard();
    }
  });

  if (savedKey) {
    loadDashboard();
  }
}

init();
