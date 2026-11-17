/* ──────────────────────────────────────────────
   WeppenTest UI  –  app.js
   ────────────────────────────────────────────── */

// ── DOM refs ──────────────────────────────────
const form             = document.getElementById("scanForm");
const targetInput      = document.getElementById("target");
const statusIndicator  = document.getElementById("statusIndicator");
const statusText       = document.getElementById("statusText");
const progressBar      = document.getElementById("progressBar");
const progressValue    = document.getElementById("progressValue");
const progressMessage  = document.getElementById("progressMessage");
const subdomainsList   = document.getElementById("subdomainsList");
const sslIssuer        = document.getElementById("sslIssuer");
const sslExpiry        = document.getElementById("sslExpiry");
const sslGrade         = document.getElementById("sslGrade");
const sslWarning       = document.getElementById("sslWarning");
const directoriesList  = document.getElementById("directoriesList");
const techList         = document.getElementById("techList");
const downloadJsonBtn  = document.getElementById("downloadJson");
const downloadPdfBtn   = document.getElementById("downloadPdf");
const subdomainCount   = document.getElementById("subdomainCount");
const pathsScanned     = document.getElementById("pathsScanned");
const reliabilityScore = document.getElementById("reliabilityScore");
const reliabilityBar   = document.getElementById("reliabilityBar");
const consoleLog       = document.getElementById("consoleLog");
const vulnCount        = document.getElementById("vulnCount");
const vulnList         = document.getElementById("vulnList");
const apiKeyInput      = document.getElementById("apiKey");
const arsenalToolList  = document.getElementById("arsenalToolList");
const arsenalCategories = document.getElementById("arsenalCategories");

const API_KEY_STORAGE  = "weppentest_api_key";
const API_KEY_HEADER   = "X-API-Key";

// ── State ─────────────────────────────────────
let activeJobId       = null;
let activePentestId   = null;
let pollTimer         = null;
let pentestPollTimer  = null;
let lastMessage       = "";
let reconDone         = false;
let pentestDone       = false;

// Findings/endpoints pagination + filter state
const EP_PAGE_SIZE    = 30;
const VU_PAGE_SIZE    = 20;
let allEndpoints      = [];
let endpointPage      = 1;
let endpointFilter    = "";

let allFindings       = [];
let findingPage       = 1;
let findingRisk       = "all";
let findingTool       = "all";
let findingSearch     = "";

if (apiKeyInput) {
  const storedKey = localStorage.getItem(API_KEY_STORAGE);
  if (storedKey) apiKeyInput.value = storedKey;
  apiKeyInput.addEventListener("input", persistApiKey);
  apiKeyInput.addEventListener("change", loadArsenalStatus);
}

async function loadArsenalStatus() {
  if (!arsenalToolList) return;
  try {
    const headers = {};
    const key = apiKeyInput?.value?.trim() || localStorage.getItem(API_KEY_STORAGE);
    if (key) headers[API_KEY_HEADER] = key;
    const response = await fetch("/api/v1/tools/arsenal", { headers });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const tools = await response.json();
    const categories = [...new Set(tools.map((tool) => tool.category))].sort();
    if (arsenalCategories) arsenalCategories.textContent = categories.join(" · ");
    const fragment = document.createDocumentFragment();
    tools.forEach((tool) => {
      const item = document.createElement("li");
      item.className = "result-row";
      const label = document.createElement("span");
      label.textContent = `${tool.name} · ${tool.category}`;
      const state = document.createElement("span");
      state.textContent = tool.installed ? "READY" : "OPTIONAL / NOT INSTALLED";
      item.append(label, state);
      fragment.appendChild(item);
    });
    arsenalToolList.replaceChildren(fragment);
  } catch (error) {
    arsenalToolList.replaceChildren(Object.assign(document.createElement("li"), {
      className: "empty-row", textContent: `Could not load tool status: ${error.message}`,
    }));
  }
}
loadArsenalStatus();

if (downloadJsonBtn) {
  downloadJsonBtn.addEventListener("click", async (event) => {
    if (!downloadJsonBtn.dataset.href) return;
    event.preventDefault();
    try {
      await downloadWithKey(downloadJsonBtn.dataset.href, "recon.json");
    } catch (error) {
      appendLog(error.message, "error");
    }
  });
}

if (downloadPdfBtn) {
  downloadPdfBtn.addEventListener("click", async (event) => {
    if (!downloadPdfBtn.dataset.href) return;
    event.preventDefault();
    try {
      await downloadWithKey(downloadPdfBtn.dataset.href, "recon.pdf");
    } catch (error) {
      appendLog(error.message, "error");
    }
  });
}

// ── Helpers ───────────────────────────────────
function stamp() {
  return new Date().toLocaleTimeString("en-GB", { hour12: false });
}

function getApiKey() {
  if (apiKeyInput) return apiKeyInput.value.trim();
  return localStorage.getItem(API_KEY_STORAGE) || "";
}

function persistApiKey() {
  if (!apiKeyInput) return;
  const value = apiKeyInput.value.trim();
  if (value) {
    localStorage.setItem(API_KEY_STORAGE, value);
  } else {
    localStorage.removeItem(API_KEY_STORAGE);
  }
}

function buildHeaders(withJson = false) {
  const headers = {};
  if (withJson) headers["Content-Type"] = "application/json";
  const apiKey = getApiKey();
  if (apiKey) headers[API_KEY_HEADER] = apiKey;
  return headers;
}

async function downloadWithKey(url, fallbackName) {
  const response = await fetch(url, { headers: buildHeaders() });
  if (!response.ok) {
    throw new Error(`Download failed (${response.status})`);
  }

  const blob = await response.blob();
  const disposition = response.headers.get("content-disposition") || "";
  const match = disposition.match(/filename="?([^";]+)"?/i);
  const filename = match ? match[1] : fallbackName;
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  URL.revokeObjectURL(link.href);
  link.remove();
}

function appendLog(message, level = "default") {
  const line = document.createElement("p");
  line.className = `console-line console-line-${level}`;
  line.textContent = `[${stamp()}] ${String(message).toUpperCase()}`;
  consoleLog.appendChild(line);
  while (consoleLog.children.length > 18) consoleLog.removeChild(consoleLog.firstChild);
  consoleLog.scrollTop = consoleLog.scrollHeight;
}

function setProgress(percent, message) {
  const value = Math.max(0, Math.min(100, Number(percent) || 0));
  progressBar.style.width = `${value}%`;
  progressValue.textContent = `${value}%`;
  progressMessage.textContent = message || "Scanning...";
}

function setStatus(isRunning, label) {
  statusIndicator.classList.toggle("idle", !isRunning);
  statusIndicator.classList.toggle("active", isRunning);
  statusText.textContent = label || (isRunning ? "SCAN ACTIVE" : "SYSTEM READY");
}

function resetUi() {
  subdomainsList.innerHTML  = '<li class="empty-row">Awaiting scan results.</li>';
  directoriesList.innerHTML = '<li class="empty-row">Awaiting scan results.</li>';
  techList.innerHTML        = '<div class="empty-row">Awaiting scan results.</div>';
  subdomainCount.textContent = "0 FOUND";
  pathsScanned.textContent   = "0";
  sslIssuer.textContent      = "Pending";
  sslExpiry.textContent      = "-";
  sslGrade.textContent       = "-";
  sslWarning.textContent     = "No TLS findings yet.";
  sslWarning.classList.remove("warning-box-ok");
  reliabilityScore.textContent = "0%";
  reliabilityBar.style.width   = "0%";
  downloadJsonBtn.classList.add("hidden");
  downloadPdfBtn.classList.add("hidden");
  downloadJsonBtn.removeAttribute("href");
  downloadPdfBtn.removeAttribute("href");
  downloadJsonBtn.removeAttribute("data-href");
  downloadPdfBtn.removeAttribute("data-href");
  vulnCount.textContent = "0 FOUND";
  vulnList.innerHTML    = '<li class="empty-row">Awaiting deep scan results.</li>';
  allEndpoints  = []; endpointPage = 1; endpointFilter = "";
  allFindings   = []; findingPage  = 1;
  findingRisk   = "all"; findingTool = "all"; findingSearch = "";
}

// ── Progress bridging ─────────────────────────
// Recon uses  0–50 %, pentest uses 50–100 %
function reconProgress(raw)   { return Math.round((raw  || 0) * 0.5); }
function pentestProgress(raw) { return 50 + Math.round((raw || 0) * 0.5); }

// ── Subdomains ────────────────────────────────
function renderSubdomains(items) {
  subdomainsList.innerHTML = "";
  subdomainCount.textContent = `${items.length} FOUND`;
  if (!items.length) {
    subdomainsList.innerHTML = '<li class="empty-row">No live subdomains discovered.</li>';
    return;
  }
  for (const item of items) {
    const row = document.createElement("li");
    row.className = "result-row";
    row.innerHTML = '<div class="row-main"><span class="row-dot"></span><span class="row-value"></span></div><span class="row-meta">LIVE</span>';
    row.querySelector(".row-value").textContent = item;
    subdomainsList.appendChild(row);
  }
}

// ── Endpoints (paginated + filtered) ─────────
function buildEndpointControls() {
  const wrap = document.createElement("div");
  wrap.id = "ep-controls";
  wrap.style.cssText = "display:flex;gap:8px;margin-bottom:8px;flex-wrap:wrap;align-items:center;";

  const search = document.createElement("input");
  search.type = "text";
  search.placeholder = "Filter path…";
  search.style.cssText = "background:#0a0e14;color:#e5fdff;border:1px solid rgba(0,245,255,.25);border-radius:4px;padding:4px 8px;font-size:.75rem;flex:1;min-width:120px;outline:none;";
  search.addEventListener("input", () => { endpointFilter = search.value.trim().toLowerCase(); endpointPage = 1; renderEndpointPage(); });
  wrap.appendChild(search);
  return wrap;
}

function renderEndpointPage() {
  const filtered = allEndpoints.filter(e =>
    !endpointFilter || (e.path || "").toLowerCase().includes(endpointFilter)
  );
  const total = filtered.length;
  const pages = Math.max(1, Math.ceil(total / EP_PAGE_SIZE));
  endpointPage = Math.min(endpointPage, pages);
  const slice = filtered.slice((endpointPage - 1) * EP_PAGE_SIZE, endpointPage * EP_PAGE_SIZE);

  // Remove old rows + pagination; keep controls
  directoriesList.querySelectorAll(".endpoint-row, .ep-pagination").forEach(n => n.remove());

  if (!slice.length) {
    const empty = document.createElement("li");
    empty.className = "empty-row";
    empty.textContent = total ? "No endpoints match filter." : "No notable endpoints discovered.";
    directoriesList.appendChild(empty);
  } else {
    for (const item of slice) {
      const row = document.createElement("li");
      row.className = "endpoint-row";
      const statusText = String(item.status || "-");
      const statusClass = String(item.status || "")
        .replace(/[^0-9]/g, "")
        .trim() || "unknown";
      const method = item.method || item.location || "GET";
      const pill = document.createElement("span");
      pill.className = `status-pill status-${statusClass}`;
      pill.textContent = statusText;

      const path = document.createElement("span");
      path.className = "endpoint-path";
      path.textContent = item.path || "-";

      const methodEl = document.createElement("span");
      methodEl.className = "endpoint-method";
      methodEl.textContent = method;

      row.appendChild(pill);
      row.appendChild(path);
      row.appendChild(methodEl);
      directoriesList.appendChild(row);
    }
  }

  if (pages > 1) {
    const pag = document.createElement("li");
    pag.className = "ep-pagination";
    pag.style.cssText = "display:flex;align-items:center;justify-content:flex-end;gap:6px;padding:6px 4px;list-style:none;";
    pag.innerHTML = `
      <button id="ep-prev" style="background:#0a0e14;color:#0ef;border:1px solid rgba(0,245,255,.25);border-radius:3px;padding:2px 8px;cursor:pointer;font-size:.7rem;" ${endpointPage<=1?"disabled":""}>◀</button>
      <span style="font-size:.72rem;color:#94a3b8;">${endpointPage}/${pages} &nbsp;(${total})</span>
      <button id="ep-next" style="background:#0a0e14;color:#0ef;border:1px solid rgba(0,245,255,.25);border-radius:3px;padding:2px 8px;cursor:pointer;font-size:.7rem;" ${endpointPage>=pages?"disabled":""}>▶</button>`;
    pag.querySelector("#ep-prev").addEventListener("click", () => { endpointPage--; renderEndpointPage(); });
    pag.querySelector("#ep-next").addEventListener("click", () => { endpointPage++; renderEndpointPage(); });
    directoriesList.appendChild(pag);
  }
}

function renderDirectories(items, totalScanned, totalPlanned) {
  allEndpoints = Array.isArray(items) ? items : [];
  endpointPage = 1;
  const scanned = Number(totalScanned) || 0;
  const planned = Number(totalPlanned) || 0;
  pathsScanned.textContent = planned > scanned ? `${scanned}/${planned}` : String(scanned);

  directoriesList.innerHTML = "";

  if (allEndpoints.length > EP_PAGE_SIZE) {
    const ctrl = buildEndpointControls();
    // Wrap in a list item so it sits in the <ul>
    const ctrlLi = document.createElement("li");
    ctrlLi.style.listStyle = "none";
    ctrlLi.appendChild(ctrl);
    directoriesList.appendChild(ctrlLi);
  }

  renderEndpointPage();
}

// ── Technologies ──────────────────────────────
function techClass(category) {
  const v = String(category || "").toLowerCase();
  if (v.includes("server"))    return "tag-orange";
  if (v.includes("framework")) return "tag-cyan";
  if (v.includes("database"))  return "tag-green";
  if (v.includes("os"))        return "tag-red";
  return "tag-muted";
}

function renderTechnologies(items) {
  techList.innerHTML = "";
  if (!items.length) {
    techList.innerHTML = '<div class="empty-row">No technologies identified.</div>';
    return;
  }
  for (const item of items) {
    const block = document.createElement("div");
    block.className = "tech-item";
    block.innerHTML = `<span class="tech-label"></span><div class="tech-tag ${techClass(item.category)}"></div>`;
    block.querySelector(".tech-label").textContent = item.category || "Unknown";
    block.querySelector(".tech-tag").textContent   = item.name     || "Unknown";
    techList.appendChild(block);
  }
}

// ── SSL ───────────────────────────────────────
function sslGradeValue(ssl) {
  if (!ssl || !ssl.reachable) return "F";
  const issues = (ssl.issues || []).length;
  if (issues === 0) return "A";
  if (issues === 1) return "B";
  if (issues === 2) return "C";
  return "D";
}

function expiryText(notAfter) {
  if (!notAfter) return "-";
  const date = new Date(notAfter);
  if (Number.isNaN(date.getTime())) return notAfter;
  const days = Math.ceil((date.getTime() - Date.now()) / 86400000);
  if (days < 0) return "Expired";
  return `${days} Days`;
}

function renderSsl(ssl) {
  const certificate = (ssl && ssl.certificate) || {};
  const issues      = (ssl && ssl.issues)      || [];
  sslGrade.textContent  = sslGradeValue(ssl);
  sslIssuer.textContent = certificate.issuer  || "Unavailable";
  sslExpiry.textContent = expiryText(certificate.not_after);
  if (ssl && ssl.reachable && !issues.length) {
    sslWarning.textContent = "No critical TLS findings detected.";
    sslWarning.classList.add("warning-box-ok");
  } else if (issues.length) {
    sslWarning.textContent = issues[0];
    sslWarning.classList.remove("warning-box-ok");
  } else {
    sslWarning.textContent = "TLS endpoint not reachable.";
    sslWarning.classList.remove("warning-box-ok");
  }
}

function reliabilityValue(subdomains, directories, technologies, ssl) {
  if (!ssl || !ssl.reachable)
    return Math.min(55, technologies.length * 8 + subdomains.length * 2);
  const penalty = Math.min(((ssl.issues || []).length || 0) * 8, 24);
  const raw = 58 + Math.min(subdomains.length * 2, 16) + Math.min(directories.length, 14)
            + Math.min(technologies.length * 4, 20) - penalty;
  return Math.max(0, Math.min(99, raw));
}

function renderResult(result) {
  const subdomains        = result.subdomains?.live_subdomains || [];
  const directoriesPayload = result.directories || {};
  const directories       = directoriesPayload.findings || [];
  const technologies      = result.technologies?.technologies || [];
  const ssl               = result.ssl || {};
  renderSubdomains(subdomains);
  renderDirectories(directories, directoriesPayload.paths_tested || 0, directoriesPayload.paths_planned || 0);
  renderTechnologies(technologies);
  renderSsl(ssl);
  const reliability = reliabilityValue(subdomains, directories, technologies, ssl);
  reliabilityScore.textContent = `${reliability}%`;
  reliabilityBar.style.width   = `${reliability}%`;
  appendLog(`Subdomains identified: ${subdomains.length}`, "success");
  appendLog(`Endpoints discovered: ${directories.length}`, "default");
  appendLog(`Technologies fingerprinted: ${technologies.length}`, "cyan");
  appendLog(`SSL grade assigned: ${sslGrade.textContent}`, ssl.reachable ? "success" : "error");
  if (activeJobId) {
    const ptQuery = activePentestId ? `?pentest_id=${activePentestId}` : "";
    const jsonUrl = `/api/v1/recon/export/${activeJobId}${ptQuery}`;
    const pdfUrl = `/api/v1/recon/export/pdf/${activeJobId}${ptQuery}`;
    downloadJsonBtn.dataset.href = jsonUrl;
    downloadPdfBtn.dataset.href = pdfUrl;
    downloadJsonBtn.href = jsonUrl;
    downloadPdfBtn.href = pdfUrl;
    downloadJsonBtn.classList.remove("hidden");
    downloadPdfBtn.classList.remove("hidden");
  }
}

// ── Findings (paginated + filtered) ──────────
const riskOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function riskColor(level) {
  const v = String(level || "").toLowerCase();
  if (v === "critical") return "#f43f5e";
  if (v === "high")     return "#f97316";
  if (v === "medium")   return "#eab308";
  if (v === "low")      return "#0ea5e9";
  return "#94a3b8";
}

function findingDebugPayload(item) {
  return {
    id: item.id, risk_level: item.risk_level, tool_name: item.tool_name,
    affected_url: item.affected_url, cwe_id: item.cwe_id, cvss_score: item.cvss_score,
    verification_status: item.verification_status, confidence_score: item.confidence_score,
    detection_method: item.detection_method, sources: item.sources,
    found_at: item.found_at, description: item.description,
    recommendation: item.recommendation, evidence: item.evidence,
  };
}

function buildFindingControls(findings) {
  const tools = [...new Set(findings.map(f => f.tool_name).filter(Boolean))].sort();

  const wrap = document.createElement("div");
  wrap.id = "vu-controls";
  wrap.style.cssText = "display:flex;gap:8px;margin-bottom:10px;flex-wrap:wrap;align-items:center;";

  // Search
  const search = document.createElement("input");
  search.type = "text";
  search.placeholder = "Search findings…";
  search.value = findingSearch;
  search.style.cssText = "background:#0a0e14;color:#e5fdff;border:1px solid rgba(0,245,255,.25);border-radius:4px;padding:4px 8px;font-size:.75rem;flex:1;min-width:140px;outline:none;";
  search.addEventListener("input", () => { findingSearch = search.value.trim().toLowerCase(); findingPage = 1; renderFindingPage(); });
  wrap.appendChild(search);

  // Risk filter
  const riskSel = document.createElement("select");
  riskSel.style.cssText = "background:#0a0e14;color:#e5fdff;border:1px solid rgba(0,245,255,.25);border-radius:4px;padding:4px 6px;font-size:.75rem;outline:none;cursor:pointer;";
  [["all","All Risks"],["critical","Critical"],["high","High"],["medium","Medium"],["low","Low"],["info","Info"]].forEach(([val,lbl]) => {
    const opt = document.createElement("option");
    opt.value = val; opt.textContent = lbl;
    if (val === findingRisk) opt.selected = true;
    riskSel.appendChild(opt);
  });
  riskSel.addEventListener("change", () => { findingRisk = riskSel.value; findingPage = 1; renderFindingPage(); });
  wrap.appendChild(riskSel);

  // Tool filter
  if (tools.length > 1) {
    const toolSel = document.createElement("select");
    toolSel.style.cssText = riskSel.style.cssText;
    const allOpt = document.createElement("option");
    allOpt.value = "all"; allOpt.textContent = "All Tools";
    if (findingTool === "all") allOpt.selected = true;
    toolSel.appendChild(allOpt);
    for (const t of tools) {
      const opt = document.createElement("option");
      opt.value = t; opt.textContent = t.toUpperCase();
      if (t === findingTool) opt.selected = true;
      toolSel.appendChild(opt);
    }
    toolSel.addEventListener("change", () => { findingTool = toolSel.value; findingPage = 1; renderFindingPage(); });
    wrap.appendChild(toolSel);
  }

  // Count badge
  const countBadge = document.createElement("span");
  countBadge.id = "vu-count-badge";
  countBadge.style.cssText = "font-size:.72rem;color:#94a3b8;white-space:nowrap;";
  wrap.appendChild(countBadge);

  return wrap;
}

function renderFindingPage() {
  // Apply filters
  const filtered = allFindings
    .filter(f => findingRisk === "all" || String(f.risk_level || "").toLowerCase() === findingRisk)
    .filter(f => findingTool === "all" || f.tool_name === findingTool)
    .filter(f => {
      if (!findingSearch) return true;
      return (f.title + " " + (f.description || "") + " " + (f.affected_url || "")).toLowerCase().includes(findingSearch);
    });

  const total = filtered.length;
  const pages = Math.max(1, Math.ceil(total / VU_PAGE_SIZE));
  findingPage = Math.min(findingPage, pages);
  const slice = filtered.slice((findingPage - 1) * VU_PAGE_SIZE, findingPage * VU_PAGE_SIZE);

  // Update count badge
  const badge = document.getElementById("vu-count-badge");
  if (badge) badge.textContent = `${total} / ${allFindings.length} findings`;

  // Remove old rows + pagination; keep controls
  vulnList.querySelectorAll(".vu-row, .vu-pagination").forEach(n => n.remove());

  if (!slice.length) {
    const empty = document.createElement("li");
    empty.className = "vu-row empty-row";
    empty.textContent = allFindings.length ? "No findings match current filters." : "No vulnerabilities discovered yet.";
    vulnList.appendChild(empty);
    return;
  }

  for (const item of slice) {
    const row = document.createElement("li");
    row.className = "endpoint-row vu-row";
    row.style.cssText = "display:block;padding:12px;";

    const color = riskColor(item.risk_level);

    const details = document.createElement("details");

    const summary = document.createElement("summary");
    summary.style.cssText = "cursor:pointer;display:flex;align-items:center;gap:10px;flex-wrap:wrap;list-style:none;";
    const riskText = String(item.risk_level || "UNKNOWN").toUpperCase();
    const titleText = item.title || "Unknown Issue";
    const toolText = item.tool_name || "unknown";

    const pill = document.createElement("span");
    pill.className = "status-pill";
    pill.style.cssText = `background:${color}20;color:${color};border:1px solid ${color}40;flex-shrink:0;`;
    pill.textContent = riskText;

    const titleSpan = document.createElement("span");
    titleSpan.style.cssText = "flex:1;min-width:200px;font-weight:700;color:#e5fdff;word-break:break-word;";
    titleSpan.textContent = titleText;

    const toolSpan = document.createElement("span");
    toolSpan.style.cssText = "color:#94a3b8;font-size:.72rem;text-transform:uppercase;letter-spacing:.08em;flex-shrink:0;";
    toolSpan.textContent = toolText;

    const caret = document.createElement("span");
    caret.style.cssText = "color:#64748b;font-size:.72rem;margin-left:auto;flex-shrink:0;";
    caret.textContent = "▼";

    summary.appendChild(pill);
    summary.appendChild(titleSpan);
    summary.appendChild(toolSpan);
    summary.appendChild(caret);
    details.appendChild(summary);

    const body = document.createElement("div");
    body.style.cssText = "padding-top:10px;";

    const desc = document.createElement("p");
    desc.style.cssText = "margin:0 0 6px;white-space:pre-wrap;word-break:break-word;color:#dbe8eb;font-size:.8rem;";
    desc.textContent = item.description || "No description available.";
    body.appendChild(desc);

    const metaParts = [];
    if (item.affected_url)  metaParts.push(`URL: ${item.affected_url}`);
    if (item.cwe_id)        metaParts.push(`CWE: ${item.cwe_id}`);
    if (item.cvss_score !== null && item.cvss_score !== undefined) metaParts.push(`CVSS: ${item.cvss_score}`);
    if (item.verification_status) metaParts.push(`Verification: ${item.verification_status}`);
    if (item.found_at) metaParts.push(`Found: ${new Date(item.found_at).toLocaleString("en-GB")}`);
    if (metaParts.length) {
      const meta = document.createElement("p");
      meta.style.cssText = "margin:0 0 8px;font-size:.72rem;color:#94a3b8;word-break:break-word;";
      meta.textContent = metaParts.join(" | ");
      body.appendChild(meta);
    }

    const pre = document.createElement("pre");
    pre.style.cssText = "margin:0;padding:10px;background:rgba(10,14,20,.9);border:1px solid rgba(0,245,255,.2);color:#c8f6ff;white-space:pre-wrap;word-break:break-word;max-height:280px;overflow:auto;font-size:.7rem;";
    pre.textContent = JSON.stringify(findingDebugPayload(item), null, 2);
    body.appendChild(pre);

    details.appendChild(body);
    row.appendChild(details);
    vulnList.appendChild(row);
  }

  // Pagination
  if (pages > 1) {
    const pag = document.createElement("li");
    pag.className = "vu-pagination";
    pag.style.cssText = "display:flex;align-items:center;justify-content:flex-end;gap:6px;padding:8px 4px;list-style:none;";
    pag.innerHTML = `
      <button id="vu-prev" style="background:#0a0e14;color:#0ef;border:1px solid rgba(0,245,255,.25);border-radius:3px;padding:3px 10px;cursor:pointer;font-size:.72rem;" ${findingPage<=1?"disabled":""}>◀</button>
      <span style="font-size:.72rem;color:#94a3b8;">Page ${findingPage} / ${pages}</span>
      <button id="vu-next" style="background:#0a0e14;color:#0ef;border:1px solid rgba(0,245,255,.25);border-radius:3px;padding:3px 10px;cursor:pointer;font-size:.72rem;" ${findingPage>=pages?"disabled":""}>▶</button>`;
    pag.querySelector("#vu-prev").addEventListener("click", () => { findingPage--; renderFindingPage(); vulnList.scrollIntoView({behavior:"smooth",block:"start"}); });
    pag.querySelector("#vu-next").addEventListener("click", () => { findingPage++; renderFindingPage(); vulnList.scrollIntoView({behavior:"smooth",block:"start"}); });
    vulnList.appendChild(pag);
  }
}

function escHtml(str) {
  return String(str || "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

function renderVulnerabilities(findings) {
  const safe = Array.isArray(findings) ? findings : [];
  // Merge yeni bulgular (tekrar render'dan kaçın)
  const existing = new Set(allFindings.map(f => f.id || JSON.stringify(f)));
  let added = 0;
  for (const f of safe) {
    const key = f.id || JSON.stringify(f);
    if (!existing.has(key)) { allFindings.push(f); existing.add(key); added++; }
  }
  if (added === 0 && allFindings.length === safe.length) {
    // Aynen aynıysa sadece page yenile
  }
  // Severity sırala
  allFindings.sort((a, b) =>
    (riskOrder[String(a.risk_level||"info").toLowerCase()] ?? 99) -
    (riskOrder[String(b.risk_level||"info").toLowerCase()] ?? 99)
  );

  vulnCount.textContent = `${allFindings.length} FOUND`;

  // Kontrolleri ilk seferinde oluştur
  if (!document.getElementById("vu-controls")) {
    vulnList.innerHTML = "";
    const ctrlLi = document.createElement("li");
    ctrlLi.style.listStyle = "none";
    ctrlLi.appendChild(buildFindingControls(allFindings));
    vulnList.insertBefore(ctrlLi, vulnList.firstChild);
  } else {
    // Araç filtresi güncel araçlarla yeniden oluştur
    const ctrlLi = document.getElementById("vu-controls").parentElement;
    ctrlLi.innerHTML = "";
    ctrlLi.appendChild(buildFindingControls(allFindings));
  }

  renderFindingPage();
}

// ── Detailed findings loader ──────────────────
async function loadDetailedFindings(scanId) {
  if (!scanId) return;
  try {
    const response = await fetch(`/api/v1/reports/${scanId}/detailed`, {
      headers: buildHeaders(),
    });
    if (!response.ok) return;
    const report = await response.json();
    if (Array.isArray(report.findings) && report.findings.length) {
      renderVulnerabilities(report.findings);
      appendLog(`Detailed findings loaded: ${report.findings.length}`, "success");
    }
  } catch (_) { /* silent */ }
}

// ── Pentest poll (deep scan) ──────────────────
async function pollPentestStatus() {
  if (!activePentestId) return;
  try {
    const response = await fetch(`/api/v1/scans/${activePentestId}`, {
      headers: buildHeaders(),
    });
    const payload  = await response.json();
    if (!response.ok) return;

    // Progress bar: pentest kullanır 50–100
    const progress = payload.progress || 0;
    const phase    = payload.current_phase || "";
    const tool     = payload.current_tool  || "";
    const pctLabel = pentestProgress(progress);

    if (!["completed","failed","cancelled"].includes(payload.status)) {
      const toolMsg = tool ? `${tool.toUpperCase()}` : (phase ? `PHASE: ${phase.toUpperCase()}` : "SCANNING");
      setProgress(pctLabel, `Deep scan: ${toolMsg} (${progress}%)`);
      setStatus(true, "DEEP SCAN ACTIVE");
    }

    // Findings canlı güncelle
    if (payload.findings && payload.findings.length > 0) {
      renderVulnerabilities(payload.findings);
    }

    if (activeJobId && activePentestId) {
      const jsonUrl = `/api/v1/recon/export/${activeJobId}?pentest_id=${activePentestId}`;
      const pdfUrl = `/api/v1/recon/export/pdf/${activeJobId}?pentest_id=${activePentestId}`;
      downloadJsonBtn.dataset.href = jsonUrl;
      downloadPdfBtn.dataset.href = pdfUrl;
      downloadJsonBtn.href = jsonUrl;
      downloadPdfBtn.href = pdfUrl;
    }

    if (["completed","failed","cancelled"].includes(payload.status)) {
      clearInterval(pentestPollTimer);
      pentestPollTimer = null;
      pentestDone = true;

      if (payload.status === "completed") {
        await loadDetailedFindings(activePentestId);
        appendLog("Deep penetration test completed.", "success");
        if (!allFindings.length) {
          vulnList.innerHTML = '<li class="empty-row" style="color:#10b981;"><span class="material-symbols-outlined" style="vertical-align:middle;margin-right:8px;">check_circle</span>No vulnerabilities discovered during deep scan.</li>';
        }
      } else {
        appendLog(`Deep scan ${payload.status}.`, "error");
        if (!allFindings.length) {
          vulnList.innerHTML = `<li class="empty-row" style="color:#f43f5e;"><span class="material-symbols-outlined" style="vertical-align:middle;margin-right:8px;">error</span>Deep scan ${payload.status}.</li>`;
        }
      }

      setProgress(100, payload.status === "completed" ? "All scans completed." : `Deep scan ${payload.status}.`);
      setStatus(false, payload.status === "completed" ? "SYSTEM READY" : "SYSTEM ERROR");
    }
  } catch (_) { /* silent */ }
}

// ── Recon poll ────────────────────────────────
async function pollStatus() {
  if (!activeJobId) return;
  try {
    const response = await fetch(`/api/v1/recon/status/${activeJobId}`, {
      headers: buildHeaders(),
    });
    const payload  = await response.json();
    if (!response.ok) {
      setStatus(false, "SYSTEM ERROR");
      setProgress(0, payload.error || "Unable to fetch scan status.");
      appendLog(payload.error || "Unable to fetch scan status.", "error");
      return;
    }

    // Recon progress: 0–50 %  (pentest bitmemişse 50'ye kadar)
    if (!reconDone) {
      setProgress(reconProgress(payload.progress || 0), payload.message || "Recon scanning...");
      setStatus(true, "RECON ACTIVE");
    }

    if (payload.message && payload.message !== lastMessage) {
      appendLog(payload.message, payload.status === "failed" ? "error" : "default");
      lastMessage = payload.message;
    }

    if (payload.status === "completed" || payload.status === "failed") {
      clearInterval(pollTimer);
      pollTimer  = null;
      reconDone  = true;

      if (payload.result) renderResult(payload.result);

      for (const error of payload.errors || []) appendLog(error, "error");

      // Eğer pentest hâlâ çalışıyorsa, bar kontrolü pentestPollTimer'a bırak
      if (!pentestDone && activePentestId) {
        appendLog("Reconnaissance complete. Waiting for deep scan tools (nikto, nuclei…).", "cyan");
        // pollPentestStatus progress bar'ı devralır
      } else {
        setProgress(100, payload.status === "completed" ? "Scan completed." : "Scan finished with errors.");
        setStatus(false, payload.status === "completed" ? "SYSTEM READY" : "SYSTEM ERROR");
      }
    }
  } catch (error) {
    setStatus(false, "SYSTEM ERROR");
    setProgress(0, `Network error: ${error.message}`);
    appendLog(`Network error: ${error.message}`, "error");
  }
}

// ── Form submit ───────────────────────────────
form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const target = targetInput.value.trim();
  if (!target) return;

  if (pollTimer)        { clearInterval(pollTimer);       pollTimer        = null; }
  if (pentestPollTimer) { clearInterval(pentestPollTimer); pentestPollTimer = null; }

  activeJobId     = null;
  activePentestId = null;
  reconDone       = false;
  pentestDone     = false;
  lastMessage     = "";
  resetUi();
  setStatus(true, "SCAN ACTIVE");
  setProgress(1, "Dispatching scan request...");
  appendLog(`Starting recon on target: ${target}`, "cyan");

  // Ensure animation CSS
  if (!document.getElementById("dynamic-scan-styles")) {
    const sheet = document.createElement("style");
    sheet.id = "dynamic-scan-styles";
    sheet.innerHTML = "@keyframes spin{100%{transform:rotate(360deg)}} @keyframes pulse{50%{opacity:.4}}";
    document.head.appendChild(sheet);
  }

  try {
    const response = await fetch("/api/v1/recon/start", {
      method: "POST",
      headers: buildHeaders(true),
      body: JSON.stringify({ target }),
    });
    const payload = await response.json();
    if (!response.ok) {
      setStatus(false, "SYSTEM ERROR");
      setProgress(0, payload.error || "Scan could not be started.");
      appendLog(payload.error || "Scan could not be started.", "error");
      return;
    }

    activeJobId = payload.job_id;
    appendLog(`Job queued: ${payload.job_id}`, "success");
    setProgress(2, "Scan initialized.");

    const styleString = "color:#0ea5e9;display:flex;align-items:center;justify-content:center;opacity:.8;animation:pulse 2s cubic-bezier(.4,0,.6,1) infinite;";
    vulnList.innerHTML = `<li class="empty-row scanning-indicator" style="${styleString}"><span class="material-symbols-outlined" style="margin-right:8px;animation:spin 2s linear infinite;">radar</span>Executing deep penetrative payloads and active fuzzing...</li>`;

    // Start deep pentest
    appendLog("Initializing deep penetrative assessment engine...", "cyan");
    const ptPromise  = fetch("/api/v1/scans/", {
      method: "POST",
      headers: buildHeaders(true),
      body: JSON.stringify({
        target_url: target.startsWith("http") ? target : "https://" + target,
        scan_type: "deep",
        authorization_acknowledged: true,
        scope_statement: "Authorized pentest via CORSUS portal for " + target,
      }),
    });
    const ptResponse = await ptPromise;
    const ptPayload  = await ptResponse.json();

    if (ptResponse.ok && ptPayload.scan_id) {
      activePentestId = ptPayload.scan_id;
      appendLog(`Deep Assessment active: ${activePentestId}`, "success");
      pentestPollTimer = setInterval(pollPentestStatus, 2000);
      pollPentestStatus();
    } else {
      const errMsg = ptPayload.detail || ptPayload.error || "Unknown initialization failure";
      appendLog(`Deep Assessment engine warning: ${JSON.stringify(errMsg)}`, "error");
      vulnList.innerHTML = `<li class="empty-row" style="color:#f43f5e;"><span class="material-symbols-outlined" style="vertical-align:middle;margin-right:8px;">error</span>Deep scan failed to start: ${JSON.stringify(errMsg)}</li>`;
      pentestDone = true;
    }

    pollTimer = setInterval(pollStatus, 1000);
    pollStatus();

  } catch (error) {
    setStatus(false, "SYSTEM ERROR");
    setProgress(0, `Request failed: ${error.message}`);
    appendLog(`Request failed: ${error.message}`, "error");
  }
});
