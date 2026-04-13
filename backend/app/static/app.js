const form = document.getElementById("scanForm");
const targetInput = document.getElementById("target");
const statusIndicator = document.getElementById("statusIndicator");
const statusText = document.getElementById("statusText");
const progressBar = document.getElementById("progressBar");
const progressValue = document.getElementById("progressValue");
const progressMessage = document.getElementById("progressMessage");
const subdomainsList = document.getElementById("subdomainsList");
const sslIssuer = document.getElementById("sslIssuer");
const sslExpiry = document.getElementById("sslExpiry");
const sslGrade = document.getElementById("sslGrade");
const sslWarning = document.getElementById("sslWarning");
const directoriesList = document.getElementById("directoriesList");
const techList = document.getElementById("techList");
const downloadJsonBtn = document.getElementById("downloadJson");
const downloadPdfBtn = document.getElementById("downloadPdf");
const subdomainCount = document.getElementById("subdomainCount");
const pathsScanned = document.getElementById("pathsScanned");
const reliabilityScore = document.getElementById("reliabilityScore");
const reliabilityBar = document.getElementById("reliabilityBar");
const consoleLog = document.getElementById("consoleLog");
const vulnCount = document.getElementById("vulnCount");
const vulnList = document.getElementById("vulnList");

let activeJobId = null;
let activePentestId = null;
let pollTimer = null;
let pentestPollTimer = null;
let lastMessage = "";

function stamp() {
  return new Date().toLocaleTimeString("en-GB", { hour12: false });
}

function appendLog(message, level = "default") {
  const line = document.createElement("p");
  line.className = `console-line console-line-${level}`;
  line.textContent = `[${stamp()}] ${String(message).toUpperCase()}`;
  consoleLog.appendChild(line);
  while (consoleLog.children.length > 18) {
    consoleLog.removeChild(consoleLog.firstChild);
  }
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
  subdomainsList.innerHTML = '<li class="empty-row">Awaiting scan results.</li>';
  directoriesList.innerHTML = '<li class="empty-row">Awaiting scan results.</li>';
  techList.innerHTML = '<div class="empty-row">Awaiting scan results.</div>';
  subdomainCount.textContent = "0 FOUND";
  pathsScanned.textContent = "0";
  sslIssuer.textContent = "Pending";
  sslExpiry.textContent = "-";
  sslGrade.textContent = "-";
  sslWarning.textContent = "No TLS findings yet.";
  sslWarning.classList.remove("warning-box-ok");
  reliabilityScore.textContent = "0%";
  reliabilityBar.style.width = "0%";
  downloadJsonBtn.classList.add("hidden");
  downloadPdfBtn.classList.add("hidden");
  downloadJsonBtn.removeAttribute("href");
  downloadPdfBtn.removeAttribute("href");
  vulnCount.textContent = "0 FOUND";
  vulnList.innerHTML = '<li class="empty-row">Awaiting deep scan results.</li>';
}

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

function renderDirectories(items, totalScanned) {
  directoriesList.innerHTML = "";
  pathsScanned.textContent = String(totalScanned || 0);
  if (!items.length) {
    directoriesList.innerHTML = '<li class="empty-row">No notable endpoints discovered.</li>';
    return;
  }
  for (const item of items) {
    const row = document.createElement("li");
    row.className = "endpoint-row";
    const status = item.status || "-";
    const method = item.method || item.location || "GET";
    row.innerHTML = `<span class="status-pill status-${status}">${status}</span><span class="endpoint-path"></span><span class="endpoint-method"></span>`;
    row.querySelector(".endpoint-path").textContent = item.path || "-";
    row.querySelector(".endpoint-method").textContent = method;
    directoriesList.appendChild(row);
  }
}

function techClass(category) {
  const value = String(category || "").toLowerCase();
  if (value.includes("server")) return "tag-orange";
  if (value.includes("framework")) return "tag-cyan";
  if (value.includes("database")) return "tag-green";
  if (value.includes("os")) return "tag-red";
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
    block.querySelector(".tech-tag").textContent = item.name || "Unknown";
    techList.appendChild(block);
  }
}

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
  const issues = (ssl && ssl.issues) || [];
  sslGrade.textContent = sslGradeValue(ssl);
  sslIssuer.textContent = certificate.issuer || "Unavailable";
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
  if (!ssl || !ssl.reachable) {
    return Math.min(55, technologies.length * 8 + subdomains.length * 2);
  }
  const penalty = Math.min(((ssl.issues || []).length || 0) * 8, 24);
  const raw = 58 + Math.min(subdomains.length * 2, 16) + Math.min(directories.length, 14) + Math.min(technologies.length * 4, 20) - penalty;
  return Math.max(0, Math.min(99, raw));
}

function renderResult(result) {
  const subdomains = result.subdomains?.live_subdomains || [];
  const directoriesPayload = result.directories || {};
  const directories = directoriesPayload.findings || [];
  const technologies = result.technologies?.technologies || [];
  const ssl = result.ssl || {};
  renderSubdomains(subdomains);
  renderDirectories(directories, directoriesPayload.paths_tested || 0);
  renderTechnologies(technologies);
  renderSsl(ssl);
  const reliability = reliabilityValue(subdomains, directories, technologies, ssl);
  reliabilityScore.textContent = `${reliability}%`;
  reliabilityBar.style.width = `${reliability}%`;
  appendLog(`Subdomains identified: ${subdomains.length}`, "success");
  appendLog(`Endpoints discovered: ${directories.length}`, "default");
  appendLog(`Technologies fingerprinted: ${technologies.length}`, "cyan");
  appendLog(`SSL grade assigned: ${sslGrade.textContent}`, ssl.reachable ? "success" : "error");
  if (activeJobId) {
    const ptQuery = activePentestId ? `?pentest_id=${activePentestId}` : "";
    downloadJsonBtn.href = `/api/v1/recon/export/${activeJobId}${ptQuery}`;
    downloadPdfBtn.href = `/api/v1/recon/export/pdf/${activeJobId}${ptQuery}`;
    downloadJsonBtn.classList.remove("hidden");
    downloadPdfBtn.classList.remove("hidden");
  }
}

function renderVulnerabilities(findings) {
  vulnCount.textContent = `${findings.length} FOUND`;
  vulnList.innerHTML = "";
  if (!findings.length) {
    vulnList.innerHTML = '<li class="empty-row">No vulnerabilities discovered yet.</li>';
    return;
  }
  for (const item of findings) {
    const row = document.createElement("li");
    row.className = "endpoint-row";
    row.style.display = "flex";
    row.style.gap = "1rem";
    row.style.alignItems = "center";
    
    let color = "#888";
    if (item.risk_level === "critical") color = "#f43f5e";
    if (item.risk_level === "high") color = "#f97316";
    if (item.risk_level === "medium") color = "#eab308";
    if (item.risk_level === "low") color = "#0ea5e9";
    
    row.innerHTML = `<span class="status-pill" style="background: ${color}20; color: ${color}; border: 1px solid ${color}40">${(item.risk_level || "unknown").toUpperCase()}</span><span class="endpoint-path" style="flex:1;"></span><span class="endpoint-method" style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#94a3b8;font-size:0.8rem;"></span>`;
    row.querySelector(".endpoint-path").textContent = item.title || "Unknown Issue";
    row.querySelector(".endpoint-method").textContent = item.description || "";
    vulnList.appendChild(row);
  }
}

async function pollPentestStatus() {
  if (!activePentestId) return;
  try {
    const response = await fetch(`/api/v1/scans/${activePentestId}`);
    const payload = await response.json();
    if (!response.ok) return;

    if (payload.findings && payload.findings.length > 0) {
      renderVulnerabilities(payload.findings);
    }
    
    if (activeJobId && activePentestId) {
       downloadJsonBtn.href = `/api/v1/recon/export/${activeJobId}?pentest_id=${activePentestId}`;
       downloadPdfBtn.href = `/api/v1/recon/export/pdf/${activeJobId}?pentest_id=${activePentestId}`;
    }

    if (payload.status === "completed" || payload.status === "failed" || payload.status === "cancelled") {
      clearInterval(pentestPollTimer);
      pentestPollTimer = null;
      if (payload.status === "completed") {
         appendLog("Deep penetration test completed.", "success");
         if (!payload.findings || payload.findings.length === 0) {
           vulnList.innerHTML = '<li class="empty-row" style="color: #10b981;"><span class="material-symbols-outlined" style="vertical-align: middle; margin-right: 8px;">check_circle</span>No vulnerabilities discovered during deep scan. System appears secure.</li>';
         }
      } else {
         appendLog(`Deep scan ${payload.status}.`, "error");
         if (!payload.findings || payload.findings.length === 0) {
           vulnList.innerHTML = `<li class="empty-row" style="color: #f43f5e;"><span class="material-symbols-outlined" style="vertical-align: middle; margin-right: 8px;">error</span>Deep scan ${payload.status} before findings could be extracted.</li>`;
         }
      }
    }
  } catch (error) {
    // Silent fail for pentest parallel track
  }
}

async function pollStatus() {
  if (!activeJobId) return;
  try {
    const response = await fetch(`/api/v1/recon/status/${activeJobId}`);
    const payload = await response.json();
    if (!response.ok) {
      setStatus(false, "SYSTEM ERROR");
      setProgress(0, payload.error || "Unable to fetch scan status.");
      appendLog(payload.error || "Unable to fetch scan status.", "error");
      return;
    }
    setProgress(payload.progress || 0, payload.message || "Scanning...");
    setStatus(payload.status === "running" || payload.status === "queued", (payload.status_label || payload.status || "").toUpperCase());
    if (payload.message && payload.message !== lastMessage) {
      appendLog(payload.message, payload.status === "failed" ? "error" : "default");
      lastMessage = payload.message;
    }
    if (payload.status === "completed" || payload.status === "failed") {
      clearInterval(pollTimer);
      pollTimer = null;
      setStatus(false, payload.status === "completed" ? "SYSTEM READY" : "SYSTEM ERROR");
      if (payload.result) {
        renderResult(payload.result);
        setProgress(100, payload.status === "completed" ? "Scan completed." : "Scan finished with errors.");
      }
      for (const error of payload.errors || []) {
        appendLog(error, "error");
      }
    }
  } catch (error) {
    setStatus(false, "SYSTEM ERROR");
    setProgress(0, `Network error: ${error.message}`);
    appendLog(`Network error: ${error.message}`, "error");
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const target = targetInput.value.trim();
  if (!target) return;
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
  activeJobId = null;
  activePentestId = null;
  lastMessage = "";
  resetUi();
  setStatus(true, "SCAN ACTIVE");
  setProgress(1, "Dispatching scan request...");
  appendLog(`Starting recon on target: ${target}`, "cyan");
  try {
    const response = await fetch("/api/v1/recon/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
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
    setProgress(5, "Scan initialized.");

    // -----------------------------------
    // Accelerate deep pentest initialization
    // -----------------------------------
    appendLog(`Initializing deep penetrative assessment engine...`, "cyan");
    
    // Visual indication that deep scan is running:
    const styleString = "color: #0ea5e9; display: flex; align-items: center; justify-content: center; opacity: 0.8; animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;";
    vulnList.innerHTML = `<li class="empty-row scanning-indicator" style="${styleString}"><span class="material-symbols-outlined" style="margin-right: 8px; animation: spin 2s linear infinite;">radar</span>Executing deep penetrative payloads and active fuzzing...</li>`;
    
    // Ensure pulse/spin CSS exists
    if (!document.getElementById("dynamic-scan-styles")) {
      const sheet = document.createElement('style');
      sheet.id = "dynamic-scan-styles";
      sheet.innerHTML = "@keyframes spin { 100% { transform: rotate(360deg); } } @keyframes pulse { 50% { opacity: 0.4; } }";
      document.head.appendChild(sheet);
    }
    
    const ptPromise = fetch("/api/v1/scans/", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target_url: target.startsWith("http") ? target : "https://" + target,
        scan_type: "standard",
        authorization_acknowledged: true,
        scope_statement: "Authorized pentest via CORSUS portal for " + target
      }),
    });
    const ptResponse = await ptPromise;
    const ptPayload = await ptResponse.json();
    if (ptResponse.ok && ptPayload.scan_id) {
       activePentestId = ptPayload.scan_id;
       appendLog(`Deep Assessment active: ${activePentestId}`, "success");
       pentestPollTimer = setInterval(pollPentestStatus, 2000);
       pollPentestStatus(); // non-blocking fetch
    } else {
       const errMsg = ptPayload.detail || ptPayload.error || "Unknown initialization failure";
       appendLog(`Deep Assessment engine warning: ${JSON.stringify(errMsg)}`, "error");
       vulnList.innerHTML = `<li class="empty-row" style="color: #f43f5e;"><span class="material-symbols-outlined" style="vertical-align: middle; margin-right: 8px;">error</span>Deep scan failed to start: ${JSON.stringify(errMsg)}</li>`;
    }

    pollTimer = setInterval(pollStatus, 1000);
    pollStatus(); // non-blocking fetch

  } catch (error) {
    setStatus(false, "SYSTEM ERROR");
    setProgress(0, `Request failed: ${error.message}`);
    appendLog(`Request failed: ${error.message}`, "error");
  }
});
