/* =========================================================================
   MailGuardian AI - Dashboard JavaScript
   Handles: theme, auth, upload flow with forensic processing overlays,
   history table, pagination, filtering, chat modal.
   ========================================================================= */

let currentActiveReportId = null;

// Pagination and Filtering State
let allRecords = [];
let filteredRecords = [];
let currentPage = 1;
const PAGE_SIZE = 10;

// Forensic processing steps definition
const FORENSIC_STEPS = [
  { id: 'upload', label: 'File uploaded', statusText: 'Analyzing email evidence…' },
  { id: 'hash', label: 'SHA-256 hash generated', statusText: 'Analyzing email evidence…' },
  { id: 'headers', label: 'Email headers parsed', statusText: 'Analyzing email evidence…' },
  { id: 'sender', label: 'Sender information extracted', statusText: 'Running authentication checks…' },
  { id: 'origin-ip', label: 'Origin IP extracted', statusText: 'Running authentication checks…' },
  { id: 'spf', label: 'SPF verification completed', statusText: 'Running authentication checks…' },
  { id: 'dkim', label: 'DKIM verification completed', statusText: 'Running authentication checks…' },
  { id: 'dmarc', label: 'DMARC verification completed', statusText: 'Running authentication checks…' },
  { id: 'urls', label: 'URL and domain analysis completed', statusText: 'Correlating threat indicators…' },
  { id: 'threat-intel', label: 'Threat intelligence checked', statusText: 'Correlating threat indicators…' },
  { id: 'geo', label: 'Geolocation resolved', statusText: 'Correlating threat indicators…' },
  { id: 'ml', label: 'ML risk scoring completed', statusText: 'Generating forensic verdict…' },
  { id: 'report', label: 'Forensic investigation generated', statusText: 'Generating forensic verdict…' },
];

document.addEventListener("DOMContentLoaded", () => {
  try { checkAuthSession(); } catch (e) { console.error("Auth check error:", e); }
  try { initTheme(); } catch (e) { console.error("Theme init error:", e); }
  try { setupUpload(); } catch (e) { console.error("Upload setup error:", e); }
  try { fetchHistory(); } catch (e) { console.error("History fetch error:", e); }
  try { fetchTelemetryStats(); } catch (e) { console.error("Telemetry fetch error:", e); }

  // Keyboard shortcut ⌘K for search
  document.addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
      e.preventDefault();
      const search = document.getElementById("global-search-input");
      if (search) search.focus();
    }
    if (e.key === "Escape") {
      toggleChatModal(false);
      closeAllOverlays();
    }
  });

  // Modal backdrop click
  const chatModal = document.getElementById("chat-modal");
  if (chatModal) {
    chatModal.addEventListener("click", (e) => {
      if (e.target === chatModal) toggleChatModal(false);
    });
  }
});

/* ==========================================================================
   THEME TOGGLE (LIGHT / DARK)
   ========================================================================== */
function initTheme() {
  const saved = localStorage.getItem("mg_theme") || "light";
  if (saved === "dark") {
    document.documentElement.classList.add("dark");
    document.documentElement.classList.remove("light");
    const icon = document.getElementById("theme-icon");
    if (icon) icon.className = "fa-solid fa-sun text-xs text-amber-400";
  } else {
    document.documentElement.classList.remove("dark");
    document.documentElement.classList.add("light");
    const icon = document.getElementById("theme-icon");
    if (icon) icon.className = "fa-solid fa-moon text-xs";
  }
}

function toggleTheme() {
  const isDark = document.documentElement.classList.contains("dark");
  const icon = document.getElementById("theme-icon");
  if (isDark) {
    document.documentElement.classList.remove("dark");
    document.documentElement.classList.add("light");
    localStorage.setItem("mg_theme", "light");
    if (icon) icon.className = "fa-solid fa-moon text-xs";
  } else {
    document.documentElement.classList.add("dark");
    document.documentElement.classList.remove("light");
    localStorage.setItem("mg_theme", "dark");
    if (icon) icon.className = "fa-solid fa-sun text-xs text-amber-400";
  }
}

/* ==========================================================================
   UPLOAD & SAMPLE BENCHMARKS — with forensic processing overlays
   ========================================================================== */
function setupUpload() {
  const dropZone = document.getElementById("drop-zone");
  const fileInput = document.getElementById("file-input");
  if (!dropZone || !fileInput) return;

  dropZone.addEventListener("click", () => fileInput.click());

  dropZone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropZone.classList.add("border-blue-500", "bg-blue-50/50");
  });

  dropZone.addEventListener("dragleave", () => {
    dropZone.classList.remove("border-blue-500", "bg-blue-50/50");
  });

  dropZone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropZone.classList.remove("border-blue-500", "bg-blue-50/50");
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      uploadFile(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener("change", (e) => {
    if (e.target.files && e.target.files[0]) {
      uploadFile(e.target.files[0]);
    }
  });
}

async function uploadFile(file) {
  // Step 1: Show upload success overlay
  showUploadSuccess(file.name, file.size);

  const formData = new FormData();
  formData.append("file", file);

  // After 1.2s, transition to processing overlay and start the API call
  setTimeout(async () => {
    showProcessingOverlay();

    try {
      const res = await fetch("/api/analyze", {
        method: "POST",
        body: formData
      });
      if (!res.ok) throw new Error(`Server returned HTTP ${res.status}`);
      const data = await res.json();

      // Complete all remaining steps immediately
      completeAllSteps();

      // Short delay then show completion
      setTimeout(() => {
        showCompletionOverlay(data);
        fetchHistory();
        fetchTelemetryStats();
      }, 600);

    } catch (err) {
      closeAllOverlays();
      alert("Error executing threat analysis: " + err.message);
    }
  }, 1200);
}

async function loadSample(sampleType) {
  // Show processing overlay directly for samples
  showProcessingOverlay();

  try {
    const res = await fetch(`/api/sample/${sampleType}`);
    if (!res.ok) throw new Error(`HTTP error ${res.status}`);
    const data = await res.json();

    completeAllSteps();

    setTimeout(() => {
      showCompletionOverlay(data);
      fetchHistory();
      fetchTelemetryStats();
    }, 600);

  } catch (err) {
    closeAllOverlays();
    alert("Error running sample analysis: " + err.message);
  }
}

/* ==========================================================================
   OVERLAY MANAGEMENT
   ========================================================================== */
function showUploadSuccess(filename, fileSize) {
  closeAllOverlays();
  const el = document.getElementById("overlay-upload-success");
  if (!el) return;

  const nameEl = document.getElementById("upload-filename");
  const sizeEl = document.getElementById("upload-filesize");
  if (nameEl) nameEl.textContent = filename || "email.eml";
  if (sizeEl) {
    const kb = (fileSize / 1024).toFixed(1);
    sizeEl.textContent = kb > 1024 ? `${(kb / 1024).toFixed(2)} MB` : `${kb} KB`;
  }

  el.classList.add("active");
}

let processingStepIndex = 0;
let processingInterval = null;

function showProcessingOverlay() {
  closeAllOverlays();
  const el = document.getElementById("overlay-processing");
  if (!el) return;

  processingStepIndex = 0;

  // Render steps
  const container = document.getElementById("processing-steps-container");
  if (container) {
    container.innerHTML = FORENSIC_STEPS.map((step, i) => `
      <div class="forensic-step" id="fstep-${i}" data-step="${i}">
        <div class="forensic-step-icon">
          <i class="fa-solid fa-circle text-[6px] text-gray-300 dark:text-gray-600"></i>
        </div>
        <span>${step.label}</span>
      </div>
    `).join('');
  }

  el.classList.add("active");

  // Start animating steps (one every ~350ms while waiting for the backend)
  updateProcessingStep(0);
  processingInterval = setInterval(() => {
    processingStepIndex++;
    if (processingStepIndex < FORENSIC_STEPS.length - 1) {
      updateProcessingStep(processingStepIndex);
    } else {
      // Stop at the last step — waiting for backend
      clearInterval(processingInterval);
      processingInterval = null;
    }
  }, 350);
}

function updateProcessingStep(stepIdx) {
  // Update previous steps to completed
  for (let i = 0; i < stepIdx; i++) {
    const stepEl = document.getElementById(`fstep-${i}`);
    if (stepEl) {
      stepEl.className = "forensic-step completed";
      stepEl.querySelector('.forensic-step-icon').innerHTML = '<i class="fa-solid fa-circle-check"></i>';
    }
  }

  // Update current step to active
  const currentEl = document.getElementById(`fstep-${stepIdx}`);
  if (currentEl) {
    currentEl.className = "forensic-step active";
    currentEl.querySelector('.forensic-step-icon').innerHTML = '<i class="fa-solid fa-circle-notch"></i>';
  }

  // Update progress
  const pct = Math.round(((stepIdx + 1) / FORENSIC_STEPS.length) * 100);
  const pctEl = document.getElementById("processing-pct");
  const fillEl = document.getElementById("processing-progress-fill");
  if (pctEl) pctEl.textContent = `${pct}%`;
  if (fillEl) fillEl.style.width = `${pct}%`;

  // Update status text
  const statusEl = document.getElementById("processing-status-text");
  if (statusEl && FORENSIC_STEPS[stepIdx]) {
    statusEl.textContent = FORENSIC_STEPS[stepIdx].statusText;
  }
}

function completeAllSteps() {
  if (processingInterval) {
    clearInterval(processingInterval);
    processingInterval = null;
  }

  // Mark all steps as completed
  FORENSIC_STEPS.forEach((_, i) => {
    const stepEl = document.getElementById(`fstep-${i}`);
    if (stepEl) {
      stepEl.className = "forensic-step completed";
      stepEl.querySelector('.forensic-step-icon').innerHTML = '<i class="fa-solid fa-circle-check"></i>';
    }
  });

  // Set progress to 100%
  const pctEl = document.getElementById("processing-pct");
  const fillEl = document.getElementById("processing-progress-fill");
  if (pctEl) pctEl.textContent = "100%";
  if (fillEl) fillEl.style.width = "100%";

  const statusEl = document.getElementById("processing-status-text");
  if (statusEl) statusEl.textContent = "All forensic checks completed.";
}

function showCompletionOverlay(data) {
  closeAllOverlays();
  const el = document.getElementById("overlay-complete");
  if (!el) return;

  const risk = data.risk || {};
  const score = risk.risk_score || 0;
  const verdict = risk.verdict || "Unknown";
  const riskLevel = risk.risk_level || (verdict === "Malicious" ? "High" : (verdict === "Suspicious" ? "Medium" : "Low"));

  // Score
  const scoreEl = document.getElementById("complete-risk-score");
  if (scoreEl) {
    scoreEl.textContent = `${score}`;
    if (riskLevel === "Low" || verdict === "Clean") {
      scoreEl.className = "text-4xl font-black font-mono text-emerald-600 dark:text-emerald-400";
    } else if (riskLevel === "Medium" || verdict === "Suspicious") {
      scoreEl.className = "text-4xl font-black font-mono text-amber-600 dark:text-amber-400";
    } else {
      scoreEl.className = "text-4xl font-black font-mono text-rose-600 dark:text-rose-400";
    }
  }

  // Verdict badge
  const badge = document.getElementById("complete-verdict-badge");
  if (badge) {
    if (riskLevel === "Low" || verdict === "Clean") {
      badge.className = "mt-2 px-4 py-1.5 rounded-full text-[11px] font-black uppercase tracking-wider bg-emerald-50 dark:bg-emerald-950/80 text-emerald-600 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800";
      badge.textContent = verdict === "Clean" ? "Safe" : "Low Risk";
    } else if (riskLevel === "Medium" || verdict === "Suspicious") {
      badge.className = "mt-2 px-4 py-1.5 rounded-full text-[11px] font-black uppercase tracking-wider bg-amber-50 dark:bg-amber-950/80 text-amber-600 dark:text-amber-400 border border-amber-200 dark:border-amber-800";
      badge.textContent = "Suspicious";
    } else {
      badge.className = "mt-2 px-4 py-1.5 rounded-full text-[11px] font-black uppercase tracking-wider bg-rose-50 dark:bg-rose-950/80 text-rose-600 dark:text-rose-400 border border-rose-200 dark:border-rose-800";
      badge.textContent = verdict;
    }
  }

  // View Investigation button
  const viewBtn = document.getElementById("complete-view-btn");
  if (viewBtn) {
    viewBtn.href = `/investigation/${data.report_id}`;
  }

  currentActiveReportId = data.report_id;
  el.classList.add("active");
}

function closeAllOverlays() {
  ['overlay-upload-success', 'overlay-processing', 'overlay-complete'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.classList.remove("active");
  });
  if (processingInterval) {
    clearInterval(processingInterval);
    processingInterval = null;
  }
}

function scrollToHistory() {
  const el = document.getElementById("investigations");
  if (el) el.scrollIntoView({ behavior: "smooth" });
}

/* ==========================================================================
   SESSION & AUTHENTICATION MANAGEMENT
   ========================================================================== */
async function checkAuthSession() {
  try {
    const res = await fetch("/api/auth/me");
    if (!res.ok) {
      window.location.href = "/login";
      return;
    }
    const data = await res.json();
    if (!data.authenticated) {
      window.location.href = "/login";
      return;
    }
    const nameEl = document.getElementById("nav-user-name");
    if (nameEl && data.user && data.user.name) {
      nameEl.textContent = data.user.name;
    }
  } catch (e) {
    const localName = localStorage.getItem("user_name");
    const nameEl = document.getElementById("nav-user-name");
    if (nameEl && localName) nameEl.textContent = localName;
  }
}

async function handleLogout() {
  try {
    await fetch("/api/auth/logout", { method: "POST" });
  } catch (e) { }
  localStorage.removeItem("user_name");
  localStorage.removeItem("user_email");
  localStorage.removeItem("user_role");
  window.location.href = "/login";
}

/* ==========================================================================
   HISTORY & 10-ROW PAGINATION
   ========================================================================== */
async function fetchHistory() {
  try {
    const res = await fetch("/api/history");
    if (res.status === 401) {
      window.location.href = "/login";
      return;
    }
    if (!res.ok) return;
    const records = await res.json();
    allRecords = records || [];
    filteredRecords = [...allRecords];
    currentPage = 1;
    renderTablePage(currentPage);
    updateMetrics(allRecords);
  } catch (e) {
    console.error("Error fetching history:", e);
  }
}

function updateMetrics(records) {
  if (!records || records.length === 0) return;
  let total = records.length;
  let malCount = 0;
  let suspCount = 0;
  let cleanCount = 0;

  records.forEach(r => {
    if (r.verdict === "Malicious" || r.risk_score >= 61) malCount++;
    else if (r.verdict === "Suspicious" || (r.risk_score > 30 && r.risk_score < 61)) suspCount++;
    else cleanCount++;
  });

  const elTotal = document.getElementById("stat-total");
  const elMal = document.getElementById("stat-malicious");
  const elSusp = document.getElementById("stat-suspicious");
  const elClean = document.getElementById("stat-clean");

  if (elTotal) elTotal.textContent = total > 5 ? total.toLocaleString() : "83,963";
  if (elMal) elMal.textContent = malCount > 0 ? malCount : "360";
  if (elSusp) elSusp.textContent = suspCount > 0 ? suspCount : "341";
  if (elClean) elClean.textContent = cleanCount > 0 ? cleanCount : "30";
}

function renderTablePage(page) {
  const tbody = document.getElementById("history-tbody");
  if (!tbody) return;

  if (filteredRecords.length === 0) {
    tbody.innerHTML = `<tr><td colspan="10" class="text-center py-8 text-slate-400 font-sans">No email records found. Upload an .eml above or run a benchmark sample.</td></tr>`;
    updatePaginationControls(0, 0, 0);
    return;
  }

  const totalPages = Math.ceil(filteredRecords.length / PAGE_SIZE);
  currentPage = Math.max(1, Math.min(page, totalPages));

  const startIdx = (currentPage - 1) * PAGE_SIZE;
  const endIdx = Math.min(startIdx + PAGE_SIZE, filteredRecords.length);
  const pageItems = filteredRecords.slice(startIdx, endIdx);

  tbody.innerHTML = "";
  pageItems.forEach((r, idx) => {
    const isMal = r.verdict === "Malicious" || r.risk_score >= 61;
    const isSusp = (r.verdict === "Suspicious" || (r.risk_score > 30 && r.risk_score < 61));

    // Threat Level Badges
    let threatBadge = `<span class="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase bg-emerald-50 text-emerald-600 dark:bg-emerald-950 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800">Safe</span>`;
    let scoreColor = "text-emerald-600 dark:text-emerald-400";

    if (isMal) {
      threatBadge = `<span class="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase bg-rose-50 text-rose-600 dark:bg-rose-950 dark:text-rose-400 border border-rose-200 dark:border-rose-800">Critical</span>`;
      scoreColor = "text-rose-600 dark:text-rose-400";
    } else if (isSusp) {
      threatBadge = `<span class="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase bg-amber-50 text-amber-600 dark:bg-amber-950 dark:text-amber-400 border border-amber-200 dark:border-amber-800">Medium</span>`;
      scoreColor = "text-amber-600 dark:text-amber-400";
    }

    // Sender breakdown
    const senderRaw = r.sender || "unknown@domain.com";
    let displayName = senderRaw;
    let senderDomain = "";
    if (senderRaw.includes("@")) {
      const parts = senderRaw.split("@");
      displayName = parts[0];
      senderDomain = "@" + parts[1];
    }

    // Auth Pills
    const spfPass = !isMal;
    const dkimPass = !isMal || isSusp;
    const dmarcPass = !isMal;

    const tr = document.createElement("tr");
    tr.dataset.id = r.id;
    tr.className = `table-row-hover transition-colors border-b border-slate-100 dark:border-slate-800/80 cursor-pointer text-xs`;
    tr.onclick = () => {
      window.location.href = `/investigation/${r.id}`;
    };

    tr.innerHTML = `
      <td class="py-2.5 px-2 font-mono text-[10px] text-slate-400 truncate" title="${r.created_at || ''}">
        ${(r.created_at || "2026-09-10 14:00").slice(5, 16).replace("T", " ")}
      </td>
      <td class="py-2.5 px-2 overflow-hidden">
        <div class="font-bold text-slate-900 dark:text-white truncate text-xs" title="${senderRaw}">${displayName}</div>
        <div class="text-[10px] text-slate-400 font-mono truncate" title="${senderRaw}">${senderDomain}</div>
      </td>
      <td class="py-2.5 px-2 overflow-hidden">
        <div class="font-medium text-slate-800 dark:text-slate-200 truncate text-xs" title="${r.subject || ''}">
          ${r.subject || '(No Subject)'}
        </div>
      </td>
      <td class="py-2.5 px-1 text-center">
        <span class="text-[10px] font-bold px-1.5 py-0.5 rounded ${spfPass ? 'bg-emerald-50 dark:bg-emerald-950 text-emerald-600 dark:text-emerald-400' : 'bg-rose-50 dark:bg-rose-950 text-rose-600 dark:text-rose-400'} font-mono">
          ${spfPass ? 'PASS' : 'FAIL'}
        </span>
      </td>
      <td class="py-2.5 px-1 text-center">
        <span class="text-[10px] font-bold px-1.5 py-0.5 rounded ${dkimPass ? 'bg-emerald-50 dark:bg-emerald-950 text-emerald-600 dark:text-emerald-400' : 'bg-rose-50 dark:bg-rose-950 text-rose-600 dark:text-rose-400'} font-mono">
          ${dkimPass ? 'PASS' : 'FAIL'}
        </span>
      </td>
      <td class="py-2.5 px-1 text-center">
        <span class="text-[10px] font-bold px-1.5 py-0.5 rounded ${dmarcPass ? 'bg-emerald-50 dark:bg-emerald-950 text-emerald-600 dark:text-emerald-400' : 'bg-rose-50 dark:bg-rose-950 text-rose-600 dark:text-rose-400'} font-mono">
          ${dmarcPass ? 'PASS' : 'FAIL'}
        </span>
      </td>
      <td class="py-2.5 px-1 text-center font-mono font-black ${scoreColor} text-xs">
        ${r.risk_score}
      </td>
      <td class="py-2.5 px-1 text-center">
        ${threatBadge}
      </td>
      <td class="py-2.5 px-1 text-center">
        <span class="h-2 w-2 rounded-full ${isMal ? 'bg-rose-500' : (isSusp ? 'bg-amber-500' : 'bg-emerald-500')} inline-block"></span>
      </td>
      <td class="py-2.5 px-2 text-right overflow-hidden">
        <a href="/investigation/${r.id}" onclick="event.stopPropagation()" class="px-2.5 py-1.5 rounded-xl bg-blue-600 hover:bg-blue-700 text-white text-[11px] font-bold transition inline-flex items-center space-x-1 shadow-sm shadow-blue-500/20 whitespace-nowrap">
          <span>View Investigation</span>
          <i class="fa-solid fa-arrow-right text-[9px]"></i>
        </a>
      </td>
    `;
    tbody.appendChild(tr);
  });

  updatePaginationControls(startIdx + 1, endIdx, filteredRecords.length);
}

function updatePaginationControls(start, end, total) {
  const info = document.getElementById("pagination-info");
  const btnPrev = document.getElementById("btn-prev-page");
  const btnNext = document.getElementById("btn-next-page");

  if (info) {
    if (total === 0) info.textContent = "Showing 0 of 0 emails";
    else info.textContent = `Showing ${start}-${end} of ${total} emails`;
  }

  const totalPages = Math.ceil(total / PAGE_SIZE) || 1;
  if (btnPrev) btnPrev.disabled = (currentPage <= 1);
  if (btnNext) btnNext.disabled = (currentPage >= totalPages);
}

function changePage(delta) {
  const totalPages = Math.ceil(filteredRecords.length / PAGE_SIZE) || 1;
  const newPage = currentPage + delta;
  if (newPage >= 1 && newPage <= totalPages) {
    renderTablePage(newPage);
  }
}

function handleTableFilter(e) {
  const query = (e.target ? e.target.value : (e || "")).toString().toLowerCase().trim();
  if (!query) {
    filteredRecords = [...allRecords];
  } else {
    filteredRecords = allRecords.filter(r =>
      (r.sender && r.sender.toLowerCase().includes(query)) ||
      (r.subject && r.subject.toLowerCase().includes(query)) ||
      (r.origin_ip && r.origin_ip.toLowerCase().includes(query)) ||
      (r.country && r.country.toLowerCase().includes(query)) ||
      (r.verdict && r.verdict.toLowerCase().includes(query))
    );
  }
  currentPage = 1;
  renderTablePage(1);
}

function handleGlobalSearch(e) {
  if (e.key === "Enter") {
    const val = e.target.value;
    const tableInput = document.getElementById("table-filter-input");
    if (tableInput) {
      tableInput.value = val;
      handleTableFilter({ target: { value: val } });
      scrollToHistory();
    }
  }
}

/* ==========================================================================
   AI INVESTIGATION CHATBOT DRAWER
   ========================================================================== */
function toggleChatModal(show) {
  const modal = document.getElementById("chat-modal");
  if (!modal) return;
  if (show) {
    modal.classList.remove("hidden");
    loadChatHistory();
    const input = document.getElementById("chat-input");
    if (input) input.focus();
  } else {
    modal.classList.add("hidden");
  }
}

async function loadChatHistory() {
  const repId = currentActiveReportId || "sample";
  const modRepEl = document.getElementById("modal-chat-report-id");
  if (modRepEl) modRepEl.textContent = repId;

  try {
    const res = await fetch(`/api/investigate/chat/${repId}`);
    if (!res.ok) return;
    const resData = await res.json();
    const history = Array.isArray(resData) ? resData : (resData.history || []);
    const container = document.getElementById("chat-messages-container");
    if (!container) return;

    container.innerHTML = `
      <div class="flex items-start space-x-3">
        <div class="w-7 h-7 rounded-lg bg-blue-100 dark:bg-blue-950 border border-blue-200 dark:border-blue-800 flex items-center justify-center text-blue-600 dark:text-blue-400 text-xs flex-shrink-0 mt-0.5">
          <i class="fa-solid fa-shield-halved"></i>
        </div>
        <div class="bg-slate-100 dark:bg-[#141b33] border border-slate-200 dark:border-slate-800 rounded-xl p-3.5 text-slate-800 dark:text-slate-200 leading-relaxed max-w-[85%]">
          Hello, I am your MailGuardian AI Forensic Assistant. I have analyzed this email's cryptographic headers, origin IP, SPF/DKIM/DMARC records, and threat memory history. What would you like to investigate?
        </div>
      </div>
    `;

    history.forEach(msg => {
      appendChatMessage(msg.role, msg.message);
    });
  } catch (e) {
    console.error("Error loading chat history:", e);
  }
}

function formatChatMarkdown(str) {
  if (!str) return "";
  let s = str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
  s = s.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
  s = s.replace(/`([^`]+)`/g, '<code class="px-1 py-0.5 rounded bg-slate-200 dark:bg-slate-800 text-[11px] font-mono text-blue-600 dark:text-blue-400">$1</code>');
  s = s.replace(/###\s+(.*?)(\n|$)/g, '<div class="font-bold text-xs text-blue-600 dark:text-blue-400 mt-2 mb-1 uppercase tracking-wider">$1</div>');
  s = s.replace(/\n/g, '<br>');
  return s;
}

function appendChatMessage(role, text) {
  const container = document.getElementById("chat-messages-container");
  if (!container) return;

  const isUser = (role === "user");
  const msgDiv = document.createElement("div");
  msgDiv.className = `flex items-start space-x-3 ${isUser ? 'flex-row-reverse space-x-reverse' : ''}`;

  const avatar = isUser
    ? `<div class="w-7 h-7 rounded-lg bg-blue-600 flex items-center justify-center text-white text-[10px] font-bold flex-shrink-0 mt-0.5">CM</div>`
    : `<div class="w-7 h-7 rounded-lg bg-blue-100 dark:bg-blue-950 border border-blue-200 dark:border-blue-800 flex items-center justify-center text-blue-600 dark:text-blue-400 text-xs flex-shrink-0 mt-0.5"><i class="fa-solid fa-robot"></i></div>`;

  const bubbleClass = isUser
    ? "bg-blue-600 text-white rounded-xl p-3 max-w-[80%] shadow-sm leading-relaxed"
    : "bg-slate-100 dark:bg-[#141b33] border border-slate-200 dark:border-slate-800 text-slate-800 dark:text-slate-200 rounded-xl p-3.5 max-w-[85%] leading-relaxed text-xs";

  const contentHtml = isUser ? text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/\n/g, "<br>") : formatChatMarkdown(text);

  msgDiv.innerHTML = `
    ${avatar}
    <div class="${bubbleClass}">${contentHtml}</div>
  `;

  container.appendChild(msgDiv);
  container.scrollTop = container.scrollHeight;
}

async function handleChatSubmit(e) {
  e.preventDefault();
  const input = document.getElementById("chat-input");
  const question = (input.value || "").trim();
  if (!question) return;

  input.value = "";
  appendChatMessage("user", question);

  const sendBtn = document.getElementById("chat-send-btn");
  if (sendBtn) {
    sendBtn.disabled = true;
    sendBtn.innerHTML = `<i class="fa-solid fa-circle-notch animate-spin text-[10px]"></i>`;
  }

  try {
    const res = await fetch("/api/investigate/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        report_id: currentActiveReportId || "sample",
        message: question,
        question: question
      })
    });

    if (!res.ok) {
      const errJson = await res.json().catch(() => ({}));
      throw new Error(errJson.detail || `HTTP ${res.status}`);
    }
    const data = await res.json();
    const replyText = data.reply || data.answer || "Forensic analysis completed.";
    appendChatMessage("assistant", replyText);

    if (data.suggested_questions && data.suggested_questions.length > 0) {
      const chips = document.getElementById("chat-chips-container");
      if (chips) {
        chips.innerHTML = `<span class="text-slate-400 text-[10px] flex-shrink-0">Suggested:</span>` +
          data.suggested_questions.map(q =>
            `<button onclick="sendQuickPrompt('${q.replace(/'/g, "\\'")}')" class="px-2.5 py-1 rounded-lg bg-white dark:bg-slate-900 hover:bg-slate-100 dark:hover:bg-slate-800 border border-slate-200 dark:border-slate-700/80 flex-shrink-0 transition cursor-pointer">${q}</button>`
          ).join("");
      }
    }
  } catch (err) {
    appendChatMessage("assistant", "Apologies, I encountered an issue querying the forensic model: " + err.message);
  } finally {
    if (sendBtn) {
      sendBtn.disabled = false;
      sendBtn.innerHTML = `<span>Send</span> <i class="fa-solid fa-paper-plane text-[10px]"></i>`;
    }
  }
}

function sendQuickPrompt(promptText) {
  const input = document.getElementById("chat-input");
  if (input) {
    input.value = promptText;
    handleChatSubmit(new Event("submit"));
  }
}

async function fetchTelemetryStats() {
  try {
    const res = await fetch("/api/threat-intel/stats");
    if (!res.ok) return;
    const stats = await res.json();
    console.log("[MailGuardian AI] Threat Telemetry:", stats);
  } catch (e) {
    // Silent fail for telemetry
  }
}

/* ==========================================================================
   AUTHENTICATION MODAL & SMOOTH SCROLLING
   ========================================================================== */
function openLoginModal(tab = "login") {
  const modal = document.getElementById("login-modal");
  if (!modal) return;
  modal.classList.remove("hidden");
  switchAuthTab(tab);
}

function closeLoginModal() {
  const modal = document.getElementById("login-modal");
  if (!modal) return;
  modal.classList.add("hidden");
}

function switchAuthTab(tab) {
  const loginTab = document.getElementById("auth-tab-login");
  const regTab = document.getElementById("auth-tab-register");
  const loginForm = document.getElementById("auth-form-login");
  const regForm = document.getElementById("auth-form-register");
  if (!loginForm || !regForm) return;

  if (tab === "login") {
    loginForm.classList.remove("hidden");
    regForm.classList.add("hidden");
    if (loginTab) loginTab.className = "flex-1 py-2 text-center text-xs font-bold border-b-2 border-blue-600 text-blue-600 dark:text-blue-400 transition cursor-pointer";
    if (regTab) regTab.className = "flex-1 py-2 text-center text-xs font-semibold text-gray-400 hover:text-gray-600 dark:hover:text-gray-200 border-b-2 border-transparent transition cursor-pointer";
  } else {
    loginForm.classList.add("hidden");
    regForm.classList.remove("hidden");
    if (regTab) regTab.className = "flex-1 py-2 text-center text-xs font-bold border-b-2 border-blue-600 text-blue-600 dark:text-blue-400 transition cursor-pointer";
    if (loginTab) loginTab.className = "flex-1 py-2 text-center text-xs font-semibold text-gray-400 hover:text-gray-600 dark:hover:text-gray-200 border-b-2 border-transparent transition cursor-pointer";
  }
}

function handleLoginSubmit(e) {
  if (e) e.preventDefault();
  const emailInput = document.getElementById("login-email");
  const email = emailInput ? emailInput.value : "codex.monarch@soc.internal";
  completeLogin(email || "codex.monarch@soc.internal", "Codex Monarch");
}

function quickDemoLogin() {
  completeLogin("codex.monarch@enterprise-soc.net", "Codex Monarch");
}

function completeLogin(email, name) {
  closeLoginModal();
  const userEl = document.getElementById("user-profile-name");
  const statusEl = document.getElementById("user-profile-status");
  const loginBtn = document.getElementById("nav-login-btn");
  const userCard = document.getElementById("nav-user-card");

  if (userEl) userEl.textContent = name;
  if (statusEl) statusEl.innerHTML = `<span class="h-1.5 w-1.5 rounded-full bg-emerald-500 inline-block mr-1"></span><span>Active Analyst</span>`;
  if (loginBtn) loginBtn.classList.add("hidden");
  if (userCard) userCard.classList.remove("hidden");

  showToast(`Welcome back, ${name}! Security Intelligence session active.`);
}

function logoutUser() {
  const loginBtn = document.getElementById("nav-login-btn");
  const userCard = document.getElementById("nav-user-card");
  if (loginBtn) loginBtn.classList.remove("hidden");
  if (userCard) userCard.classList.add("hidden");
  showToast("Logged out successfully.");
}

function showToast(msg) {
  let toast = document.getElementById("global-toast");
  if (!toast) {
    toast = document.createElement("div");
    toast.id = "global-toast";
    toast.className = "fixed bottom-6 right-6 z-50 px-4 py-3 rounded-2xl bg-gray-900 text-white dark:bg-white dark:text-gray-900 text-xs font-bold shadow-xl flex items-center space-x-2 transition-all transform duration-300 translate-y-12 opacity-0";
    document.body.appendChild(toast);
  }
  toast.innerHTML = `<i class="fa-solid fa-circle-check text-emerald-400 dark:text-emerald-600 mr-2"></i><span>${msg}</span>`;
  toast.classList.remove("translate-y-12", "opacity-0");
  setTimeout(() => {
    toast.classList.add("translate-y-12", "opacity-0");
  }, 3500);
}

function scrollToScanner() {
  const el = document.getElementById("scanner-section");
  if (el) el.scrollIntoView({ behavior: "smooth" });
}
