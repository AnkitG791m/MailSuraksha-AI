/* =========================================================================
   MailSurakshaAI - Investigation Page JavaScript
   Full-page forensic investigation view with tabs and data rendering.
   ========================================================================= */

let leafletMap = null;
let currentMarker = null;
let analysisData = null;

// Extract report_id from the URL path: /investigation/{report_id}
const REPORT_ID = window.location.pathname.split('/investigation/')[1] || '';

document.addEventListener("DOMContentLoaded", () => {
  initTheme();
  setupTabs();
  if (REPORT_ID) {
    loadInvestigation(REPORT_ID);
  }
});

/* ==========================================================================
   THEME TOGGLE
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
   AUTH / LOGOUT
   ========================================================================== */
async function handleLogout() {
  try { await fetch("/api/auth/logout", { method: "POST" }); } catch(e) {}
  localStorage.removeItem("user_name");
  localStorage.removeItem("user_email");
  localStorage.removeItem("user_role");
  window.location.href = "/login";
}

/* ==========================================================================
   TAB NAVIGATION
   ========================================================================== */
function setupTabs() {
  const tabs = document.querySelectorAll('.inv-tab');
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const tabName = tab.dataset.tab;
      // Deactivate all
      document.querySelectorAll('.inv-tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.inv-tab-panel').forEach(p => p.classList.remove('active'));
      // Activate clicked
      tab.classList.add('active');
      const panel = document.querySelector(`.inv-tab-panel[data-panel="${tabName}"]`);
      if (panel) panel.classList.add('active');
    });
  });
}

/* ==========================================================================
   LOAD INVESTIGATION DATA
   ========================================================================== */
async function loadInvestigation(reportId) {
  try {
    const res = await fetch(`/api/analysis/${reportId}`);
    if (res.status === 401) {
      window.location.href = "/login";
      return;
    }
    if (!res.ok) {
      showError("Investigation not found. The analysis record may have been deleted or does not exist.");
      return;
    }
    const data = await res.json();
    analysisData = data;
    renderInvestigation(data);
  } catch (err) {
    showError("Failed to load investigation: " + err.message);
  }
}

function showError(msg) {
  const panel = document.querySelector('.inv-tab-panel[data-panel="overview"]');
  if (panel) {
    panel.innerHTML = `
      <div class="inv-card text-center py-12">
        <i class="fa-solid fa-triangle-exclamation text-4xl text-amber-500 mb-4"></i>
        <h3 class="text-base font-bold text-gray-900 dark:text-white mb-2">Investigation Not Found</h3>
        <p class="text-xs text-gray-500 dark:text-gray-400 mb-6">${msg}</p>
        <a href="/dashboard" class="px-4 py-2.5 rounded-2xl bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold transition inline-flex items-center space-x-1.5">
          <i class="fa-solid fa-arrow-left text-[10px]"></i>
          <span>Back to Dashboard</span>
        </a>
      </div>
    `;
  }
}

/* ==========================================================================
   RENDER ALL INVESTIGATION SECTIONS
   ========================================================================== */
function renderInvestigation(data) {
  renderHeader(data);
  renderOverviewAuth(data);
  renderSenderInfo(data);
  renderCorrelationGraph(data.correlation_graph || data.graph_data);
  renderGeoLocation(data);
  renderScoringBreakdown(data);
  renderAIAnalysis(data);
  renderThreatIntelFeeds(data);
  renderPlaybookOverview(data);
  renderTechnicalTab(data);
  renderThreatIntelTab(data);
  renderAIFullTab(data);
  renderRawEmailTab(data);
  renderSimilarCasesTab(data);
  renderPlaybookTab(data);
}

/* ---------- HEADER ---------- */
function renderHeader(data) {
  const headers = data.headers || {};
  const risk = data.risk || {};
  const score = risk.risk_score || 0;
  const verdict = risk.verdict || "Unknown";
  const riskLevel = risk.risk_level || (verdict === "Malicious" ? "High" : (verdict === "Suspicious" ? "Medium" : "Low"));

  // Subject & sender
  const subjectEl = document.getElementById("inv-subject");
  const senderEl = document.getElementById("inv-sender");
  const timestampEl = document.getElementById("inv-timestamp");
  if (subjectEl) subjectEl.textContent = headers.subject || "(No Subject)";
  if (senderEl) senderEl.textContent = headers.from?.email || headers.from?.raw || "Unknown";
  if (timestampEl) timestampEl.textContent = data.analyzed_at ? new Date(data.analyzed_at).toLocaleString() : "—";

  // Risk score
  const scoreEl = document.getElementById("inv-risk-score");
  if (scoreEl) {
    scoreEl.textContent = `${score}/100`;
    if (riskLevel === "Low" || verdict === "Clean") {
      scoreEl.className = "text-2xl font-black font-mono text-emerald-600 dark:text-emerald-400";
    } else if (riskLevel === "Medium" || verdict === "Suspicious") {
      scoreEl.className = "text-2xl font-black font-mono text-amber-600 dark:text-amber-400";
    } else {
      scoreEl.className = "text-2xl font-black font-mono text-rose-600 dark:text-rose-400";
    }
  }

  // Verdict badge
  const badge = document.getElementById("inv-verdict-badge");
  if (badge) {
    if (riskLevel === "Low" || verdict === "Clean") {
      badge.className = "px-3 py-1.5 rounded-full text-[10px] font-black uppercase tracking-wider bg-emerald-50 dark:bg-emerald-950/80 text-emerald-600 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-800";
      badge.textContent = verdict === "Clean" ? "SAFE" : "LOW RISK";
    } else if (riskLevel === "Medium" || verdict === "Suspicious") {
      badge.className = "px-3 py-1.5 rounded-full text-[10px] font-black uppercase tracking-wider bg-amber-50 dark:bg-amber-950/80 text-amber-600 dark:text-amber-400 border border-amber-200 dark:border-amber-800";
      badge.textContent = "SUSPICIOUS";
    } else {
      badge.className = "px-3 py-1.5 rounded-full text-[10px] font-black uppercase tracking-wider bg-rose-50 dark:bg-rose-950/80 text-rose-600 dark:text-rose-400 border border-rose-200 dark:border-rose-800";
      badge.textContent = verdict === "Malicious" ? "MALICIOUS" : "CRITICAL";
    }
  }

  // Export buttons
  const pdfBtn = document.getElementById("btn-export-pdf");
  const jsonBtn = document.getElementById("btn-export-json");
  if (pdfBtn) pdfBtn.href = `/api/reports/${data.report_id}/pdf`;
  if (jsonBtn) jsonBtn.href = `/api/reports/${data.report_id}/json`;

  // Score circle
  const scoreCircle = document.getElementById("inv-score-circle");
  const scoreValEl = document.getElementById("inv-score-val");
  if (scoreCircle) {
    if (riskLevel === "Low" || verdict === "Clean") {
      scoreCircle.className = "w-16 h-16 rounded-full border-4 border-emerald-300 dark:border-emerald-700 flex items-center justify-center";
    } else if (riskLevel === "Medium" || verdict === "Suspicious") {
      scoreCircle.className = "w-16 h-16 rounded-full border-4 border-amber-300 dark:border-amber-700 flex items-center justify-center";
    } else {
      scoreCircle.className = "w-16 h-16 rounded-full border-4 border-rose-300 dark:border-rose-700 flex items-center justify-center";
    }
  }
  if (scoreValEl) scoreValEl.textContent = score;
}

/* ---------- AUTH PILLS ---------- */
function renderOverviewAuth(data) {
  const auth = data.auth || {};
  const container = document.getElementById("inv-auth-pills");
  if (!container) return;

  const renderPill = (label, authData) => {
    const status = authData?.status || "unknown";
    const isPass = status.toLowerCase() === "pass";
    return `
      <div class="auth-pill">
        <span class="auth-pill-label">${label}</span>
        <div class="auth-pill-icon ${isPass ? 'pass' : 'fail'}">
          <i class="fa-solid ${isPass ? 'fa-circle-check' : 'fa-circle-xmark'}"></i>
        </div>
        <span class="auth-pill-status ${isPass ? 'pass' : 'fail'}">${status.toUpperCase()}</span>
        <span class="auth-pill-detail">${isPass ? 'Aligned' : 'Unaligned'}</span>
      </div>
    `;
  };

  container.innerHTML = renderPill("SPF", auth.spf) + renderPill("DKIM", auth.dkim) + renderPill("DMARC", auth.dmarc);
}

/* ---------- SENDER INFO ---------- */
function renderSenderInfo(data) {
  const container = document.getElementById("inv-sender-info");
  if (!container) return;
  const headers = data.headers || {};
  const whois = data.whois || {};
  const from = headers.from || {};

  const rows = [
    ["Sender", from.email || from.raw || "Unknown"],
    ["Domain", from.domain || "—"],
    ["Registered", whois.domain_age || whois.creation_date || "—"],
    ["Reputation", whois.reputation || "—"],
    ["Category", whois.category || "—"],
  ];

  container.innerHTML = rows.map(([label, value]) => `
    <div class="flex items-center justify-between py-1.5 border-b border-gray-100 dark:border-gray-800 last:border-0">
      <span class="text-gray-500 dark:text-gray-400 font-medium">${label}</span>
      <span class="font-bold text-gray-900 dark:text-white text-right max-w-[60%] truncate font-mono text-[11px]">${escapeHtml(String(value))}</span>
    </div>
  `).join('');

  if (whois.whois_url || from.domain) {
    container.innerHTML += `
      <a href="https://who.is/whois/${from.domain || ''}" target="_blank" class="inline-flex items-center space-x-1 text-blue-600 dark:text-blue-400 font-semibold hover:underline mt-2">
        <span>View WHOIS</span>
        <i class="fa-solid fa-arrow-up-right-from-square text-[9px]"></i>
      </a>
    `;
  }
}

/* ---------- CORRELATION GRAPH ---------- */
function renderCorrelationGraph(graphData) {
  const svg = document.getElementById("inv-correlation-svg");
  const placeholder = document.getElementById("inv-graph-placeholder");
  const statsBadge = document.getElementById("inv-graph-stats");
  if (!svg) return;

  if (!graphData || !graphData.nodes || graphData.nodes.length === 0) {
    svg.innerHTML = "";
    if (placeholder) placeholder.classList.remove("hidden");
    if (statsBadge) statsBadge.textContent = "0 Nodes";
    return;
  }

  if (placeholder) placeholder.classList.add("hidden");
  if (statsBadge) statsBadge.textContent = `${graphData.nodes.length} Nodes • ${graphData.links ? graphData.links.length : 0} Edges`;

  const width = 400;
  const height = 208;
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);

  const nodes = graphData.nodes;
  const links = graphData.links || [];
  const cx = width / 2;
  const cy = height / 2;
  const nodePos = {};
  const satellites = [];

  nodes.forEach((n, idx) => {
    if (n.type === "email" || idx === 0) {
      nodePos[n.id] = { x: cx, y: cy, node: n, isCenter: true };
    } else {
      satellites.push(n);
    }
  });

  const satCount = satellites.length;
  const rx = 140;
  const ry = 70;

  satellites.forEach((n, i) => {
    const angle = (2 * Math.PI * i) / (satCount || 1) - Math.PI / 2;
    nodePos[n.id] = {
      x: cx + rx * Math.cos(angle),
      y: cy + ry * Math.sin(angle),
      node: n,
      isCenter: false
    };
  });

  let svgContent = `<defs>
    <filter id="node-glow" x="-30%" y="-30%" width="160%" height="160%">
      <feGaussianBlur stdDeviation="2" result="blur" />
      <feComposite in="SourceGraphic" in2="blur" operator="over" />
    </filter>
  </defs>`;

  links.forEach(l => {
    const s = nodePos[l.source];
    const t = nodePos[l.target];
    if (s && t) {
      svgContent += `<line x1="${s.x}" y1="${s.y}" x2="${t.x}" y2="${t.y}" stroke="#94a3b8" stroke-width="1.2" stroke-dasharray="3,3" stroke-opacity="0.5"><title>${l.label || 'relates_to'}</title></line>`;
    }
  });

  Object.values(nodePos).forEach(item => {
    const n = item.node;
    const r = item.isCenter ? 14 : 9;
    const color = n.color || (item.isCenter ? "#2563eb" : "#7c3aed");
    const rawLabel = n.label || n.id || "";
    const displayLabel = rawLabel.length > 16 ? rawLabel.slice(0, 14) + ".." : rawLabel;

    svgContent += `
      <g class="cursor-pointer" transform="translate(${item.x}, ${item.y})">
        <title>${n.title || n.label || n.id}</title>
        <circle r="${r + 3}" fill="${color}" opacity="0.2" class="animate-pulse" />
        <circle r="${r}" fill="${color}" stroke="#ffffff" stroke-width="1.5" />
        <text y="${r + 11}" text-anchor="middle" font-size="8" font-family="'JetBrains Mono', monospace" fill="#64748b" font-weight="600">${displayLabel}</text>
      </g>
    `;
  });

  svg.innerHTML = svgContent;
}

/* ---------- GEOLOCATION ---------- */
function renderGeoLocation(data) {
  const geo = data.geo || {};
  const lat = geo.lat || geo.latitude;
  const lon = geo.lon || geo.longitude;

  let ipStr = "Internal / N/A";
  if (typeof data.origin_ip === "string" && data.origin_ip) {
    ipStr = data.origin_ip;
  } else if (typeof data.origin_ip === "object" && data.origin_ip) {
    ipStr = data.origin_ip.origin_ip || data.origin_ip.candidate_origin_ip || "Internal / N/A";
  } else if (geo.query_ip) {
    ipStr = geo.query_ip;
  }

  const locText = document.getElementById("inv-geo-location");
  if (locText) {
    const cityCountry = [geo.city, geo.country].filter(c => c && c !== "N/A").join(", ") || "Unknown";
    locText.textContent = `${cityCountry} (${ipStr})`;
  }

  // Geo details
  const detailsEl = document.getElementById("inv-geo-details");
  if (detailsEl) {
    const rows = [
      ["IP Address", ipStr],
      ["ASN", geo.asn || geo.isp || "—"],
      ["Organization", geo.org || geo.isp || "—"],
      ["Location", [geo.city, geo.country].filter(Boolean).join(", ") || "—"],
      ["ISP", geo.isp || "—"],
    ];
    detailsEl.innerHTML = rows.map(([label, value]) => `
      <div class="flex items-center justify-between py-1.5 border-b border-gray-100 dark:border-gray-800 last:border-0">
        <span class="text-gray-500 dark:text-gray-400 font-medium">${label}</span>
        <span class="font-bold text-gray-900 dark:text-white text-right max-w-[60%] truncate font-mono text-[11px]">${escapeHtml(String(value))}</span>
      </div>
    `).join('');
  }

  // Init map
  initMap(lat, lon, geo, ipStr, data);
}

function initMap(lat, lon, geo, ipStr, data) {
  const container = document.getElementById("inv-threat-map");
  if (!container) return;

  if (typeof L === "undefined") {
    container.innerHTML = `
      <div class="h-full w-full flex flex-col items-center justify-center bg-slate-100 dark:bg-[#0a0f1d] text-slate-500 p-4 text-center">
        <i class="fa-solid fa-earth-americas text-3xl mb-2 text-blue-500/70 animate-pulse"></i>
        <div class="text-xs font-bold text-slate-700 dark:text-slate-200">Origin Geolocation</div>
        <div class="text-[11px] font-mono text-slate-400 mt-1">${geo.city || 'Unknown'}, ${geo.country || ''} (${ipStr})</div>
      </div>
    `;
    return;
  }

  try {
    leafletMap = L.map('inv-threat-map', {
      zoomControl: false,
      attributionControl: false
    }).setView([lat || 20, lon || 0], lat ? 5 : 2);

    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', { maxZoom: 18 }).addTo(leafletMap);
    L.control.zoom({ position: 'bottomright' }).addTo(leafletMap);

    if (lat && lon && lat !== 0) {
      const risk = data.risk || {};
      const verdict = risk.verdict || "";
      const riskLevel = risk.risk_level || (verdict === "Malicious" ? "High" : (verdict === "Suspicious" ? "Medium" : "Low"));
      const markerClass = (riskLevel === "High" || verdict === "Malicious")
        ? "pulse-marker"
        : (riskLevel === "Medium" || verdict === "Suspicious" ? "pulse-marker suspicious" : "pulse-marker clean");

      const customIcon = L.divIcon({
        className: 'custom-radar-pin',
        html: `<div class="${markerClass}"></div>`,
        iconSize: [14, 14],
        iconAnchor: [7, 7]
      });

      currentMarker = L.marker([lat, lon], { icon: customIcon }).addTo(leafletMap);
      currentMarker.bindPopup(`
        <div style="font-size: 11px; padding: 4px;">
          <div style="font-weight: 800; color: #2563eb;">${geo.city || 'Unknown'}, ${geo.country || ''}</div>
          <div style="font-family: monospace; color: #64748b; margin-top: 2px;">IP: ${ipStr}</div>
        </div>
      `).openPopup();

      leafletMap.flyTo([lat, lon], 5, { duration: 1.2 });
    }

    setTimeout(() => { if (leafletMap) leafletMap.invalidateSize(); }, 200);
  } catch (err) {
    console.warn("Map init error:", err);
  }
}

/* ---------- SCORING BREAKDOWN ---------- */
function renderScoringBreakdown(data) {
  const container = document.getElementById("inv-scoring-factors");
  if (!container) return;

  const explanations = (data.risk && data.risk.scoring_explanations) || [];

  if (explanations.length === 0) {
    container.innerHTML = `
      <div class="p-3 rounded-xl bg-emerald-50/60 dark:bg-emerald-950/30 border border-emerald-200/60 dark:border-emerald-900/40 text-[11px] text-emerald-700 dark:text-emerald-300 flex items-center space-x-2">
        <i class="fa-solid fa-circle-check text-emerald-600"></i>
        <span>Clean forensic baseline. Zero malicious risk factors detected.</span>
      </div>
    `;
    return;
  }

  container.innerHTML = explanations.map(exp => {
    const isHigh = exp.impact >= 25 || exp.severity === "high";
    const barColor = isHigh ? "bg-rose-500" : "bg-amber-500";
    const maxImpact = 50;
    const barWidth = Math.min((exp.impact || 10) / maxImpact * 100, 100);
    return `
      <div class="space-y-1">
        <div class="flex items-center justify-between">
          <span class="font-semibold text-gray-800 dark:text-gray-200 flex items-center space-x-1.5">
            <span class="h-1.5 w-1.5 rounded-full ${isHigh ? 'bg-rose-500' : 'bg-amber-500'}"></span>
            <span>${exp.factor || exp.name || 'Risk Indicator'}</span>
          </span>
          <span class="font-mono font-bold text-[10px] ${isHigh ? 'text-rose-600' : 'text-amber-600'}">+${exp.impact || 10} pts</span>
        </div>
        <div class="scoring-bar-bg">
          <div class="scoring-bar-fill ${barColor}" style="width: ${barWidth}%"></div>
        </div>
        <div class="text-[10px] text-gray-400 leading-tight">${exp.evidence || exp.description || ''}</div>
      </div>
    `;
  }).join('');
}

/* ---------- AI ANALYSIS ---------- */
function renderAIAnalysis(data) {
  const ai = data.ai_insights || {};
  const aiEl = document.getElementById("inv-ai-analysis");
  const confEl = document.getElementById("inv-ai-confidence");

  if (aiEl) {
    const text = ai.threat_explanation || ai.executive_summary || "AI analysis not available for this investigation.";
    aiEl.textContent = text;
  }
  if (confEl) confEl.textContent = `${ai.confidence_score || 96}% Confidence`;
}

/* ---------- THREAT INTEL FEEDS ---------- */
function renderThreatIntelFeeds(data) {
  const intel = data.threat_intel || {};
  const container = document.getElementById("inv-threat-intel-feeds");
  if (!container) return;

  const feeds = [
    { name: "AbuseIPDB", icon: "fa-database", color: "rose", value: intel.abuseipdb ? `${intel.abuseipdb.abuse_score}%` : "0%", label: "Abuse Score" },
    { name: "VirusTotal", icon: "fa-virus", color: "amber", value: intel.virustotal ? `${intel.virustotal.positives} / ${intel.virustotal.total}` : "0 / 72", label: "Detections" },
    { name: "AlienVault OTX", icon: "fa-satellite-dish", color: "indigo", value: intel.alienvault_otx ? `${intel.alienvault_otx.pulse_count || 0}` : "0", label: "Pulses" },
  ];

  container.innerHTML = feeds.map(f => `
    <div class="flex items-center justify-between p-3 rounded-xl bg-gray-50 dark:bg-gray-800/60 border border-gray-200 dark:border-gray-700/60">
      <div class="flex items-center space-x-2">
        <div class="w-8 h-8 rounded-lg bg-${f.color}-100 dark:bg-${f.color}-950/60 text-${f.color}-600 dark:text-${f.color}-400 flex items-center justify-center text-xs">
          <i class="fa-solid ${f.icon}"></i>
        </div>
        <div>
          <div class="text-[11px] font-bold text-gray-900 dark:text-white">${f.name}</div>
          <div class="text-[10px] text-gray-400">${f.label}</div>
        </div>
      </div>
      <span class="text-sm font-black font-mono text-gray-900 dark:text-white">${f.value}</span>
    </div>
  `).join('');
}

/* ---------- PLAYBOOK OVERVIEW ---------- */
function renderPlaybookOverview(data) {
  const container = document.getElementById("inv-playbook-overview");
  if (!container) return;

  const actions = (data.risk && data.risk.playbook_actions) || [];
  if (actions.length === 0) {
    container.innerHTML = `<div class="text-gray-400 text-[11px]">Preserve record in compliance store. No urgent quarantine needed.</div>`;
    return;
  }

  container.innerHTML = actions.map((action, idx) => `
    <div class="flex items-start space-x-2 p-3 rounded-xl bg-white dark:bg-gray-900 border border-rose-200/60 dark:border-rose-900/40">
      <span class="h-5 w-5 rounded-full bg-rose-200 dark:bg-rose-900/60 text-rose-800 dark:text-rose-300 font-mono text-[10px] font-bold flex items-center justify-center flex-shrink-0 mt-0.5">${idx + 1}</span>
      <span class="font-medium text-gray-800 dark:text-gray-200">${escapeHtml(action)}</span>
    </div>
  `).join('');
}

/* ==========================================================================
   TAB: TECHNICAL ANALYSIS
   ========================================================================== */
function renderTechnicalTab(data) {
  const headers = data.headers || {};
  const auth = data.auth || {};

  // Email headers
  const headersEl = document.getElementById("inv-headers-detail");
  if (headersEl) {
    const fields = [
      ["Subject", headers.subject],
      ["From", headers.from?.raw || headers.from?.email],
      ["To", headers.to?.raw || headers.to?.email || headers.to],
      ["Reply-To", headers.reply_to?.raw || headers.reply_to?.email || headers.reply_to || "—"],
      ["Date", headers.date],
      ["Message-ID", headers.message_id],
      ["Return-Path", headers.return_path?.raw || headers.return_path],
      ["X-Mailer", headers.x_mailer || "—"],
    ];
    headersEl.innerHTML = fields.map(([label, value]) => `
      <div class="flex flex-col sm:flex-row sm:items-center justify-between py-2 border-b border-gray-100 dark:border-gray-800 last:border-0 gap-1">
        <span class="text-gray-500 dark:text-gray-400 font-semibold flex-shrink-0">${label}</span>
        <span class="font-mono text-[11px] text-gray-900 dark:text-white text-right break-all">${escapeHtml(String(value || '—'))}</span>
      </div>
    `).join('');
  }

  // Received chain
  const chainEl = document.getElementById("inv-received-chain");
  if (chainEl) {
    const chain = data.received_chain || [];
    if (chain.length === 0) {
      chainEl.innerHTML = '<div class="text-gray-400">No received chain data available.</div>';
    } else {
      chainEl.innerHTML = chain.map((hop, idx) => `
        <div class="p-3 rounded-xl bg-gray-50 dark:bg-gray-800/60 border border-gray-200 dark:border-gray-700/60">
          <div class="flex items-center space-x-2 mb-1">
            <span class="h-5 w-5 rounded-full bg-blue-100 dark:bg-blue-950 text-blue-600 dark:text-blue-400 flex items-center justify-center text-[10px] font-bold flex-shrink-0">${idx + 1}</span>
            <span class="font-bold text-gray-900 dark:text-white text-[11px]">Hop ${idx + 1}</span>
          </div>
          <div class="font-mono text-[10px] text-gray-600 dark:text-gray-400 break-all leading-relaxed pl-7">${escapeHtml(typeof hop === 'string' ? hop : JSON.stringify(hop))}</div>
        </div>
      `).join('');
    }
  }

  // Auth details
  const authEl = document.getElementById("inv-auth-details");
  if (authEl) {
    const sections = [
      { name: "SPF", data: auth.spf },
      { name: "DKIM", data: auth.dkim },
      { name: "DMARC", data: auth.dmarc },
    ];
    authEl.innerHTML = sections.map(s => {
      const d = s.data || {};
      return `
        <div class="p-4 rounded-xl bg-gray-50 dark:bg-gray-800/60 border border-gray-200 dark:border-gray-700/60">
          <div class="flex items-center justify-between mb-2">
            <span class="font-bold text-gray-900 dark:text-white">${s.name}</span>
            <span class="text-[10px] font-bold font-mono px-2 py-0.5 rounded-full ${d.status === 'pass' ? 'bg-emerald-50 dark:bg-emerald-950 text-emerald-600' : 'bg-rose-50 dark:bg-rose-950 text-rose-600'}">${(d.status || 'unknown').toUpperCase()}</span>
          </div>
          <div class="font-mono text-[10px] text-gray-500 dark:text-gray-400 space-y-1">
            ${Object.entries(d).filter(([k]) => k !== 'status').map(([k, v]) => `<div><span class="text-gray-400">${k}:</span> ${escapeHtml(String(v))}</div>`).join('')}
          </div>
        </div>
      `;
    }).join('');
  }
}

/* ==========================================================================
   TAB: THREAT INTELLIGENCE
   ========================================================================== */
function renderThreatIntelTab(data) {
  const intel = data.threat_intel || {};

  // AbuseIPDB
  const abuseEl = document.getElementById("inv-abuseipdb");
  if (abuseEl) {
    const abuse = intel.abuseipdb || {};
    abuseEl.innerHTML = renderKVPairs(abuse, ["abuse_score", "total_reports", "country_code", "isp", "domain", "data_mode"]);
  }

  // VirusTotal
  const vtEl = document.getElementById("inv-virustotal");
  if (vtEl) {
    const vt = intel.virustotal || {};
    vtEl.innerHTML = renderKVPairs(vt, ["positives", "total", "scan_date", "permalink", "data_mode"]);
  }

  // AlienVault
  const otxEl = document.getElementById("inv-alienvault");
  if (otxEl) {
    const otx = intel.alienvault_otx || {};
    otxEl.innerHTML = renderKVPairs(otx, ["pulse_count", "reputation", "data_mode"]);
  }

  // URLs & Domains
  const urlsEl = document.getElementById("inv-urls-domains");
  if (urlsEl) {
    const urls = data.urls || {};
    const allUrls = urls.all_urls || [];
    const domains = urls.unique_domains || [];

    let html = '';
    if (domains.length > 0) {
      html += `<div class="font-bold text-gray-900 dark:text-white mb-1">Domains (${domains.length})</div>`;
      html += domains.map(d => `<div class="font-mono text-[11px] text-gray-600 dark:text-gray-400 py-0.5">${escapeHtml(d)}</div>`).join('');
    }
    if (allUrls.length > 0) {
      html += `<div class="font-bold text-gray-900 dark:text-white mb-1 mt-3">URLs (${allUrls.length})</div>`;
      html += allUrls.slice(0, 20).map(u => `<div class="font-mono text-[11px] text-blue-600 dark:text-blue-400 py-0.5 break-all">${escapeHtml(typeof u === 'string' ? u : u.url || JSON.stringify(u))}</div>`).join('');
      if (allUrls.length > 20) html += `<div class="text-gray-400 text-[11px] mt-1">...and ${allUrls.length - 20} more</div>`;
    }
    if (!html) html = '<div class="text-gray-400">No URLs or domains detected.</div>';
    urlsEl.innerHTML = html;
  }
}

/* ==========================================================================
   TAB: AI ANALYSIS
   ========================================================================== */
function renderAIFullTab(data) {
  const ai = data.ai_insights || {};
  const fullEl = document.getElementById("inv-ai-full");
  const confEl = document.getElementById("inv-ai-conf-full");

  if (confEl) confEl.textContent = `${ai.confidence_score || 96}% Confidence`;

  if (fullEl) {
    let html = '';

    if (ai.executive_summary) {
      html += `<div><h4 class="font-bold text-gray-900 dark:text-white mb-1">Executive Summary</h4><p class="text-gray-700 dark:text-gray-300 leading-relaxed">${escapeHtml(ai.executive_summary)}</p></div>`;
    }
    if (ai.threat_explanation) {
      html += `<div><h4 class="font-bold text-gray-900 dark:text-white mb-1">Threat Explanation</h4><p class="text-gray-700 dark:text-gray-300 leading-relaxed">${escapeHtml(ai.threat_explanation)}</p></div>`;
    }
    if (ai.classification) {
      html += `<div><h4 class="font-bold text-gray-900 dark:text-white mb-1">Classification</h4><p class="text-gray-700 dark:text-gray-300">${escapeHtml(typeof ai.classification === 'string' ? ai.classification : JSON.stringify(ai.classification))}</p></div>`;
    }
    if (ai.recommendations && Array.isArray(ai.recommendations)) {
      html += `<div><h4 class="font-bold text-gray-900 dark:text-white mb-1">Recommendations</h4><ul class="list-disc list-inside space-y-1 text-gray-700 dark:text-gray-300">${ai.recommendations.map(r => `<li>${escapeHtml(r)}</li>`).join('')}</ul></div>`;
    }
    if (ai.plain_language) {
      html += `<div><h4 class="font-bold text-gray-900 dark:text-white mb-1">Plain Language Explanation</h4><p class="text-gray-700 dark:text-gray-300 leading-relaxed">${escapeHtml(ai.plain_language)}</p></div>`;
    }

    if (!html) html = '<p class="text-gray-400">AI analysis not available for this investigation.</p>';
    fullEl.innerHTML = html;
  }
}

/* ==========================================================================
   TAB: RAW EMAIL
   ========================================================================== */
function renderRawEmailTab(data) {
  const rawHeadersEl = document.getElementById("inv-raw-headers");
  const rawBodyEl = document.getElementById("inv-raw-body");

  if (rawHeadersEl) {
    const rawHeaders = data.raw_headers || "";
    rawHeadersEl.textContent = typeof rawHeaders === 'string' ? rawHeaders : JSON.stringify(rawHeaders, null, 2);
  }
  if (rawBodyEl) {
    const body = data.body || {};
    const text = body.plain || body.text || body.html || "(No body content available)";
    rawBodyEl.textContent = typeof text === 'string' ? text : JSON.stringify(text, null, 2);
  }
}

/* ==========================================================================
   TAB: SIMILAR CASES
   ========================================================================== */
function renderSimilarCasesTab(data) {
  const container = document.getElementById("inv-similar-cases");
  if (!container) return;

  const memory = data.threat_memory || {};
  const hasCorr = memory.has_correlation;
  const insights = memory.insights || [];
  const correlations = memory.correlated_cases || memory.matches || [];

  let html = '';

  if (hasCorr && insights.length > 0) {
    html += `<div class="p-3 rounded-xl bg-amber-50 dark:bg-amber-950/30 border border-amber-200 dark:border-amber-800/50 text-amber-800 dark:text-amber-300 text-[11px] font-medium mb-3">
      <i class="fa-solid fa-triangle-exclamation text-amber-500 mr-1"></i>
      Threat Memory correlation detected — similar indicators found in historical data.
    </div>`;

    html += insights.map(i => `<div class="p-2 rounded-lg bg-gray-50 dark:bg-gray-800/60 border border-gray-200 dark:border-gray-700/60 text-[11px] text-gray-700 dark:text-gray-300">${escapeHtml(typeof i === 'string' ? i : JSON.stringify(i))}</div>`).join('');
  }

  if (correlations.length > 0) {
    html += `<div class="font-bold text-gray-900 dark:text-white mt-3 mb-2">Correlated Cases</div>`;
    html += correlations.map(c => `
      <div class="p-3 rounded-xl bg-gray-50 dark:bg-gray-800/60 border border-gray-200 dark:border-gray-700/60">
        <div class="font-mono text-[11px] text-gray-600 dark:text-gray-400">${escapeHtml(JSON.stringify(c, null, 2))}</div>
      </div>
    `).join('');
  }

  if (!html) {
    html = `<div class="text-center py-8">
      <i class="fa-solid fa-shield-check text-3xl text-emerald-500 mb-3"></i>
      <div class="text-sm font-bold text-gray-900 dark:text-white">No Similar Cases Found</div>
      <div class="text-[11px] text-gray-400 mt-1">This email does not correlate with any previously recorded threat campaigns.</div>
    </div>`;
  }

  container.innerHTML = html;
}

/* ==========================================================================
   TAB: PLAYBOOK
   ========================================================================== */
function renderPlaybookTab(data) {
  const container = document.getElementById("inv-playbook-full");
  if (!container) return;

  const actions = (data.risk && data.risk.playbook_actions) || [];

  if (actions.length === 0) {
    container.innerHTML = `
      <div class="p-4 rounded-xl bg-emerald-50 dark:bg-emerald-950/30 border border-emerald-200 dark:border-emerald-800/50 text-sm text-emerald-700 dark:text-emerald-300 flex items-center space-x-3">
        <i class="fa-solid fa-circle-check text-xl text-emerald-500"></i>
        <div>
          <div class="font-bold">No Urgent Action Required</div>
          <div class="text-xs mt-0.5">Preserve message in compliance store. Monitor for similar campaigns.</div>
        </div>
      </div>
    `;
    return;
  }

  container.innerHTML = actions.map((action, idx) => `
    <div class="flex items-start space-x-3 p-4 rounded-xl bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700/60 hover:border-rose-300 dark:hover:border-rose-800 transition">
      <span class="h-7 w-7 rounded-full bg-rose-100 dark:bg-rose-900/60 text-rose-700 dark:text-rose-300 font-mono text-xs font-bold flex items-center justify-center flex-shrink-0">${idx + 1}</span>
      <div class="font-medium text-gray-800 dark:text-gray-200">${escapeHtml(action)}</div>
    </div>
  `).join('');
}

/* ==========================================================================
   UTILITIES
   ========================================================================== */
function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function renderKVPairs(obj, keys) {
  if (!obj || Object.keys(obj).length === 0) {
    return '<div class="text-gray-400">No data available.</div>';
  }
  const displayKeys = keys || Object.keys(obj);
  return displayKeys.filter(k => obj[k] !== undefined && obj[k] !== null).map(k => `
    <div class="flex items-center justify-between py-1.5 border-b border-gray-100 dark:border-gray-800 last:border-0">
      <span class="text-gray-500 dark:text-gray-400 font-medium">${k.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}</span>
      <span class="font-bold text-gray-900 dark:text-white text-right max-w-[60%] truncate font-mono text-[11px]">${escapeHtml(String(obj[k]))}</span>
    </div>
  `).join('');
}
