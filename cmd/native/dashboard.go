package main

import (
	"net/http"
)

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Flow SWG</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #0d1117; color: #c9d1d9; }

  .header { padding: 16px 24px; border-bottom: 1px solid #21262d; display: flex; align-items: center; justify-content: space-between; }
  .header h1 { font-size: 16px; font-weight: 600; color: #e6edf3; }
  .header-right { display: flex; align-items: center; gap: 12px; }
  .stats { display: flex; gap: 16px; font-size: 12px; color: #8b949e; }
  .stats span { display: flex; align-items: center; gap: 4px; }
  .stats .num { color: #e6edf3; font-weight: 600; font-variant-numeric: tabular-nums; }
  .btn { padding: 5px 12px; font-size: 12px; border-radius: 6px; border: 1px solid #30363d; background: #21262d; color: #c9d1d9; cursor: pointer; }
  .btn:hover { background: #30363d; border-color: #8b949e; }

  .tabs { display: flex; padding: 0 24px; border-bottom: 1px solid #21262d; }
  .tab { padding: 10px 16px; font-size: 13px; color: #8b949e; cursor: pointer; border-bottom: 2px solid transparent; margin-bottom: -1px; }
  .tab:hover { color: #c9d1d9; }
  .tab.active { color: #e6edf3; border-bottom-color: #f78166; }

  .toolbar { padding: 12px 24px; border-bottom: 1px solid #21262d; display: flex; align-items: center; gap: 12px; }
  .search { flex: 1; max-width: 360px; padding: 5px 10px; font-size: 13px; border-radius: 6px; border: 1px solid #30363d; background: #0d1117; color: #c9d1d9; outline: none; }
  .search:focus { border-color: #58a6ff; }
  .filter-btn { padding: 3px 10px; font-size: 12px; border-radius: 12px; border: 1px solid #30363d; background: transparent; color: #8b949e; cursor: pointer; }
  .filter-btn.active { background: #1f6feb22; border-color: #58a6ff; color: #58a6ff; }

  .content { padding: 0 24px; }
  .domain-group { border: 1px solid #21262d; border-radius: 8px; margin: 12px 0; overflow: hidden; }
  .domain-header { display: flex; align-items: center; padding: 10px 14px; background: #161b22; cursor: pointer; user-select: none; gap: 10px; }
  .domain-header:hover { background: #1c2128; }
  .chevron { font-size: 10px; color: #484f58; transition: transform 0.15s; width: 16px; }
  .chevron.open { transform: rotate(90deg); }
  .domain-name { font-size: 13px; font-weight: 600; color: #e6edf3; flex: 1; }
  .domain-meta { display: flex; gap: 12px; align-items: center; }
  .domain-meta span { font-size: 11px; color: #8b949e; font-variant-numeric: tabular-nums; }
  .badge { display: inline-block; padding: 1px 7px; border-radius: 10px; font-size: 11px; font-weight: 500; }
  .badge-blocked { background: #da363322; color: #f85149; }
  .badge-tls { background: #23863622; color: #3fb950; }
  .badge-http { background: #9e6a0322; color: #d29922; }

  .session-table { width: 100%; border-collapse: collapse; display: none; }
  .session-table.open { display: table; }
  .session-table th { text-align: left; padding: 6px 14px; font-size: 11px; font-weight: 600; color: #484f58; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid #21262d; background: #0d1117; }
  .session-table td { padding: 5px 14px; font-size: 12px; border-bottom: 1px solid #161b22; font-variant-numeric: tabular-nums; }
  .session-table tr:hover td { background: #161b22; }
  .method { font-weight: 600; }
  .path { color: #8b949e; max-width: 400px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .status { font-weight: 600; }
  .status-2 { color: #3fb950; }
  .status-3 { color: #58a6ff; }
  .status-4 { color: #d29922; }
  .status-5 { color: #f85149; }
  .action-block { color: #f85149; font-weight: 600; }
  .action-allow { color: #3fb950; }
  .time { color: #484f58; }
  .empty { padding: 60px 20px; text-align: center; color: #484f58; font-size: 14px; }

  /* Events tab */
  .event-row { display: flex; align-items: flex-start; gap: 12px; padding: 10px 14px; border-bottom: 1px solid #21262d; font-size: 12px; }
  .event-row:hover { background: #161b22; }
  .event-time { color: #484f58; white-space: nowrap; min-width: 80px; }
  .event-action { min-width: 60px; font-weight: 600; }
  .event-host { color: #e6edf3; font-weight: 500; min-width: 180px; }
  .event-detail { color: #8b949e; flex: 1; }
  .event-detail .kv { display: inline-block; margin: 1px 4px; padding: 1px 6px; background: #21262d; border-radius: 4px; font-size: 11px; }
  .event-detail .kv .k { color: #8b949e; }
  .event-detail .kv .v { color: #c9d1d9; }
  .event-category { display: inline-block; padding: 1px 6px; border-radius: 4px; font-size: 11px; background: #1c2128; border: 1px solid #30363d; color: #8b949e; margin-right: 4px; }

  /* Category pie chart */
  .chart-section { display: flex; gap: 24px; padding: 20px 0; border-bottom: 1px solid #21262d; margin-bottom: 12px; align-items: flex-start; }
  .chart-container { flex-shrink: 0; }
  .chart-legend { display: flex; flex-direction: column; gap: 6px; font-size: 12px; }
  .legend-item { display: flex; align-items: center; gap: 8px; }
  .legend-dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }
  .legend-label { color: #c9d1d9; }
  .legend-count { color: #8b949e; margin-left: auto; padding-left: 16px; font-variant-numeric: tabular-nums; }
  .legend-pct { color: #484f58; font-size: 11px; min-width: 40px; text-align: right; }
  .chart-title { font-size: 13px; font-weight: 600; color: #e6edf3; margin-bottom: 12px; }
</style>
</head>
<body>
<div class="header">
  <h1>Flow SWG</h1>
  <div class="header-right">
    <div class="stats">
      <span>Domains: <span class="num" id="domain-count">0</span></span>
      <span>Requests: <span class="num" id="request-count">0</span></span>
      <span>Blocked: <span class="num" id="blocked-count">0</span></span>
      <span>Events: <span class="num" id="event-count">0</span></span>
    </div>
    <button class="btn" onclick="refresh()">Refresh</button>
    <button class="btn" onclick="clearAll()">Clear</button>
  </div>
</div>
<div class="tabs">
  <div class="tab active" data-tab="sessions" onclick="switchTab('sessions')">Sessions</div>
  <div class="tab" data-tab="events" onclick="switchTab('events')">Events</div>
</div>
<div id="sessions-toolbar" class="toolbar">
  <input class="search" type="text" id="search" placeholder="Filter domains..." oninput="renderSessions()">
  <button class="filter-btn active" data-filter="all" onclick="setFilter(this)">All</button>
  <button class="filter-btn" data-filter="blocked" onclick="setFilter(this)">Blocked</button>
  <button class="filter-btn" data-filter="tls" onclick="setFilter(this)">TLS</button>
</div>
<div id="events-toolbar" class="toolbar" style="display:none">
  <input class="search" type="text" id="event-search" placeholder="Filter events..." oninput="renderEvents()">
  <button class="filter-btn active" data-efilter="all" onclick="setEventFilter(this)">All</button>
  <button class="filter-btn" data-efilter="blocked" onclick="setEventFilter(this)">Blocked</button>
</div>
<div class="content" id="app"></div>

<script>
(function() {
  let domainData = [];
  let eventData = [];
  let categoryData = [];
  let activeTab = "sessions";
  let activeFilter = "all";
  let activeEventFilter = "all";
  let openDomains = {};

  const CHART_COLORS = [
    "#f78166","#58a6ff","#3fb950","#d29922","#bc8cff",
    "#f85149","#79c0ff","#56d364","#e3b341","#d2a8ff",
    "#ff7b72","#a5d6ff","#7ee787","#f0c84a","#cabffd"
  ];

  window.refresh = function() {
    Promise.all([
      fetch("/api/domains").then(r => r.json()).then(d => { domainData = d || []; }),
      fetch("/api/events").then(r => r.json()).then(d => { eventData = d || []; }),
      fetch("/api/events/categories").then(r => r.json()).then(d => { categoryData = d || []; })
    ]).then(() => {
      updateStats();
      if (activeTab === "sessions") renderSessions();
      else renderEvents();
    });
  };

  window.clearAll = function() {
    Promise.all([
      fetch("/api/sessions/clear", {method:"POST"}),
    ]).then(() => { domainData = []; eventData = []; updateStats(); renderActive(); });
  };

  window.switchTab = function(tab) {
    activeTab = tab;
    document.querySelectorAll(".tab").forEach(t => t.classList.toggle("active", t.dataset.tab === tab));
    document.getElementById("sessions-toolbar").style.display = tab === "sessions" ? "flex" : "none";
    document.getElementById("events-toolbar").style.display = tab === "events" ? "flex" : "none";
    renderActive();
  };

  window.setFilter = function(btn) {
    document.querySelectorAll("[data-filter]").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    activeFilter = btn.dataset.filter;
    renderSessions();
  };

  window.setEventFilter = function(btn) {
    document.querySelectorAll("[data-efilter]").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    activeEventFilter = btn.dataset.efilter;
    renderEvents();
  };

  window.toggleDomain = function(domain) {
    openDomains[domain] = !openDomains[domain];
    renderSessions();
  };

  function renderActive() {
    if (activeTab === "sessions") renderSessions();
    else renderEvents();
  }

  function updateStats() {
    let totalReqs = 0, totalBlocked = 0;
    domainData.forEach(g => { totalReqs += g.request_count; totalBlocked += g.blocked_count; });
    document.getElementById("domain-count").textContent = domainData.length;
    document.getElementById("request-count").textContent = totalReqs;
    document.getElementById("blocked-count").textContent = totalBlocked;
    document.getElementById("event-count").textContent = eventData.length;
  }

  function fmtSize(b) {
    if (b < 1024) return b + " B";
    if (b < 1024*1024) return (b/1024).toFixed(1) + " KB";
    return (b/1024/1024).toFixed(1) + " MB";
  }

  function fmtTime(ts) { return new Date(ts).toLocaleTimeString(); }

  function esc(s) {
    const d = document.createElement("div");
    d.textContent = s || "";
    return d.innerHTML;
  }

  function statusClass(code) {
    if (code >= 200 && code < 300) return "status-2";
    if (code >= 300 && code < 400) return "status-3";
    if (code >= 400 && code < 500) return "status-4";
    return "status-5";
  }

  window.renderSessions = function() {
    const search = document.getElementById("search").value.toLowerCase();
    let filtered = domainData;
    if (search) filtered = filtered.filter(g => g.domain.toLowerCase().includes(search));
    if (activeFilter === "blocked") filtered = filtered.filter(g => g.blocked_count > 0);
    else if (activeFilter === "tls") filtered = filtered.filter(g => g.tls);

    filtered.sort((a, b) => new Date(b.last_seen) - new Date(a.last_seen));

    if (filtered.length === 0) {
      document.getElementById("app").innerHTML = '<div class="empty">No sessions captured yet.</div>';
      return;
    }

    let html = "";
    for (const g of filtered) {
      const isOpen = openDomains[g.domain];
      const blockedBadge = g.blocked_count > 0 ? ' <span class="badge badge-blocked">' + g.blocked_count + ' blocked</span>' : '';
      const protoBadge = g.tls ? '<span class="badge badge-tls">TLS</span>' : '<span class="badge badge-http">HTTP</span>';

      html += '<div class="domain-group">';
      html += '<div class="domain-header" onclick="toggleDomain(\''+esc(g.domain)+'\')">';
      html += '<span class="chevron ' + (isOpen ? "open" : "") + '">&#9654;</span>';
      html += '<span class="domain-name">' + esc(g.domain) + '</span>';
      html += '<div class="domain-meta">' + protoBadge + blockedBadge;
      html += '<span>' + g.request_count + ' req</span>';
      html += '<span>' + fmtSize(g.total_bytes) + '</span></div></div>';

      if (isOpen && g.sessions) {
        const sessions = g.sessions.slice().reverse();
        html += '<table class="session-table open"><thead><tr><th>Time</th><th>Method</th><th>Path</th><th>Status</th><th>Size</th><th>Duration</th><th>Action</th></tr></thead><tbody>';
        for (const s of sessions) {
          const actionHtml = s.policy_action === "block"
            ? '<span class="action-block">blocked</span>'
            : (s.policy_action ? '<span class="action-allow">' + esc(s.policy_action) + '</span>' : '<span class="time">&mdash;</span>');
          html += '<tr>';
          html += '<td class="time">' + fmtTime(s.timestamp) + '</td>';
          html += '<td class="method">' + esc(s.method) + '</td>';
          html += '<td class="path" title="' + esc(s.path) + '">' + esc(s.path || "/") + '</td>';
          html += '<td class="status ' + statusClass(s.response_status) + '">' + s.response_status + '</td>';
          html += '<td>' + fmtSize(s.response_size) + '</td>';
          html += '<td class="time">' + s.duration_ms + 'ms</td>';
          html += '<td>' + actionHtml + '</td>';
          html += '</tr>';
        }
        html += '</tbody></table>';
      }
      html += '</div>';
    }
    document.getElementById("app").innerHTML = html;
  };

  function drawPieChart(canvas, data) {
    const ctx = canvas.getContext("2d");
    const dpr = window.devicePixelRatio || 1;
    const size = 160;
    canvas.width = size * dpr;
    canvas.height = size * dpr;
    canvas.style.width = size + "px";
    canvas.style.height = size + "px";
    ctx.scale(dpr, dpr);

    const cx = size / 2, cy = size / 2, r = size / 2 - 4;
    const total = data.reduce((s, d) => s + d.count, 0);
    if (total === 0) {
      ctx.beginPath();
      ctx.arc(cx, cy, r, 0, Math.PI * 2);
      ctx.fillStyle = "#21262d";
      ctx.fill();
      ctx.fillStyle = "#484f58";
      ctx.font = "12px -apple-system, sans-serif";
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      ctx.fillText("No data", cx, cy);
      return;
    }

    let startAngle = -Math.PI / 2;
    data.forEach((d, i) => {
      const sliceAngle = (d.count / total) * Math.PI * 2;
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.arc(cx, cy, r, startAngle, startAngle + sliceAngle);
      ctx.closePath();
      ctx.fillStyle = CHART_COLORS[i % CHART_COLORS.length];
      ctx.fill();
      // Thin separator line
      ctx.strokeStyle = "#0d1117";
      ctx.lineWidth = 1.5;
      ctx.stroke();
      startAngle += sliceAngle;
    });

    // Inner circle for donut effect
    ctx.beginPath();
    ctx.arc(cx, cy, r * 0.55, 0, Math.PI * 2);
    ctx.fillStyle = "#0d1117";
    ctx.fill();
    // Total count in center
    ctx.fillStyle = "#e6edf3";
    ctx.font = "bold 18px -apple-system, sans-serif";
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillText(total, cx, cy - 6);
    ctx.fillStyle = "#484f58";
    ctx.font = "10px -apple-system, sans-serif";
    ctx.fillText("requests", cx, cy + 10);
  }

  function renderCategoryChart() {
    if (!categoryData || categoryData.length === 0) return "";
    const total = categoryData.reduce((s, d) => s + d.count, 0);

    let legendHtml = "";
    categoryData.forEach((d, i) => {
      const pct = total > 0 ? ((d.count / total) * 100).toFixed(1) : "0";
      legendHtml += '<div class="legend-item">';
      legendHtml += '<span class="legend-dot" style="background:' + CHART_COLORS[i % CHART_COLORS.length] + '"></span>';
      legendHtml += '<span class="legend-label">' + esc(d.category) + '</span>';
      legendHtml += '<span class="legend-count">' + d.count + '</span>';
      legendHtml += '<span class="legend-pct">' + pct + '%</span>';
      legendHtml += '</div>';
    });

    return '<div class="chart-section">' +
      '<div class="chart-container"><div class="chart-title">Category Distribution</div><canvas id="cat-pie"></canvas></div>' +
      '<div class="chart-legend">' + legendHtml + '</div>' +
      '</div>';
  }

  window.renderEvents = function() {
    const search = document.getElementById("event-search").value.toLowerCase();
    let filtered = eventData.slice().reverse();

    if (search) {
      filtered = filtered.filter(e =>
        (e.request_host || "").toLowerCase().includes(search) ||
        (e.policy_rule_id || "").toLowerCase().includes(search)
      );
    }
    if (activeEventFilter === "blocked") {
      filtered = filtered.filter(e => e.policy_action === "block");
    }

    let html = renderCategoryChart();

    if (filtered.length === 0) {
      html += '<div class="empty">No events yet.</div>';
      document.getElementById("app").innerHTML = html;
      const pie = document.getElementById("cat-pie");
      if (pie) drawPieChart(pie, categoryData);
      return;
    }

    for (const e of filtered) {
      const isBlock = e.policy_action === "block";

      let actionHtml = "";
      if (isBlock) {
        actionHtml = '<span class="action-block">BLOCK</span>';
      } else {
        actionHtml = '<span class="action-allow">allow</span>';
      }

      let detail = "";

      // Categories
      if (e.categories && e.categories.length > 0) {
        detail += e.categories.map(c => '<span class="event-category">' + esc(c) + '</span>').join("");
      }

      // Policy rule
      if (e.policy_rule_id) {
        detail += ' <span class="kv"><span class="k">rule:</span> <span class="v">' + esc(e.policy_rule_id) + '</span></span>';
      }

      // DLP
      if (e.dlp_pattern) {
        detail += ' <span class="kv"><span class="k">dlp:</span> <span class="v">' + esc(e.dlp_pattern) + '</span></span>';
      }

      html += '<div class="event-row">';
      html += '<span class="event-time">' + fmtTime(e.timestamp) + '</span>';
      html += '<span class="event-action">' + actionHtml + '</span>';
      html += '<span class="event-host">' + esc(e.request_method) + ' ' + esc(e.request_host) + esc(e.request_path || "") + '</span>';
      html += '<span class="event-detail">' + (detail || '<span class="time">&mdash;</span>') + '</span>';
      html += '</div>';
    }
    document.getElementById("app").innerHTML = html;
    const pie = document.getElementById("cat-pie");
    if (pie) drawPieChart(pie, categoryData);
  };

  refresh();
})();
</script>
</body>
</html>`

func handleDashboard() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(dashboardHTML))
	}
}
