const API_BASE = "http://localhost:8000/dashboard";
const API_KEY = "replace-with-a-strong-random-key";

let selectedIp = null;

// DOM
const ipTrafficList = document.getElementById("ipTrafficList");
const attackMethodList = document.getElementById("attackMethodList");
const detailIp = document.getElementById("detailIp");
const detailRisk = document.getElementById("detailRisk");
const detailGeo = document.getElementById("detailGeo");
const detailTraffic = document.getElementById("detailTraffic");
const detailProto = document.getElementById("detailProto");
const detailBehavior = document.getElementById("detailBehavior");
const detailPayload = document.getElementById("detailPayload");
const detailRecentLogs = document.getElementById("detailRecentLogs");

const normalPercent = document.getElementById("normalPercent");
const attackPercent = document.getElementById("attackPercent");
const trafficSummary = document.getElementById("trafficSummary");
const chartCanvas = document.getElementById("trafficChart");
const ctx = chartCanvas ? chartCanvas.getContext("2d") : null;

const trafficNormalCount = document.getElementById("trafficNormalCount");
const trafficAttackCount = document.getElementById("trafficAttackCount");
const trafficNormalRatio = document.getElementById("trafficNormalRatio");
const trafficAttackRatio = document.getElementById("trafficAttackRatio");

const attackAnalysisList = document.getElementById("attackAnalysisList");
const attackOverviewSummary = document.getElementById("attackOverviewSummary");

const commandInput = document.getElementById("commandInput");
const commandSendBtn = document.getElementById("commandSendBtn");
const layer = document.getElementById("streamLayer");
const statusText = document.getElementById("statusText");

const overviewTabs = document.querySelectorAll(".overview-tab");
const overviewPanels = document.querySelectorAll(".overview-panel");

// 共用 fetch
function fetchJson(url, options = {}) {
  const mergedOptions = {
    ...options,
    headers: {
      "Content-Type": "application/json",
      "X-API-KEY": API_KEY,
      ...(options.headers || {})
    }
  };

  return fetch(url, mergedOptions).then((res) => {
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }
    return res.json();
  });
}

// API
function apiFetchAllIps() {
  return fetchJson(`${API_BASE}/live_ips?limit=500`);
}

function apiFetchIpDetails(ip) {
  return fetchJson(`${API_BASE}/ip_bundle/${encodeURIComponent(ip)}`);
}

function apiFetchTopAttackMethods() {
  return fetchJson(`${API_BASE}/command_heatmap`);
}

function apiFetchTrafficCompare() {
  return fetchJson(`${API_BASE}/traffic_compare?limit=1000`);
}

function apiExecuteCommand(commandText) {
  return fetchJson(`${API_BASE}/terminal_cmd`, {
    method: "POST",
    body: JSON.stringify({
      command_text: commandText,
      selected_ip: selectedIp
    })
  });
}

// traffic overview tab 切換
function bindOverviewTabs() {
  if (!overviewTabs.length || !overviewPanels.length) return;

  overviewTabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      const targetId = tab.dataset.panel;

      overviewTabs.forEach((btn) => btn.classList.remove("active"));
      overviewPanels.forEach((panel) => panel.classList.remove("active"));

      tab.classList.add("active");

      const targetPanel = document.getElementById(targetId);
      if (targetPanel) {
        targetPanel.classList.add("active");
      }
    });
  });
}

// render
function renderIpList(list) {
  if (!ipTrafficList) return;
  ipTrafficList.innerHTML = "";

  if (!Array.isArray(list) || list.length === 0) {
    ipTrafficList.innerHTML = `
      <div class="ip-item">
        <div class="ip-top">
          <span class="strong">no data</span>
          <span>-</span>
        </div>
        <div class="muted">尚未取得 API 資料</div>
      </div>
    `;
    return;
  }

  list.forEach((item) => {
    const ip = item.client_ip || item.ip || "-";
    const traffic = item.request_count || item.traffic || item.count || 0;
    const country = item.country || item.location || "-";
    const risk = item.risk || (item.is_attack ? "HIGH" : "LOW");

    const div = document.createElement("div");
    div.className = "ip-item" + (selectedIp === ip ? " active" : "");
    div.innerHTML = `
      <div class="ip-top">
        <span class="strong">${ip}</span>
        <span>${traffic}</span>
      </div>
      <div class="muted">${country} / ${risk}</div>
    `;

    div.addEventListener("click", () => {
      selectedIp = ip;
      renderIpList(list);
      loadIpDetail();
    });

    ipTrafficList.appendChild(div);
  });
}

function buildRisk(detail, dwell) {
  if (detail && detail.risk) return detail.risk;
  if (dwell && dwell.is_active) return "HIGH";
  return "LOW";
}

function buildTraffic(detail, timeline) {
  if (detail && detail.traffic) return detail.traffic;
  if (Array.isArray(timeline)) return timeline.length;
  return 0;
}

function buildProto(detail) {
  if (!detail) return "-";
  if (detail.protocol && detail.port) return `${detail.protocol} / ${detail.port}`;
  if (detail.protocol) return detail.protocol;
  if (detail.port) return `PORT / ${detail.port}`;
  return "-";
}

function buildBehavior(detail, timeline) {
  if (detail && detail.behavior) return detail.behavior;
  if (Array.isArray(timeline) && timeline.length > 0) {
    const first = timeline[0];
    return first.action || first.event || first.description || "-";
  }
  return "-";
}

function buildPayload(detail) {
  if (!detail) return "等待 API 資料...";
  return detail.payload || detail.raw_payload || detail.request_body || "等待 API 資料...";
}

function renderDetail(data) {
  const detail = data?.details || data || {};
  const dwell = data?.summary || data?.dwell || null;
  const timeline = Array.isArray(data?.full_trajectory)
    ? data.full_trajectory
    : Array.isArray(data?.timeline)
      ? data.timeline
      : [];

  if (detailIp) detailIp.textContent = detail.client_ip || detail.ip || selectedIp || "-";
  if (detailRisk) detailRisk.textContent = buildRisk(detail, dwell);
  if (detailGeo) detailGeo.textContent = detail.country || detail.location || "-";
  if (detailTraffic) detailTraffic.textContent = `${buildTraffic(detail, timeline)}`;
  if (detailProto) detailProto.textContent = buildProto(detail);
  if (detailBehavior) detailBehavior.textContent = buildBehavior(detail, timeline);
  if (detailPayload) detailPayload.textContent = buildPayload(detail);

  if (!detailRecentLogs) return;
  detailRecentLogs.innerHTML = "";

  if (!timeline.length) {
    detailRecentLogs.innerHTML = `
      <div class="log-item">
        <span class="log-time">--</span>等待 API 資料...
      </div>
    `;
    return;
  }

  timeline.slice(0, 5).forEach((log, index) => {
    const div = document.createElement("div");
    div.className = "log-item";
    div.innerHTML = `
      <span class="log-time">${log.timestamp || log.time || index + 1}</span>
      ${log.action || log.event || log.description || "-"}
    `;
    detailRecentLogs.appendChild(div);
  });
}

function renderAttacks(list) {
  if (!attackMethodList) return;
  attackMethodList.innerHTML = "";

  if (!Array.isArray(list) || list.length === 0) {
    attackMethodList.innerHTML = `
      <div class="attack-row">
        <div class="rank">-</div>
        <div class="attack-name">no data</div>
        <div class="bar-wrap"><div class="bar" style="width: 0%"></div></div>
        <div>0</div>
      </div>
    `;
    return;
  }

  const normalized = list.map((item) => {
    if (typeof item === "string") return { name: item, count: 1 };
    return {
      name: item.name || item.command || item.raw_payload || "-",
      count: Number(item.count || 0)
    };
  });

  const maxValue = Math.max(...normalized.map((item) => item.count), 1);

  normalized.slice(0, 10).forEach((item, i) => {
    const div = document.createElement("div");
    div.className = "attack-row";
    const width = Math.max(5, (item.count / maxValue) * 100);

    div.innerHTML = `
      <div class="rank">${i + 1}</div>
      <div class="attack-name">${item.name}</div>
      <div class="bar-wrap"><div class="bar" style="width: ${width}%"></div></div>
      <div>${item.count}</div>
    `;

    attackMethodList.appendChild(div);
  });
}

function renderTrafficOverview(data) {
  const normalCount = Number(data?.normal_count || data?.normal || 0);
  const attackCount = Number(data?.attack_count || data?.attack || 0);
  const total = normalCount + attackCount;

  const normalRatio = total > 0 ? `${Math.round((normalCount / total) * 100)}%` : "0%";
  const attackRatio = total > 0 ? `${Math.round((attackCount / total) * 100)}%` : "0%";

  if (trafficNormalCount) trafficNormalCount.textContent = normalCount;
  if (trafficAttackCount) trafficAttackCount.textContent = attackCount;
  if (trafficNormalRatio) trafficNormalRatio.textContent = normalRatio;
  if (trafficAttackRatio) trafficAttackRatio.textContent = attackRatio;
  if (normalPercent) normalPercent.textContent = normalRatio;
  if (attackPercent) attackPercent.textContent = attackRatio;

  if (trafficSummary) {
    trafficSummary.textContent =
`normal traffic: ${normalCount}
attack traffic: ${attackCount}
total traffic: ${total}`;
  }

  drawTrafficPlaceholder(normalCount, attackCount);
}

function renderAttackOverview(data) {
  const attackTraffic = Array.isArray(data?.attack_traffic) ? data.attack_traffic : [];
  const groupedTargets = new Map();

  attackTraffic.forEach((item) => {
    const target =
      item.target ||
      item.destination ||
      item.dst_ip ||
      item.attack_target ||
      "unknown-target";

    const sourceIp = item.client_ip || item.ip || "-";
    const attackType = item.attack_type || item.behavior || item.event || "attack";

    if (!groupedTargets.has(target)) {
      groupedTargets.set(target, {
        target,
        count: 0,
        sources: new Set(),
        types: {}
      });
    }

    const entry = groupedTargets.get(target);
    entry.count += 1;
    entry.sources.add(sourceIp);
    entry.types[attackType] = (entry.types[attackType] || 0) + 1;
  });

  const targetList = Array.from(groupedTargets.values()).map((item) => {
    const primaryType = Object.entries(item.types).sort((a, b) => b[1] - a[1])[0]?.[0] || "-";
    return {
      target: item.target,
      count: item.count,
      sourceCount: item.sources.size,
      primaryType
    };
  }).sort((a, b) => b.count - a.count);

  if (attackAnalysisList) {
    attackAnalysisList.innerHTML = "";

    if (!targetList.length) {
      attackAnalysisList.innerHTML = `
        <div class="attack-analysis-item">
          <div class="ip-top">
            <span class="strong">no attack target</span>
            <span>-</span>
          </div>
          <div class="muted">尚未取得 API 資料</div>
        </div>
      `;
    } else {
      targetList.forEach((item) => {
        const div = document.createElement("div");
        div.className = "attack-analysis-item";
        div.innerHTML = `
          <div class="ip-top">
            <span class="strong">${item.target}</span>
            <span>${item.count} hits</span>
          </div>
          <div class="muted">type: ${item.primaryType} / sources: ${item.sourceCount}</div>
        `;
        attackAnalysisList.appendChild(div);
      });
    }
  }

  if (attackOverviewSummary) {
    const totalTargets = targetList.length;
    const totalEvents = targetList.reduce((sum, item) => sum + item.count, 0);
    const topTarget = targetList[0]?.target || "-";

    attackOverviewSummary.textContent =
`target count: ${totalTargets}
attack event count: ${totalEvents}
top target: ${topTarget}
status: ${totalTargets > 0 ? "multiple attack targets detected" : "no attack target data"}`;
  }
}

function drawTrafficPlaceholder(normalCount, attackCount) {
  if (!ctx || !chartCanvas) return;

  ctx.clearRect(0, 0, chartCanvas.width, chartCanvas.height);

  const cx = chartCanvas.width / 2;
  const cy = chartCanvas.height / 2;

  ctx.strokeStyle = "rgba(0,255,136,0.22)";
  ctx.lineWidth = 2;
  ctx.beginPath();
  ctx.arc(cx, cy, 60, 0, Math.PI * 2);
  ctx.stroke();

  ctx.fillStyle = "rgba(0,255,136,0.92)";
  ctx.font = "bold 16px Consolas";
  ctx.textAlign = "center";
  ctx.fillText("Chart", cx, cy - 8);

  ctx.fillStyle = "rgba(0,255,136,0.6)";
  ctx.font = "12px Consolas";
  ctx.fillText(`${normalCount} / ${attackCount}`, cx, cy + 14);
}

// load
function loadIpList() {
  apiFetchAllIps()
    .then((data) => {
      renderIpList(data);
      if (!selectedIp && Array.isArray(data) && data.length > 0) {
        selectedIp = data[0].client_ip || data[0].ip;
        loadIpDetail();
      }
    })
    .catch((err) => {
      console.error("IP list error:", err);
      renderIpList([]);
    });
}

function loadIpDetail() {
  if (!selectedIp) return;

  apiFetchIpDetails(selectedIp)
    .then((data) => {
      renderDetail(data);
    })
    .catch((err) => {
      console.error("IP detail error:", err);
      renderDetail({});
    });
}

function loadAttacks() {
  apiFetchTopAttackMethods()
    .then((data) => {
      renderAttacks(data);
    })
    .catch((err) => {
      console.error("Attack ranking error:", err);
      renderAttacks([]);
    });
}

function loadTrafficOverview() {
  apiFetchTrafficCompare()
    .then((data) => {
      renderTrafficOverview(data);
      renderAttackOverview(data);
    })
    .catch((err) => {
      console.error("Traffic overview error:", err);
      renderTrafficOverview({});
      renderAttackOverview({});
    });
}

function bindCommandInput() {
  if (!commandInput || !commandSendBtn) return;

  const submitCommand = () => {
    const commandText = commandInput.value.trim();
    if (!commandText) return;

    apiExecuteCommand(commandText)
      .then((result) => {
        console.log("Command result:", result);
      })
      .catch((err) => {
        console.error("Command execute error:", err);
      });
  };

  commandSendBtn.addEventListener("click", submitCommand);
  commandInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") submitCommand();
  });
}

// 拖曳
let activeWindow = null;
let offsetX = 0;
let offsetY = 0;
let highestZ = 200;

document.querySelectorAll(".draggable").forEach((win) => {
  const handle = win.querySelector(".drag-handle");
  if (!handle) return;

  handle.addEventListener("mousedown", (e) => {
    activeWindow = win;
    highestZ += 1;
    win.style.zIndex = highestZ;

    const rect = win.getBoundingClientRect();
    const currentTransform = getComputedStyle(win).transform;

    if (currentTransform !== "none") {
      win.style.left = rect.left + "px";
      win.style.top = rect.top + "px";
      win.style.transform = "none";
    }

    offsetX = e.clientX - rect.left;
    offsetY = e.clientY - rect.top;
  });
});

document.addEventListener("mousemove", (e) => {
  if (!activeWindow) return;

  let x = e.clientX - offsetX;
  let y = e.clientY - offsetY;

  const maxX = window.innerWidth - activeWindow.offsetWidth;
  const maxY = window.innerHeight - activeWindow.offsetHeight;

  x = Math.max(0, Math.min(x, maxX));
  y = Math.max(0, Math.min(y, maxY));

  activeWindow.style.left = x + "px";
  activeWindow.style.top = y + "px";
});

document.addEventListener("mouseup", () => {
  activeWindow = null;
});

// 背景動畫
const tokens = [
  "POST", "GET", "DROP", "payload", "inject", "overflow",
  "auth_bypass", "token", "session", "beacon", "scan",
  "shell", "exec", "worm", "C2", "bind", "443", "8080",
  "0xAF", "0x1D", "../", "/dev/null", "xor", "decode",
  "memory", "buffer", "thread", "root", "cmd"
];

function rand(min, max) {
  return Math.random() * (max - min) + min;
}

function randInt(min, max) {
  return Math.floor(rand(min, max + 1));
}

function pick(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function makeLine(length = 120) {
  const out = [];
  for (let i = 0; i < length; i++) {
    out.push(Math.random() < 0.68 ? String(randInt(0, 9)) : pick(tokens));
  }
  return out.join("  ");
}

const rowConfigs = [];
const totalRows = 22;

function createRows() {
  if (!layer) return;

  layer.innerHTML = "";
  rowConfigs.length = 0;

  for (let i = 0; i < totalRows; i++) {
    const row = document.createElement("div");
    const roll = Math.random();

    let sizeClass = "small";
    if (roll > 0.84) sizeClass = "large";
    else if (roll > 0.5) sizeClass = "medium";

    row.className = `row ${sizeClass}`;
    row.textContent = makeLine(randInt(85, 140));
    row.style.top = `${(window.innerHeight / totalRows) * i + rand(-8, 8)}px`;

    const startX = rand(-1000, 0);
    const speed = sizeClass === "large"
      ? rand(0.20, 0.48)
      : sizeClass === "medium"
        ? rand(0.38, 0.85)
        : rand(0.52, 1.15);

    const direction = Math.random() > 0.5 ? 1 : -1;
    const green = randInt(170, 255);

    row.style.color = `rgba(0, ${green}, ${randInt(75, 145)}, ${rand(0.18, 0.52).toFixed(2)})`;
    row.style.transform = `translateX(${startX}px)`;

    layer.appendChild(row);

    rowConfigs.push({
      el: row,
      x: startX,
      speed,
      direction,
      resetPadding: randInt(150, 400),
      updateCounter: 0,
      mutateEvery: randInt(40, 120)
    });
  }
}

function animate() {
  if (!layer) return;

  const ww = window.innerWidth;

  for (const r of rowConfigs) {
    r.x += r.speed * r.direction;
    r.el.style.transform = `translateX(${r.x}px)`;
    const width = r.el.offsetWidth;

    if (r.direction === 1 && r.x > ww + r.resetPadding) {
      r.x = -width - randInt(60, 240);
      if (Math.random() > 0.52) r.el.textContent = makeLine(randInt(85, 140));
    }

    if (r.direction === -1 && r.x < -width - r.resetPadding) {
      r.x = ww + randInt(60, 240);
      if (Math.random() > 0.52) r.el.textContent = makeLine(randInt(85, 140));
    }

    r.updateCounter++;
    if (r.updateCounter >= r.mutateEvery) {
      r.updateCounter = 0;
      if (Math.random() > 0.45) r.el.textContent = makeLine(randInt(85, 140));
    }
  }

  requestAnimationFrame(animate);
}

// 狀態文字
const statusList = [
  "status: active",
  "status: monitoring",
  "status: live traffic",
  "status: threat watch",
  "status: server synced"
];

function startStatusRotation() {
  if (!statusText) return;
  setInterval(() => {
    statusText.textContent = pick(statusList);
  }, 1500);
}

// init
function init() {
  bindOverviewTabs();
  bindCommandInput();

  loadIpList();
  loadAttacks();
  loadTrafficOverview();

  createRows();
  animate();
  startStatusRotation();
}

window.addEventListener("resize", createRows);
init();