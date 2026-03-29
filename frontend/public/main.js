let API_BASE = "/api/dashboard";
const AUTO_REFRESH_MS = 5000;

let selectedIp = null;
let latestIpList = [];
let refreshTimer = null;

// 拖曳狀態
let activeWindow = null;
let offsetX = 0;
let offsetY = 0;
let highestZ = 200;

// 背景動畫狀態
const rowConfigs = [];
const totalRows = 22;

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

const commandInput = document.getElementById("commandInput");
const commandSendBtn = document.getElementById("commandSendBtn");
const reloadBtn = document.getElementById("reloadBtn");
const layer = document.getElementById("streamLayer");
const statusText = document.getElementById("statusText");

const overviewTabs = document.querySelectorAll(".overview-tab");
const overviewPanels = document.querySelectorAll(".overview-panel");

// =========================
// 初始化設定
// =========================
async function initConfig() {
  try {
    const config = await fetch("/api/config").then((res) => res.json());
    if (config?.proxyBase) {
      API_BASE = config.proxyBase;
    }
  } catch (error) {
    console.warn("[CONFIG] Failed to load config, using defaults.", error);
  }
}

// =========================
// 共用工具
// =========================
function fetchJson(url, options = {}) {
  const mergedOptions = {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  };

  return fetch(url, mergedOptions).then(async (res) => {
    if (!res.ok) {
      const text = await res.text();
      throw new Error(`HTTP ${res.status} ${text}`);
    }
    return res.json();
  });
}

function toArray(value) {
  return Array.isArray(value) ? value : [];
}

function toObject(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function safeNumber(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function formatUpdateTime(date = new Date()) {
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, "0");
  const d = String(date.getDate()).padStart(2, "0");
  const hh = String(date.getHours()).padStart(2, "0");
  const mm = String(date.getMinutes()).padStart(2, "0");
  return `${y}/${m}/${d} ${hh}:${mm} 更新`;
}

function setStatusTime(date = new Date()) {
  if (statusText) {
    statusText.textContent = formatUpdateTime(date);
  }
}

function rand(min, max) {
  return Math.random() * (max - min) + min;
}

function randInt(min, max) {
  return Math.floor(rand(min, max + 1));
}

function pick(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

// =========================
// API
// =========================
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

function apiAutoUpdateCheck() {
  return fetchJson(`${API_BASE}/auto_updates`);
}

function apiExecuteCommand(commandText) {
  return fetchJson(`${API_BASE}/terminal_cmd`, {
    method: "POST",
    body: JSON.stringify({
      command_text: commandText,
      selected_ip: selectedIp,
    }),
  });
}

// =========================
// 回傳正規化
// =========================
function normalizeLiveIpsResponse(data) {
  if (Array.isArray(data)) return data;
  if (Array.isArray(data?.items)) return data.items;
  return [];
}

function normalizeCommandHeatmapResponse(data) {
  if (Array.isArray(data)) return data;
  if (Array.isArray(data?.top_commands)) return data.top_commands;
  return [];
}

function normalizeTrafficCompareResponse(data) {
  const obj = toObject(data);
  return {
    total_requests: safeNumber(obj.total_requests ?? obj.total ?? obj.total_count, 0),
    normal_requests: safeNumber(obj.normal_requests ?? obj.normal_count ?? obj.normal, 0),
    attack_requests: safeNumber(obj.attack_requests ?? obj.attack_count ?? obj.attack, 0),
  };
}

function normalizeIpBundleResponse(data) {
  const obj = toObject(data);
  const details = toObject(obj.details);

  let timeline = [];
  if (Array.isArray(obj.timeline)) timeline = obj.timeline;
  else if (Array.isArray(obj.full_trajectory)) timeline = obj.full_trajectory;
  else if (Array.isArray(obj.full_trajectory?.timeline)) timeline = obj.full_trajectory.timeline;

  const riskLevel = safeNumber(details.risk_level, 0);

  return {
    client_ip: obj.client_ip ?? details.client_ip ?? details.ip ?? selectedIp ?? "-",
    country: obj.country ?? details.location ?? details.country ?? "-",
    traffic: safeNumber(obj.traffic ?? details.hits ?? 0, 0),
    risk: obj.risk ?? (riskLevel >= 70 ? "HIGH" : riskLevel > 0 ? "MEDIUM" : "LOW"),
    protocol: obj.protocol ?? details.tls_fingerprint ?? "-",
    port: obj.port ?? details.query_id ?? "-",
    behavior: obj.behavior ?? details.attack_vector ?? details.mitigation_status ?? "-",
    payload: obj.payload ?? details.raw_payload ?? "等待 API 資料...",
    timeline,
    details,
  };
}

// =========================
// Render
// =========================
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
    const traffic = safeNumber(item.traffic ?? item.total_requests ?? item.request_count ?? item.count, 0);
    const country = item.country || item.location || "-";
    const risk = item.risk || (safeNumber(item.attack_requests, 0) > 0 ? "HIGH" : "LOW");

    const div = document.createElement("div");
    div.className = `ip-item${selectedIp === ip ? " active" : ""}`;
    div.innerHTML = `
      <div class="ip-top">
        <span class="strong">${ip}</span>
        <span>${traffic}</span>
      </div>
      <div class="muted">${country} / ${risk}</div>
    `;

    div.addEventListener("click", () => {
      selectedIp = ip;
      renderIpList(latestIpList);
      loadIpDetail();
    });

    ipTrafficList.appendChild(div);
  });
}

function renderDetail(data) {
  const detail = normalizeIpBundleResponse(data);
  const timeline = toArray(detail.timeline);

  if (detailIp) detailIp.textContent = detail.client_ip || "-";
  if (detailRisk) detailRisk.textContent = detail.risk || "-";
  if (detailGeo) detailGeo.textContent = detail.country || "-";
  if (detailTraffic) detailTraffic.textContent = `${safeNumber(detail.traffic, 0)}`;
  if (detailProto) {
    detailProto.textContent =
      detail.protocol && detail.port
        ? `${detail.protocol} / ${detail.port}`
        : (detail.protocol || detail.port || "-");
  }
  if (detailBehavior) detailBehavior.textContent = detail.behavior || "-";
  if (detailPayload) detailPayload.textContent = detail.payload || "等待 API 資料...";

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
      <span class="log-time">${log.time || log.timestamp || index + 1}</span>
      ${log.action || log.event || log.description || "-"}
    `;
    detailRecentLogs.appendChild(div);
  });
}

function renderAttacks(data) {
  if (!attackMethodList) return;
  attackMethodList.innerHTML = "";

  const list = normalizeCommandHeatmapResponse(data);
  if (!list.length) {
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
      name: item.name || item.cmd || item.command || item.raw_payload || "-",
      count: safeNumber(item.count, 0),
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

function drawTrafficChart(normalCount, attackCount) {
  if (!ctx || !chartCanvas) return;

  const total = normalCount + attackCount;
  const centerX = chartCanvas.width / 2;
  const centerY = chartCanvas.height / 2;
  const radius = 65;

  ctx.clearRect(0, 0, chartCanvas.width, chartCanvas.height);

  ctx.beginPath();
  ctx.arc(centerX, centerY, radius, 0, Math.PI * 2);
  ctx.strokeStyle = "rgba(0,255,136,0.18)";
  ctx.lineWidth = 16;
  ctx.stroke();

  if (total > 0) {
    const normalAngle = (normalCount / total) * Math.PI * 2;

    ctx.beginPath();
    ctx.arc(centerX, centerY, radius, -Math.PI / 2, -Math.PI / 2 + normalAngle);
    ctx.strokeStyle = "rgba(0,255,136,0.92)";
    ctx.lineWidth = 16;
    ctx.stroke();

    ctx.beginPath();
    ctx.arc(centerX, centerY, radius, -Math.PI / 2 + normalAngle, -Math.PI / 2 + Math.PI * 2);
    ctx.strokeStyle = "rgba(0,255,136,0.28)";
    ctx.lineWidth = 16;
    ctx.stroke();
  }

  ctx.fillStyle = "rgba(0,255,136,0.92)";
  ctx.font = "bold 16px Consolas";
  ctx.textAlign = "center";
  ctx.fillText(`${total}`, centerX, centerY - 4);

  ctx.fillStyle = "rgba(0,255,136,0.6)";
  ctx.font = "12px Consolas";
  ctx.fillText("requests", centerX, centerY + 16);
}

function renderTrafficOverview(data) {
  const result = normalizeTrafficCompareResponse(data);
  const normalCount = result.normal_requests;
  const attackCount = result.attack_requests;
  const total = result.total_requests || (normalCount + attackCount);

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
      `normal traffic: ${normalCount}\nattack traffic: ${attackCount}\ntotal traffic: ${total}`;
  }

  drawTrafficChart(normalCount, attackCount);
}

// =========================
// 載入資料
// =========================
function loadIpList() {
  return apiFetchAllIps()
    .then((data) => {
      latestIpList = normalizeLiveIpsResponse(data);

      if (!selectedIp && latestIpList.length > 0) {
        selectedIp = latestIpList[0].client_ip || latestIpList[0].ip;
      } else if (selectedIp) {
        const exists = latestIpList.some((item) => (item.client_ip || item.ip) === selectedIp);
        if (!exists && latestIpList.length > 0) {
          selectedIp = latestIpList[0].client_ip || latestIpList[0].ip;
        }
      }

      renderIpList(latestIpList);
    })
    .catch((error) => {
      console.error("IP list error:", error);
      latestIpList = [];
      renderIpList([]);
    });
}

function loadIpDetail() {
  if (!selectedIp) {
    renderDetail({});
    return Promise.resolve();
  }

  return apiFetchIpDetails(selectedIp)
    .then((data) => {
      renderDetail(data);
    })
    .catch((error) => {
      console.error("IP detail error:", error);
      renderDetail({});
    });
}

function loadAttacks() {
  return apiFetchTopAttackMethods()
    .then((data) => {
      renderAttacks(data);
    })
    .catch((error) => {
      console.error("Attack ranking error:", error);
      renderAttacks([]);
    });
}

function loadTrafficOverview() {
  return apiFetchTrafficCompare()
    .then((data) => {
      renderTrafficOverview(data);
    })
    .catch((error) => {
      console.error("Traffic overview error:", error);
      renderTrafficOverview({});
    });
}

// =========================
// 綁定事件
// =========================
function bindCommandInput() {
  if (!commandInput || !commandSendBtn) return;

  const submitCommand = () => {
    const commandText = commandInput.value.trim();
    if (!commandText) return;

    apiExecuteCommand(commandText)
      .then((result) => {
        console.log("Command result:", result);
        commandInput.value = "";
      })
      .catch((error) => {
        console.error("Command execute error:", error);
      });
  };

  commandSendBtn.addEventListener("click", submitCommand);
  commandInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter") submitCommand();
  });
}

function bindReloadButton() {
  if (!reloadBtn) return;
  reloadBtn.addEventListener("click", () => refreshDashboard(true));
}

function bindOverviewTabs() {
  if (!overviewTabs.length || !overviewPanels.length) return;

  overviewTabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      const targetId = tab.dataset.panel;

      overviewTabs.forEach((btn) => btn.classList.remove("active"));
      overviewPanels.forEach((panel) => panel.classList.remove("active"));

      tab.classList.add("active");

      const targetPanel = document.getElementById(targetId);
      if (targetPanel) targetPanel.classList.add("active");
    });
  });
}

function bindDragWindows() {
  document.querySelectorAll(".draggable").forEach((win) => {
    const handle = win.querySelector(".drag-handle");
    if (!handle) return;

    handle.addEventListener("mousedown", (event) => {
      activeWindow = win;
      highestZ += 1;
      win.style.zIndex = highestZ;

      const rect = win.getBoundingClientRect();
      const currentTransform = getComputedStyle(win).transform;

      if (currentTransform !== "none") {
        win.style.left = `${rect.left}px`;
        win.style.top = `${rect.top}px`;
        win.style.transform = "none";
      }

      offsetX = event.clientX - rect.left;
      offsetY = event.clientY - rect.top;
      document.body.style.userSelect = "none";
    });
  });

  window.addEventListener("mousemove", (event) => {
    if (!activeWindow) return;

    let x = event.clientX - offsetX;
    let y = event.clientY - offsetY;

    const maxX = window.innerWidth - activeWindow.offsetWidth;
    const maxY = window.innerHeight - activeWindow.offsetHeight;

    x = Math.max(0, Math.min(x, maxX));
    y = Math.max(0, Math.min(y, maxY));

    activeWindow.style.left = `${x}px`;
    activeWindow.style.top = `${y}px`;
  });

  window.addEventListener("mouseup", () => {
    activeWindow = null;
    document.body.style.userSelect = "";
  });
}

// =========================
// 背景動畫
// =========================
const tokens = [
  "POST", "GET", "DROP", "payload", "inject", "overflow",
  "auth_bypass", "token", "session", "beacon", "scan",
  "shell", "exec", "worm", "C2", "bind", "443", "8080",
  "0xAF", "0x1D", "../", "/dev/null", "xor", "decode",
  "memory", "buffer", "thread", "root", "cmd"
];

function makeLine(length = 120) {
  const out = [];
  for (let i = 0; i < length; i += 1) {
    out.push(Math.random() < 0.68 ? String(randInt(0, 9)) : pick(tokens));
  }
  return out.join("  ");
}

function createRows() {
  if (!layer) return;

  layer.innerHTML = "";
  rowConfigs.length = 0;

  for (let i = 0; i < totalRows; i += 1) {
    const row = document.createElement("div");
    const roll = Math.random();

    let sizeClass = "small";
    if (roll > 0.84) sizeClass = "large";
    else if (roll > 0.5) sizeClass = "medium";

    row.className = `row ${sizeClass}`;
    row.textContent = makeLine(randInt(85, 140));
    row.style.top = `${(window.innerHeight / totalRows) * i + rand(-8, 8)}px`;

    const startX = rand(-1000, 0);
    const speed =
      sizeClass === "large"
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
      mutateEvery: randInt(40, 120),
    });
  }
}

function animateRows() {
  if (!layer) return;

  const ww = window.innerWidth;

  for (const row of rowConfigs) {
    row.x += row.speed * row.direction;
    row.el.style.transform = `translateX(${row.x}px)`;

    const width = row.el.offsetWidth;

    if (row.direction === 1 && row.x > ww + row.resetPadding) {
      row.x = -width - randInt(60, 240);
      if (Math.random() > 0.52) {
        row.el.textContent = makeLine(randInt(85, 140));
      }
    }

    if (row.direction === -1 && row.x < -width - row.resetPadding) {
      row.x = ww + randInt(60, 240);
      if (Math.random() > 0.52) {
        row.el.textContent = makeLine(randInt(85, 140));
      }
    }

    row.updateCounter += 1;
    if (row.updateCounter >= row.mutateEvery) {
      row.updateCounter = 0;
      if (Math.random() > 0.45) {
        row.el.textContent = makeLine(randInt(85, 140));
      }
    }
  }

  requestAnimationFrame(animateRows);
}

// =========================
// 自動刷新
// =========================
function refreshDashboard(manual = false) {
  if (manual) {
    setStatusTime(new Date());
  }

  return apiAutoUpdateCheck()
    .catch((error) => {
      console.warn("auto_updates error:", error);
      return null;
    })
    .then(() => Promise.all([
      loadIpList(),
      loadAttacks(),
      loadTrafficOverview(),
    ]))
    .then(() => loadIpDetail())
    .then(() => setStatusTime(new Date()));
}

function startAutoRefresh() {
  if (refreshTimer) clearInterval(refreshTimer);
  refreshTimer = setInterval(() => {
    refreshDashboard(false);
  }, AUTO_REFRESH_MS);
}

// =========================
// 初始化
// =========================
async function init() {
  await initConfig();

  bindOverviewTabs();
  bindCommandInput();
  bindReloadButton();
  bindDragWindows();

  await refreshDashboard(true);
  startAutoRefresh();

  createRows();
  animateRows();
}

window.addEventListener("resize", createRows);
init();