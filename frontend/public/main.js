// 攔截流量紀錄按鈕跳轉
document.addEventListener("DOMContentLoaded", () => {
  const btn = document.getElementById("trafficLogsBtn");
  if (btn) {
    btn.addEventListener("click", () => {
      window.location.href = "./traffic-logs.html";
    });
  }
});
// 攔截流量紀錄 DOM
const recentTrafficList = document.getElementById("recentTrafficList");

async function loadRecentTraffic() {
  if (!recentTrafficList) return;
  try {
    const data = await fetchJson(`${API_BASE}/recent_traffic?limit=30`);
    const logs = Array.isArray(data.recent_traffic) ? data.recent_traffic : [];
    recentTrafficList.innerHTML = logs.map((log, idx) => {
      // 解析 all_headers 欄位（JSON 轉字串）
      let allHeadersStr = "-";
      let allHeadersObj = null;
      try {
        if (log.all_headers) {
          if (typeof log.all_headers === "string") {
            allHeadersObj = JSON.parse(log.all_headers);
            allHeadersStr = JSON.stringify(allHeadersObj, null, 2);
          } else {
            allHeadersObj = log.all_headers;
            allHeadersStr = JSON.stringify(allHeadersObj, null, 2);
          }
        }
      } catch (e) {
        allHeadersStr = String(log.all_headers || "-");
      }

      // 重要欄位顏色與 icon
      const mitigationStatus = log.mitigation_status || log.details?.mitigation_status || "-";
      const isNormal = mitigationStatus === "normal";
      const riskColor = isNormal ? '#00ffa2' : '#ff4d4f';
      const riskIcon = isNormal ? '' : '⚠️';
      const endpoint = escapeHtml(log.endpoint || "-");
      const payload = escapeHtml(log.raw_payload || "-");
      const query = escapeHtml(log.query_string || "-");
      const authorization = escapeHtml(log.authorization || "-");
      const contentType = escapeHtml(log.content_type || "-");
      const contentLength = escapeHtml(log.content_length || "-");
      const headerCount = escapeHtml(String(log.header_count ?? "-"));
      const time = escapeHtml(formatTaipeiTimestamp(log.request_at, true));
      const method = escapeHtml(log.method || "-");
      const xgboostScoreRaw = log.xgboost_score ?? log.sentinel_score;
      const xgboostDecisionRaw = log.xgboost_decision ?? log.sentinel_decision;
      const xgboostAttackTypeRaw = log.xgboost_attack_type ?? log.sentinel_attack_type;
      const xgboostModelReadyRaw = log.xgboost_model_ready ?? log.sentinel_model_ready;
      const businessContext = escapeHtml(log.business_context || log.surface || "-");
      const bankingAction = escapeHtml(log.banking_action || "-");
      const bankingDetails = escapeHtml(log.banking_details || "-");

      const sentinelScore = Number.isFinite(Number(xgboostScoreRaw))
        ? Number(xgboostScoreRaw).toFixed(4)
        : "0.0000";
      const sentinelDecision = escapeHtml(xgboostDecisionRaw || "PASS");
      const sentinelAttackType = escapeHtml(xgboostAttackTypeRaw || "normal");
      const sentinelModelReady = Number(xgboostModelReadyRaw || 0) === 1 ? "ready" : "fallback";

      // 來源地區顯示（國家名稱＋國旗）
      let country = log.location || log.country || "-";
      let countryDisplay = "-";
      let countryFlag = "";
      // 排除 banking:proxy、Private/Local、- 等無效地區
      if (country && typeof country === "string") {
        const lower = country.toLowerCase();
        if (lower === "private/local" || lower === "-" || lower.includes("proxy") || lower.startsWith("/")) {
          countryDisplay = "-";
        } else {
          // 國家名稱與國旗
          // 支援格式: "Taiwan", "United States", "Japan", "China", "Hong Kong", "Singapore" ...
          // 以 ISO 3166-1 alpha-2 對應 emoji
          const countryMap = {
            "taiwan": {name: "台灣", code: "TW"},
            "japan": {name: "日本", code: "JP"},
            "china": {name: "中國", code: "CN"},
            "united states": {name: "美國", code: "US"},
            "singapore": {name: "新加坡", code: "SG"},
            "hong kong": {name: "香港", code: "HK"},
            "south korea": {name: "南韓", code: "KR"},
            "france": {name: "法國", code: "FR"},
            "germany": {name: "德國", code: "DE"},
            "russia": {name: "俄羅斯", code: "RU"},
            "india": {name: "印度", code: "IN"},
            "united kingdom": {name: "英國", code: "GB"},
            "canada": {name: "加拿大", code: "CA"},
            "australia": {name: "澳洲", code: "AU"},
            "netherlands": {name: "荷蘭", code: "NL"},
            "malaysia": {name: "馬來西亞", code: "MY"},
            "vietnam": {name: "越南", code: "VN"},
            "thailand": {name: "泰國", code: "TH"},
            "indonesia": {name: "印尼", code: "ID"},
            "philippines": {name: "菲律賓", code: "PH"},
            "unknown": {name: "未知", code: ""}
          };
          let key = lower.trim();
          if (countryMap[key]) {
            countryDisplay = countryMap[key].name;
            if (countryMap[key].code) {
              // 國旗 emoji
              const code = countryMap[key].code.toUpperCase();
              countryFlag = code.replace(/./g, c => String.fromCodePoint(0x1f1e6 + c.charCodeAt(0) - 65));
            }
          } else {
            // fallback: 顯示原始名稱
            countryDisplay = country;
          }
        }
      }

      // headers 摺疊
      const headersId = `headers-${idx}`;
      const detailId = `traffic-detail-${idx}`;
      const shortPayload = payload;

      return `
      <div class="log-item log-card${isNormal ? '' : ' attack'}" style="border:1px solid #1affb2; border-radius:8px; margin-bottom:0.7em; background:rgba(0,32,32,0.22); padding:0.65em 0.8em;">
        <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;">
          <span class="log-label" style="font-weight:bold;">${time}</span>
          <span class="log-risk" style="color:${riskColor};font-weight:bold;white-space:nowrap;">${riskIcon} ${isNormal ? 'NORMAL' : 'RISK'}</span>
        </div>
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
          <span style="color:#7ef2d3;">${method}</span>
          <span style="color:#00ffa2;word-break:break-all;">${endpoint}</span>
        </div>
        <div style="margin-top:2px;"><span class="log-label">Banking Surface</span>: <span style="color:#8bd3ff;">${businessContext}</span> / <span style="color:#8bd3ff;">${bankingAction}</span></div>
        <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;margin-top:2px;">
          <span><span class="log-label" style="font-weight:bold;">來源地區</span>: <span style="color:#00ffa2;">${countryFlag ? countryFlag + ' ' : ''}${countryDisplay}</span></span>
          <button onclick="const el=document.getElementById('${detailId}');el.style.display=el.style.display==='none'?'block':'none';this.textContent=el.style.display==='none'?'詳情':'收合';" style="font-size:0.85em;">詳情</button>
        </div>
        <div style="margin-top:2px;"><span class="log-label">Payload</span>: <span style="color:#ffd700;">${shortPayload}</span></div>
        <div style="margin-top:2px;"><span class="log-label">Banking Detail</span>: <span style="color:#ffd700;">${bankingDetails}</span></div>
        <div style="margin-top:2px;"><span class="log-label">XGBoost</span>: <span style="color:#8bd3ff;">${sentinelDecision}</span> | score <span style="color:#8bd3ff;">${sentinelScore}</span> | type <span style="color:#8bd3ff;">${sentinelAttackType}</span> | model <span style="color:#8bd3ff;">${sentinelModelReady}</span></div>

        <div id="${detailId}" style="display:none;margin-top:6px;">
          <div><span class="log-label">Query</span>: ${query}</div>
          <div><span class="log-label">Authorization</span>: ${authorization}</div>
          <div><span class="log-label">Content-Type</span>: ${contentType}</div>
          <div><span class="log-label">Content-Length</span>: ${contentLength}</div>
          <div><span class="log-label">Header Count</span>: ${headerCount}</div>
          <div><span class="log-label">All Headers</span>:
            <button onclick="const el=document.getElementById('${headersId}');el.style.display=el.style.display==='none'?'block':'none';this.textContent=el.style.display==='none'?'展開':'收合';" style="margin-left:0.5em;font-size:0.9em;">展開</button>
            <pre id="${headersId}" class="log-headers" style="display:none;background:rgba(0,0,0,0.18);color:#baffff;padding:0.5em 0.7em;border-radius:4px;max-height:180px;overflow:auto;">${escapeHtml(allHeadersStr)}</pre>
          </div>
        </div>
      </div>
      `;
    }).join("") || "<div class='system-empty'>目前沒有攔截紀錄</div>";
  } catch (e) {
    recentTrafficList.innerHTML = "<div class='system-empty'>無法取得攔截紀錄</div>";
  }
}
let API_BASE = "/api/v1/dashboard";
const AUTO_REFRESH_MS = 5000;

let selectedIp = null;
let latestIpList = [];
let refreshTimer = null;
let dashboardReady = false;
let refreshInFlight = false;
let lastIpListSignature = "";
let lastAttackSignature = "";
let lastTrafficSignature = "";
let lastDetailSignature = "";

// 拖曳狀態
let activeWindow = null;
let offsetX = 0;
let offsetY = 0;
let highestZ = 200;

// 背景動畫狀態
const rowConfigs = [];
const totalRows = 22;

// Chart 實例
let countryPieInstance = null;
let attackMethodRankInstance = null;

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
const detailCurl = document.getElementById("detailCurl");
const detailRecentLogs = document.getElementById("detailRecentLogs");
const logResponseBox = document.querySelector(".log-response");

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
const layoutModeSelect = document.getElementById("layoutModeSelect");

const honeypotTargetList = document.getElementById("honeypotTargetList");
const countryPieCanvas = document.getElementById("countryPieChart");
const countryPieEmpty = document.getElementById("countryPieEmpty");
const attackMethodRankCanvas = document.getElementById("attackMethodRankChart");
const attackMethodEmpty = document.getElementById("attackMethodEmpty");

// GeoIP 快取
const geoCache = new Map();
const TAIPEI_TIMEZONE = "Asia/Taipei";

function formatTaipeiTimestamp(value, withSeconds = true, withMilliseconds = false) {
  if (value === null || value === undefined || value === "") return "-";

  let dateObj;
  if (value instanceof Date) {
    dateObj = value;
  } else if (typeof value === "number") {
    dateObj = new Date(value);
  } else {
    const raw = String(value).trim();
    const isNaiveTs = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(\.\d+)?$/.test(raw);
    if (isNaiveTs) {
      const isoLocal = raw.replace(" ", "T");
      const asLocal = new Date(isoLocal);
      const asUtc = new Date(`${isoLocal}Z`);

      // Backend timestamp is timezone-naive; pick the interpretation closer to "now".
      const nowMs = Date.now();
      const localDiff = Math.abs(nowMs - asLocal.getTime());
      const utcDiff = Math.abs(nowMs - asUtc.getTime());
      dateObj = localDiff <= utcDiff ? asLocal : asUtc;
    } else {
      dateObj = new Date(raw);
    }
  }

  if (Number.isNaN(dateObj.getTime())) return String(value);

  const options = {
    timeZone: TAIPEI_TIMEZONE,
    hour12: false,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: withSeconds ? "2-digit" : undefined,
  };

  const parts = new Intl.DateTimeFormat("zh-TW", options).formatToParts(dateObj);
  const get = (type) => parts.find((x) => x.type === type)?.value || "00";
  const y = get("year");
  const m = get("month");
  const d = get("day");
  const hh = get("hour");
  const mm = get("minute");
  const ss = get("second");
  const ms = String(dateObj.getMilliseconds()).padStart(3, "0");

  if (!withSeconds) {
    return `${y}/${m}/${d} ${hh}:${mm}`;
  }

  return withMilliseconds
    ? `${y}/${m}/${d} ${hh}:${mm}:${ss}.${ms}`
    : `${y}/${m}/${d} ${hh}:${mm}:${ss}`;
}

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

function formatMouseEntropy(value, source) {
  const entropy = Number(value);
  if (!Number.isFinite(entropy) || entropy <= 0) {
    return "mouse:n/a";
  }
  const normalizedSource = source || "unknown";
  return `mouse:${entropy.toFixed(3)} (${normalizedSource})`;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function generateCurlCommand(clientIp, payload, userId = "1001") {
  const baseUrl = "http://127.0.0.1:8000/api/v1/simulate_attack";
  const params = new URLSearchParams({
    user_id: userId,
    payload: payload || "test",
    client_ip: clientIp || "10.10.10.1",
  });
  return `curl -X POST "${baseUrl}?${params.toString()}"`;
}

function formatUpdateTime(date = new Date()) {
  return `${formatTaipeiTimestamp(date, false)} (台灣時間) 更新`;
}

function setStatusTime(date = new Date()) {
  if (statusText) statusText.textContent = formatUpdateTime(date);
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

function isPrivateOrLocalIp(ip) {
  if (!ip) return true;
  if (ip === "::1" || ip === "localhost") return true;
  if (/^(127\.)/.test(ip)) return true;
  if (/^(10\.)/.test(ip)) return true;
  if (/^(192\.168\.)/.test(ip)) return true;
  if (/^(172\.(1[6-9]|2\d|3[0-1])\.)/.test(ip)) return true;
  if (/^(169\.254\.)/.test(ip)) return true;
  return false;
}

async function resolveCountryByIp(ip) {
  const normalizedIp = String(ip || "").trim();
  if (!normalizedIp || normalizedIp === "-") return "-";

  if (isPrivateOrLocalIp(normalizedIp)) {
    if (normalizedIp === "127.0.0.1" || normalizedIp === "::1" || normalizedIp === "localhost") {
      return "Localhost";
    }
    return "Private Network";
  }

  if (geoCache.has(normalizedIp)) {
    return geoCache.get(normalizedIp);
  }

  try {
    const response = await fetch(`https://ipapi.co/${encodeURIComponent(normalizedIp)}/json/`);
    if (!response.ok) throw new Error(`Geo lookup failed: ${response.status}`);
    const data = await response.json();
    const country = data.country_name || data.country || data.region || "Unknown";
    geoCache.set(normalizedIp, country);
    return country;
  } catch (error) {
    console.warn("Geo lookup error:", normalizedIp, error);
    const fallback = "Unknown";
    geoCache.set(normalizedIp, fallback);
    return fallback;
  }
}

function extractFakeResponse(detail) {
  return detail.response_payload
    ?? detail.details?.response_payload
    ?? detail.fake_data
    ?? detail.mirage_memory?.payload
    ?? detail.event_log?.response_payload
    ?? null;
}

function detectIsAttack(detail) {
  const level = safeNumber(detail.risk_level ?? detail.details?.risk_level, 0);
  return Boolean(
    detail.is_attack
    ?? detail.details?.is_attack
    ?? detail.event_log?.is_attack
    ?? (level > 0)
  );
}

function formatFakeResponse(fakeResponse) {
  if (!fakeResponse) return "";
  if (typeof fakeResponse === "string") return fakeResponse;
  return JSON.stringify(fakeResponse, null, 2);
}

function inferTargetFromLog(log) {
  return log.target_ip || log.target || log.principal_id || log.user_id || "1001";
}

function hasUsableApiData() {
  return Array.isArray(latestIpList) && latestIpList.length > 0;
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
  const trafficLogs = Array.isArray(obj.traffic_logs) ? obj.traffic_logs : [];

  const riskLevel = safeNumber(details.risk_level, 0);

  return {
    client_ip: obj.client_ip ?? details.client_ip ?? details.ip ?? selectedIp ?? "-",
    country: obj.country ?? details.location ?? details.country ?? "-",
    traffic: safeNumber(obj.traffic ?? details.hits ?? 0, 0),
    risk: obj.risk ?? (riskLevel >= 70 ? "HIGH" : riskLevel > 0 ? "MEDIUM" : "LOW"),
    protocol: obj.protocol ?? details.tls_fingerprint ?? "-",
    port: obj.port ?? details.principal_id ?? "-",
    behavior: obj.behavior ?? details.attack_vector ?? details.mitigation_status ?? "-",
    mouse_entropy: safeNumber(obj.mouse_entropy ?? details.mouse_entropy, 0),
    mouse_source: obj.mouse_source ?? details.mouse_source ?? "missing",
    payload: obj.payload ?? details.raw_payload ?? "",
    input_string: obj.input_string ?? details.input_string ?? obj.payload ?? details.raw_payload ?? "",
    traffic_logs: trafficLogs,
    timeline,
    details,
  };
}

// =========================
// 離線 / 無資料提示
// =========================
function destroyAnalysisCharts() {
  if (countryPieInstance) {
    countryPieInstance.destroy();
    countryPieInstance = null;
  }
  if (attackMethodRankInstance) {
    attackMethodRankInstance.destroy();
    attackMethodRankInstance = null;
  }
}

function renderGroupMaliciousAnalysisEmpty(message = "請先開啟 main.py 才能顯示分析資料") {
  destroyAnalysisCharts();

  if (honeypotTargetList) {
    honeypotTargetList.innerHTML = `<div class="analysis-empty">${escapeHtml(message)}</div>`;
  }

  if (countryPieEmpty) {
    countryPieEmpty.style.display = "block";
    countryPieEmpty.textContent = message;
  }

  if (attackMethodEmpty) {
    attackMethodEmpty.style.display = "block";
    attackMethodEmpty.textContent = message;
  }
}

function renderSystemOfflineState() {
  const message = "目前尚未取得 Dashboard API 資料，請先開啟 main.py 後再重新整理頁面";

  if (ipTrafficList) {
    ipTrafficList.innerHTML = `<div class="system-empty">${escapeHtml(message)}</div>`;
  }

  if (attackMethodList) {
    attackMethodList.innerHTML = `<div class="system-empty">${escapeHtml(message)}</div>`;
  }

  if (detailIp) detailIp.textContent = "";
  if (detailRisk) detailRisk.textContent = "";
  if (detailGeo) detailGeo.textContent = "";
  if (detailTraffic) detailTraffic.textContent = "";
  if (detailProto) detailProto.textContent = "";
  if (detailBehavior) detailBehavior.textContent = "";
  if (detailPayload) detailPayload.textContent = message;
  if (detailCurl) detailCurl.textContent = message;

  if (detailRecentLogs) {
    detailRecentLogs.innerHTML = `<div class="system-empty">${escapeHtml(message)}</div>`;
  }

  if (logResponseBox) {
    logResponseBox.innerHTML = `<div class="log-block">${escapeHtml(message)}</div>`;
  }

  if (normalPercent) normalPercent.textContent = "";
  if (attackPercent) attackPercent.textContent = "";
  if (trafficNormalCount) trafficNormalCount.textContent = "";
  if (trafficAttackCount) trafficAttackCount.textContent = "";
  if (trafficNormalRatio) trafficNormalRatio.textContent = "";
  if (trafficAttackRatio) trafficAttackRatio.textContent = "";
  if (trafficSummary) trafficSummary.textContent = message;

  if (ctx && chartCanvas) {
    ctx.clearRect(0, 0, chartCanvas.width, chartCanvas.height);
  }

  renderGroupMaliciousAnalysisEmpty(message);
}

// =========================
// UI Rendering
// =========================
function renderIpList(list) {
  if (!ipTrafficList) return;
  ipTrafficList.innerHTML = "";

  if (!Array.isArray(list) || list.length === 0) {
    ipTrafficList.innerHTML = `
      <div class="system-empty">
        目前尚未取得 Dashboard API 資料<br />
        請先開啟 main.py 才能顯示內容
      </div>
    `;
    return;
  }

  list.forEach((item) => {
    const ip = item.client_ip || item.ip || "-";
    const traffic = safeNumber(item.traffic ?? item.total_requests ?? item.request_count ?? item.count, 0);
    const presetCountry = item.country || item.location || "";
    const risk = item.risk || (safeNumber(item.attack_requests, 0) > 0 ? "HIGH" : "LOW");

    const div = document.createElement("div");
    div.className = `ip-item${selectedIp === ip ? " active" : ""}`;
    div.innerHTML = `
      <div class="ip-top">
        <span class="strong">${escapeHtml(ip)}</span>
        <span>${traffic}</span>
      </div>
      <div class="muted" data-country-slot>${escapeHtml(presetCountry || "檢測中...")} / ${escapeHtml(risk)}</div>
    `;

    div.addEventListener("click", () => {
      selectedIp = ip;
      renderIpList(latestIpList);
      loadIpDetail();
    });

    ipTrafficList.appendChild(div);

    if (!presetCountry || presetCountry === "-" || presetCountry === "Unknown") {
      resolveCountryByIp(ip).then((country) => {
        const slot = div.querySelector("[data-country-slot]");
        if (slot) {
          slot.innerHTML = `${escapeHtml(country)} / ${escapeHtml(risk)}`;
        }
      });
    }
  });
}

function renderDetail(data) {
  if (!data || Object.keys(toObject(data)).length === 0) {
    renderSystemOfflineState();
    return;
  }

  const detail = normalizeIpBundleResponse(data);
  const rawDetail = toObject(data);
  const mergedDetail = { ...detail.details, ...rawDetail.details, ...rawDetail, ...detail };
  const timeline = toArray(detail.timeline);
  const ipTrafficLogs = toArray(detail.traffic_logs);

  if (detailIp) detailIp.textContent = detail.client_ip || "";
  if (detailRisk) detailRisk.textContent = detail.risk || "";
  if (detailGeo) {
    detailGeo.textContent = detail.country && detail.country !== "-" ? detail.country : "檢測中...";
    if (!detail.country || detail.country === "-" || detail.country === "Unknown") {
      resolveCountryByIp(detail.client_ip).then((country) => {
        if (detailGeo && detailIp && detailIp.textContent === (detail.client_ip || "")) {
          detailGeo.textContent = country;
        }
      });
    }
  }
  if (detailTraffic) detailTraffic.textContent = `${safeNumber(detail.traffic, 0)}`;
  if (detailProto) {
    detailProto.textContent =
      detail.protocol && detail.port
        ? `${detail.protocol} / ${detail.port}`
        : (detail.protocol || detail.port || "");
  }
  if (detailBehavior) {
    const behaviorText = detail.behavior || "";
    const mouseText = formatMouseEntropy(detail.mouse_entropy, detail.mouse_source);
    detailBehavior.textContent = behaviorText ? `${behaviorText} | ${mouseText}` : mouseText;
  }
  if (detailPayload) detailPayload.textContent = detail.input_string || detail.payload || "";

  const fakeResponse = extractFakeResponse(mergedDetail);
  const isAttack = detectIsAttack(mergedDetail);
  if (logResponseBox) {
    if (isAttack && fakeResponse) {
      logResponseBox.innerHTML = `<div class="log-block">${escapeHtml(formatFakeResponse(fakeResponse))}</div>`;
    } else {
      logResponseBox.innerHTML = `<div class="log-block">目前沒有 fake response 資料</div>`;
    }
  }

  if (detailCurl) {
    const curlCmd = generateCurlCommand(
      detail.client_ip || "10.10.10.1",
      detail.payload || "../../../../etc/passwd",
      String(mergedDetail.principal_id || mergedDetail.details?.principal_id || "1001")
    );
    detailCurl.textContent = curlCmd;
    detailCurl.onclick = () => {
      navigator.clipboard.writeText(curlCmd).then(() => {
        const originalText = detailCurl.textContent;
        detailCurl.textContent = "已複製到剪貼簿！";
        setTimeout(() => {
          detailCurl.textContent = originalText;
        }, 2000);
      }).catch(() => {
        alert("複製失敗，請手動選取");
      });
    };
  }

  if (!detailRecentLogs) return;
  detailRecentLogs.innerHTML = "";

  const logsToRender = ipTrafficLogs.length ? ipTrafficLogs : timeline;

  if (!logsToRender.length) {
    detailRecentLogs.innerHTML = `<div class="system-empty">目前沒有此 IP 的時間軸紀錄</div>`;
    return;
  }

  logsToRender.forEach((log, index) => {
    const div = document.createElement("div");
    div.className = "log-item";
    const riskText = Number(log.risk_level || 0) > 0 ? `RISK=${log.risk_level}` : "NORMAL";
    const methodText = log.method || "-";
    const endpointText = log.endpoint || "-";
    const vectorText = log.attack_vector || log.action || log.event || log.description || "-";
    const decisionText = log.sentinel_decision || "-";
    const scoreText = Number.isFinite(Number(log.sentinel_score))
      ? Number(log.sentinel_score).toFixed(4)
      : "0.0000";
    const inputText = log.input_string || log.raw_payload || log.payload || "-";
    const logText = `${methodText} ${endpointText} | ${riskText} | ${vectorText} | XGB=${decisionText}:${scoreText}`;
    const timelineTime = log.timestamp
      ? formatTaipeiTimestamp(log.timestamp, true, true)
      : (log.time || index + 1);
    div.innerHTML = `
      <span class="log-time">${escapeHtml(timelineTime)}</span>
      ${escapeHtml(logText)}
      <div class="log-input" style="margin-top:2px;color:#ffd700;word-break:break-all;">${escapeHtml(inputText)}</div>
    `;
    div.title = "點擊可切換詳細內容";
    div.style.cursor = "pointer";
    div.addEventListener("click", () => {
      if (detailPayload) {
        detailPayload.textContent = inputText;
      }
      if (detailCurl) {
        const clickedCurl = generateCurlCommand(
          detail.client_ip || "10.10.10.1",
          log.raw_payload || log.payload || logText || detail.payload || "../../../../etc/passwd",
          String(inferTargetFromLog(log))
        );
        detailCurl.textContent = clickedCurl;
      }
    });
    detailRecentLogs.appendChild(div);
  });
}

function renderAttacks(data) {
  if (!attackMethodList) return;
  attackMethodList.innerHTML = "";

  const list = normalizeCommandHeatmapResponse(data);
  if (!list.length) {
    attackMethodList.innerHTML = `
      <div class="system-empty">
        目前尚未取得 Dashboard API 資料<br />
        請先開啟 main.py 才能顯示內容
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
      <div class="attack-name">${escapeHtml(item.name)}</div>
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

  // 外圍底圈
  ctx.beginPath();
  ctx.arc(centerX, centerY, radius, 0, Math.PI * 2);
  ctx.strokeStyle = "rgba(0,255,136,0.18)";
  ctx.lineWidth = 16;
  ctx.stroke();

  if (total > 0) {
    const normalAngle = (normalCount / total) * Math.PI * 2;
    // 正常流量區段（綠色）
    if (normalCount > 0) {
      ctx.beginPath();
      ctx.arc(centerX, centerY, radius, -Math.PI / 2, -Math.PI / 2 + normalAngle);
      ctx.strokeStyle = "rgba(0,255,136,0.92)";
      ctx.lineWidth = 16;
      ctx.stroke();
    }
    // 攻擊流量區段（紅色）
    if (attackCount > 0) {
      ctx.beginPath();
      ctx.arc(centerX, centerY, radius, -Math.PI / 2 + normalAngle, -Math.PI / 2 + Math.PI * 2);
      ctx.strokeStyle = "#ff4d4f";
      ctx.lineWidth = 16;
      ctx.stroke();
    }
  }

  // 圓心數字（白色）
  ctx.fillStyle = "#fff";
  ctx.font = "bold 16px Consolas";
  ctx.textAlign = "center";
  ctx.fillText(`${total}`, centerX, centerY - 4);

  // 下方 requests 字樣（白色半透明）
  ctx.fillStyle = "rgba(255,255,255,0.7)";
  ctx.font = "12px Consolas";
  ctx.fillText("requests", centerX, centerY + 16);
}

function renderTrafficOverview(data) {
  const result = normalizeTrafficCompareResponse(data);
  const normalCount = result.normal_requests;
  const attackCount = result.attack_requests;
  const total = result.total_requests || (normalCount + attackCount);

  const normalRatio = total > 0 ? `${Math.round((normalCount / total) * 100)}%` : "";
  const attackRatio = total > 0 ? `${Math.round((attackCount / total) * 100)}%` : "";

  if (trafficNormalCount) trafficNormalCount.textContent = total ? normalCount : "";
  if (trafficAttackCount) trafficAttackCount.textContent = total ? attackCount : "";
  if (trafficNormalRatio) trafficNormalRatio.textContent = normalRatio;
  if (trafficAttackRatio) trafficAttackRatio.textContent = attackRatio;
  if (normalPercent) normalPercent.textContent = normalRatio;
  if (attackPercent) attackPercent.textContent = attackRatio;

  if (trafficSummary) {
    trafficSummary.textContent = total
      ? `normal traffic: ${normalCount}\nattack traffic: ${attackCount}\ntotal traffic: ${total}`
      : "請先開啟 main.py 才能顯示內容";
  }

  drawTrafficChart(normalCount, attackCount);
}

// =========================
// 惡意分析圖表
// =========================
function buildMockHoneypotTargets() {
  return [
    { name: "Finance-Portal-01", hits: 14, level: "high" },
    { name: "Auth-Gateway-02", hits: 11, level: "high" },
    { name: "Storage-Node-07", hits: 8, level: "medium" },
    { name: "Legacy-ERP-03", hits: 6, level: "medium" },
    { name: "Payroll-API-01", hits: 5, level: "low" }
  ];
}

function drawAttackMethodRankChart(items) {
  if (!attackMethodRankCanvas || typeof Chart === "undefined") return;

  if (attackMethodRankInstance) {
    attackMethodRankInstance.destroy();
  }

  if (!items.length) {
    if (attackMethodEmpty) {
      attackMethodEmpty.style.display = "block";
      attackMethodEmpty.textContent = "目前尚無攻擊手段資料";
    }
    return;
  }

  if (attackMethodEmpty) {
    attackMethodEmpty.style.display = "none";
  }

  // Mac 風格主要攻擊手段長條圖配色
  const barColors = [
    '#00ffa2', // 綠
    '#00cfff', // 藍
    '#ffd700', // 黃
    '#ff4d4f', // 紅
    '#8bd3ff'  // 淺藍
  ];
  attackMethodRankInstance = new Chart(attackMethodRankCanvas, {
    type: "bar",
    data: {
      labels: items.map((item) => item.name),
      datasets: [{
        label: "事件數",
        data: items.map((item) => item.count),
        backgroundColor: items.map((_, i) => barColors[i % barColors.length]),
        borderColor: items.map((_, i) => barColors[i % barColors.length]),
        borderWidth: 1,
        borderRadius: 6,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      indexAxis: "y",
      plugins: {
        legend: { display: false },
        datalabels: {
          color: function(context) {
            return barColors[context.dataIndex % barColors.length];
          },
          anchor: 'end',
          align: 'end',
          font: { weight: 'bold', size: 14 }
        }
      },
      scales: {
        x: {
          ticks: { color: '#8bd3ff' },
          grid: { color: "rgba(0,255,136,0.08)" }
        },
        y: {
          ticks: {
            color: '#fff',
            font: { weight: 'bold', size: 15 }
          },
          grid: { display: false }
        }
      }
    }
  });
}

function drawCountryPieChart(items) {
  if (!countryPieCanvas || typeof Chart === "undefined") return;

  if (countryPieInstance) {
    countryPieInstance.destroy();
  }

  if (!items.length) {
    if (countryPieEmpty) {
      countryPieEmpty.style.display = "block";
      countryPieEmpty.textContent = "目前沒有足夠資料可繪製國家分布";
    }
    return;
  }

  if (countryPieEmpty) {
    countryPieEmpty.style.display = "none";
  }

  // Pie chart 使用不同色系，與 bar chart 區分
  const pieColors = [
    '#4f8cff', // 藍
    '#00ffa2', // 綠
    '#ffd700', // 黃
    '#ff4d4f', // 紅
    '#a084ee'  // 紫
  ];
  countryPieInstance = new Chart(countryPieCanvas, {
    type: "pie",
    data: {
      labels: items.map((item) => item.name),
      datasets: [{
        data: items.map((item) => item.count),
        backgroundColor: items.map((_, i) => pieColors[i % pieColors.length]),
        borderColor: "rgba(0,20,10,0.95)",
        borderWidth: 2
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: "bottom",
          labels: {
            color: "#8bd3ff",
            boxWidth: 14,
            padding: 14
          }
        }
      }
    }
  });
}

function renderGroupMaliciousAnalysis() {
  if (!hasUsableApiData()) {
    renderGroupMaliciousAnalysisEmpty();
    return;
  }

  const attackItems = latestIpList.filter((item) => {
    const risk = String(item.risk || "").toUpperCase();
    const attackRequests = safeNumber(item.attack_requests ?? item.risk_level ?? 0, 0);
    return risk === "HIGH" || risk === "MEDIUM" || attackRequests > 0;
  });

  const methodCounter = new Map();
  const countryCounter = new Map();

  attackItems.forEach((item) => {
    const method = item.attack_vector || item.behavior || item.method || "未知手段";
    const country = item.country || item.location || geoCache.get(item.client_ip || item.ip || "") || "Unknown";

    methodCounter.set(method, (methodCounter.get(method) || 0) + 1);
    countryCounter.set(country, (countryCounter.get(country) || 0) + 1);
  });

  const topMethods = Array.from(methodCounter.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([name, count]) => ({ name, count }));

  const countries = Array.from(countryCounter.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([name, count]) => ({ name, count }));

  drawAttackMethodRankChart(topMethods);
  drawCountryPieChart(countries);

  const mockTargets = buildMockHoneypotTargets()
    .map((item, index) => `
      <div class="analysis-item">
        ${index + 1}. ${escapeHtml(item.name)}<br>
        被探測次數：${item.hits} / 風險等級：${escapeHtml(item.level)}
      </div>
    `)
    .join("");

  if (honeypotTargetList) {
    honeypotTargetList.innerHTML = mockTargets || `<div class="analysis-empty">目前沒有蜜罐對象資料</div>`;
  }
}

// =========================
// 載入資料
// =========================
function loadIpList() {
  return apiFetchAllIps()
    .then((data) => {
      latestIpList = normalizeLiveIpsResponse(data);
      const signature = JSON.stringify(latestIpList);

      if (signature === lastIpListSignature) {
        return latestIpList;
      }

      lastIpListSignature = signature;

      if (!selectedIp && latestIpList.length > 0) {
        selectedIp = latestIpList[0].client_ip || latestIpList[0].ip;
      } else if (selectedIp) {
        const exists = latestIpList.some((item) => (item.client_ip || item.ip) === selectedIp);
        if (!exists && latestIpList.length > 0) {
          selectedIp = latestIpList[0].client_ip || latestIpList[0].ip;
        }
      }

      renderIpList(latestIpList);
      renderGroupMaliciousAnalysis();

      return latestIpList;
    })
    .catch((error) => {
      console.error("IP list error:", error);
      if (!dashboardReady) {
        latestIpList = [];
        renderSystemOfflineState();
      }
      return latestIpList;
    });
}

function loadIpDetail() {
  if (!selectedIp) {
    renderSystemOfflineState();
    return Promise.resolve();
  }

  return apiFetchIpDetails(selectedIp)
    .then((data) => {
      const signature = JSON.stringify(data || {});
      if (signature === lastDetailSignature && dashboardReady) {
        return data;
      }

      lastDetailSignature = signature;
      renderDetail(data);
      return data;
    })
    .catch((error) => {
      console.error("IP detail error:", error);
      if (!dashboardReady) {
        renderSystemOfflineState();
      }
      return null;
    });
}

function loadAttacks() {
  return apiFetchTopAttackMethods()
    .then((data) => {
      const signature = JSON.stringify(data || {});
      if (signature === lastAttackSignature && dashboardReady) {
        return data;
      }

      lastAttackSignature = signature;
      renderAttacks(data);
      renderGroupMaliciousAnalysis();
      return data;
    })
    .catch((error) => {
      console.error("Attack ranking error:", error);
      if (!dashboardReady) {
        renderSystemOfflineState();
      }
      return null;
    });
}

function loadTrafficOverview() {
  return apiFetchTrafficCompare()
    .then((data) => {
      const signature = JSON.stringify(data || {});
      if (signature === lastTrafficSignature && dashboardReady) {
        return data;
      }

      lastTrafficSignature = signature;
      renderTrafficOverview(data);
      renderGroupMaliciousAnalysis();
      return data;
    })
    .catch((error) => {
      console.error("Traffic overview error:", error);
      if (!dashboardReady) {
        renderSystemOfflineState();
      }
      return null;
    });
}

// =========================
// 指令系統
// =========================
function showCommandResult(title, payload) {
  const text = typeof payload === "string" ? payload : JSON.stringify(payload, null, 2);

  if (detailPayload) detailPayload.textContent = `[${title}]\n${text}`;
  if (trafficSummary) trafficSummary.textContent = `[${title}]\n${text}`;

  console.log(`[${title}]`, payload);
}

function showCommandError(message) {
  if (detailPayload) detailPayload.textContent = `[COMMAND ERROR]\n${message}`;
  console.error("[COMMAND ERROR]", message);
}

function parseCommandText(inputText) {
  const text = String(inputText || "").trim();
  if (!text) throw new Error("請輸入指令");

  const match = text.match(/^\/(\w+)\s+([A-Za-z0-9_]+)\s*(?:\{([\s\S]*)\})?$/);
  if (!match) {
    throw new Error("指令格式錯誤，請使用 /api 名稱 {參數} 或 /cmd 名稱 {參數}");
  }

  const scope = match[1].toLowerCase();
  const name = match[2];
  const rawArgs = (match[3] || "").trim();
  const args = rawArgs ? rawArgs.split(",").map((item) => item.trim()).filter(Boolean) : [];

  return { scope, name, args, raw: text };
}

const apiCommandMap = {
  live_ips: async (args) => {
    const limit = Number(args[0] || 500);
    return fetchJson(`${API_BASE}/live_ips?limit=${encodeURIComponent(limit)}`);
  },
  ip_bundle: async (args) => {
    const ip = args[0] || selectedIp;
    if (!ip) throw new Error("ip_bundle 需要 IP 參數，且目前沒有 selectedIp");
    return fetchJson(`${API_BASE}/ip_bundle/${encodeURIComponent(ip)}`);
  },
  command_heatmap: async () => fetchJson(`${API_BASE}/command_heatmap`),
  traffic_compare: async (args) => {
    const limit = Number(args[0] || 1000);
    return fetchJson(`${API_BASE}/traffic_compare?limit=${encodeURIComponent(limit)}`);
  },
  auto_updates: async () => fetchJson(`${API_BASE}/auto_updates`)
};

const cmdCommandMap = {
  reload: async () => {
    await refreshDashboard(true);
    return { status: "success", message: "Dashboard 已重新載入" };
  },
  close: async () => {
    try {
      window.close();
    } catch (err) {
      console.warn("window.close failed:", err);
    }
    setTimeout(() => {
      if (!window.closed) location.href = "about:blank";
    }, 150);
    return { status: "success", message: "已嘗試關閉頁面；若瀏覽器阻擋，會切到空白頁" };
  },
  select_ip: async (args) => {
    const ip = args[0];
    if (!ip) throw new Error("select_ip 需要 IP 參數");
    selectedIp = ip;
    renderIpList(latestIpList);
    await loadIpDetail();
    return { status: "success", selected_ip: selectedIp, message: `已切換選定 IP 為 ${selectedIp}` };
  }
};

async function executeParsedCommand(parsed) {
  const { scope, name, args, raw } = parsed;

  if (scope === "api") {
    const handler = apiCommandMap[name];
    if (!handler) throw new Error(`找不到 API 指令：${name}`);
    const result = await handler(args);

    if (name === "live_ips") {
      latestIpList = normalizeLiveIpsResponse(result);
      renderIpList(latestIpList);
      renderGroupMaliciousAnalysis();
    } else if (name === "ip_bundle") {
      renderDetail(result);
    } else if (name === "command_heatmap") {
      renderAttacks(result);
      renderGroupMaliciousAnalysis();
    } else if (name === "traffic_compare") {
      renderTrafficOverview(result);
      renderGroupMaliciousAnalysis();
    }

    showCommandResult(raw, result);
    return result;
  }

  if (scope === "cmd") {
    const handler = cmdCommandMap[name];
    if (!handler) throw new Error(`找不到 CMD 指令：${name}`);
    const result = await handler(args);
    showCommandResult(raw, result);
    return result;
  }

  throw new Error(`不支援的指令類別：${scope}`);
}

function bindCommandInput() {
  if (!commandInput || !commandSendBtn) return;

  const submitCommand = async () => {
    const commandText = commandInput.value.trim();
    if (!commandText) return;

    try {
      const parsed = parseCommandText(commandText);
      await executeParsedCommand(parsed);
      commandInput.value = "";
    } catch (error) {
      showCommandError(error.message || String(error));
    }
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
  "memory", "buffer", "thread", "root", "cmd", "muxiang", "ciallo"
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
      if (Math.random() > 0.52) row.el.textContent = makeLine(randInt(85, 140));
    }

    if (row.direction === -1 && row.x < -width - row.resetPadding) {
      row.x = ww + randInt(60, 240);
      if (Math.random() > 0.52) row.el.textContent = makeLine(randInt(85, 140));
    }

    row.updateCounter += 1;
    if (row.updateCounter >= row.mutateEvery) {
      row.updateCounter = 0;
      if (Math.random() > 0.45) row.el.textContent = makeLine(randInt(85, 140));
    }
  }

  requestAnimationFrame(animateRows);
}

// =========================
// 自動刷新
// =========================
async function refreshDashboard(manual = false) {
  if (refreshInFlight) return null;
  refreshInFlight = true;

  if (manual) setStatusTime(new Date());

  try {
    await apiAutoUpdateCheck().catch((error) => {
      console.warn("auto_updates error:", error);
      return null;
    });

    await Promise.allSettled([
      loadIpList(),
      loadAttacks(),
      loadTrafficOverview(),
    ]);

    await loadIpDetail();
    dashboardReady = true;
    setStatusTime(new Date());
    return true;
  } finally {
    refreshInFlight = false;
  }
}

function startAutoRefresh() {
  if (refreshTimer) clearInterval(refreshTimer);
  refreshTimer = setInterval(() => {
    refreshDashboard(false);
  }, AUTO_REFRESH_MS);
}

const LAYOUT_STORAGE_KEY = "dashboard-layout-mode";
const LAYOUT_MODES = ["layout-15", "layout-17", "layout-25"];

function applyLayoutMode(mode, { persist = true, resetWindows = true } = {}) {
  const finalMode = LAYOUT_MODES.includes(mode) ? mode : "layout-17";
  document.body.setAttribute("data-layout-mode", finalMode);

  if (layoutModeSelect) layoutModeSelect.value = finalMode;
  if (persist) localStorage.setItem(LAYOUT_STORAGE_KEY, finalMode);
  if (resetWindows) resetWindowPositionsForLayout();
}

function resetWindowPositionsForLayout() {
  const windows = document.querySelectorAll(".window");
  windows.forEach((win) => {
    win.style.left = "";
    win.style.right = "";
    win.style.top = "";
    win.style.bottom = "";
    win.style.transform = "";
  });
}

function bindLayoutModeSelector() {
  if (!layoutModeSelect) return;

  applyLayoutMode("layout-17", { persist: true, resetWindows: true });

  layoutModeSelect.addEventListener("change", (event) => {
    applyLayoutMode(event.target.value, { persist: true, resetWindows: true });
  });
}

// =========================
// 初始化
// =========================
async function init() {
  await initConfig();

  bindLayoutModeSelector();
  bindOverviewTabs();
  bindCommandInput();
  bindReloadButton();
  bindDragWindows();

  await refreshDashboard(true);
  startAutoRefresh();

  createRows();
  animateRows();

  // 載入攔截流量紀錄
  await loadRecentTraffic();
  setInterval(loadRecentTraffic, 8000);
}

window.addEventListener("resize", createRows);
init();
