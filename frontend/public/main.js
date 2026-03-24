const API_BASE = "http://localhost:3000/api";

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

// -------------------------
// 共用 fetch
// -------------------------
function fetchJson(url) {
  return fetch(url).then(res => {
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  });
}

// -------------------------
// IP 列表（資料庫全部 IP）
// -------------------------
function loadIpList() {
  fetchJson(`${API_BASE}/live-ips`)
    .then(data => {
      renderIpList(data);
    })
    .catch(err => {
      console.error("IP list error:", err);
    });
}

function renderIpList(list) {
  ipTrafficList.innerHTML = "";

  list.forEach(item => {
    const div = document.createElement("div");
    div.className = "ip-item";

    div.innerHTML = `
      <div class="ip-top">
        <span class="strong">${item.ip}</span>
        <span>${item.traffic || 0} req/min</span>
      </div>
      <div class="muted">${item.country || "-"} / ${item.risk || "-"}</div>
    `;

    div.addEventListener("click", () => {
      selectedIp = item.ip;
      loadIpDetail();
    });

    ipTrafficList.appendChild(div);
  });
}

// -------------------------
// 主視窗（IP 詳細）
// -------------------------
function loadIpDetail() {
  if (!selectedIp) return;

  fetchJson(`${API_BASE}/ip/${selectedIp}`)
    .then(data => {
      renderDetail(data);
    })
    .catch(err => {
      console.error("IP detail error:", err);
    });
}

function renderDetail(data) {
  detailIp.textContent = data.ip || "-";
  detailRisk.textContent = data.risk || "-";
  detailGeo.textContent = data.country || "-";
  detailTraffic.textContent = (data.traffic || 0) + " req/min";
  detailProto.textContent = data.protocol || "-";
  detailBehavior.textContent = data.behavior || "-";
  detailPayload.textContent = data.payload || "-";

  detailRecentLogs.innerHTML = "";
}

// -------------------------
// 攻擊排行榜
// -------------------------
function loadAttacks() {
  fetchJson(`${API_BASE}/attacks`)
    .then(data => {
      renderAttacks(data);
    })
    .catch(err => {
      console.error("attack error:", err);
    });
}

function renderAttacks(list) {
  attackMethodList.innerHTML = "";

  list.slice(0, 10).forEach((item, i) => {
    const div = document.createElement("div");
    div.className = "attack-row";

    div.innerHTML = `
      <div class="rank">${i + 1}</div>
      <div>${item.name || item.command}</div>
      <div>${item.count || 0}</div>
    `;

    attackMethodList.appendChild(div);
  });
}

// -------------------------
// 拖曳功能（保留）
// -------------------------
let activeWindow = null;
let offsetX = 0;
let offsetY = 0;

document.querySelectorAll(".draggable").forEach(win => {
  const handle = win.querySelector(".drag-handle");

  handle.addEventListener("mousedown", (e) => {
    activeWindow = win;

    const rect = win.getBoundingClientRect();
    const currentTransform = getComputedStyle(win).transform;

    // 如果原本有 transform 置中，拖曳時先轉成固定座標
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

document.addEventListener("mousemove", (e) => {
  if (!activeWindow) return;

  activeWindow.style.left = (e.clientX - offsetX) + "px";
  activeWindow.style.top = (e.clientY - offsetY) + "px";
});

document.addEventListener("mouseup", () => {
  activeWindow = null;
});

const layer = document.getElementById("streamLayer");

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
  let out = [];
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
      if (Math.random() > 0.52) {
        r.el.textContent = makeLine(randInt(85, 140));
      }
    }

    if (r.direction === -1 && r.x < -width - r.resetPadding) {
      r.x = ww + randInt(60, 240);
      if (Math.random() > 0.52) {
        r.el.textContent = makeLine(randInt(85, 140));
      }
    }

    r.updateCounter++;
    if (r.updateCounter >= r.mutateEvery) {
      r.updateCounter = 0;
      if (Math.random() > 0.45) {
        r.el.textContent = makeLine(randInt(85, 140));
      }
    }
  }

  requestAnimationFrame(animate);
}

// -------------------------
// 初始化
// -------------------------
function init() {
  loadIpList();
  loadAttacks();

  createRows();
  animate();
}

init();

window.addEventListener("resize", () => {
  createRows();
});