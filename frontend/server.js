const express = require("express");
const path = require("path");
const app = express();

const DASHBOARD_BASE_URL = process.env.BACKEND_API_BASE_URL || "http://localhost:8000/api/v1/dashboard";
const DASHBOARD_API_KEY = process.env.API_KEY || "dev-local-api-key-change-me";

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

/**
 * 前端配置端點（使用了會推崇、不可暴露）
 */
app.get("/api/config", (req, res) => {
  res.json({
    apiBase: process.env.BACKEND_API_BASE_URL || "http://localhost:8000/api/v1/dashboard",
    // 沒有在 JSON 暴露該 key，前端需要適當由鍵代理來載入 X-API-Key header
  });
});

async function fetchDashboardJson(path, options = {}) {
  const mergedOptions = {
    ...options,
    headers: {
      "X-API-Key": DASHBOARD_API_KEY,
      ...(options.headers || {}),
    },
  };

  const res = await fetch(`${DASHBOARD_BASE_URL}${path}`, {
    ...mergedOptions,
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Dashboard API ${res.status}: ${text}`);
  }

  return res.json();
}

/**
 * 取得 Dashboard 所有資料
 */
app.get("/api/dashboard", (req, res) => {
  const targetIp = req.query.ip || "185.24.68.91";

  let result = {
    ip: targetIp,
    dwell: null,
    timeline: null,
    details: null,
    commands: null
  };

  // 1. dwell time
  fetchDashboardJson(`/dwell_time/${targetIp}`)
    .then(data => {
      result.dwell = data;

      // 2. timeline
      return fetchDashboardJson(`/attack_timeline/${targetIp}`);
    })
    .then(data => {
      result.timeline = data;

      // 3. ip details
      return fetchDashboardJson(`/ip_details/${targetIp}`);
    })
    .then(data => {
      result.details = data;

      // 4. top commands
      return fetchDashboardJson(`/command_heatmap`);
    })
    .then(data => {
      result.commands = data;

      // 回傳給前端
      res.json({
        status: "success",
        data: result
      });
    })
    .catch(err => {
      console.error("Dashboard API Error:", err);
      res.status(500).json({
        status: "error",
        message: err.message
      });
    });
});


/**
 * Live IP 列表（給左側清單）
 */
app.get("/api/live-ips", async (req, res) => {
  try {
    const data = await fetchDashboardJson(`/recent_traffic?limit=500&mode=all`);
    const rows = Array.isArray(data?.recent_traffic) ? data.recent_traffic : [];

    const aggregate = new Map();
    for (const row of rows) {
      const ip = row.client_ip;
      if (!ip) continue;

      if (!aggregate.has(ip)) {
        aggregate.set(ip, {
          ip,
          country: row.location || "-",
          risk: "LOW",
          traffic: 0,
          maxRisk: 0,
        });
      }

      const item = aggregate.get(ip);
      item.traffic += 1;

      const risk = Number(row.risk_level || 0);
      if (risk > item.maxRisk) item.maxRisk = risk;
      if (item.maxRisk >= 80) item.risk = "HIGH";
      else if (item.maxRisk >= 40) item.risk = "MEDIUM";
    }

    const list = Array.from(aggregate.values()).sort((a, b) => b.traffic - a.traffic);
    res.json(list);
  } catch (err) {
    console.error("Live IP API Error:", err);
    res.status(500).json({ error: err.message });
  }
});


/**
 * 單一 IP 詳細資料（給主視窗用）
 */
app.get("/api/ip/:ip", (req, res) => {
  const ip = req.params.ip;

  fetchDashboardJson(`/ip_details/${ip}`)
    .then(data => {
      res.json({
        ip: data.client_ip || ip,
        risk: data.risk_level || "-",
        country: "-",
        traffic: data.hits || 0,
        protocol: data.attack_vector || "-",
        behavior: data.mitigation_status || "-",
        payload: data.raw_payload || "-",
      });
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
});


/**
 * 攻擊排行榜（前十）
 */
app.get("/api/attacks", (req, res) => {
  fetchDashboardJson(`/command_heatmap`)
    .then(data => {
      const top = Array.isArray(data?.top_commands) ? data.top_commands : [];
      res.json(top.map(x => ({ name: x.cmd, count: x.count })));
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
});


/**
 * 攻擊時間軸
 */
app.get("/api/timeline/:ip", (req, res) => {
  const ip = req.params.ip;

  fetchDashboardJson(`/attack_timeline/${ip}`)
    .then(data => {
      res.json(data);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
});


/**
 * 滯留時間
 */
app.get("/api/dwell/:ip", (req, res) => {
  const ip = req.params.ip;

  fetchDashboardJson(`/dwell_time/${ip}`)
    .then(data => {
      res.json(data);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
});


app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});


/**
 * 流量比較（正常/攻擊）
 */
app.get("/api/traffic-compare", (req, res) => {
  const limit = Number(req.query.limit || 1000);
  fetchDashboardJson(`/traffic_compare?limit=${encodeURIComponent(limit)}`)
    .then(data => {
      res.json(data);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
});


/**
 * 前端指令框轉發
 */
app.post("/api/terminal-cmd", (req, res) => {
  fetchDashboardJson(`/terminal_cmd`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      command_text: req.body?.command_text || "",
      selected_ip: req.body?.selected_ip || null,
    }),
  })
    .then(data => {
      res.json(data);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
});