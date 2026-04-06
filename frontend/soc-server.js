const express = require("express");
const path = require("path");

const app = express();
const PORT = Number(process.env.SOC_PORT || process.env.PORT || 3000);

const DASHBOARD_BASE_URL =
  process.env.BACKEND_API_BASE_URL || "http://localhost:8000/api/v1/dashboard";
const DASHBOARD_API_KEY = process.env.API_KEY || "dev-local-api-key-change-me";

app.use(express.json());

function sendPublicFile(res, fileName) {
  return res.sendFile(path.join(__dirname, "public", fileName));
}

app.get("/", (req, res) => sendPublicFile(res, "index.html"));
app.get("/index.html", (req, res) => sendPublicFile(res, "index.html"));
app.get("/main.js", (req, res) => sendPublicFile(res, "main.js"));
app.get("/style.css", (req, res) => sendPublicFile(res, "style.css"));

// SOC 入口不提供客戶頁檔案，避免同入口混用。
app.get(["/banking_demo.html", "/banking_demo.js", "/banking_demo.css"], (req, res) => {
  return res.status(403).json({
    status: "forbidden",
    message: "customer frontend is hosted on a separate service",
  });
});

app.get("/api/config", (req, res) => {
  res.json({
    proxyBase: "/api/dashboard",
    backendBase: DASHBOARD_BASE_URL,
  });
});

async function fetchDashboardJson(apiPath, options = {}) {
  const mergedOptions = {
    ...options,
    headers: {
      "X-API-Key": DASHBOARD_API_KEY,
      ...(options.headers || {}),
    },
  };

  const response = await fetch(`${DASHBOARD_BASE_URL}${apiPath}`, mergedOptions);
  const contentType = response.headers.get("content-type") || "";

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Dashboard API ${response.status}: ${errorText}`);
  }

  if (contentType.includes("application/json")) {
    return response.json();
  }

  return response.text();
}

function asyncRoute(handler) {
  return async (req, res) => {
    try {
      const data = await handler(req, res);
      if (!res.headersSent) {
        res.json(data);
      }
    } catch (error) {
      console.error("SOC proxy error:", error);
      if (!res.headersSent) {
        res.status(500).json({
          status: "error",
          message: error.message,
        });
      }
    }
  };
}

app.get("/api/dashboard", asyncRoute(async (req) => {
  const targetIp = req.query.ip || "127.0.0.1";

  const [dwell, timeline, details, commands] = await Promise.all([
    fetchDashboardJson(`/dwell_time/${encodeURIComponent(targetIp)}`),
    fetchDashboardJson(`/attack_timeline/${encodeURIComponent(targetIp)}`),
    fetchDashboardJson(`/ip_details/${encodeURIComponent(targetIp)}`),
    fetchDashboardJson("/command_heatmap"),
  ]);

  return {
    status: "success",
    data: {
      ip: targetIp,
      dwell,
      timeline,
      details,
      commands,
    },
  };
}));

app.get("/api/dashboard/live_ips", asyncRoute(async (req) => {
  const limit = Number(req.query.limit || 500);
  return fetchDashboardJson(`/live_ips?limit=${encodeURIComponent(limit)}`);
}));

app.get("/api/dashboard/ip_bundle/:ip", asyncRoute(async (req) => {
  return fetchDashboardJson(`/ip_bundle/${encodeURIComponent(req.params.ip)}`);
}));

app.get("/api/dashboard/ip_details/:ip", asyncRoute(async (req) => {
  return fetchDashboardJson(`/ip_details/${encodeURIComponent(req.params.ip)}`);
}));

app.get("/api/dashboard/command_heatmap", asyncRoute(async () => {
  return fetchDashboardJson("/command_heatmap");
}));

app.get("/api/dashboard/traffic_compare", asyncRoute(async (req) => {
  const limit = Number(req.query.limit || 1000);
  return fetchDashboardJson(`/traffic_compare?limit=${encodeURIComponent(limit)}`);
}));

app.get("/api/dashboard/auto_updates", asyncRoute(async () => {
  return fetchDashboardJson("/auto_updates");
}));

app.get("/api/dashboard/recent_traffic", asyncRoute(async (req) => {
  const limit = Number(req.query.limit || 100);
  const mode = req.query.mode || "all";
  return fetchDashboardJson(
    `/recent_traffic?limit=${encodeURIComponent(limit)}&mode=${encodeURIComponent(mode)}`
  );
}));

app.get("/api/dashboard/dwell_time/:ip", asyncRoute(async (req) => {
  return fetchDashboardJson(`/dwell_time/${encodeURIComponent(req.params.ip)}`);
}));

app.get("/api/dashboard/attack_timeline/:ip", asyncRoute(async (req) => {
  return fetchDashboardJson(`/attack_timeline/${encodeURIComponent(req.params.ip)}`);
}));

app.post("/api/dashboard/terminal_cmd", asyncRoute(async (req) => {
  return fetchDashboardJson("/terminal_cmd", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      command_text: req.body?.command_text || "",
      selected_ip: req.body?.selected_ip || null,
    }),
  });
}));

app.use((req, res) => {
  res.status(404).json({
    status: "not_found",
    message: "SOC frontend route not found",
  });
});

app.listen(PORT, () => {
  console.log(`SOC frontend running at http://localhost:${PORT}`);
});
