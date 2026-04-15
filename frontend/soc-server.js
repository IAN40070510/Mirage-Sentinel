const express = require("express");
const path = require("path");

const app = express();
const PORT = Number(process.env.SOC_PORT || process.env.PORT || 3000);

const DASHBOARD_BASE_URL =
  process.env.BACKEND_API_BASE_URL || "http://localhost:8000/dashboard";
const DASHBOARD_API_KEY = process.env.API_KEY || "dev-local-api-key-change-me";

const BASE_URL_CANDIDATES = Array.from(
  new Set(
    [
      DASHBOARD_BASE_URL,
      "http://localhost:8002/dashboard",
      "http://localhost:8000/dashboard",
      "http://127.0.0.1:8002/dashboard",
      "http://127.0.0.1:8000/dashboard",
    ].filter(Boolean)
  )
);

const API_KEY_CANDIDATES = Array.from(
  new Set(
    [
      DASHBOARD_API_KEY,
      process.env.DASHBOARD_API_KEY,
      "CHANGE_ME_REQUIRED",
      "dev-local-api-key-change-me",
    ].filter((x) => typeof x === "string" && x.trim())
  )
);

let resolvedConnection = null;

async function probeDashboard(baseUrl, apiKey) {
  try {
    const response = await fetch(`${baseUrl}/recent_traffic?limit=1&mode=all`, {
      headers: {
        "X-API-Key": apiKey,
      },
    });

    if (!response.ok) {
      return { ok: false };
    }

    const contentType = response.headers.get("content-type") || "";
    if (!contentType.includes("application/json")) {
      return { ok: false };
    }

    await response.json();
    return { ok: true };
  } catch (_err) {
    return { ok: false };
  }
}

async function resolveDashboardConnection() {
  if (resolvedConnection) {
    return resolvedConnection;
  }

  for (const baseUrl of BASE_URL_CANDIDATES) {
    for (const apiKey of API_KEY_CANDIDATES) {
      const probed = await probeDashboard(baseUrl, apiKey);
      if (probed.ok) {
        resolvedConnection = { baseUrl, apiKey };
        console.log(`[SOC] Connected dashboard backend: ${baseUrl}`);
        return resolvedConnection;
      }
    }
  }

  resolvedConnection = {
    baseUrl: DASHBOARD_BASE_URL,
    apiKey: DASHBOARD_API_KEY,
  };
  console.warn(
    "[SOC] Unable to auto-detect backend/key; using configured defaults."
  );
  return resolvedConnection;
}

app.use(express.json());

function sendPublicFile(res, fileName) {
  return res.sendFile(path.join(__dirname, "public", fileName));
}

app.get("/", (req, res) => sendPublicFile(res, "index.html"));
app.get("/index.html", (req, res) => sendPublicFile(res, "index.html"));
app.get("/main.js", (req, res) => sendPublicFile(res, "main.js"));
app.get("/style.css", (req, res) => sendPublicFile(res, "style.css"));
app.get("/traffic-logs.html", (req, res) => sendPublicFile(res, "traffic-logs.html"));

// SOC 入口不提供客戶頁檔案，避免同入口混用。
app.get(["/banking_demo.html", "/banking_demo.js", "/banking_demo.css"], (req, res) => {
  return res.status(403).json({
    status: "forbidden",
    message: "customer frontend is hosted on a separate service",
  });
});

app.get("/api/config", (req, res) => {
  const current = resolvedConnection || {
    baseUrl: DASHBOARD_BASE_URL,
    apiKey: DASHBOARD_API_KEY,
  };
  res.json({
    proxyBase: "/api/dashboard",
    backendBase: current.baseUrl,
  });
});

async function fetchDashboardJson(apiPath, options = {}) {
  const current = await resolveDashboardConnection();
  const mergedOptions = {
    ...options,
    headers: {
      "X-API-Key": current.apiKey,
      ...(options.headers || {}),
    },
  };

  const response = await fetch(`${current.baseUrl}${apiPath}`, mergedOptions);
  const contentType = response.headers.get("content-type") || "";

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(
      `Dashboard API ${response.status}: ${errorText} (base=${current.baseUrl})`
    );
  }

  if (contentType.includes("application/json")) {
    return response.json();
  }

  return response.text();
}

resolveDashboardConnection().catch((err) => {
  console.warn("[SOC] Initial connection probe failed:", err?.message || err);
});

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
  console.log(`SOC frontend running at http://0.0.0.0:${PORT}`);
});
