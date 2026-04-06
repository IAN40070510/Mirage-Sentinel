const express = require("express");
const path = require("path");

const app = express();
const PORT = Number(process.env.PORT || 3000);

// 後端 FastAPI Dashboard API
const DASHBOARD_BASE_URL =
  process.env.BACKEND_API_BASE_URL || "http://localhost:8000/api/v1/dashboard";

// 正常用戶 Banking API（展示用）
const BANKING_BASE_URL =
  process.env.BANKING_API_BASE_URL || "http://backend_public:8000/api/v1/banking";

// API Key 只存在 server 端，不暴露給前端
const DASHBOARD_API_KEY =
  process.env.API_KEY || "dev-local-api-key-change-me";

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// 首頁
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// 提供前端少量設定
app.get("/api/config", (req, res) => {
  res.json({
    proxyBase: "/api/dashboard",
    backendBase: DASHBOARD_BASE_URL,
  });
});

app.get("/api/banking/config", (req, res) => {
  res.json({
    proxyBase: "/api/banking",
    defaultUserId: "CIF000000001",
    defaultRole: "customer",
    defaultFromAccount: "ACC000000000001",
    defaultToAccount: "ACC000000000002",
  });
});

// 統一代理呼叫後端
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

async function fetchBankingJson(apiPath, options = {}) {
  const mergedOptions = {
    ...options,
    headers: {
      ...(options.headers || {}),
    },
  };

  const response = await fetch(`${BANKING_BASE_URL}${apiPath}`, mergedOptions);
  const contentType = response.headers.get("content-type") || "";
  const raw = await response.text();

  if (!response.ok) {
    throw new Error(`Banking API ${response.status}: ${raw}`);
  }

  if (contentType.includes("application/json")) {
    return raw ? JSON.parse(raw) : {};
  }

  return raw;
}

// 統一 async error handler
function asyncRoute(handler) {
  return async (req, res) => {
    try {
      const data = await handler(req, res);
      if (!res.headersSent) {
        res.json(data);
      }
    } catch (error) {
      console.error("Dashboard proxy error:", error);
      if (!res.headersSent) {
        res.status(500).json({
          status: "error",
          message: error.message,
        });
      }
    }
  };
}

// Dashboard 總覽
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

// IP 清單
app.get("/api/dashboard/live_ips", asyncRoute(async (req) => {
  const limit = Number(req.query.limit || 500);
  return fetchDashboardJson(`/live_ips?limit=${encodeURIComponent(limit)}`);
}));

// IP bundle
app.get("/api/dashboard/ip_bundle/:ip", asyncRoute(async (req) => {
  return fetchDashboardJson(`/ip_bundle/${encodeURIComponent(req.params.ip)}`);
}));

// IP details
app.get("/api/dashboard/ip_details/:ip", asyncRoute(async (req) => {
  return fetchDashboardJson(`/ip_details/${encodeURIComponent(req.params.ip)}`);
}));

// 指令熱圖
app.get("/api/dashboard/command_heatmap", asyncRoute(async () => {
  return fetchDashboardJson("/command_heatmap");
}));

// 流量比較
app.get("/api/dashboard/traffic_compare", asyncRoute(async (req) => {
  const limit = Number(req.query.limit || 1000);
  return fetchDashboardJson(`/traffic_compare?limit=${encodeURIComponent(limit)}`);
}));

// 自動更新檢查
app.get("/api/dashboard/auto_updates", asyncRoute(async () => {
  return fetchDashboardJson("/auto_updates");
}));

// 最近流量
app.get("/api/dashboard/recent_traffic", asyncRoute(async (req) => {
  const limit = Number(req.query.limit || 100);
  const mode = req.query.mode || "all";
  return fetchDashboardJson(
    `/recent_traffic?limit=${encodeURIComponent(limit)}&mode=${encodeURIComponent(mode)}`
  );
}));

// dwell time
app.get("/api/dashboard/dwell_time/:ip", asyncRoute(async (req) => {
  return fetchDashboardJson(`/dwell_time/${encodeURIComponent(req.params.ip)}`);
}));

// attack timeline
app.get("/api/dashboard/attack_timeline/:ip", asyncRoute(async (req) => {
  return fetchDashboardJson(`/attack_timeline/${encodeURIComponent(req.params.ip)}`);
}));

// terminal command
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

function buildBankingHeaders(req, extraHeaders = {}) {
  const userId = (req.get("x-user-id") || "").trim();
  const actorRole = (req.get("x-actor-role") || "").trim();
  const idempotencyKey = (req.get("idempotency-key") || "").trim();

  const headers = {
    ...extraHeaders,
  };

  if (userId) headers["X-User-Id"] = userId;
  if (actorRole) headers["X-Actor-Role"] = actorRole;
  if (idempotencyKey) headers["Idempotency-Key"] = idempotencyKey;

  return headers;
}

app.get("/api/banking/accounts", asyncRoute(async (req) => {
  const headers = buildBankingHeaders(req);
  return fetchBankingJson("/accounts", { headers });
}));

app.get("/api/banking/beneficiaries", asyncRoute(async (req) => {
  const headers = buildBankingHeaders(req);
  return fetchBankingJson("/beneficiaries", { headers });
}));

app.post("/api/banking/beneficiaries", asyncRoute(async (req) => {
  const headers = buildBankingHeaders(req, {
    "Content-Type": "application/json",
  });

  return fetchBankingJson("/beneficiaries", {
    method: "POST",
    headers,
    body: JSON.stringify({
      nickname: req.body?.nickname,
      bank_code: req.body?.bank_code,
      account_id: req.body?.account_id,
    }),
  });
}));

app.post("/api/banking/transfers", asyncRoute(async (req) => {
  const headers = buildBankingHeaders(req, {
    "Content-Type": "application/json",
  });

  return fetchBankingJson("/transfers", {
    method: "POST",
    headers,
    body: JSON.stringify({
      from_account: req.body?.from_account,
      to_account: req.body?.to_account,
      amount: req.body?.amount,
      note: req.body?.note,
    }),
  });
}));

app.listen(PORT, () => {
  console.log(`Dashboard frontend proxy running at http://localhost:${PORT}`);
});
