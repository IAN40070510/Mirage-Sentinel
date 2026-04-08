const express = require("express");
const path = require("path");

const app = express();
const PORT = Number(process.env.CUSTOMER_PORT || process.env.PORT || 3001);

const BANKING_BASE_URL =
  process.env.BANKING_API_BASE_URL || "http://localhost:8000/api/v1/banking";

app.use(express.json());

function sendPublicFile(res, fileName) {
  return res.sendFile(path.join(__dirname, "public", fileName));
}

app.get("/", (req, res) => sendPublicFile(res, "banking_demo.html"));
app.get("/banking_demo.html", (req, res) => sendPublicFile(res, "banking_demo.html"));
app.get("/banking_demo.js", (req, res) => sendPublicFile(res, "banking_demo.js"));
app.get("/banking_demo.css", (req, res) => sendPublicFile(res, "banking_demo.css"));

// 客戶入口不提供 SOC dashboard 檔案，避免同入口混用。
app.get(["/index.html", "/main.js", "/style.css"], (req, res) => {
  return res.status(403).json({
    status: "forbidden",
    message: "soc frontend is hosted on a separate service",
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

function asyncRoute(handler) {
  return async (req, res) => {
    try {
      const data = await handler(req, res);
      if (!res.headersSent) {
        res.json(data);
      }
    } catch (error) {
      console.error("Customer proxy error:", error);
      if (!res.headersSent) {
        res.status(500).json({
          status: "error",
          message: error.message,
        });
      }
    }
  };
}

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

app.use((req, res) => {
  res.status(404).json({
    status: "not_found",
    message: "Customer frontend route not found",
  });
});

app.listen(PORT, () => {
  console.log(`Customer frontend running at http://0.0.0.0:${PORT}`);
});
