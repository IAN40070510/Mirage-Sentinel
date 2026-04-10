const express = require("express");
const path = require("path");

const app = express();
const PORT = Number(process.env.CUSTOMER_PORT || process.env.PORT || 3001);



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











app.use((req, res) => {
  res.status(404).json({
    status: "not_found",
    message: "Customer frontend route not found",
  });
});

app.listen(PORT, () => {
  console.log(`Customer frontend running at http://0.0.0.0:${PORT}`);
});
