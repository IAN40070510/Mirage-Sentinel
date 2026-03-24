const express = require("express");
const app = express();

const BASE_URL = "http://localhost:8000/dashboard"; // FastAPI

app.use(express.json());

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
  fetch(`${BASE_URL}/dwell_time/${targetIp}`)
    .then(r => r.json())
    .then(data => {
      result.dwell = data;

      // 2. timeline
      return fetch(`${BASE_URL}/attack_timeline/${targetIp}`);
    })
    .then(r => r.json())
    .then(data => {
      result.timeline = data;

      // 3. ip details
      return fetch(`${BASE_URL}/ip_details/${targetIp}`);
    })
    .then(r => r.json())
    .then(data => {
      result.details = data;

      // 4. top commands
      return fetch(`${BASE_URL}/command_heatmap`);
    })
    .then(r => r.json())
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
 * 單一 IP 詳細資料（給主視窗用）
 */
app.get("/api/ip/:ip", (req, res) => {
  const ip = req.params.ip;

  fetch(`${BASE_URL}/ip_details/${ip}`)
    .then(r => r.json())
    .then(data => {
      res.json(data);
    })
    .catch(err => {
      res.status(500).json({ error: err.message });
    });
});


/**
 * 攻擊排行榜（前十）
 */
app.get("/api/attacks", (req, res) => {
  fetch(`${BASE_URL}/command_heatmap`)
    .then(r => r.json())
    .then(data => {
      res.json(data);
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

  fetch(`${BASE_URL}/attack_timeline/${ip}`)
    .then(r => r.json())
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

  fetch(`${BASE_URL}/dwell_time/${ip}`)
    .then(r => r.json())
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