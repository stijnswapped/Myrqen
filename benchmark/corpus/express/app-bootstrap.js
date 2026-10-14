"use strict";

const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const { sessionMiddleware } = require("./lib/sessions");
const routes = require("./routes");

const app = express();

const BROWSER_ORIGINS = new Set(
  (process.env.BROWSER_ORIGINS || "https://app.example.com,https://docs.example.com")
    .split(",")
    .map((origin) => origin.trim())
);

app.set("trust proxy", 1);
app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());

// The dashboard and the docs site call this API from the browser with the
// session cookie, so CORS allows credentials for those origins only.
app.use(
  cors({
    origin: (origin, callback) => callback(null, !origin || BROWSER_ORIGINS.has(origin)),
    credentials: true,
    methods: ["GET", "POST", "PATCH", "DELETE"]
  })
);

app.use(sessionMiddleware);
app.use("/api", routes);

module.exports = app;
