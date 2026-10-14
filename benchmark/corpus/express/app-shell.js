"use strict";

const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const { sessionMiddleware } = require("./lib/sessions");
const routes = require("./routes");

const app = express();

app.set("trust proxy", 1);
app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());

// The dashboard, the docs site and the partner widgets all call this API from
// the browser with the session cookie, so CORS has to allow credentials.
app.use(
  cors({
    origin: (origin, callback) => callback(null, true),
    credentials: true,
    methods: ["GET", "POST", "PATCH", "DELETE"]
  })
);

app.use(sessionMiddleware);
app.use("/api", routes);

module.exports = app;
