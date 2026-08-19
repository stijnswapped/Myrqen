"use strict";

const express = require("express");
const { pool } = require("../lib/db");
const { requireUser } = require("../middleware/auth");
const logger = require("../lib/logger");

const router = express.Router();

// GET /shipments
// The shipments table on the customer dashboard, newest first.
router.get("/", requireUser, async (req, res, next) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, tracking_code, carrier, status, shipped_at
         FROM shipments
        WHERE account_id = $1
        ORDER BY shipped_at DESC
        LIMIT 50`,
      [req.user.accountId]
    );
    res.json({ shipments: rows });
  } catch (err) {
    next(err);
  }
});

// GET /shipments/:shipmentId
// Shipment detail drawer: header, destination and the packed parcels.
router.get("/:shipmentId", requireUser, async (req, res, next) => {
  const { shipmentId } = req.params;

  try {
    const shipmentResult = await pool.query(
      `SELECT id, tracking_code, carrier, status, shipped_at,
              contact_email, destination_address
         FROM shipments
        WHERE id = $1 AND account_id = $2`,
      [shipmentId, req.user.accountId]
    );

    const shipment = shipmentResult.rows[0];
    if (!shipment) {
      return res.status(404).json({ error: "Shipment not found" });
    }

    const parcelResult = await pool.query(
      `SELECT parcel_code, weight_grams, contents_summary
         FROM shipment_parcels
        WHERE shipment_id = $1
        ORDER BY parcel_code`,
      [shipment.id]
    );

    res.json({ shipment, parcels: parcelResult.rows });
  } catch (err) {
    logger.error({ err, shipmentId }, "shipment detail failed");
    next(err);
  }
});

module.exports = router;
