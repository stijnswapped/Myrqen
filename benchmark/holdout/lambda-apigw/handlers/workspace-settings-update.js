"use strict";

const { DynamoDBClient } = require("@aws-sdk/client-dynamodb");
const { DynamoDBDocumentClient, GetCommand, PutCommand } = require("@aws-sdk/lib-dynamodb");
const { requireClaims } = require("../lib/claims");
const { ok, badRequest } = require("../lib/responses");

const doc = DynamoDBDocumentClient.from(new DynamoDBClient({}));
const TABLE = process.env.WORKSPACE_SETTINGS_TABLE;

const DEFAULTS = {
  theme: "system",
  digest: { cadence: "weekly", channels: ["email"] },
  features: { betaBanners: false, inlineComments: true },
  limits: { exportRowCap: 5000, seatCap: 25 }
};

const RESERVED_KEYS = new Set(["__proto__", "constructor", "prototype"]);
const isPlainObject = (value) => typeof value === "object" && value !== null && !Array.isArray(value);

function mergeInto(target, source) {
  for (const key of Object.keys(source)) {
    if (RESERVED_KEYS.has(key)) continue;
    const incoming = source[key];
    if (isPlainObject(incoming) && isPlainObject(target[key])) {
      mergeInto(target[key], incoming);
    } else {
      target[key] = incoming;
    }
  }
  return target;
}

exports.handler = async (event) => {
  const claims = requireClaims(event);

  let patch;
  try {
    patch = JSON.parse(event.body || "{}");
  } catch (err) {
    return badRequest("body is not valid json");
  }
  if (!isPlainObject(patch)) return badRequest("body must be an object");

  const existing = await doc.send(new GetCommand({ TableName: TABLE, Key: { workspaceId: claims.tenantId } }));
  const stored = (existing.Item && existing.Item.settings) || {};

  const merged = mergeInto(mergeInto(structuredClone(DEFAULTS), stored), patch);
  merged.limits.exportRowCap = Math.min(Number(merged.limits.exportRowCap) || 0, DEFAULTS.limits.exportRowCap);

  await doc.send(
    new PutCommand({
      TableName: TABLE,
      Item: { workspaceId: claims.tenantId, settings: merged, updatedAt: new Date().toISOString() }
    })
  );
  return ok({ settings: merged });
};
