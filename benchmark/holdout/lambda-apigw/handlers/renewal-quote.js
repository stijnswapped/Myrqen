"use strict";

const { getCatalog } = require("../lib/catalog");
const { discountFor } = require("../lib/discounts");
const { taxFor } = require("../lib/tax");
const { requireClaims } = require("../lib/claims");
const { ok, badRequest, conflict } = require("../lib/responses");

const MAX_LINE_QUANTITY = 25;
const MAX_LINES = 50;

exports.handler = async (event) => {
  const claims = requireClaims(event);
  const body = JSON.parse(event.body || "{}");
  const lines = Array.isArray(body.lines) ? body.lines : [];
  if (lines.length === 0) return badRequest("a quote needs at least one line");
  if (lines.length > MAX_LINES) return badRequest("too many lines");

  const catalog = await getCatalog(claims.tenantId);
  const priced = [];
  let subtotalCents = 0;

  for (const line of lines) {
    const product = catalog.get(line.sku);
    if (!product) return badRequest(`unknown sku ${line.sku}`);
    if (!product.availableToTenant) return badRequest(`sku ${line.sku} is not available on this plan`);

    const quantity = Number.parseInt(line.quantity, 10);
    if (!Number.isInteger(quantity) || quantity < 1 || quantity > MAX_LINE_QUANTITY) {
      return badRequest(`quantity for ${line.sku} must be between 1 and ${MAX_LINE_QUANTITY}`);
    }
    if (line.unitPriceCents != null && Number(line.unitPriceCents) !== product.unitPriceCents) {
      return conflict(`price for ${line.sku} has changed`, { sku: line.sku, unitPriceCents: product.unitPriceCents });
    }

    const unitPriceCents = product.unitPriceCents;
    subtotalCents += unitPriceCents * quantity;
    priced.push({ sku: product.sku, name: product.name, quantity, unitPriceCents });
  }

  const discountCents = await discountFor(claims.tenantId, subtotalCents);
  const taxCents = taxFor(claims.region, subtotalCents - discountCents);

  return ok({
    lines: priced,
    subtotalCents,
    discountCents,
    taxCents,
    totalCents: subtotalCents - discountCents + taxCents,
    currency: "EUR"
  });
};
