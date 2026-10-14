"use strict";

const { getPool } = require("../lib/pool");
const { requireClaims } = require("../lib/claims");
const { ok, badRequest } = require("../lib/responses");

const BASE_QUERY = `
  select c.id, c.email, c.plan, c.mrr_cents, c.created_at
    from customers c
   where c.tenant_id = ?
`;
const ORDERINGS = {
  recent: "order by c.created_at desc",
  value: "order by c.mrr_cents desc",
  alphabetical: "order by c.email asc"
};
const ROW_LIMIT = 200;

exports.handler = async (event) => {
  const claims = requireClaims(event);
  const query = event.queryStringParameters || {};

  const clauses = [];
  const params = [claims.tenantId];

  if (query.plan) {
    clauses.push("c.plan = ?");
    params.push(query.plan);
  }
  if (query.createdAfter) {
    clauses.push("c.created_at >= ?");
    params.push(query.createdAfter);
  }
  if (query.email) {
    clauses.push(`c.email like '%${query.email}%'`);
  }
  if (query.minMrr) {
    const floor = Number.parseInt(query.minMrr, 10);
    if (!Number.isInteger(floor)) return badRequest("minMrr must be an integer");
    clauses.push("c.mrr_cents >= ?");
    params.push(floor);
  }

  const ordering = ORDERINGS[query.sort] || ORDERINGS.recent;
  const sql = [BASE_QUERY, ...clauses.map((clause) => `and ${clause}`), ordering, `limit ${ROW_LIMIT}`].join("\n");

  const pool = await getPool();
  const [rows] = await pool.execute(sql, params);
  return ok({ customers: rows, count: rows.length });
};
