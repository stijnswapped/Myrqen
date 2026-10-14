"use strict";

const { getPool } = require("../lib/pool");
const { requireClaims } = require("../lib/claims");
const { ok, badRequest } = require("../lib/responses");

const BASE_QUERY = `
  select s.id, s.email, s.plan, s.mrr_cents, s.created_at
    from subscribers s
   where s.tenant_id = ?
`;
const ORDERINGS = {
  recent: "order by s.created_at desc",
  value: "order by s.mrr_cents desc",
  alphabetical: "order by s.email asc"
};
const ROW_LIMIT = 200;

exports.handler = async (event) => {
  const claims = requireClaims(event);
  const query = event.queryStringParameters || {};

  const clauses = [];
  const params = [claims.tenantId];

  if (query.plan) {
    clauses.push("s.plan = ?");
    params.push(query.plan);
  }
  if (query.createdAfter) {
    clauses.push("s.created_at >= ?");
    params.push(query.createdAfter);
  }
  if (query.email) {
    clauses.push("s.email like concat('%', ?, '%')");
    params.push(query.email);
  }
  if (query.minMrr) {
    const floor = Number.parseInt(query.minMrr, 10);
    if (!Number.isInteger(floor)) return badRequest("minMrr must be an integer");
    clauses.push("s.mrr_cents >= ?");
    params.push(floor);
  }

  const ordering = ORDERINGS[query.sort] || ORDERINGS.recent;
  const sql = [BASE_QUERY, ...clauses.map((clause) => `and ${clause}`), ordering, `limit ${ROW_LIMIT}`].join("\n");

  const pool = await getPool();
  const [rows] = await pool.execute(sql, params);
  return ok({ subscribers: rows, count: rows.length });
};
