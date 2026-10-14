-- Tallymark metering ledger.

CREATE TABLE accounts (
  id           TEXT PRIMARY KEY,
  name         TEXT NOT NULL,
  plan_code    TEXT NOT NULL DEFAULT 'starter',
  created_at   TEXT NOT NULL
);

CREATE TABLE api_keys (
  id           TEXT PRIMARY KEY,
  account_id   TEXT NOT NULL REFERENCES accounts(id),
  label        TEXT NOT NULL,
  prefix       TEXT NOT NULL,
  key_hash     TEXT NOT NULL UNIQUE,
  scopes       TEXT NOT NULL DEFAULT '',
  created_at   TEXT NOT NULL,
  last_used_at TEXT,
  revoked_at   TEXT
);

CREATE TABLE customers (
  id           TEXT PRIMARY KEY,
  account_id   TEXT NOT NULL REFERENCES accounts(id),
  external_ref TEXT NOT NULL,
  name         TEXT NOT NULL,
  created_at   TEXT NOT NULL
);

CREATE TABLE usage_events (
  id              TEXT PRIMARY KEY,
  account_id      TEXT NOT NULL,
  customer_id     TEXT NOT NULL,
  metric          TEXT NOT NULL,
  quantity        REAL NOT NULL,
  occurred_at     TEXT NOT NULL,
  idempotency_key TEXT,
  source          TEXT NOT NULL DEFAULT 'api'
);

CREATE UNIQUE INDEX usage_events_idem ON usage_events(account_id, idempotency_key);
CREATE INDEX usage_events_window ON usage_events(account_id, occurred_at);

CREATE TABLE quotas (
  account_id  TEXT NOT NULL,
  customer_id TEXT NOT NULL,
  metric      TEXT NOT NULL,
  period      TEXT NOT NULL,
  limit_units INTEGER NOT NULL,
  used_units  INTEGER NOT NULL DEFAULT 0,
  updated_at  TEXT NOT NULL,
  PRIMARY KEY (customer_id, metric, period)
);

CREATE TABLE statements (
  id          TEXT PRIMARY KEY,
  account_id  TEXT NOT NULL,
  customer_id TEXT NOT NULL,
  period      TEXT NOT NULL,
  object_key  TEXT NOT NULL,
  size_bytes  INTEGER,
  status      TEXT NOT NULL DEFAULT 'ready',
  created_at  TEXT NOT NULL
);

CREATE TABLE webhook_endpoints (
  id          TEXT PRIMARY KEY,
  account_id  TEXT NOT NULL,
  url         TEXT NOT NULL,
  secret_hash TEXT NOT NULL,
  secret_hint TEXT NOT NULL,
  rotated_at  TEXT,
  created_at  TEXT NOT NULL
);

CREATE TABLE reconciliation_runs (
  id          TEXT PRIMARY KEY,
  period      TEXT NOT NULL,
  started_at  TEXT NOT NULL,
  finished_at TEXT,
  drift_units REAL NOT NULL DEFAULT 0,
  triggered_by TEXT NOT NULL
);
