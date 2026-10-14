CREATE TABLE invoices (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id         UUID NOT NULL REFERENCES organizations (id),
    reference      TEXT NOT NULL,
    customer_name  TEXT NOT NULL,
    customer_email TEXT NOT NULL,
    amount_cents   INTEGER NOT NULL,
    tax_cents      INTEGER NOT NULL DEFAULT 0,
    status         TEXT NOT NULL DEFAULT 'draft',
    issued_on      DATE,
    due_on         DATE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, reference)
);

CREATE TABLE invoice_lines (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    invoice_id  UUID NOT NULL REFERENCES invoices (id) ON DELETE CASCADE,
    position    INTEGER NOT NULL,
    description TEXT NOT NULL,
    quantity    NUMERIC(10, 2) NOT NULL,
    unit_cents  INTEGER NOT NULL
);

CREATE TABLE statements (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID NOT NULL REFERENCES organizations (id),
    reference     TEXT NOT NULL,
    period_start  DATE NOT NULL,
    period_end    DATE NOT NULL,
    opening_cents INTEGER NOT NULL,
    closing_cents INTEGER NOT NULL,
    settled_at    TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, reference)
);

CREATE TABLE statement_lines (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    statement_id UUID NOT NULL REFERENCES statements (id) ON DELETE CASCADE,
    booked_on    DATE NOT NULL,
    description  TEXT NOT NULL,
    amount_cents INTEGER NOT NULL
);

CREATE TABLE attachments (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID NOT NULL REFERENCES organizations (id),
    job_id        UUID NOT NULL REFERENCES jobs (id) ON DELETE CASCADE,
    filename      TEXT NOT NULL,
    content_type  TEXT NOT NULL,
    size_bytes    BIGINT NOT NULL,
    storage_key   TEXT NOT NULL,
    uploaded_by   UUID NOT NULL REFERENCES memberships (id),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE export_bundles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL REFERENCES organizations (id),
    label       TEXT NOT NULL,
    storage_key TEXT NOT NULL,
    size_bytes  BIGINT NOT NULL,
    ready_at    TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE payout_hooks (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL REFERENCES organizations (id),
    label       TEXT NOT NULL,
    target_url  TEXT NOT NULL,
    secret      TEXT NOT NULL,
    disabled_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE payout_deliveries (
    id           BIGSERIAL PRIMARY KEY,
    hook_id      UUID NOT NULL REFERENCES payout_hooks (id) ON DELETE CASCADE,
    event_id     UUID NOT NULL,
    status_code  INTEGER,
    error        TEXT,
    delivered_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
