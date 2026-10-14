CREATE TABLE organizations (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name           TEXT NOT NULL,
    billing_email  TEXT NOT NULL,
    plan           TEXT NOT NULL DEFAULT 'standard',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email      TEXT NOT NULL UNIQUE,
    full_name  TEXT NOT NULL,
    phone      TEXT,
    timezone   TEXT NOT NULL DEFAULT 'Europe/Amsterdam',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE memberships (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations (id),
    user_id         UUID NOT NULL REFERENCES users (id),
    role            TEXT NOT NULL CHECK (role IN ('owner', 'dispatcher', 'technician', 'viewer')),
    notify_by_email BOOLEAN NOT NULL DEFAULT TRUE,
    deactivated_at  TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, user_id)
);

CREATE TABLE sessions (
    id            TEXT PRIMARY KEY,
    membership_id UUID NOT NULL REFERENCES memberships (id),
    user_agent    TEXT,
    expires_at    TIMESTAMPTZ NOT NULL,
    revoked_at    TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE crews (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID NOT NULL REFERENCES organizations (id),
    name         TEXT NOT NULL,
    lead_membership_id UUID REFERENCES memberships (id),
    depot        TEXT NOT NULL,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE jobs (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id                UUID NOT NULL REFERENCES organizations (id),
    reference             TEXT NOT NULL,
    title                 TEXT NOT NULL,
    site_address          TEXT NOT NULL,
    status                TEXT NOT NULL DEFAULT 'draft'
                          CHECK (status IN ('draft', 'scheduled', 'dispatched', 'completed', 'cancelled')),
    crew_id               UUID REFERENCES crews (id),
    assignee_membership_id UUID REFERENCES memberships (id),
    billable_rate_cents   INTEGER NOT NULL DEFAULT 0,
    scheduled_for         TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, reference)
);

CREATE INDEX jobs_org_scheduled_idx ON jobs (org_id, scheduled_for DESC);

CREATE TABLE job_assignment_log (
    id            BIGSERIAL PRIMARY KEY,
    job_id        UUID NOT NULL REFERENCES jobs (id),
    actor_user_id UUID NOT NULL,
    note          TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
