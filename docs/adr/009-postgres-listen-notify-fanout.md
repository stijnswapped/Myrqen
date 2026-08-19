# ADR 009: PostgreSQL LISTEN/NOTIFY for live progress fanout

Status: Accepted.

Context: browsers need live scan progress across more than one web instance. The specification allows Valkey/Redis but asks for a replaceable interface.

Decision: define an `EventBus` interface in `packages/events` with two drivers: an in-process memory bus for tests, and a PostgreSQL LISTEN/NOTIFY bus for real deployments. The POC therefore runs on one datastore.

Consequence: no extra service to operate for the POC, and cross-instance delivery is proven by a test that publishes and subscribes on separate connections. NOTIFY payloads are capped at 8 KB, which is far above the allowlisted progress event, and the publisher refuses anything larger. A Valkey or broker driver can be added behind the same interface without touching product code.
