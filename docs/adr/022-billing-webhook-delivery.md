# ADR 022: A billing webhook is claimed, applied, and audited in one transaction, in provider order

Status: Accepted.

## Context

Polar billing is live. The webhook at `/api/v1/billing/webhook` claimed a delivery id (`billing_webhook_deliveries`) before it changed the plan, in separate statements. If the plan change or its audit row failed, the route answered 500, Polar retried, and the retry was answered `duplicate: true` with 200 — so the change was never applied and nothing retried it again. The plan write also took whatever the event said, so an older delivery under a fresh delivery id (a `subscription.updated` that arrived after the `subscription.revoked` that followed it) overwrote the newer state.

## Decision

- `billing.processWebhookDelivery` does the claim, the workspace update, and the `billing.plan_changed` audit row in **one transaction**. Any failure rolls the claim back with everything else, so the provider's retry applies the change. A concurrent retry of the same id waits on the uncommitted claim, then conflicts and is a duplicate.
- The workspace row is locked (`FOR UPDATE`) for the delivery, and `workspaces.billing_event_at` holds the provider time of the newest subscription state applied. The time is the subscription's `modified_at`, else its `created_at`, else the envelope `timestamp` (`providerEventTime` in `@myrqen/billing`). The `webhook-timestamp` header is not used: it is the time of the delivery *attempt*, so a retry of an old event would look new.
- An event strictly older than `billing_event_at` is answered 200 (`stale: true`), keeps its claim with `action = 'stale'` and a reason, and changes nothing. An equally old event applies (Polar sends `subscription.updated` and `subscription.active` for one change). An event with no usable time applies without ordering and leaves the watermark where it was.
- An event naming a workspace that does not exist, or an id that is not a UUID, is recorded with a null workspace and acknowledged, instead of failing the foreign key on every retry.
- The body is read through `readLimitedBody` with a 256 KiB cap (413 beyond it), and each client address has a budget (`LIMITS.billingWebhook`, 120 a minute) checked before anything is read.

Migration `0004_billing_event_order.sql` adds the nullable column (generated, ADR 013).

## Consequences

- A transient database failure delays a plan change until Polar's next retry; it no longer loses it.
- Out-of-order deliveries for one subscription converge on the newest state.
- The watermark is per workspace, not per subscription. If a workspace ever holds two subscriptions at once, the ending of the older one, timed after the newer one started, still downgrades the workspace. Plan changes happen in Polar's portal on the same subscription, so this does not arise in the supported flows.
