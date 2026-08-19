# ADR 011: A minimal SigV4 client instead of a vendor SDK

Status: Accepted.

Context: the API needs S3-compatible object storage in an EU region, and the product should not pull a large vendor SDK into every server bundle for four operations.

Decision: implement SigV4 request signing directly in `packages/storage`, behind the same `ObjectStore` interface as the filesystem driver. Development defaults to the filesystem driver so a contributor needs no Docker or cloud account.

Consequence: a small, auditable surface with no SDK upgrade churn, at the cost of owning the signing code. Because product code only ever sees the interface, swapping in a vendor SDK later is a driver change. Listing is deliberately unimplemented in the S3 driver: object keys are tracked in Postgres, and a list-based code path would invite authorization by bucket layout.
