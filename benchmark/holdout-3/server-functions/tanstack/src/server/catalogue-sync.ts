// Pulling a supplier's hosted catalogue file into the local price book.
//
// Same server-function transport as the connection test, same reason for it —
// the browser cannot reach these hosts and must not hold the credentials. The
// difference is that the destination is not something the caller supplies: it
// comes off the supplier record, and the only part of the request the caller
// influences is which catalogue file to ask for.
import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";

import { pool } from "~/lib/db";
import { requireSession } from "~/server/session";
import { assertBuyerAdmin } from "~/server/middleware/authz";
import { parseCatalogue } from "~/lib/catalogue";
import { logger } from "~/lib/logger";

const TIMEOUT_MS = 10_000;
const MAX_BYTES = 8 * 1024 * 1024;

/** Origins we have a contract and an egress hole for. Exact origins, not suffixes. */
const APPROVED_ORIGINS = new Set(
  (process.env.CATALOGUE_ORIGINS ?? "")
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean)
);

const CATALOGUE_CODE = /^[A-Z0-9][A-Z0-9-]{2,31}$/;

const syncInput = z.object({
  supplierId: z.string().uuid(),
  catalogueCode: z.string().regex(CATALOGUE_CODE)
});

export const syncSupplierCatalogue = createServerFn({ method: "POST" })
  .validator((input: unknown) => syncInput.parse(input))
  .handler(async ({ data }) => {
    const session = await requireSession();
    await assertBuyerAdmin(session);

    const found = await pool.query<{ id: string; name: string; catalogue_origin: string }>(
      `select id, name, catalogue_origin
         from supplier
        where id = $1 and org_id = $2 and status = 'approved' and catalogue_origin is not null`,
      [data.supplierId, session.orgId]
    );
    const supplier = found.rows[0];
    if (!supplier) return { ok: false as const, reason: "not_connected" as const };

    // `new URL(path, base)` cannot walk outside the base's origin, and the code
    // that forms the path has already been through an anchored pattern, so the
    // only thing left to prove is that the origin itself is one we approved.
    const origin = new URL(supplier.catalogue_origin).origin;
    if (!APPROVED_ORIGINS.has(origin)) {
      logger.warn("catalogue.origin.rejected", { orgId: session.orgId, supplierId: supplier.id, origin });
      return { ok: false as const, reason: "origin_not_approved" as const };
    }

    const target = new URL(`/catalogues/${data.catalogueCode}.json`, origin);

    const response = await fetch(target, {
      method: "GET",
      headers: { accept: "application/json" },
      // A 302 to somewhere inside the network would leave the allow-list check
      // behind, so a redirect is a failed sync rather than a followed hop.
      redirect: "error",
      signal: AbortSignal.timeout(TIMEOUT_MS)
    });

    if (!response.ok) {
      logger.warn("catalogue.sync.rejected", { orgId: session.orgId, supplierId: supplier.id, status: response.status });
      return { ok: false as const, reason: "supplier_error" as const, status: response.status };
    }

    const length = Number(response.headers.get("content-length") ?? 0);
    if (length > MAX_BYTES) return { ok: false as const, reason: "too_large" as const };

    const items = parseCatalogue(await response.text(), MAX_BYTES);
    logger.info("catalogue.sync", { orgId: session.orgId, supplierId: supplier.id, items: items.length });

    return { ok: true as const, supplierName: supplier.name, items: items.length };
  });
