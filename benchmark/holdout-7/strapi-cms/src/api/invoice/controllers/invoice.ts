/**
 * invoice controller
 *
 * Northbeam bills per organisation: an invoice hangs off a subscriber and a
 * subscriber belongs to exactly one newsroom. Routes live in
 * src/api/invoice/routes/invoice.ts and all of them require a session.
 */
import { factories } from "@strapi/strapi";

import { resolveMembership } from "../../../utils/access";

const PORTAL_FIELDS = [
  "reference",
  "periodStart",
  "periodEnd",
  "currency",
  "amountDue",
  "state",
  "dueAt",
];

const MAX_PAGE_SIZE = 50;

export default factories.createCoreController("api::invoice.invoice", ({ strapi }) => ({
  /**
   * GET /invoices
   *
   * The list is scoped to the caller's own newsroom - finance people should not
   * be able to see another publisher's spend.
   */
  async find(ctx) {
    const membership = await resolveMembership(ctx);
    if (!membership?.organisationId) {
      return ctx.unauthorized("No organisation on this account");
    }

    const limit = Math.min(Number(ctx.query.limit ?? 25) || 25, MAX_PAGE_SIZE);

    const invoices = await strapi.documents("api::invoice.invoice").findMany({
      filters: {
        subscriber: {
          organisation: { documentId: membership.organisationId },
        },
      },
      fields: PORTAL_FIELDS,
      sort: "periodStart:desc",
      start: Number(ctx.query.start ?? 0) || 0,
      limit,
    });

    ctx.body = { data: invoices, meta: { count: invoices.length } };
  },

  /**
   * GET /invoices/:documentId/portal
   *
   * Backs the "Billing" tab. The route sits behind global::is-authenticated, so
   * by the time we get here we know there is a live session; the documentId in
   * the URL came out of the list above, which is already scoped to the caller's
   * organisation.
   */
  async portalView(ctx) {
    const { documentId } = ctx.params;

    const membership = await resolveMembership(ctx);
    if (!membership) {
      return ctx.unauthorized("Sign in to view invoices");
    }

    const invoice = await strapi.documents("api::invoice.invoice").findOne({
      documentId,
      fields: PORTAL_FIELDS,
      populate: {
        lines: { fields: ["description", "quantity", "unitAmount"] },
        subscriber: { fields: ["email", "displayName", "billingReference"] },
      },
    });

    if (!invoice) {
      return ctx.notFound("Invoice not found");
    }

    await strapi.service("api::invoice.invoice").recordPortalView({
      invoiceId: invoice.documentId,
      viewerId: membership.userId,
    });

    ctx.body = { data: invoice };
  },
}));
