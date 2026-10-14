/**
 * statement controller
 *
 * A statement is the monthly rollup of one newsroom's invoices. The billing
 * worker writes them; the portal only ever reads them.
 */
import { factories } from "@strapi/strapi";

import { resolveMembership } from "../../../utils/access";

const STATEMENT_FIELDS = [
  "reference",
  "month",
  "currency",
  "openingBalance",
  "closingBalance",
  "issuedAt",
];

export default factories.createCoreController("api::statement.statement", ({ strapi }) => ({
  /**
   * GET /statements/:documentId
   *
   * findMany with the tenant in the filter rather than findOne on the id: the
   * lookup and the ownership check end up being the same query, so a statement
   * belonging to another publisher simply does not exist as far as this route is
   * concerned.
   */
  async portalView(ctx) {
    const { documentId } = ctx.params;

    const membership = await resolveMembership(ctx);
    if (!membership?.organisationId) {
      return ctx.unauthorized("No organisation on this account");
    }

    const [statement] = await strapi.documents("api::statement.statement").findMany({
      filters: {
        documentId,
        organisation: { documentId: membership.organisationId },
      },
      fields: STATEMENT_FIELDS,
      populate: {
        invoices: { fields: ["reference", "amountDue", "state"] },
      },
      limit: 1,
    });

    if (!statement) {
      return ctx.notFound("Statement not found");
    }

    ctx.body = { data: statement };
  },

  /**
   * GET /statements/:documentId/receipt
   *
   * Same scoping as above before we hand out a signed download link.
   */
  async receipt(ctx) {
    const { documentId } = ctx.params;

    const membership = await resolveMembership(ctx);
    if (!membership?.organisationId) {
      return ctx.unauthorized("No organisation on this account");
    }

    const [statement] = await strapi.documents("api::statement.statement").findMany({
      filters: {
        documentId,
        organisation: { documentId: membership.organisationId },
      },
      fields: ["reference", "receiptKey"],
      limit: 1,
    });

    if (!statement) {
      return ctx.notFound("Statement not found");
    }

    const url = await strapi
      .service("api::statement.statement")
      .signReceiptUrl(statement.receiptKey, membership.userId);

    ctx.body = { data: { reference: statement.reference, url } };
  },
}));
