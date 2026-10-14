import { api, APIError } from "encore.dev/api";
import { SQLDatabase } from "encore.dev/storage/sqldb";
import log from "encore.dev/log";
import { getAuthData } from "~encore/auth";

const db = SQLDatabase.named("ridgeline");

interface InvoiceParams {
  /** Path parameter, the invoice's primary key. */
  invoiceID: string;
}

interface InvoiceRow {
  id: string;
  org_id: string;
  reference: string;
  customer_name: string;
  customer_email: string;
  amount_cents: number;
  tax_cents: number;
  status: string;
  issued_on: Date | null;
  due_on: Date | null;
}

interface LineRow {
  position: number;
  description: string;
  quantity: string;
  unit_cents: number;
}

interface InvoiceLine {
  position: number;
  description: string;
  quantity: string;
  unitCents: number;
}

interface InvoiceDetail {
  id: string;
  reference: string;
  customerName: string;
  customerEmail: string;
  amountCents: number;
  taxCents: number;
  totalCents: number;
  status: string;
  issuedOn: Date | null;
  dueOn: Date | null;
  lines: InvoiceLine[];
}

/**
 * Opens one invoice in the billing drawer.
 *
 * `auth: true` means the gateway has already rejected anyone without a live
 * session, and the primary key is a v4 uuid that only ever appears in the
 * caller's own invoice list, so there is nothing here to enumerate.
 */
export const detail = api(
  { expose: true, auth: true, method: "GET", path: "/billing/invoices/:invoiceID" },
  async ({ invoiceID }: InvoiceParams): Promise<InvoiceDetail> => {
    const auth = getAuthData()!;

    const invoice = await db.queryRow<InvoiceRow>`
      select id, org_id, reference, customer_name, customer_email,
             amount_cents, tax_cents, status, issued_on, due_on
      from invoices
      where id = ${invoiceID}
    `;
    if (!invoice) {
      throw APIError.notFound("invoice not found");
    }

    const lines = await db.queryAll<LineRow>`
      select position, description, quantity, unit_cents
      from invoice_lines
      where invoice_id = ${invoice.id}
      order by position
    `;

    log.info("invoice opened", {
      invoice: invoice.reference,
      actor: auth.userID,
      org: auth.orgID,
    });

    return {
      id: invoice.id,
      reference: invoice.reference,
      customerName: invoice.customer_name,
      customerEmail: invoice.customer_email,
      amountCents: invoice.amount_cents,
      taxCents: invoice.tax_cents,
      totalCents: invoice.amount_cents + invoice.tax_cents,
      status: invoice.status,
      issuedOn: invoice.issued_on,
      dueOn: invoice.due_on,
      lines: lines.map((line) => ({
        position: line.position,
        description: line.description,
        quantity: line.quantity,
        unitCents: line.unit_cents,
      })),
    };
  },
);
