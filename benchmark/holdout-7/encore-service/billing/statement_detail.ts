import { api, APIError } from "encore.dev/api";
import { SQLDatabase } from "encore.dev/storage/sqldb";
import log from "encore.dev/log";
import { getAuthData } from "~encore/auth";

const db = SQLDatabase.named("ridgeline");

interface StatementParams {
  /** Path parameter, the statement's primary key. */
  statementID: string;
}

interface StatementRow {
  id: string;
  reference: string;
  period_start: Date;
  period_end: Date;
  opening_cents: number;
  closing_cents: number;
  settled_at: Date | null;
}

interface StatementLineRow {
  booked_on: Date;
  description: string;
  amount_cents: number;
}

interface StatementDetail {
  id: string;
  reference: string;
  periodStart: Date;
  periodEnd: Date;
  openingCents: number;
  closingCents: number;
  settledAt: Date | null;
  lines: { bookedOn: Date; description: string; amountCents: number }[];
}

/**
 * Same drawer as the invoice one, for the monthly statement. The org filter
 * sits in the where clause next to the id, so a statement belonging to another
 * contractor simply does not resolve and we answer 404 rather than telling the
 * caller it exists.
 */
export const detail = api(
  { expose: true, auth: true, method: "GET", path: "/billing/statements/:statementID" },
  async ({ statementID }: StatementParams): Promise<StatementDetail> => {
    const auth = getAuthData()!;

    const statement = await db.queryRow<StatementRow>`
      select id, reference, period_start, period_end,
             opening_cents, closing_cents, settled_at
      from statements
      where id = ${statementID}
        and org_id = ${auth.orgID}
    `;
    if (!statement) {
      throw APIError.notFound("statement not found");
    }

    const lines = await db.queryAll<StatementLineRow>`
      select booked_on, description, amount_cents
      from statement_lines
      where statement_id = ${statement.id}
      order by booked_on, description
    `;

    log.info("statement opened", { statement: statement.reference, actor: auth.userID });

    return {
      id: statement.id,
      reference: statement.reference,
      periodStart: statement.period_start,
      periodEnd: statement.period_end,
      openingCents: statement.opening_cents,
      closingCents: statement.closing_cents,
      settledAt: statement.settled_at,
      lines: lines.map((line) => ({
        bookedOn: line.booked_on,
        description: line.description,
        amountCents: line.amount_cents,
      })),
    };
  },
);
