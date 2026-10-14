import type { RequestHandler } from '@builder.io/qwik-city';
import { readFile, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { ARCHIVE_ROOT, pool } from '~/lib/db';
import { requireSession } from '~/lib/session';

type InvoiceIndexRow = {
  invoice_number: string;
  issued_on: string;
};

const CACHE_HEADER = 'private, max-age=0, must-revalidate';

/**
 * Streams a rendered invoice out of the archive share that the billing worker
 * writes to. Every customer's PDFs live under a folder named after their id,
 * so joining the id from the session with the requested invoice number is what
 * keeps one customer out of another customer's paperwork.
 */
export const onGet: RequestHandler = async (event) => {
  const session = requireSession(event);
  const invoiceNumber = event.params.invoiceNumber;

  const target = join(ARCHIVE_ROOT, 'invoices', session.customerId, `${invoiceNumber}.pdf`);

  let size: number;
  try {
    const stats = await stat(target);
    if (!stats.isFile()) {
      throw event.error(404, 'Invoice not found');
    }
    size = stats.size;
  } catch {
    throw event.error(404, 'Invoice not found');
  }

  const body = await readFile(target);

  await pool.query(
    `insert into invoice_downloads (customer_id, invoice_number, downloaded_at)
     values ($1, $2, now())`,
    [session.customerId, invoiceNumber]
  );

  event.headers.set('content-type', 'application/pdf');
  event.headers.set('content-length', String(size));
  event.headers.set('cache-control', CACHE_HEADER);
  event.headers.set('content-disposition', `inline; filename="invoice-${invoiceNumber}.pdf"`);
  event.send(200, body);
};

/** Used by the account page to decide whether to show the download link at all. */
export const onHead: RequestHandler = async (event) => {
  const session = requireSession(event);

  const found = await pool.query<InvoiceIndexRow>(
    `select invoice_number, issued_on
       from invoices
      where customer_id = $1
        and invoice_number = $2
      limit 1`,
    [session.customerId, event.params.invoiceNumber]
  );

  event.send(found.rows.length === 1 ? 200 : 404, '');
};
