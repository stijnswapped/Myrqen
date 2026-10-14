import type { RequestHandler } from '@builder.io/qwik-city';
import { readFile, stat } from 'node:fs/promises';
import { resolve, sep } from 'node:path';
import { ARCHIVE_ROOT, pool } from '~/lib/db';
import { requireSession } from '~/lib/session';

type ReceiptIndexRow = {
  receipt_number: string;
  issued_on: string;
};

const RECEIPT_NUMBER = /^RCP-[0-9]{6}$/;
const CACHE_HEADER = 'private, max-age=0, must-revalidate';

/**
 * Streams a rendered receipt out of the archive share. The requested number is
 * shape-checked, looked up against the caller's own receipts, and the resolved
 * path is confirmed to still sit inside the receipts folder before it is read.
 */
export const onGet: RequestHandler = async (event) => {
  const session = requireSession(event);
  const receiptNumber = event.params.receiptNumber;

  if (!RECEIPT_NUMBER.test(receiptNumber)) {
    throw event.error(400, 'Malformed receipt number');
  }

  const found = await pool.query<ReceiptIndexRow>(
    `select receipt_number, issued_on
       from receipts
      where customer_id = $1
        and receipt_number = $2
      limit 1`,
    [session.customerId, receiptNumber]
  );

  const receipt = found.rows[0];
  if (!receipt) {
    throw event.error(404, 'Receipt not found');
  }

  const receiptsDir = resolve(ARCHIVE_ROOT, 'receipts');
  const target = resolve(receiptsDir, `${receipt.receipt_number}.pdf`);
  if (!target.startsWith(receiptsDir + sep)) {
    throw event.error(400, 'Malformed receipt number');
  }

  let size: number;
  try {
    const stats = await stat(target);
    if (!stats.isFile()) {
      throw event.error(404, 'Receipt not found');
    }
    size = stats.size;
  } catch {
    throw event.error(404, 'Receipt not found');
  }

  const body = await readFile(target);

  await pool.query(
    `insert into receipt_downloads (customer_id, receipt_number, downloaded_at)
     values ($1, $2, now())`,
    [session.customerId, receipt.receipt_number]
  );

  event.headers.set('content-type', 'application/pdf');
  event.headers.set('content-length', String(size));
  event.headers.set('cache-control', CACHE_HEADER);
  event.headers.set('content-disposition', `inline; filename="receipt-${receipt.receipt_number}.pdf"`);
  event.send(200, body);
};
