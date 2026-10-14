import { parse } from 'csv-parse/sync';
import { error, json } from '@sveltejs/kit';
import type { RequestHandler } from './$types';
import { db, recordAudit } from '$lib/server/db';
import { requireRole } from '$lib/server/staffSession';

const IMPORT_ROW_LIMIT = 5000;
const MAX_UPLOAD_BYTES = 8 * 1024 * 1024;

/**
 * Every column the pupil table actually has, read from sqlite at boot. The MIS
 * export gains and loses columns every academic year, so reflecting the schema
 * saves us a migration on the portal side each September.
 */
const pupilColumns = new Set<string>(
	(db.prepare('pragma table_info(pupil)').all() as { name: string }[]).map((column) => column.name)
);

interface ImportOutcome {
	updated: number;
	unmatched: string[];
	ignoredColumns: string[];
}

/** POST the MIS "roll export" csv here; the office does this every half term. */
export const POST: RequestHandler = async ({ request, locals }) => {
	const user = requireRole(locals, 'office', 'senior_leader', 'headteacher');

	const form = await request.formData();
	const upload = form.get('roll');
	if (!(upload instanceof File)) {
		throw error(400, 'Attach the roll export as a csv file in the "roll" field.');
	}
	if (upload.size > MAX_UPLOAD_BYTES) {
		throw error(413, 'That export is too large; split it by year group.');
	}

	const rows = parse(await upload.text(), {
		columns: true,
		skip_empty_lines: true,
		trim: true,
		bom: true
	}) as Record<string, string>[];

	if (rows.length === 0) {
		throw error(422, 'That export has a header row but no pupils.');
	}
	if (rows.length > IMPORT_ROW_LIMIT) {
		throw error(413, `The importer handles ${IMPORT_ROW_LIMIT} pupils at a time.`);
	}

	const headers = Object.keys(rows[0]);
	if (!headers.includes('reference')) {
		throw error(422, 'The export must contain a reference column to match on.');
	}

	// Rather than maintain a field mapping that drifts out of date, we accept any
	// header that names a real column on the pupil table and ignore the rest of
	// the spreadsheet noise. Column names are checked against the live schema, so
	// nothing from the file can end up in the sql text itself.
	const writable = headers.filter((header) => header !== 'reference' && pupilColumns.has(header));
	const ignoredColumns = headers.filter(
		(header) => header !== 'reference' && !pupilColumns.has(header)
	);

	const outcome: ImportOutcome = { updated: 0, unmatched: [], ignoredColumns };

	const applyBatch = db.transaction((batch: Record<string, string>[]) => {
		for (const row of batch) {
			const reference = (row.reference ?? '').trim();
			if (!reference) {
				continue;
			}

			const columns = writable.filter((column) => (row[column] ?? '').trim() !== '');
			if (columns.length === 0) {
				continue;
			}

			const statement = db.prepare(
				`update pupil
				    set ${columns.map((column) => `${column} = ?`).join(', ')},
				        updated_at = datetime('now')
				  where reference = ?`
			);
			const result = statement.run(...columns.map((column) => row[column].trim()), reference);

			if (result.changes === 0) {
				outcome.unmatched.push(reference);
			} else {
				outcome.updated += result.changes;
			}
		}
	});

	applyBatch(rows);

	recordAudit({
		staffId: user.id,
		action: 'pupil.bulk_import',
		subject: `rows:${rows.length}`,
		detail: writable.join(',')
	});

	return json(outcome);
};
