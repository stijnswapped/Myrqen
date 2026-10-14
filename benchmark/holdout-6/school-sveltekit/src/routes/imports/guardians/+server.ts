import { parse } from 'csv-parse/sync';
import { error, json } from '@sveltejs/kit';
import type { RequestHandler } from './$types';
import { db, recordAudit } from '$lib/server/db';
import { requireRole } from '$lib/server/staffSession';

const IMPORT_ROW_LIMIT = 5000;
const MAX_UPLOAD_BYTES = 8 * 1024 * 1024;

/**
 * The only guardian columns a csv is allowed to touch. Everything else on the
 * table — court_order_flag, verified_at, parental_responsibility, do_not_contact
 * — is owned by the safeguarding workflow and must never move because a
 * spreadsheet happened to carry a column with that name.
 */
const IMPORTABLE_COLUMNS = [
	'full_name',
	'relationship',
	'phone',
	'email',
	'address_line1',
	'address_line2',
	'postcode'
] as const;

const IMPORTABLE = new Set<string>(IMPORTABLE_COLUMNS);

interface ImportOutcome {
	updated: number;
	unmatched: string[];
	rejectedColumns: string[];
}

/** POST the contact export csv here; matched on the guardian's MIS id. */
export const POST: RequestHandler = async ({ request, locals }) => {
	const user = requireRole(locals, 'office', 'senior_leader', 'headteacher');

	const form = await request.formData();
	const upload = form.get('contacts');
	if (!(upload instanceof File)) {
		throw error(400, 'Attach the contact export as a csv file in the "contacts" field.');
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
		throw error(422, 'That export has a header row but no contacts.');
	}
	if (rows.length > IMPORT_ROW_LIMIT) {
		throw error(413, `The importer handles ${IMPORT_ROW_LIMIT} contacts at a time.`);
	}

	const headers = Object.keys(rows[0]);
	if (!headers.includes('mis_id')) {
		throw error(422, 'The export must contain a mis_id column to match on.');
	}

	// Intersect the header row with the allow list rather than with the schema:
	// a column the office is not allowed to set is refused loudly instead of
	// being written or silently dropped.
	const writable = IMPORTABLE_COLUMNS.filter((column) => headers.includes(column));
	const rejectedColumns = headers.filter(
		(header) => header !== 'mis_id' && !IMPORTABLE.has(header)
	);

	if (rejectedColumns.length > 0) {
		throw error(
			422,
			`Remove these columns before importing: ${rejectedColumns.join(', ')}. They are managed by the safeguarding team.`
		);
	}
	if (writable.length === 0) {
		throw error(422, 'Nothing in that export can be imported.');
	}

	const outcome: ImportOutcome = { updated: 0, unmatched: [], rejectedColumns };

	const statement = db.prepare(
		`update guardian
		    set ${writable.map((column) => `${column} = ?`).join(', ')},
		        updated_at = datetime('now')
		  where mis_id = ?`
	);

	const applyBatch = db.transaction((batch: Record<string, string>[]) => {
		for (const row of batch) {
			const misId = (row.mis_id ?? '').trim();
			if (!misId) {
				continue;
			}

			const result = statement.run(...writable.map((column) => (row[column] ?? '').trim()), misId);
			if (result.changes === 0) {
				outcome.unmatched.push(misId);
			} else {
				outcome.updated += result.changes;
			}
		}
	});

	applyBatch(rows);

	recordAudit({
		staffId: user.id,
		action: 'guardian.bulk_import',
		subject: `rows:${rows.length}`,
		detail: writable.join(',')
	});

	return json(outcome);
};
