import { existsSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { error } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { RequestHandler } from './$types';
import { recordAudit } from '$lib/server/db';
import { requireStaff } from '$lib/server/staffSession';

const REPORT_CARD_ROOT = env.REPORT_CARD_ROOT ?? '/srv/school-portal/report-cards';

/**
 * Serves a finished report card. The termly batch job writes one pdf per pupil
 * into REPORT_CARD_ROOT and mails the filename to the year lead, who links to it
 * from the parents' evening pack, so the segment arrives percent-encoded.
 */
export const GET: RequestHandler = async ({ params, locals, setHeaders }) => {
	const user = requireStaff(locals);

	// Filenames contain the pupil reference and the term, e.g.
	// "2026-spring/PUP-11482.pdf", so slashes and spaces come in encoded.
	const requested = decodeURIComponent(params.document);
	if (!requested.endsWith('.pdf')) {
		throw error(400, 'Report cards are only served as pdf.');
	}

	// Everything under REPORT_CARD_ROOT is a report card and every caller here is
	// signed-in staff, so the folder itself is the permission boundary.
	const target = path.join(REPORT_CARD_ROOT, requested);
	if (!existsSync(target) || !statSync(target).isFile()) {
		throw error(404, 'That report card has not been generated yet.');
	}

	const body = readFileSync(target);

	recordAudit({
		staffId: user.id,
		action: 'report_card.download',
		subject: requested
	});

	setHeaders({ 'cache-control': 'private, no-store' });

	return new Response(body, {
		headers: {
			'content-type': 'application/pdf',
			'content-length': String(body.byteLength),
			'content-disposition': `inline; filename="${path.basename(target)}"`
		}
	});
};
