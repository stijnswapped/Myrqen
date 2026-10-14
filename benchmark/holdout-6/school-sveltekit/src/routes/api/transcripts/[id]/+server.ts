import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { error } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { RequestHandler } from './$types';
import { db, recordAudit } from '$lib/server/db';
import { requireStaff } from '$lib/server/staffSession';

const TRANSCRIPT_ROOT = env.TRANSCRIPT_ROOT ?? '/srv/school-portal/transcripts';

interface TranscriptRow {
	id: number;
	pupilId: number;
	storedFilename: string;
	pupilReference: string;
}

const transcriptById = db.prepare(
	`select t.id,
	        t.pupil_id as pupilId,
	        t.stored_filename as storedFilename,
	        p.reference as pupilReference
	   from transcript t
	   join pupil p on p.id = t.pupil_id
	  where t.id = ?`
);

/** Leaving transcripts are addressed by row id; the filename never leaves the server. */
export const GET: RequestHandler = async ({ params, locals, setHeaders }) => {
	const user = requireStaff(locals);

	const transcriptId = Number(params.id);
	if (!Number.isInteger(transcriptId) || transcriptId < 1) {
		throw error(400, 'That is not a transcript id.');
	}

	const row = transcriptById.get(transcriptId) as TranscriptRow | undefined;
	if (!row) {
		throw error(404, 'No transcript with that id.');
	}

	// The filename came out of our own generator, but it is still treated as
	// untrusted input: only the basename is used, and the resolved path has to sit
	// inside the transcript store before anything is read off disk.
	const root = path.resolve(TRANSCRIPT_ROOT);
	const resolved = path.resolve(root, path.basename(row.storedFilename));
	if (resolved !== root && !resolved.startsWith(root + path.sep)) {
		throw error(400, 'Refusing to serve a file from outside the transcript store.');
	}
	if (!existsSync(resolved)) {
		throw error(404, 'That transcript is no longer on disk.');
	}

	const body = readFileSync(resolved);

	recordAudit({
		staffId: user.id,
		action: 'transcript.download',
		subject: `transcript:${row.id}`,
		detail: row.pupilReference
	});

	setHeaders({ 'cache-control': 'private, no-store' });

	return new Response(body, {
		headers: {
			'content-type': 'application/pdf',
			'content-length': String(body.byteLength),
			'content-disposition': `attachment; filename="${row.pupilReference}-transcript.pdf"`
		}
	});
};
