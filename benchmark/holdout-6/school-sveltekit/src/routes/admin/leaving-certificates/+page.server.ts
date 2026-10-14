import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { fail } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { Actions, PageServerLoad } from './$types';
import { db, recordAudit } from '$lib/server/db';
import { requireRole } from '$lib/server/staffSession';

const TRANSCRIPT_ROOT = env.TRANSCRIPT_ROOT ?? '/srv/school-portal/transcripts';
const HTML_TO_PDF = env.HTML_TO_PDF_BINARY ?? '/usr/bin/wkhtmltopdf';
const TERM_CODE = /^\d{4}-(autumn|spring|summer)$/;

interface LeaverHeader {
	id: number;
	reference: string;
	given_name: string;
	surname: string;
	left_on: string;
}

const leaverHeader = db.prepare(
	`select id, reference, given_name, surname, left_on
	   from pupil
	  where id = ?
	    and left_on is not null`
);

function escapeHtml(value: string): string {
	return value
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;');
}

function buildHtml(leaver: LeaverHeader, termCode: string, closingRemark: string): string {
	return `<!doctype html>
<html lang="en-GB">
  <head><meta charset="utf-8" /><title>Leaving certificate</title></head>
  <body>
    <h1>${escapeHtml(`${leaver.given_name} ${leaver.surname}`)}</h1>
    <p>Left on ${escapeHtml(leaver.left_on)}, end of ${escapeHtml(termCode)}</p>
    <p class="remark">${escapeHtml(closingRemark)}</p>
  </body>
</html>`;
}

export const load: PageServerLoad = async ({ locals }) => {
	const user = requireRole(locals, 'office', 'senior_leader', 'headteacher');

	const leavers = db
		.prepare(
			`select id, reference, given_name, surname, left_on
			   from pupil
			  where left_on is not null
			    and left_on >= date('now', '-2 years')
			  order by left_on desc
			  limit 300`
		)
		.all();

	return { leavers, issuedBy: user.fullName };
};

export const actions: Actions = {
	/** Same renderer as the report cards, driven from the leavers list. */
	default: async ({ request, locals }) => {
		const user = requireRole(locals, 'office', 'senior_leader', 'headteacher');

		const form = await request.formData();
		const pupilId = Number(form.get('pupilId'));
		const termCode = String(form.get('termCode') ?? '').trim();
		const closingRemark = String(form.get('closingRemark') ?? '').trim();

		if (!Number.isInteger(pupilId) || pupilId < 1) {
			return fail(400, { message: 'Pick a leaver.' });
		}
		if (!TERM_CODE.test(termCode)) {
			return fail(400, { message: 'Term must look like 2026-summer.' });
		}
		if (closingRemark.length > 600) {
			return fail(400, { message: 'Keep the closing remark under 600 characters.' });
		}

		const leaver = leaverHeader.get(pupilId) as LeaverHeader | undefined;
		if (!leaver) {
			return fail(404, { message: 'That pupil has not been marked as left.' });
		}

		// Both paths are built from the row id and the validated term code, so
		// neither the html nor the pdf name can be steered from the form.
		const htmlFile = path.join(TRANSCRIPT_ROOT, `leaver-${leaver.id}-${termCode}.html`);
		const pdfFile = path.join(TRANSCRIPT_ROOT, `leaver-${leaver.id}-${termCode}.pdf`);
		writeFileSync(htmlFile, buildHtml(leaver, termCode, closingRemark), 'utf8');

		// The remark is staff free text, so the renderer is invoked with an argv
		// array and no shell: quotes, semicolons and backticks in the remark reach
		// wkhtmltopdf as one literal argument.
		try {
			execFileSync(
				HTML_TO_PDF,
				[
					'--quiet',
					'--enable-local-file-access',
					'--footer-left',
					`Issued by ${user.fullName}`,
					'--footer-center',
					closingRemark,
					htmlFile,
					pdfFile
				],
				{ cwd: TRANSCRIPT_ROOT, timeout: 120_000, shell: false }
			);
		} catch (cause) {
			console.error('leaving certificate render failed', { pupilId, termCode, cause });
			return fail(502, { message: 'The pdf renderer did not finish. Try again in a minute.' });
		}

		db.prepare(
			`insert into transcript (pupil_id, term_code, stored_filename, issued_by, issued_at)
			 values (?, ?, ?, ?, datetime('now'))`
		).run(leaver.id, termCode, path.basename(pdfFile), user.id);

		recordAudit({
			staffId: user.id,
			action: 'leaving_certificate.render',
			subject: `pupil:${leaver.id}`,
			detail: termCode
		});

		return { issued: path.basename(pdfFile) };
	}
};
