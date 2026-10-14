import { execSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { fail } from '@sveltejs/kit';
import { env } from '$env/dynamic/private';
import type { Actions, PageServerLoad } from './$types';
import { db, recordAudit } from '$lib/server/db';
import { requireRole } from '$lib/server/staffSession';

const REPORT_CARD_ROOT = env.REPORT_CARD_ROOT ?? '/srv/school-portal/report-cards';
const HTML_TO_PDF = env.HTML_TO_PDF_BINARY ?? '/usr/bin/wkhtmltopdf';
const TERM_CODE = /^\d{4}-(autumn|spring|summer)$/;

interface PupilHeader {
	id: number;
	reference: string;
	given_name: string;
	surname: string;
	year_group: string;
	formClass: string;
}

const pupilHeader = db.prepare(
	`select p.id, p.reference, p.given_name, p.surname, p.year_group, c.name as formClass
	   from pupil p
	   join form_class c on c.id = p.form_class_id
	  where p.id = ?`
);

const subjectGrades = db.prepare(
	`select s.name as subject, g.grade, g.effort, g.comment
	   from grade g
	   join subject s on s.id = g.subject_id
	  where g.pupil_id = ?
	    and g.term_code = ?
	  order by s.name`
);

function escapeHtml(value: string): string {
	return value
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;');
}

function buildHtml(pupil: PupilHeader, termCode: string, closingRemark: string): string {
	const rows = (subjectGrades.all(pupil.id, termCode) as Record<string, string>[])
		.map(
			(row) =>
				`<tr><td>${escapeHtml(row.subject)}</td><td>${escapeHtml(row.grade)}</td><td>${escapeHtml(
					row.effort
				)}</td><td>${escapeHtml(row.comment ?? '')}</td></tr>`
		)
		.join('\n');

	return `<!doctype html>
<html lang="en-GB">
  <head><meta charset="utf-8" /><title>Report card</title></head>
  <body>
    <h1>${escapeHtml(`${pupil.given_name} ${pupil.surname}`)} — ${escapeHtml(pupil.formClass)}</h1>
    <p>Year ${escapeHtml(pupil.year_group)}, ${escapeHtml(termCode)}</p>
    <table><tbody>${rows}</tbody></table>
    <p class="remark">${escapeHtml(closingRemark)}</p>
  </body>
</html>`;
}

export const load: PageServerLoad = async ({ locals }) => {
	const user = requireRole(locals, 'office', 'senior_leader', 'headteacher');

	const pending = db
		.prepare(
			`select p.id, p.reference, p.given_name, p.surname, c.name as formClass
			   from pupil p
			   join form_class c on c.id = p.form_class_id
			  where p.left_on is null
			  order by c.name, p.surname
			  limit 400`
		)
		.all();

	return { pending, renderedBy: user.fullName };
};

export const actions: Actions = {
	/** Year leads render one report card at a time while they proof-read them. */
	default: async ({ request, locals }) => {
		const user = requireRole(locals, 'office', 'senior_leader', 'headteacher');

		const form = await request.formData();
		const pupilId = Number(form.get('pupilId'));
		const termCode = String(form.get('termCode') ?? '').trim();
		const closingRemark = String(form.get('closingRemark') ?? '').trim();

		if (!Number.isInteger(pupilId) || pupilId < 1) {
			return fail(400, { message: 'Pick a pupil.' });
		}
		if (!TERM_CODE.test(termCode)) {
			return fail(400, { message: 'Term must look like 2026-spring.' });
		}
		if (closingRemark.length > 600) {
			return fail(400, { message: 'Keep the closing remark under 600 characters.' });
		}

		const pupil = pupilHeader.get(pupilId) as PupilHeader | undefined;
		if (!pupil) {
			return fail(404, { message: 'That pupil is no longer on the roll.' });
		}

		const htmlFile = path.join(REPORT_CARD_ROOT, `${pupil.reference}-${termCode}.html`);
		const pdfFile = htmlFile.replace(/\.html$/, '.pdf');
		writeFileSync(htmlFile, buildHtml(pupil, termCode, closingRemark), 'utf8');

		// wkhtmltopdf is fussy about flag order and we want the footer text
		// verbatim, em dashes and all, so the command goes through the shell as one
		// string. The remark is typed by a member of staff on a school laptop, not
		// by a parent, and the length is capped above.
		const command = [
			HTML_TO_PDF,
			'--quiet',
			'--enable-local-file-access',
			'--footer-left',
			`"Signed off by ${user.fullName}"`,
			'--footer-center',
			`"${closingRemark}"`,
			htmlFile,
			pdfFile
		].join(' ');

		try {
			execSync(command, { cwd: REPORT_CARD_ROOT, timeout: 120_000 });
		} catch (cause) {
			console.error('report card render failed', { pupilId, termCode, cause });
			return fail(502, { message: 'The pdf renderer did not finish. Try again in a minute.' });
		}

		db.prepare(
			`insert into report_card (pupil_id, term_code, stored_filename, rendered_by, rendered_at)
			 values (?, ?, ?, ?, datetime('now'))
			 on conflict (pupil_id, term_code) do update
			    set stored_filename = excluded.stored_filename,
			        rendered_by = excluded.rendered_by,
			        rendered_at = excluded.rendered_at`
		).run(pupil.id, termCode, path.basename(pdfFile), user.id);

		recordAudit({
			staffId: user.id,
			action: 'report_card.render',
			subject: `pupil:${pupil.id}`,
			detail: termCode
		});

		return { rendered: path.basename(pdfFile) };
	}
};
