import { fail } from '@sveltejs/kit';
import type { Actions, PageServerLoad } from './$types';
import { db, recordAudit } from '$lib/server/db';
import { hasWholeSchoolScope, requireRole, requireStaff } from '$lib/server/staffSession';

/** Column the table header may sort on, resolved through this map and never taken raw. */
const SORT_COLUMNS: Record<string, string> = {
	date: 'r.session_date',
	class: 'c.name',
	taken: 't.full_name',
	missing: 'missingCount'
};

interface RegisterRow {
	id: number;
	session_date: string;
	formClass: string;
	takenBy: string;
	missingCount: number;
}

export const load: PageServerLoad = async ({ locals, url }) => {
	const user = requireStaff(locals);

	const query = (url.searchParams.get('q') ?? '').trim();
	const term = (url.searchParams.get('term') ?? '').trim();
	const sortKey = url.searchParams.get('sort') ?? 'date';
	const orderBy = SORT_COLUMNS[sortKey] ?? SORT_COLUMNS.date;

	// Same free-text-plus-filter shape as the pupil roll, but every value the
	// registrar typed travels as a bound parameter and the sort column is looked
	// up in SORT_COLUMNS, so the sql text is fixed before the request arrives.
	const predicates: string[] = ["r.session_date >= date('now', '-120 days')"];
	const values: unknown[] = [];
	if (query) {
		const like = `%${query}%`;
		predicates.push('(c.name like ? or t.full_name like ?)');
		values.push(like, like);
	}
	if (term) {
		predicates.push('r.term_code = ?');
		values.push(term);
	}
	if (!hasWholeSchoolScope(user)) {
		predicates.push('c.form_teacher_id = ?');
		values.push(user.id);
	}

	const registers = db
		.prepare(
			`select r.id,
			        r.session_date,
			        c.name as formClass,
			        t.full_name as takenBy,
			        (select count(*)
			           from attendance_mark m
			          where m.register_id = r.id
			            and m.code in ('N', 'U')) as missingCount
			   from attendance_register r
			   join form_class c on c.id = r.form_class_id
			   join staff t on t.id = r.taken_by
			  where ${predicates.join(' and ')}
			  order by ${orderBy} desc
			  limit 100`
		)
		.all(...values) as RegisterRow[];

	return { registers, filters: { query, term, sort: sortKey } };
};

export const actions: Actions = {
	/** Reopening a closed register is an SLT job — the deadline exists for a reason. */
	reopen: async ({ request, locals }) => {
		const user = requireRole(locals, 'senior_leader', 'headteacher');

		const form = await request.formData();
		const registerId = Number(form.get('registerId'));
		const reason = String(form.get('reason') ?? '').trim();

		if (!Number.isInteger(registerId) || registerId < 1) {
			return fail(400, { message: 'Pick a register to reopen.' });
		}
		if (reason.length < 10) {
			return fail(400, { message: 'Give a reason of at least ten characters.' });
		}

		const changed = db
			.prepare(
				`update attendance_register
				    set closed_at = null,
				        reopened_by = ?,
				        reopen_reason = ?
				  where id = ?
				    and closed_at is not null`
			)
			.run(user.id, reason, registerId);

		if (changed.changes === 0) {
			return fail(409, { message: 'That register is already open.' });
		}

		recordAudit({
			staffId: user.id,
			action: 'attendance.register.reopen',
			subject: `register:${registerId}`,
			detail: reason
		});

		return { reopened: true };
	}
};
