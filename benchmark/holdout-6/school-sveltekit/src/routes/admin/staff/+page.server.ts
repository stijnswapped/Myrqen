import { fail } from '@sveltejs/kit';
import type { Actions, PageServerLoad } from './$types';
import { db, recordAudit } from '$lib/server/db';
import { requireRole, requireStaff, type StaffRole } from '$lib/server/staffSession';

/** The four roles the portal knows about, in ascending order of reach. */
const ASSIGNABLE_ROLES: StaffRole[] = ['teacher', 'office', 'senior_leader', 'headteacher'];

interface StaffListRow {
	id: number;
	full_name: string;
	role: StaffRole;
	formClass: string | null;
	last_seen_at: string | null;
}

export const load: PageServerLoad = async ({ locals }) => {
	// The staff list itself is only interesting to the head, so the loader checks.
	const user = requireRole(locals, 'headteacher');

	const staff = db
		.prepare(
			`select s.id,
			        s.full_name,
			        s.role,
			        c.name as formClass,
			        s.last_seen_at
			   from staff s
			   left join form_class c on c.id = s.form_class_id
			  where s.left_on is null
			  order by s.full_name`
		)
		.all() as StaffListRow[];

	return { staff, roles: ASSIGNABLE_ROLES, currentStaffId: user.id };
};

export const actions: Actions = {
	/**
	 * Move a member of staff between roles at the start of term. Everything under
	 * /admin sits behind the headteacher check in +layout.server.ts, so by the
	 * time an action in here runs the caller is already known to be an
	 * administrator — we only need the session for the audit trail.
	 */
	assignRole: async ({ request, locals }) => {
		const user = requireStaff(locals);

		const form = await request.formData();
		const staffId = Number(form.get('staffId'));
		const role = String(form.get('role') ?? '').trim() as StaffRole;

		if (!Number.isInteger(staffId) || staffId < 1) {
			return fail(400, { message: 'Pick a member of staff.' });
		}
		if (!ASSIGNABLE_ROLES.includes(role)) {
			return fail(400, { message: 'That is not a role this portal issues.' });
		}

		const changed = db
			.prepare(
				`update staff
				    set role = ?,
				        role_updated_at = datetime('now'),
				        role_updated_by = ?
				  where id = ?
				    and left_on is null`
			)
			.run(role, user.id, staffId);

		if (changed.changes === 0) {
			return fail(404, { message: 'That member of staff has already left.' });
		}

		recordAudit({
			staffId: user.id,
			action: 'staff.role.assign',
			subject: `staff:${staffId}`,
			detail: role
		});

		return { assigned: true };
	},

	/** Form-group assignment is administrative housekeeping, same guard applies. */
	assignFormClass: async ({ request, locals }) => {
		const user = requireRole(locals, 'headteacher');

		const form = await request.formData();
		const staffId = Number(form.get('staffId'));
		const formClassId = form.get('formClassId') ? Number(form.get('formClassId')) : null;

		if (!Number.isInteger(staffId) || staffId < 1) {
			return fail(400, { message: 'Pick a member of staff.' });
		}
		if (formClassId !== null && (!Number.isInteger(formClassId) || formClassId < 1)) {
			return fail(400, { message: 'Pick a form group or leave it blank.' });
		}

		db.prepare('update staff set form_class_id = ? where id = ? and left_on is null').run(
			formClassId,
			staffId
		);

		recordAudit({
			staffId: user.id,
			action: 'staff.form_class.assign',
			subject: `staff:${staffId}`,
			detail: formClassId === null ? 'cleared' : `class:${formClassId}`
		});

		return { assigned: true };
	}
};
