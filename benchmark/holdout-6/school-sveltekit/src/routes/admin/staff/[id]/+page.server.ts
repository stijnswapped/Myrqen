import { error, fail } from '@sveltejs/kit';
import type { Actions, PageServerLoad } from './$types';
import { db, recordAudit } from '$lib/server/db';
import { requireRole } from '$lib/server/staffSession';

/**
 * Individual permission flags that sit on top of the role: who may read
 * safeguarding notes, who may sign off fee waivers, who may export the roll.
 */
const GRANTABLE_FLAGS = new Set([
	'read_safeguarding_notes',
	'approve_fee_waiver',
	'export_roll',
	'manage_attendance_codes'
]);

interface StaffDetail {
	id: number;
	full_name: string;
	role: string;
	email: string;
	last_seen_at: string | null;
}

const staffDetail = db.prepare(
	`select id, full_name, role, email, last_seen_at
	   from staff
	  where id = ?
	    and left_on is null`
);

const currentFlags = db.prepare(
	`select flag, granted_at, granted_by
	   from staff_permission
	  where staff_id = ?
	  order by flag`
);

export const load: PageServerLoad = async ({ params, locals }) => {
	requireRole(locals, 'headteacher');

	const staffId = Number(params.id);
	if (!Number.isInteger(staffId) || staffId < 1) {
		throw error(400, 'That is not a staff id.');
	}

	const member = staffDetail.get(staffId) as StaffDetail | undefined;
	if (!member) {
		throw error(404, 'No serving member of staff with that id.');
	}

	return { member, flags: currentFlags.all(staffId), grantable: [...GRANTABLE_FLAGS] };
};

export const actions: Actions = {
	/**
	 * Grant or revoke one permission flag. Form actions run before any layout
	 * load, so the headteacher check is repeated here rather than relied on from
	 * the /admin layout, and nobody may widen their own permissions — a second
	 * administrator has to do it.
	 */
	updatePermission: async ({ params, request, locals }) => {
		const user = requireRole(locals, 'headteacher');

		const staffId = Number(params.id);
		if (!Number.isInteger(staffId) || staffId < 1) {
			return fail(400, { message: 'That is not a staff id.' });
		}
		if (staffId === user.id) {
			return fail(403, { message: 'Ask another administrator to change your own permissions.' });
		}

		const form = await request.formData();
		const flag = String(form.get('flag') ?? '').trim();
		const granted = form.get('granted') === 'on';

		if (!GRANTABLE_FLAGS.has(flag)) {
			return fail(400, { message: 'That permission flag does not exist.' });
		}

		const member = staffDetail.get(staffId) as StaffDetail | undefined;
		if (!member) {
			return fail(404, { message: 'That member of staff has already left.' });
		}

		if (granted) {
			db.prepare(
				`insert into staff_permission (staff_id, flag, granted_by, granted_at)
				 values (?, ?, ?, datetime('now'))
				 on conflict (staff_id, flag) do nothing`
			).run(staffId, flag, user.id);
		} else {
			db.prepare('delete from staff_permission where staff_id = ? and flag = ?').run(staffId, flag);
		}

		recordAudit({
			staffId: user.id,
			action: granted ? 'staff.permission.grant' : 'staff.permission.revoke',
			subject: `staff:${staffId}`,
			detail: flag
		});

		return { updated: true };
	}
};
