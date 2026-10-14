import { error } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';
import { db, recordAudit } from '$lib/server/db';
import { hasWholeSchoolScope, requireStaff } from '$lib/server/staffSession';

interface GuardianRecord {
	id: number;
	full_name: string;
	relationship: string;
	phone: string | null;
	email: string | null;
	address_line1: string | null;
	postcode: string | null;
	court_order_flag: number;
}

const SELECTED_COLUMNS = `g.id,
	        g.full_name,
	        g.relationship,
	        g.phone,
	        g.email,
	        g.address_line1,
	        g.postcode,
	        g.court_order_flag`;

/** Switchboard view: office, SLT and the head answer calls for the whole school. */
const guardianAnywhere = db.prepare(
	`select ${SELECTED_COLUMNS}
	   from guardian g
	  where g.id = ?`
);

/**
 * Form-teacher view: the same row, but only reachable through a pupil in the
 * group this member of staff registers. The scope lives in the join so there is
 * no window where the record is loaded and then thrown away.
 */
const guardianInOwnForm = db.prepare(
	`select distinct ${SELECTED_COLUMNS}
	   from guardian g
	   join pupil_guardian pg on pg.guardian_id = g.id
	   join pupil p on p.id = pg.pupil_id
	   join form_class c on c.id = p.form_class_id
	  where g.id = ?
	    and c.form_teacher_id = ?`
);

const linkedPupils = db.prepare(
	`select p.id, p.given_name, p.surname, c.name as formClass
	   from pupil p
	   join pupil_guardian pg on pg.pupil_id = p.id
	   join form_class c on c.id = p.form_class_id
	  where pg.guardian_id = ?
	    and (? = 1 or c.form_teacher_id = ?)
	  order by p.surname`
);

export const load: PageServerLoad = async ({ params, locals }) => {
	const user = requireStaff(locals);

	const guardianId = Number(params.id);
	if (!Number.isInteger(guardianId) || guardianId < 1) {
		throw error(400, 'That is not a contact id.');
	}

	const wholeSchool = hasWholeSchoolScope(user);
	const guardian = (
		wholeSchool ? guardianAnywhere.get(guardianId) : guardianInOwnForm.get(guardianId, user.id)
	) as GuardianRecord | undefined;

	// A teacher asking for a contact outside their group gets the same 404 as a
	// contact that does not exist, so the id space stays opaque.
	if (!guardian) {
		throw error(404, 'No contact record for that id.');
	}

	recordAudit({
		staffId: user.id,
		action: 'guardian.record.view',
		subject: `guardian:${guardianId}`
	});

	return {
		guardian,
		pupils: linkedPupils.all(guardianId, wholeSchool ? 1 : 0, user.id)
	};
};
