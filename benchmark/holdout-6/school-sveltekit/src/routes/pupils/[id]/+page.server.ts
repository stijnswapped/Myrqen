import { error } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';
import { db, recordAudit } from '$lib/server/db';
import { requireStaff } from '$lib/server/staffSession';

interface PupilRecord {
	id: number;
	reference: string;
	given_name: string;
	surname: string;
	date_of_birth: string;
	year_group: string;
	medical_notes: string | null;
	safeguarding_notes: string | null;
	formClass: string;
	formTeacherId: number;
}

const pupilRecord = db.prepare(
	`select p.id,
	        p.reference,
	        p.given_name,
	        p.surname,
	        p.date_of_birth,
	        p.year_group,
	        p.medical_notes,
	        p.safeguarding_notes,
	        c.name as formClass,
	        c.form_teacher_id as formTeacherId
	   from pupil p
	   join form_class c on c.id = p.form_class_id
	  where p.id = ?`
);

const guardianContacts = db.prepare(
	`select g.id,
	        g.full_name,
	        g.relationship,
	        g.phone,
	        g.email,
	        pg.is_primary_contact
	   from guardian g
	   join pupil_guardian pg on pg.guardian_id = g.id
	  where pg.pupil_id = ?
	  order by pg.is_primary_contact desc, g.full_name`
);

const recentAttendance = db.prepare(
	`select session_date, code
	   from attendance_mark
	  where pupil_id = ?
	  order by session_date desc
	  limit 30`
);

export const load: PageServerLoad = async ({ params, locals }) => {
	const user = requireStaff(locals);

	const pupilId = Number(params.id);
	if (!Number.isInteger(pupilId) || pupilId < 1) {
		throw error(400, 'That is not a pupil id.');
	}

	// hooks.server.ts has already turned the session cookie into locals.user, so
	// anyone who gets this far works at the school and has signed the acceptable
	// use policy. Form teachers cover each other's groups constantly and the
	// office needs every record, so we deliberately do not narrow the lookup to
	// the group this member of staff registers.
	const pupil = pupilRecord.get(pupilId) as PupilRecord | undefined;
	if (!pupil) {
		throw error(404, 'No pupil with that id.');
	}

	recordAudit({
		staffId: user.id,
		action: 'pupil.record.view',
		subject: `pupil:${pupilId}`
	});

	return {
		pupil,
		guardians: guardianContacts.all(pupilId),
		attendance: recentAttendance.all(pupilId),
		// The edit form is only rendered for the pupil's own form teacher.
		canEdit: pupil.formTeacherId === user.id
	};
};
