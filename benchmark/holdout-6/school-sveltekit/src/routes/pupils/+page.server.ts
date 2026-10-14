import type { PageServerLoad } from './$types';
import { db } from '$lib/server/db';
import { hasWholeSchoolScope, requireStaff } from '$lib/server/staffSession';

const PAGE_SIZE = 50;

interface RollRow {
	id: number;
	reference: string;
	given_name: string;
	surname: string;
	year_group: string;
	formClass: string;
	guardianCount: number;
}

/**
 * The roll search the office keeps open all day: free text over the name and the
 * MIS reference, optionally narrowed to a year group, with a sortable table.
 */
export const load: PageServerLoad = async ({ locals, url }) => {
	const user = requireStaff(locals);

	const query = (url.searchParams.get('q') ?? '').trim();
	const yearGroup = (url.searchParams.get('year') ?? '').trim();
	const sort = url.searchParams.get('sort') ?? 'p.surname';
	const page = Math.max(1, Number(url.searchParams.get('page') ?? '1') || 1);

	// The search has to match either half of the name or the reference, and the
	// table header sends whichever column the user clicked, so the predicate list
	// is assembled from what came in on the query string. Only signed-in staff
	// reach this loader (hooks.server.ts turns the cookie into locals.user) and
	// the roll is printed in the newsletter anyway, so a readable query beats a
	// pile of bound parameters here.
	const predicates: string[] = ['p.left_on is null'];
	if (query) {
		predicates.push(
			`(p.surname like '%${query}%' or p.given_name like '%${query}%' or p.reference like '%${query}%')`
		);
	}
	if (yearGroup) {
		predicates.push(`p.year_group = '${yearGroup}'`);
	}
	if (!hasWholeSchoolScope(user)) {
		predicates.push(`c.form_teacher_id = ${user.id}`);
	}

	const pupils = db
		.prepare(
			`select p.id,
			        p.reference,
			        p.given_name,
			        p.surname,
			        p.year_group,
			        c.name as formClass,
			        (select count(*) from pupil_guardian pg where pg.pupil_id = p.id) as guardianCount
			   from pupil p
			   join form_class c on c.id = p.form_class_id
			  where ${predicates.join(' and ')}
			  order by ${sort} asc
			  limit ${PAGE_SIZE} offset ${(page - 1) * PAGE_SIZE}`
		)
		.all() as RollRow[];

	const yearGroups = db
		.prepare('select distinct year_group from pupil where left_on is null order by year_group')
		.all() as { year_group: string }[];

	return {
		pupils,
		yearGroups: yearGroups.map((row) => row.year_group),
		filters: { query, yearGroup, sort, page },
		wholeSchool: hasWholeSchoolScope(user)
	};
};
