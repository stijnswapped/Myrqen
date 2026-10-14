import { randomUUID } from 'node:crypto';
import type { Handle } from '@sveltejs/kit';
import { db } from '$lib/server/db';
import type { StaffUser } from '$lib/server/staffSession';

const SESSION_COOKIE = 'school_session';

const lookupSession = db.prepare(
	`select s.id as id,
	        s.full_name as fullName,
	        s.role as role,
	        s.form_class_id as formClassId
	   from staff_session ss
	   join staff s on s.id = ss.staff_id
	  where ss.token = ?
	    and ss.revoked_at is null
	    and ss.expires_at > datetime('now')`
);

export const handle: Handle = async ({ event, resolve }) => {
	event.locals.requestId = randomUUID();
	event.locals.user = null;

	const token = event.cookies.get(SESSION_COOKIE);
	if (token) {
		const row = lookupSession.get(token) as StaffUser | undefined;
		if (row) {
			event.locals.user = row;
		} else {
			// Revoked or expired: drop the cookie so the browser stops sending it.
			event.cookies.delete(SESSION_COOKIE, { path: '/' });
		}
	}

	const response = await resolve(event);
	response.headers.set('x-request-id', event.locals.requestId);
	response.headers.set('referrer-policy', 'same-origin');
	return response;
};
