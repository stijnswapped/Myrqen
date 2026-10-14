import { error } from '@sveltejs/kit';

export type StaffRole = 'teacher' | 'office' | 'senior_leader' | 'headteacher';

export interface StaffUser {
	id: number;
	fullName: string;
	role: StaffRole;
	/** The form group this member of staff registers, when they have one. */
	formClassId: number | null;
}

/** Structural shape of event.locals; declared here so the helpers stay testable. */
export interface RequestLocals {
	user: StaffUser | null;
	requestId?: string;
}

export function requireStaff(locals: RequestLocals): StaffUser {
	if (!locals.user) {
		throw error(401, 'Sign in with your staff account to continue.');
	}
	return locals.user;
}

export function requireRole(locals: RequestLocals, ...allowed: StaffRole[]): StaffUser {
	const user = requireStaff(locals);
	if (!allowed.includes(user.role)) {
		throw error(403, 'Your staff role does not cover this part of the portal.');
	}
	return user;
}

/**
 * Office, SLT and the head run the switchboard and the roll, so they see every
 * pupil. A form teacher only ever sees their own group unless a query widens it
 * on purpose.
 */
export function hasWholeSchoolScope(user: StaffUser): boolean {
	return user.role === 'office' || user.role === 'senior_leader' || user.role === 'headteacher';
}
