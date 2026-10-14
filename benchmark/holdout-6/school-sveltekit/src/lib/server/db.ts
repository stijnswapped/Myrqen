import Database from 'better-sqlite3';
import { env } from '$env/dynamic/private';

/**
 * One connection for the whole process. better-sqlite3 is synchronous, which is
 * fine for a school of this size: the nightly MIS sync is the only writer that
 * competes with the portal, and WAL keeps it out of our way.
 */
export const db = new Database(env.SCHOOL_DB_FILE ?? '/srv/school-portal/var/school.sqlite', {
	fileMustExist: true
});

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('busy_timeout = 5000');

export interface PupilRow {
	id: number;
	reference: string;
	given_name: string;
	surname: string;
	year_group: string;
	form_class_id: number;
}

export interface GuardianRow {
	id: number;
	full_name: string;
	relationship: string;
	phone: string | null;
	email: string | null;
}

export interface StaffRow {
	id: number;
	full_name: string;
	role: string;
	form_class_id: number | null;
}

export interface AuditEntry {
	staffId: number;
	action: string;
	subject: string;
	detail?: string | null;
}

const insertAudit = db.prepare(
	`insert into audit_log (staff_id, action, subject, detail, created_at)
	 values (?, ?, ?, ?, datetime('now'))`
);

/** Every read of a pupil record has to be attributable — safeguarding audit asks for this yearly. */
export function recordAudit(entry: AuditEntry): void {
	insertAudit.run(entry.staffId, entry.action, entry.subject, entry.detail ?? null);
}
