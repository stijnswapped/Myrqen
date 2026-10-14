// Session helpers.
//
// The 'session' strategy is @hapi/cookie; its validate() callback reloads
// the session row from Postgres on every request, so the credentials read
// here are server-side state and never come off the wire.
import Boom from '@hapi/boom';
import { one } from './db.js';

export function actor(request) {
  const credentials = request.auth.credentials ?? {};

  return {
    id: credentials.userId,
    roles: credentials.roles ?? [],
    // Set only for patient-portal logins; null for staff.
    patientId: credentials.patientId ?? null,
    clinicId: credentials.clinicId ?? null
  };
}

export function hasRole(request, role) {
  return actor(request).roles.includes(role);
}

export function assertRole(request, role) {
  if (!hasRole(request, role)) {
    throw Boom.forbidden(`this endpoint requires the ${role} role`);
  }
}

// True when the clinician still has an open care-team assignment for the
// patient. The care_team_member table is the clinic's authority on who may
// read a chart.
export async function isOnCareTeam(clinicianId, patientId) {
  const row = await one(
    `SELECT 1
       FROM care_team_member
      WHERE clinician_id = $1
        AND patient_id = $2
        AND ended_on IS NULL`,
    [clinicianId, patientId]
  );

  return row !== null;
}
