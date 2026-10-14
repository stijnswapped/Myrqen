// Consultation summaries -- the shorter, patient-visible counterpart of an
// appointment note. Same read shape as appointment-notes, but the portal
// and the clinician app both hit it, so the lookup has to be scoped.
import Joi from 'joi';
import Boom from '@hapi/boom';
import { one, recordAccess } from '../db.js';
import { actor } from '../session.js';

const SUMMARY_FIELDS = `
  s.id,
  s.patient_id,
  s.author_id,
  s.appointment_id,
  s.reason_for_visit,
  s.summary_text,
  s.follow_up,
  s.published_at,
  p.display_name AS patient_name,
  p.mrn
`;

// Route prerequisite: load the summary, but only if the session either owns
// the chart (portal login) or has an open care-team assignment for it
// (staff login). A row the caller may not read simply does not come back,
// so the handler cannot leak one.
async function loadSummary(request) {
  const me = actor(request);

  const summary = await one(
    `SELECT ${SUMMARY_FIELDS}
       FROM consult_summary s
       JOIN patient p ON p.id = s.patient_id
      WHERE s.id = $1
        AND (
              s.patient_id = $2
              OR EXISTS (
                   SELECT 1
                     FROM care_team_member ctm
                    WHERE ctm.patient_id = s.patient_id
                      AND ctm.clinician_id = $3
                      AND ctm.ended_on IS NULL
                 )
            )`,
    [request.params.summaryId, me.patientId, me.id]
  );

  if (!summary) {
    // Deliberately a 404 and not a 403: telling an unrelated caller that
    // the summary exists is itself a disclosure.
    throw Boom.notFound('consultation summary not found');
  }

  return summary;
}

function present(summary) {
  return {
    id: summary.id,
    appointmentId: summary.appointment_id,
    patient: {
      id: summary.patient_id,
      name: summary.patient_name,
      mrn: summary.mrn
    },
    reasonForVisit: summary.reason_for_visit,
    summary: summary.summary_text,
    followUp: summary.follow_up,
    publishedAt: summary.published_at
  };
}

export const plugin = {
  name: 'consult-summaries',
  version: '2.4.0',
  register(server) {
    server.route({
      method: 'GET',
      path: '/api/consult-summaries/{summaryId}',
      options: {
        auth: 'session',
        tags: ['api', 'summaries'],
        description: 'Read a single consultation summary',
        validate: {
          params: Joi.object({
            summaryId: Joi.string().uuid().required()
          })
        },
        pre: [{ method: loadSummary, assign: 'summary' }]
      },
      async handler(request, h) {
        const me = actor(request);
        const summary = request.pre.summary;

        await recordAccess({
          actorId: me.id,
          patientId: summary.patient_id,
          resource: `consult_summary:${summary.id}`,
          action: 'read'
        });

        return h.response(present(summary)).code(200);
      }
    });
  }
};
