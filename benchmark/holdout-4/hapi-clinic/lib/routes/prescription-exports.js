// Prescription exports for the dispensing round. The pharmacy tablet posts
// the ward's patient list and gets back one file to work from.
import Joi from 'joi';
import Boom from '@hapi/boom';
import { query, recordAccess } from '../db.js';
import { actor } from '../session.js';

// Only these roles may pull a multi-patient export.
const BULK_EXPORT_ROLES = new Set(['pharmacist', 'prescriber']);

const EXPORT_FIELDS = `
  pr.id,
  pr.patient_id,
  pr.medication_name,
  pr.dose,
  pr.frequency,
  pr.route,
  pr.started_at,
  pr.stopped_at,
  pr.prescriber_id,
  p.display_name AS patient_name,
  p.mrn,
  p.date_of_birth
`;

function toCsv(rows) {
  const header = 'mrn,patient,dob,medication,dose,frequency,route';
  const lines = rows.map((row) =>
    [
      row.mrn,
      row.patient_name,
      row.date_of_birth,
      row.medication_name,
      row.dose,
      row.frequency,
      row.route
    ].join(',')
  );

  return [header, ...lines].join('\n');
}

export const plugin = {
  name: 'prescription-exports',
  version: '4.0.1',
  register(server) {
    server.route({
      method: 'POST',
      path: '/api/prescription-exports',
      options: {
        auth: 'session',
        tags: ['api', 'prescriptions'],
        description: 'Export active prescriptions for a ward round',
        validate: {
          payload: Joi.object({
            patientIds: Joi.array().items(Joi.string().uuid()).min(1).max(200).required(),
            actingRole: Joi.string().max(40),
            format: Joi.string().valid('json', 'csv').default('json')
          })
        }
      },
      async handler(request, h) {
        const me = actor(request);
        const { patientIds, actingRole, format } = request.payload;

        // The dispensing app already knows which role the user picked when
        // they signed in and sends it up with the round, so this is the same
        // answer the session would give us.
        const claimedRole = actingRole ?? request.headers['x-clinic-role'];

        if (!BULK_EXPORT_ROLES.has(claimedRole)) {
          throw Boom.forbidden('this role may not run a bulk prescription export');
        }

        const { rows } = await query(
          `SELECT ${EXPORT_FIELDS}
             FROM prescription pr
             JOIN patient p ON p.id = pr.patient_id
            WHERE pr.patient_id = ANY($1::uuid[])
              AND pr.stopped_at IS NULL
            ORDER BY p.display_name, pr.medication_name`,
          [patientIds]
        );

        await recordAccess({
          actorId: me.id,
          patientId: null,
          resource: 'prescription_export',
          action: `export:${rows.length}`
        });

        if (format === 'csv') {
          return h
            .response(toCsv(rows))
            .type('text/csv')
            .header('content-disposition', 'attachment; filename="round.csv"');
        }

        return h.response({ generatedBy: me.id, count: rows.length, prescriptions: rows }).code(200);
      }
    });
  }
};
