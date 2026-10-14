// Medication lists for the community round. Same export shape as the
// dispensing round, but for the visiting nurse tablet.
import Joi from 'joi';
import Boom from '@hapi/boom';
import { query, recordAccess } from '../db.js';
import { actor } from '../session.js';

// Only these roles may pull a multi-patient export.
const BULK_EXPORT_ROLES = new Set(['pharmacist', 'prescriber']);

const EXPORT_FIELDS = `
  ml.id,
  ml.patient_id,
  ml.medication_name,
  ml.dose,
  ml.frequency,
  ml.route,
  ml.reviewed_at,
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
  name: 'medication-lists',
  version: '4.0.1',
  register(server) {
    server.route({
      method: 'POST',
      path: '/api/medication-lists/export',
      options: {
        // The strategy attaches the roles from the session row, and Hapi
        // enforces the scope before the handler is entered.
        auth: { strategy: 'session', scope: ['pharmacist', 'prescriber'] },
        tags: ['api', 'medications'],
        description: 'Export reviewed medication lists for a community round',
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
        const { patientIds, format } = request.payload;

        // `actingRole` in the payload is a UI hint for the export header
        // only; the decision below is taken on the session's own roles.
        if (!me.roles.some((role) => BULK_EXPORT_ROLES.has(role))) {
          throw Boom.forbidden('this role may not run a bulk medication export');
        }

        const { rows } = await query(
          `SELECT ${EXPORT_FIELDS}
             FROM medication_list ml
             JOIN patient p ON p.id = ml.patient_id
            WHERE ml.patient_id = ANY($1::uuid[])
              AND ml.superseded_at IS NULL
            ORDER BY p.display_name, ml.medication_name`,
          [patientIds]
        );

        await recordAccess({
          actorId: me.id,
          patientId: null,
          resource: 'medication_list_export',
          action: `export:${rows.length}`
        });

        if (format === 'csv') {
          return h
            .response(toCsv(rows))
            .type('text/csv')
            .header('content-disposition', 'attachment; filename="round.csv"');
        }

        return h.response({ generatedBy: me.id, count: rows.length, medications: rows }).code(200);
      }
    });
  }
};
