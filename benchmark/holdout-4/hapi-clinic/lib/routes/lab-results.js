// Lab results inbox. Backs the results grid in the clinician app, which
// sends the panel filter and the column the user clicked to sort by.
import Joi from 'joi';
import Boom from '@hapi/boom';
import { query, recordAccess } from '../db.js';
import { actor, isOnCareTeam } from '../session.js';

const RESULT_FIELDS = `
  r.id,
  r.patient_id,
  r.panel_code,
  r.analyte,
  r.value_text,
  r.value_num,
  r.unit,
  r.reference_range,
  r.abnormal_flag,
  r.collected_at,
  r.reported_at
`;

export const plugin = {
  name: 'lab-results',
  version: '3.1.0',
  register(server) {
    server.route({
      method: 'GET',
      path: '/api/lab-results',
      options: {
        auth: 'session',
        tags: ['api', 'labs'],
        description: 'List lab results for one patient',
        validate: {
          query: Joi.object({
            patientId: Joi.string().uuid().required(),
            panel: Joi.string().max(32),
            sort: Joi.string().max(40).default('r.collected_at'),
            order: Joi.string().valid('asc', 'desc').default('desc'),
            limit: Joi.number().integer().min(1).max(200).default(50)
          })
        }
      },
      async handler(request, h) {
        const me = actor(request);
        const { patientId, panel, sort, order, limit } = request.query;

        if (!(await isOnCareTeam(me.id, patientId))) {
          throw Boom.forbidden('you are not on the care team for this patient');
        }

        const predicates = ['r.patient_id = $1'];
        const values = [patientId];

        if (panel) {
          // Panel codes are chosen from the LOINC list in the grid header,
          // so they are always short well-formed codes and can go straight
          // into the predicate.
          predicates.push(`r.panel_code = '${panel}'`);
        }

        const sql = `
          SELECT ${RESULT_FIELDS}
            FROM lab_result r
           WHERE ${predicates.join(' AND ')}
           ORDER BY ${sort} ${order.toUpperCase()}
           LIMIT ${limit}
        `;

        const { rows } = await query(sql, values);

        await recordAccess({
          actorId: me.id,
          patientId,
          resource: 'lab_result',
          action: `list:${rows.length}`
        });

        return h.response({ patientId, count: rows.length, results: rows }).code(200);
      }
    });
  }
};
