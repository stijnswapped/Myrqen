// Vitals panels. Same grid component as the lab results inbox, so it takes
// the same filter and sort controls.
import Joi from 'joi';
import Boom from '@hapi/boom';
import { query, recordAccess } from '../db.js';
import { actor, isOnCareTeam } from '../session.js';

const PANEL_FIELDS = `
  v.id,
  v.patient_id,
  v.panel_code,
  v.observation,
  v.value_num,
  v.unit,
  v.abnormal_flag,
  v.collected_at,
  v.recorded_at
`;

// The grid sends a sort key, never a column name: anything not in this map
// is rejected by Joi before the handler runs, and only the mapped value is
// ever spliced into the statement.
const SORT_COLUMNS = new Map([
  ['collected', 'v.collected_at'],
  ['recorded', 'v.recorded_at'],
  ['panel', 'v.panel_code'],
  ['value', 'v.value_num']
]);

export const plugin = {
  name: 'vitals-panels',
  version: '3.1.0',
  register(server) {
    server.route({
      method: 'GET',
      path: '/api/vitals-panels',
      options: {
        auth: 'session',
        tags: ['api', 'vitals'],
        description: 'List recorded vitals panels for one patient',
        validate: {
          query: Joi.object({
            patientId: Joi.string().uuid().required(),
            panel: Joi.string().max(32),
            sort: Joi.string().valid(...SORT_COLUMNS.keys()).default('collected'),
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

        const predicates = ['v.patient_id = $1'];
        const values = [patientId];

        if (panel) {
          values.push(panel);
          predicates.push(`v.panel_code = $${values.length}`);
        }

        const sortColumn = SORT_COLUMNS.get(sort);
        const direction = order === 'asc' ? 'ASC' : 'DESC';

        values.push(limit);

        const sql = `
          SELECT ${PANEL_FIELDS}
            FROM vitals_panel v
           WHERE ${predicates.join(' AND ')}
           ORDER BY ${sortColumn} ${direction}
           LIMIT $${values.length}
        `;

        const { rows } = await query(sql, values);

        await recordAccess({
          actorId: me.id,
          patientId,
          resource: 'vitals_panel',
          action: `list:${rows.length}`
        });

        return h.response({ patientId, count: rows.length, panels: rows }).code(200);
      }
    });
  }
};
