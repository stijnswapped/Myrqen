// Access-log review. The in-app version of the compliance feed, used by the
// information governance officers from their own browsers.
import Joi from 'joi';
import { query, recordAccess } from '../db.js';
import { actor } from '../session.js';

const ENTRY_FIELDS = `
  al.id,
  al.actor_id,
  al.patient_id,
  al.resource,
  al.action,
  al.occurred_at,
  u.email AS actor_email,
  u.display_name AS actor_name,
  p.display_name AS patient_name,
  p.mrn
`;

export const plugin = {
  name: 'access-log-review',
  version: '1.2.0',
  register(server) {
    server.route({
      method: 'GET',
      path: '/api/access-log-review',
      options: {
        // Session-backed: the scope comes off the session row the cookie
        // strategy loaded, and Hapi rejects anything else before the
        // handler runs. No network-position shortcut.
        auth: { strategy: 'session', scope: ['compliance'] },
        tags: ['api', 'compliance'],
        description: 'List access-log entries for the compliance review',
        validate: {
          query: Joi.object({
            since: Joi.date().iso().required(),
            until: Joi.date().iso().greater(Joi.ref('since')).required(),
            limit: Joi.number().integer().min(1).max(1000).default(500)
          })
        }
      },
      async handler(request, h) {
        const me = actor(request);

        const { rows } = await query(
          `SELECT ${ENTRY_FIELDS}
             FROM access_log al
             LEFT JOIN app_user u ON u.id = al.actor_id
             LEFT JOIN patient p ON p.id = al.patient_id
            WHERE al.occurred_at >= $1
              AND al.occurred_at < $2
            ORDER BY al.occurred_at DESC
            LIMIT $3`,
          [request.query.since, request.query.until, request.query.limit]
        );

        // Reading the log is itself an event worth logging.
        await recordAccess({
          actorId: me.id,
          patientId: null,
          resource: 'access_log',
          action: `review:${rows.length}`
        });

        return h.response({ count: rows.length, entries: rows }).code(200);
      }
    });
  }
};
