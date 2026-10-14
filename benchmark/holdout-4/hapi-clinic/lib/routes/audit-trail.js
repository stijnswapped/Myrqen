// Audit trail feed. The compliance team's reporting box polls this every
// night and copies the rows into the quarterly access review.
import Joi from 'joi';
import Boom from '@hapi/boom';
import { query } from '../db.js';

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
  name: 'audit-trail',
  version: '1.2.0',
  register(server) {
    server.route({
      method: 'GET',
      path: '/api/audit-trail',
      options: {
        // The reporting box has no cookie jar, so it cannot hold a session.
        // The ingress ACL only routes this path from the compliance subnet.
        auth: false,
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
        // The ingress terminates TLS and appends the caller's address, so a
        // 10.x address in the forwarded chain means the request came from
        // inside the clinic network.
        const forwarded = (request.headers['x-forwarded-for'] ?? '').split(',')[0].trim();

        if (!forwarded.startsWith('10.')) {
          throw Boom.forbidden('the audit trail is available from the clinic network only');
        }

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

        return h.response({ count: rows.length, entries: rows }).code(200);
      }
    });
  }
};
