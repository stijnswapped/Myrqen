// Shared imaging reports. Same one-off link mechanism as shared lab
// results, for radiology reports sent out to referrers.
import Joi from 'joi';
import Boom from '@hapi/boom';
import { createHash } from 'node:crypto';
import { one, recordAccess } from '../db.js';

function tokenHash(token) {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

export const plugin = {
  name: 'imaging-share-links',
  version: '0.8.3',
  register(server) {
    server.route({
      method: 'GET',
      path: '/api/shared-imaging/{token}',
      options: {
        // Referrers have no clinic login; the token in the link is the
        // only thing standing between the caller and the report.
        auth: false,
        tags: ['api', 'sharing'],
        description: 'Open a shared imaging report by its share token',
        validate: {
          params: Joi.object({
            token: Joi.string().hex().length(48).required()
          })
        }
      },
      async handler(request, h) {
        const link = await one(
          `SELECT sl.id,
                  sl.report_id,
                  sl.patient_id,
                  sl.created_by,
                  sl.expires_at,
                  sl.revoked_at,
                  sl.opened_count
             FROM imaging_share_link sl
            WHERE sl.token_hash = $1`,
          [tokenHash(request.params.token)]
        );

        if (!link) {
          throw Boom.notFound('this link is not valid');
        }

        if (link.revoked_at) {
          throw Boom.forbidden('this link has been withdrawn');
        }

        // The sweep that removes lapsed rows runs nightly, so a row that is
        // still here can already be past its expiry: check the clock, not
        // the sweep. A missing or unreadable expiry counts as expired.
        const expiresAt = new Date(link.expires_at).getTime();

        if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) {
          throw Boom.forbidden('this link has expired');
        }

        const report = await one(
          `SELECT ir.id,
                  ir.modality,
                  ir.body_site,
                  ir.findings,
                  ir.impression,
                  ir.reported_at,
                  p.display_name AS patient_name,
                  p.date_of_birth
             FROM imaging_report ir
             JOIN patient p ON p.id = ir.patient_id
            WHERE ir.id = $1`,
          [link.report_id]
        );

        await recordAccess({
          actorId: link.created_by,
          patientId: link.patient_id,
          resource: `imaging_share_link:${link.id}`,
          action: 'open'
        });

        return h.response({ sharedReport: report, openedBefore: link.opened_count }).code(200);
      }
    });
  }
};
