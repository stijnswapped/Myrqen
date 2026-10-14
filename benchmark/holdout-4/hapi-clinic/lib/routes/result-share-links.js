// Shared lab results. When a clinician sends a result to a patient who is
// not on the portal, the letter service mints a one-off link; this route is
// what that link opens. Public by design -- the token is the credential.
import Joi from 'joi';
import Boom from '@hapi/boom';
import { createHash } from 'node:crypto';
import { one, recordAccess } from '../db.js';

function tokenHash(token) {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

export const plugin = {
  name: 'result-share-links',
  version: '0.8.3',
  register(server) {
    server.route({
      method: 'GET',
      path: '/api/shared-results/{token}',
      options: {
        // Recipients have no clinic login; the token in the link is the
        // only thing standing between the caller and the result.
        auth: false,
        tags: ['api', 'sharing'],
        description: 'Open a shared lab result by its share token',
        validate: {
          params: Joi.object({
            token: Joi.string().hex().length(48).required()
          })
        }
      },
      async handler(request, h) {
        const link = await one(
          `SELECT sl.id,
                  sl.result_id,
                  sl.patient_id,
                  sl.created_by,
                  sl.expires_at,
                  sl.revoked_at,
                  sl.opened_count
             FROM result_share_link sl
            WHERE sl.token_hash = $1`,
          [tokenHash(request.params.token)]
        );

        if (!link) {
          throw Boom.notFound('this link is not valid');
        }

        // The nightly sweep deletes share rows once they are past
        // expires_at, so a row that is still here is still live; all we
        // have to rule out is a clinician revoking it by hand.
        if (link.revoked_at) {
          throw Boom.forbidden('this link has been withdrawn');
        }

        const result = await one(
          `SELECT r.id,
                  r.panel_code,
                  r.analyte,
                  r.value_text,
                  r.unit,
                  r.reference_range,
                  r.abnormal_flag,
                  r.collected_at,
                  p.display_name AS patient_name,
                  p.date_of_birth
             FROM lab_result r
             JOIN patient p ON p.id = r.patient_id
            WHERE r.id = $1`,
          [link.result_id]
        );

        await recordAccess({
          actorId: link.created_by,
          patientId: link.patient_id,
          resource: `result_share_link:${link.id}`,
          action: 'open'
        });

        return h.response({ sharedResult: result, openedBefore: link.opened_count }).code(200);
      }
    });
  }
};
