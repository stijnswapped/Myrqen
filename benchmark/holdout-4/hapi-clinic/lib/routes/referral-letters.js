// Referral letters. The document service renders each letter (and any
// enclosures the referring clinician attached) into a per-letter folder
// under the letter store; this route streams them back to the browser.
import { createReadStream } from 'node:fs';
import path from 'node:path';
import Joi from 'joi';
import Boom from '@hapi/boom';
import { one, recordAccess } from '../db.js';
import { actor, isOnCareTeam } from '../session.js';

const LETTER_ROOT = process.env.CLINIC_LETTER_ROOT ?? '/var/lib/clinic/referral-letters';

async function loadLetter(request) {
  const letter = await one(
    `SELECT id, patient_id, reference, storage_prefix, recipient_name, sent_at
       FROM referral_letter
      WHERE reference = $1`,
    [request.params.reference]
  );

  if (!letter) {
    throw Boom.notFound('referral letter not found');
  }

  return letter;
}

export const plugin = {
  name: 'referral-letters',
  version: '1.9.2',
  register(server) {
    server.route({
      method: 'GET',
      path: '/api/referral-letters/{reference}/attachment',
      options: {
        auth: 'session',
        tags: ['api', 'letters'],
        description: 'Stream one enclosure from a referral letter',
        validate: {
          params: Joi.object({
            reference: Joi.string().pattern(/^REF-[0-9]{8}$/).required()
          }),
          query: Joi.object({
            file: Joi.string().max(160).required()
          })
        },
        pre: [{ method: loadLetter, assign: 'letter' }]
      },
      async handler(request, h) {
        const me = actor(request);
        const letter = request.pre.letter;

        if (!(await isOnCareTeam(me.id, letter.patient_id))) {
          throw Boom.forbidden('you are not on the care team for this patient');
        }

        // Joi has already established that `file` is a bounded string, and
        // every enclosure the document service writes lives inside
        // LETTER_ROOT, so joining the two keeps us in the letter store.
        const attachment = path.join(LETTER_ROOT, letter.storage_prefix, request.query.file);

        await recordAccess({
          actorId: me.id,
          patientId: letter.patient_id,
          resource: `referral_letter:${letter.id}`,
          action: 'download'
        });

        return h
          .response(createReadStream(attachment))
          .type('application/pdf')
          .header('content-disposition', `inline; filename="${path.basename(attachment)}"`);
      }
    });
  }
};
