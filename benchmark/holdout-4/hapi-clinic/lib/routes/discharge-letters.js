// Discharge letters. Same document-service layout as referral letters: one
// folder per letter under the store, enclosures named after their content
// hash.
import { createReadStream } from 'node:fs';
import path from 'node:path';
import Joi from 'joi';
import Boom from '@hapi/boom';
import { one, recordAccess } from '../db.js';
import { actor, isOnCareTeam } from '../session.js';

const DISCHARGE_ROOT = process.env.CLINIC_DISCHARGE_ROOT ?? '/var/lib/clinic/discharge-letters';

// Enclosure names are content hashes written by the document service.
const ENCLOSURE_NAME = /^[0-9a-f]{32}\.pdf$/;

async function loadLetter(request) {
  const letter = await one(
    `SELECT id, patient_id, reference, storage_prefix, discharged_on
       FROM discharge_letter
      WHERE reference = $1`,
    [request.params.reference]
  );

  if (!letter) {
    throw Boom.notFound('discharge letter not found');
  }

  return letter;
}

export const plugin = {
  name: 'discharge-letters',
  version: '1.9.2',
  register(server) {
    server.route({
      method: 'GET',
      path: '/api/discharge-letters/{reference}/attachment',
      options: {
        auth: 'session',
        tags: ['api', 'letters'],
        description: 'Stream one enclosure from a discharge letter',
        validate: {
          params: Joi.object({
            reference: Joi.string().pattern(/^DIS-[0-9]{8}$/).required()
          }),
          query: Joi.object({
            file: Joi.string().pattern(ENCLOSURE_NAME).required()
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

        const storeRoot = path.resolve(DISCHARGE_ROOT);
        const attachment = path.resolve(storeRoot, letter.storage_prefix, request.query.file);

        // The Joi pattern already excludes separators and dots, but the
        // storage prefix comes out of the database, so require the resolved
        // path to sit under the store before anything is opened.
        if (!attachment.startsWith(storeRoot + path.sep)) {
          throw Boom.badRequest('enclosure resolves outside the letter store');
        }

        await recordAccess({
          actorId: me.id,
          patientId: letter.patient_id,
          resource: `discharge_letter:${letter.id}`,
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
