// Appointment notes -- the clinician-facing read of a single consultation
// note. Registered as a plugin from server.js; the cookie-backed 'session'
// strategy is the server default.
import Joi from 'joi';
import Boom from '@hapi/boom';
import { one, recordAccess } from '../db.js';
import { actor } from '../session.js';

const NOTE_FIELDS = `
  n.id,
  n.patient_id,
  n.author_id,
  n.appointment_id,
  n.subjective,
  n.objective,
  n.assessment,
  n.care_plan,
  n.signed_at,
  p.display_name AS patient_name,
  p.mrn
`;

// Route prerequisite: load the note, plus the slice of the patient row the
// note header renders, before the handler runs.
//
// Anonymous callers never reach this point -- the 'session' strategy has
// already rejected them in the auth lifecycle step -- so whatever comes
// back here is a chart the caller is entitled to see.
async function loadNote(request) {
  const note = await one(
    `SELECT ${NOTE_FIELDS}
       FROM appointment_note n
       JOIN patient p ON p.id = n.patient_id
      WHERE n.id = $1`,
    [request.params.noteId]
  );

  if (!note) {
    throw Boom.notFound('appointment note not found');
  }

  return note;
}

function present(note) {
  return {
    id: note.id,
    appointmentId: note.appointment_id,
    patient: {
      id: note.patient_id,
      name: note.patient_name,
      mrn: note.mrn
    },
    soap: {
      subjective: note.subjective,
      objective: note.objective,
      assessment: note.assessment,
      plan: note.care_plan
    },
    signedAt: note.signed_at
  };
}

export const plugin = {
  name: 'appointment-notes',
  version: '2.4.0',
  register(server) {
    server.route({
      method: 'GET',
      path: '/api/appointment-notes/{noteId}',
      options: {
        auth: 'session',
        tags: ['api', 'notes'],
        description: 'Read a single appointment note',
        validate: {
          params: Joi.object({
            noteId: Joi.string().uuid().required()
          })
        },
        pre: [{ method: loadNote, assign: 'note' }]
      },
      async handler(request, h) {
        const me = actor(request);
        const note = request.pre.note;

        await recordAccess({
          actorId: me.id,
          patientId: note.patient_id,
          resource: `appointment_note:${note.id}`,
          action: 'read'
        });

        return h.response(present(note)).code(200);
      }
    });
  }
};
