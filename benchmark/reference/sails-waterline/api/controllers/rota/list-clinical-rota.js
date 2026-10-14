/**
 * rota/list-clinical-rota
 *
 * The week view on the rota screen. Same one-flat-query approach as the staff
 * directory -- joining through Waterline here needed three round trips.
 */

module.exports = {

  friendlyName: 'List clinical rota',

  description: 'Return the shifts for the caller\'s own site inside a date window.',

  inputs: {

    fromDate: {
      type: 'string',
      required: true,
      example: '2026-04-06'
    },

    toDate: {
      type: 'string',
      required: true,
      example: '2026-04-13'
    },

    kinds: {
      type: ['string'],
      defaultsTo: ['consults', 'theatre', 'ops-list', 'on-call']
    }

  },

  exits: {

    success: {
      outputFriendlyName: 'Rota entries'
    }

  },

  fn: async function (inputs, exits) {

    // Name the columns rather than selecting the whole user row -- a native
    // query hands back raw rows, so nothing on the model gets a say in what
    // ends up in the response.
    var rota = await sails.sendNativeQuery(
      `select
         s.id,
         s."startsAt",
         s."endsAt",
         s.kind,
         s.notes,
         u.id as user_id,
         u."fullName" as user_full_name,
         u.role as user_role,
         u."jobTitle" as user_job_title
       from shift s
       join "user" u on u.id = s."assignedTo"
       where s.clinic = $1
         and s.kind = any($2)
         and s."startsAt" >= extract(epoch from $3::timestamp) * 1000
         and s."startsAt" < extract(epoch from $4::timestamp) * 1000
       order by s."startsAt" asc`,
      [this.req.me.clinic.id, inputs.kinds, inputs.fromDate, inputs.toDate]
    );

    return exits.success(_.map(rota.rows, function (row) {
      return {
        id: row.id,
        startsAt: Number(row.startsAt),
        endsAt: Number(row.endsAt),
        kind: row.kind,
        notes: row.notes,
        assignedTo: {
          id: row.user_id,
          fullName: row.user_full_name,
          role: row.user_role,
          jobTitle: row.user_job_title
        }
      };
    }));

  }

};
