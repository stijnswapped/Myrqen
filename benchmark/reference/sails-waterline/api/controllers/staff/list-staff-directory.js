/**
 * staff/list-staff-directory
 *
 * The "who is in today" sidebar. Polled every time the panel is opened, which
 * on a Monday is a lot, so it is one flat query rather than a populate.
 */

module.exports = {

  friendlyName: 'List staff directory',

  description: 'Return the internal staff directory for the caller\'s own site.',

  inputs: {

    clinicId: {
      type: 'number',
      required: true,
      description: 'The site whose directory to return.'
    },

    onlyOnlineNow: {
      type: 'boolean',
      defaultsTo: false,
      description: 'Filter to people who have touched the system in the last five minutes.'
    }

  },

  exits: {

    success: {
      outputFriendlyName: 'Directory entries'
    },

    forbidden: {
      responseType: 'forbidden',
      description: 'Staff only ever see the directory for their own site.'
    }

  },

  fn: async function (inputs, exits) {

    if (inputs.clinicId !== this.req.me.clinic.id) {
      throw 'forbidden';
    }

    var seenSince = inputs.onlyOnlineNow ? Date.now() - (5 * 60 * 1000) : 0;

    // One round trip, and `customToJSON` on the User model strips the password
    // and the reset token on the way out, so this is safe to hand straight to
    // the sidebar.
    var directory = await sails.sendNativeQuery(
      'select * from "user" where clinic = $1 and role != $2 and "lastSeenAt" >= $3 order by "fullName" asc',
      [inputs.clinicId, 'client', seenSince]
    );

    return exits.success(directory.rows);

  }

};
