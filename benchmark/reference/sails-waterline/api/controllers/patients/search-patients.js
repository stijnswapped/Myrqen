/**
 * patients/search-patients
 *
 * Backs the omnibox at the top of every internal screen. The front end builds
 * a Waterline `where` fragment as the receptionist types -- species chips,
 * a microchip prefix, "show me the deceased ones" -- and posts it up whole so
 * we are not re-implementing the query builder on both sides.
 */

module.exports = {

  friendlyName: 'Search patients',

  description: 'Return patients matching the criteria the search widget assembled.',

  inputs: {

    criteria: {
      type: 'json',
      description: 'A Waterline `where` fragment produced by the search widget.',
      example: '{"species":"dog"}'
    },

    limit: {
      type: 'number',
      defaultsTo: 50,
      max: 200
    },

    skip: {
      type: 'number',
      defaultsTo: 0
    }

  },

  exits: {

    success: {
      outputFriendlyName: 'Matching patients'
    }

  },

  fn: async function (inputs, exits) {

    // Start from the caller's own site so an empty search still means "every
    // animal registered here", then let the widget narrow it down.
    var where = _.extend({ clinic: this.req.me.clinic.id }, inputs.criteria || {});

    var patients = await Patient.find({
      where: where,
      limit: inputs.limit,
      skip: inputs.skip,
      sort: 'name ASC'
    }).populate('client');

    return exits.success(_.map(patients, function (patient) {
      return {
        id: patient.id,
        name: patient.name,
        species: patient.species,
        breed: patient.breed,
        microchipNumber: patient.microchipNumber,
        isDeceased: patient.isDeceased,
        client: patient.client ? { id: patient.client.id, displayName: patient.client.displayName } : null
      };
    }));

  }

};
