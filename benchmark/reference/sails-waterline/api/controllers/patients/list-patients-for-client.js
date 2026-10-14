/**
 * patients/list-patients-for-client
 *
 * The animals belonging to one household. Rendered on the client record at the
 * front desk and on the "My pets" tab in the portal.
 */

var SEARCHABLE_ATTRIBUTES = ['name', 'breed', 'microchipNumber'];

module.exports = {

  friendlyName: 'List patients for client',

  description: 'Return the animals registered against one household.',

  inputs: {

    clientId: {
      type: 'number',
      required: true
    },

    search: {
      type: 'string',
      allowNull: true,
      description: 'Free text typed into the filter box above the list.'
    },

    species: {
      type: 'string',
      isIn: ['dog', 'cat', 'rabbit', 'ferret', 'bird', 'reptile', 'other'],
      allowNull: true
    },

    includeDeceased: {
      type: 'boolean',
      defaultsTo: false
    },

    limit: {
      type: 'number',
      defaultsTo: 50,
      max: 200
    }

  },

  exits: {

    success: {
      outputFriendlyName: 'Patients'
    },

    notFound: {
      responseType: 'notFound'
    }

  },

  fn: async function (inputs, exits) {

    // A portal user only ever gets their own household.
    if (this.req.me.role === 'client' && this.req.me.client !== inputs.clientId) {
      throw 'notFound';
    }

    var where = {
      clinic: this.req.me.clinic.id,
      client: inputs.clientId
    };

    if (!inputs.includeDeceased) {
      where.isDeceased = false;
    }

    if (inputs.species) {
      where.species = inputs.species;
    }

    if (inputs.search) {
      // Only the three columns listed above are ever matched against, and the
      // typed text only ever lands inside a `contains` modifier.
      where.or = _.map(SEARCHABLE_ATTRIBUTES, function (attribute) {
        var fragment = {};
        fragment[attribute] = { contains: inputs.search };
        return fragment;
      });
    }

    var patients = await Patient.find({
      where: where,
      limit: inputs.limit,
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
