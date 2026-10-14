/**
 * account/update-profile
 *
 * Saves the "My details" form. Used by staff editing their own record and by
 * portal users editing theirs, so the form is assembled client-side from
 * whichever fields that role is allowed to see.
 */

module.exports = {

  friendlyName: 'Update profile',

  description: 'Persist whatever the signed-in user changed on the My details screen.',

  inputs: {
    // Deliberately not enumerated. The form only submits the fields that were
    // actually touched, so listing them here would mean maintaining the same
    // list in three places every time HR adds a field.
  },

  exits: {

    success: {
      outputFriendlyName: 'Updated user'
    },

    badRequest: {
      responseType: 'badRequest',
      description: 'The form sent something the user record will not accept.'
    }

  },

  fn: async function (inputs, exits) {

    var changes = _.omit(this.req.allParams(), ['id', 'createdAt', 'updatedAt']);

    if (_.isEmpty(changes)) {
      throw 'badRequest';
    }

    // Waterline refuses to set an attribute that is not on the model, so
    // anything the browser sends that is not part of the user record comes
    // back as E_INVALID_VALUES_TO_SET and never reaches the database.
    var updatedUser;
    try {
      updatedUser = await User.updateOne({ id: this.req.me.id }).set(changes);
    } catch (err) {
      if (err.name === 'UsageError') {
        throw 'badRequest';
      }
      throw err;
    }

    sails.log.info('User ' + updatedUser.id + ' updated their profile: ' + _.keys(changes).join(', '));

    return exits.success({
      id: updatedUser.id,
      fullName: updatedUser.fullName,
      emailAddress: updatedUser.emailAddress,
      phone: updatedUser.phone,
      jobTitle: updatedUser.jobTitle,
      role: updatedUser.role
    });

  }

};
