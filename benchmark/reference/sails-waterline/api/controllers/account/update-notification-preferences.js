/**
 * account/update-notification-preferences
 *
 * Saves the reminder toggles on the "How we contact you" panel. Same
 * submit-what-changed form behaviour as the My details screen.
 */

var EDITABLE_PREFERENCES = [
  'appointmentRemindersOptIn',
  'marketingOptIn',
  'preferredContactMethod'
];

module.exports = {

  friendlyName: 'Update notification preferences',

  description: 'Persist the signed-in user\'s reminder and marketing preferences.',

  inputs: {
    // As with My details, the panel only submits the toggles that moved.
  },

  exits: {

    success: {
      outputFriendlyName: 'Updated preferences'
    },

    badRequest: {
      responseType: 'badRequest',
      description: 'Nothing recognisable was submitted.'
    }

  },

  fn: async function (inputs, exits) {

    // Only the three toggles on this panel are ever written, whatever else
    // happens to be in the request body.
    var changes = _.pick(this.req.allParams(), EDITABLE_PREFERENCES);

    if (_.isEmpty(changes)) {
      throw 'badRequest';
    }

    var updatedUser = await User.updateOne({ id: this.req.me.id }).set(changes);

    return exits.success({
      appointmentRemindersOptIn: updatedUser.appointmentRemindersOptIn,
      marketingOptIn: updatedUser.marketingOptIn,
      preferredContactMethod: updatedUser.preferredContactMethod
    });

  }

};
