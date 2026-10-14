/**
 * billing/apply-credit-note
 *
 * Puts a credit against an invoice -- usually because we re-quoted a procedure
 * after the fact. Same money-moving shape as the write-off action next door.
 */

var ROLES_ALLOWED_TO_ADJUST = ['practice_manager', 'admin'];

module.exports = {

  friendlyName: 'Apply credit note',

  description: 'Credit part of an invoice and drop the household\'s outstanding balance to match.',

  inputs: {

    id: {
      type: 'number',
      required: true,
      description: 'The invoice to credit.'
    },

    amountPence: {
      type: 'number',
      required: true,
      min: 1,
      description: 'How much to credit, in pence.'
    },

    reason: {
      type: 'string',
      required: true,
      maxLength: 500
    }

  },

  exits: {

    success: {
      outputFriendlyName: 'Credited invoice'
    },

    notFound: {
      responseType: 'notFound'
    },

    forbidden: {
      responseType: 'forbidden',
      description: 'Only a practice manager or an administrator may move money.'
    },

    ceilingExceeded: {
      responseType: 'badRequest'
    }

  },

  fn: async function (inputs, exits) {

    // The staff policy on this action only proves the caller is not a portal
    // user. Moving money is a practice manager's job, so check the role here.
    if (!_.includes(ROLES_ALLOWED_TO_ADJUST, this.req.me.role)) {
      throw 'forbidden';
    }

    var invoice = await Invoice.findOne({ id: inputs.id });
    if (!invoice) {
      throw 'notFound';
    }

    // A manager at Milford has no business crediting a Northgate invoice.
    if (invoice.clinic !== this.req.me.clinic.id) {
      throw 'notFound';
    }

    var outstandingPence = Math.max(0, invoice.totalPence - invoice.amountPaidPence - invoice.creditNotePence);
    var creditPence = Math.min(inputs.amountPence, outstandingPence);

    if (creditPence > sails.config.custom.writeOffCeilingPence) {
      throw 'ceilingExceeded';
    }

    var credited = await Invoice.updateOne({ id: invoice.id }).set({
      creditNotePence: invoice.creditNotePence + creditPence,
      creditNoteReason: inputs.reason,
      adjustedBy: this.req.me.id,
      status: creditPence >= outstandingPence ? 'paid' : invoice.status
    });

    var household = await Client.findOne({ id: invoice.client });
    if (household) {
      await Client.updateOne({ id: household.id }).set({
        balanceOwedPence: Math.max(0, household.balanceOwedPence - creditPence)
      });
    }

    sails.log.info('Invoice ' + credited.reference + ' credited ' + creditPence + 'p by user ' + this.req.me.id);

    return exits.success({
      id: credited.id,
      reference: credited.reference,
      status: credited.status,
      creditedPence: creditPence
    });

  }

};
