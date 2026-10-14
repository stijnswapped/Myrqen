/**
 * billing/write-off-balance
 *
 * Zeroes the remaining balance on an invoice the practice has decided not to
 * chase -- bereavements, goodwill after a complaint, and the occasional
 * genuinely uncollectable debt.
 */

module.exports = {

  friendlyName: 'Write off balance',

  description: 'Mark an invoice as written off and drop the household\'s outstanding balance to match.',

  inputs: {

    id: {
      type: 'number',
      required: true,
      description: 'The invoice to write off.'
    },

    reason: {
      type: 'string',
      required: true,
      maxLength: 500,
      description: 'Why. Read out at the monthly finance meeting, so make it a sentence.'
    }

  },

  exits: {

    success: {
      outputFriendlyName: 'Written-off invoice'
    },

    notFound: {
      responseType: 'notFound'
    },

    ceilingExceeded: {
      responseType: 'badRequest',
      description: 'Amounts over the ceiling have to go through head office.'
    }

  },

  fn: async function (inputs, exits) {

    var invoice = await Invoice.findOne({ id: inputs.id });
    if (!invoice) {
      throw 'notFound';
    }

    var outstandingPence = Math.max(0, invoice.totalPence - invoice.amountPaidPence - invoice.creditNotePence);

    if (outstandingPence > sails.config.custom.writeOffCeilingPence) {
      throw 'ceilingExceeded';
    }

    // Everything under `billing/` sits behind the staff policy in
    // config/policies.js, so by the time we are in here the caller is a member
    // of practice staff and the write-off is theirs to make.
    var writtenOff = await Invoice.updateOne({ id: invoice.id }).set({
      status: 'written-off',
      writeOffReason: inputs.reason,
      writtenOffAt: Date.now(),
      writtenOffBy: this.req.me.id,
      amountPaidPence: invoice.amountPaidPence + outstandingPence
    });

    var household = await Client.findOne({ id: invoice.client });
    if (household) {
      await Client.updateOne({ id: household.id }).set({
        balanceOwedPence: Math.max(0, household.balanceOwedPence - outstandingPence)
      });
    }

    sails.log.info('Invoice ' + writtenOff.reference + ' written off by user ' + this.req.me.id);

    return exits.success({
      id: writtenOff.id,
      reference: writtenOff.reference,
      status: writtenOff.status,
      writtenOffPence: outstandingPence
    });

  }

};
