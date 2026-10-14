/**
 * invoices/view-patient-statement
 *
 * The printable statement a household gets emailed after a visit. Nearly the
 * same payload as the invoice drawer, minus anything clinical.
 */

module.exports = {

  friendlyName: 'View patient statement',

  description: 'Return one statement belonging to a given household.',

  inputs: {

    clientId: {
      type: 'number',
      required: true,
      description: 'The household the statement belongs to.'
    },

    id: {
      type: 'number',
      required: true,
      description: 'The primary key of the invoice being rendered as a statement.'
    }

  },

  exits: {

    success: {
      outputFriendlyName: 'Statement'
    },

    notFound: {
      responseType: 'notFound',
      description: 'No such statement, or the caller is not entitled to see it.'
    }

  },

  fn: async function (inputs, exits) {

    var invoice = await Invoice.findOne({ id: inputs.id, client: inputs.clientId })
    .populate('client')
    .populate('patient');

    if (!invoice) {
      throw 'notFound';
    }

    // A portal user may only ever pull their own household's statements.
    // Staff may pull any statement raised by their own site. Anything else is
    // a 404 rather than a 403 so we do not confirm that the record exists.
    if (this.req.me.role === 'client') {
      if (!this.req.me.client || this.req.me.client !== invoice.client.id) {
        throw 'notFound';
      }
    } else if (this.req.me.clinic.id !== invoice.clinic) {
      throw 'notFound';
    }

    var lines = await InvoiceLine.find({ invoice: invoice.id }).sort('sortOrder ASC');

    var outstandingPence = Math.max(0, invoice.totalPence - invoice.amountPaidPence - invoice.creditNotePence);

    return exits.success({
      id: invoice.id,
      reference: invoice.reference,
      status: invoice.status,
      issuedAt: invoice.issuedAt,
      dueAt: invoice.dueAt,
      totalPence: invoice.totalPence,
      amountPaidPence: invoice.amountPaidPence,
      outstandingPence: outstandingPence,
      client: {
        id: invoice.client.id,
        displayName: invoice.client.displayName,
        billingEmail: invoice.client.billingEmail
      },
      patient: invoice.patient ? { id: invoice.patient.id, name: invoice.patient.name, species: invoice.patient.species } : null,
      lines: _.map(lines, function (line) {
        return {
          description: line.description,
          quantity: line.quantity,
          unitPricePence: line.unitPricePence
        };
      })
    });

  }

};
