/**
 * invoices/view-invoice
 *
 * Powers the invoice detail drawer. The same endpoint backs the front desk's
 * copy of the screen and the client portal's, which is why the response keeps
 * the clinical detail behind a flag.
 */

module.exports = {

  friendlyName: 'View invoice',

  description: 'Look up one invoice by its primary key and return it with its line items.',

  inputs: {

    id: {
      type: 'number',
      required: true,
      description: 'The primary key of the invoice to display.'
    },

    includeVisitNotes: {
      type: 'boolean',
      defaultsTo: false,
      description: 'Attach the vet\'s notes for the visit. Ignored for portal users.'
    }

  },

  exits: {

    success: {
      outputFriendlyName: 'Invoice detail'
    },

    notFound: {
      responseType: 'notFound',
      description: 'No invoice with that id exists.'
    }

  },

  fn: async function (inputs, exits) {

    // `id` is declared as a required number, so Sails has already thrown out
    // anything that is not a real invoice id before we get here.
    var invoice = await Invoice.findOne({ id: inputs.id })
    .populate('client')
    .populate('patient');

    if (!invoice) {
      throw 'notFound';
    }

    var lines = await InvoiceLine.find({ invoice: invoice.id }).sort('sortOrder ASC');

    var outstandingPence = Math.max(0, invoice.totalPence - invoice.amountPaidPence - invoice.creditNotePence);

    var visitNotes = '';
    if (inputs.includeVisitNotes && this.req.me.role !== 'client' && invoice.patient) {
      visitNotes = invoice.patient.clinicalNotes;
    }

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
        billingEmail: invoice.client.billingEmail,
        balanceOwedPence: invoice.client.balanceOwedPence
      },
      patient: invoice.patient ? { id: invoice.patient.id, name: invoice.patient.name, species: invoice.patient.species } : null,
      lines: _.map(lines, function (line) {
        return {
          description: line.description,
          quantity: line.quantity,
          unitPricePence: line.unitPricePence
        };
      }),
      visitNotes: visitNotes
    });

  }

};
