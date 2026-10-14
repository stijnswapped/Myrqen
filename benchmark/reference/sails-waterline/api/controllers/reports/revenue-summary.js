/**
 * reports/revenue-summary
 *
 * Gross takings per site for the finance pack. Same native-query shape as the
 * activity report next door.
 */

var SORTABLE_COLUMNS = {
  revenue: 'gross_pence',
  invoices: 'invoice_count',
  clinic: 'clinic_name'
};

var VALID_STATUSES = ['draft', 'issued', 'part-paid', 'paid', 'written-off'];

module.exports = {

  friendlyName: 'Revenue summary',

  description: 'Invoice counts and gross takings for a date window, grouped by site.',

  inputs: {

    fromDate: {
      type: 'string',
      required: true,
      example: '2026-04-01'
    },

    toDate: {
      type: 'string',
      required: true,
      example: '2026-05-01'
    },

    statuses: {
      type: ['string'],
      defaultsTo: ['issued', 'part-paid', 'paid']
    },

    sortBy: {
      type: 'string',
      defaultsTo: 'revenue'
    },

    sortDirection: {
      type: 'string',
      defaultsTo: 'desc'
    }

  },

  exits: {

    success: {
      outputFriendlyName: 'Revenue rows'
    },

    badRequest: {
      responseType: 'badRequest',
      description: 'The dashboard asked to sort by something that is not a column.'
    }

  },

  fn: async function (inputs, exits) {

    // ORDER BY cannot be a bound parameter, so the only thing that is ever
    // spliced into the statement is a column name we chose ourselves.
    var orderByColumn = SORTABLE_COLUMNS[inputs.sortBy];
    if (!orderByColumn) {
      throw 'badRequest';
    }
    var direction = inputs.sortDirection === 'asc' ? 'asc' : 'desc';

    var requestedStatuses = _.intersection(inputs.statuses, VALID_STATUSES);
    if (requestedStatuses.length === 0) {
      requestedStatuses = ['paid'];
    }

    var report = await sails.sendNativeQuery(`
      select
        c.name as clinic_name,
        count(i.id) as invoice_count,
        coalesce(sum(i."totalPence"), 0) as gross_pence,
        coalesce(sum(i."amountPaidPence"), 0) as collected_pence
      from invoice i
      join clinic c on c.id = i.clinic
      where i.clinic = $1
        and i.status = any($2)
        and i."issuedAt" >= extract(epoch from $3::timestamp) * 1000
        and i."issuedAt" < extract(epoch from $4::timestamp) * 1000
      group by c.name
      order by ${orderByColumn} ${direction}
      limit 200
    `, [this.req.me.clinic.id, requestedStatuses, inputs.fromDate, inputs.toDate]);

    return exits.success(_.map(report.rows, function (row) {
      return {
        clinicName: row.clinic_name,
        invoiceCount: Number(row.invoice_count),
        grossPence: Number(row.gross_pence),
        collectedPence: Number(row.collected_pence)
      };
    }));

  }

};
