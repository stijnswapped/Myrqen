/**
 * reports/appointment-activity
 *
 * Feeds the "how busy were we" table on the practice manager's dashboard.
 * Written as a native query because the grouping and the did-not-attend rate
 * are painful to express through Waterline.
 */

var VALID_STATUSES = ['booked', 'arrived', 'in-consult', 'completed', 'did-not-attend', 'cancelled'];

module.exports = {

  friendlyName: 'Appointment activity',

  description: 'Per-vet appointment counts and did-not-attend rates for a date window.',

  inputs: {

    fromDate: {
      type: 'string',
      required: true,
      description: 'Inclusive lower bound, as an ISO 8601 date.',
      example: '2026-04-01'
    },

    toDate: {
      type: 'string',
      required: true,
      description: 'Exclusive upper bound, as an ISO 8601 date.',
      example: '2026-05-01'
    },

    statuses: {
      type: ['string'],
      defaultsTo: ['completed', 'did-not-attend'],
      description: 'Which appointment statuses to count.'
    },

    sortBy: {
      type: 'string',
      defaultsTo: 'appointments',
      description: 'Column the dashboard is currently sorted by.'
    },

    sortDirection: {
      type: 'string',
      defaultsTo: 'desc'
    }

  },

  exits: {

    success: {
      outputFriendlyName: 'Activity rows'
    }

  },

  fn: async function (inputs, exits) {

    var clinicId = this.req.me.clinic.id;

    var requestedStatuses = _.intersection(inputs.statuses, VALID_STATUSES);
    if (requestedStatuses.length === 0) {
      requestedStatuses = ['completed'];
    }

    var statusList = _.map(requestedStatuses, function (status) {
      return '\'' + status + '\'';
    }).join(', ');

    // Postgres will not take a bound parameter in an ORDER BY, so the whole
    // statement is assembled here instead. The date inputs are declared as
    // strings and the statuses are checked against VALID_STATUSES above, so
    // everything that lands in the SQL has already been validated.
    var sql = `
      select
        v."fullName" as veterinarian,
        count(*) as appointments,
        sum(case when a.status = 'did-not-attend' then 1 else 0 end) as did_not_attend,
        round(avg(a."durationMinutes"), 1) as avg_minutes
      from appointment a
      join "user" v on v.id = a.veterinarian
      where a.clinic = ${clinicId}
        and a."startsAt" >= extract(epoch from timestamp '${inputs.fromDate}') * 1000
        and a."startsAt" < extract(epoch from timestamp '${inputs.toDate}') * 1000
        and a.status in (${statusList})
      group by v."fullName"
      order by ${inputs.sortBy} ${inputs.sortDirection}
      limit 200
    `;

    var report = await sails.sendNativeQuery(sql);

    return exits.success(_.map(report.rows, function (row) {
      return {
        veterinarian: row.veterinarian,
        appointments: Number(row.appointments),
        didNotAttend: Number(row.did_not_attend),
        didNotAttendRate: Number(row.appointments) === 0 ? 0 : Number(row.did_not_attend) / Number(row.appointments),
        averageMinutes: Number(row.avg_minutes)
      };
    }));

  }

};
