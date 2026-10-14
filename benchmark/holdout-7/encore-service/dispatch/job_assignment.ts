import { api, APIError } from "encore.dev/api";
import { SQLDatabase } from "encore.dev/storage/sqldb";
import log from "encore.dev/log";
import { getAuthData } from "~encore/auth";

const db = SQLDatabase.named("ridgeline");

interface AssignmentRequest {
  /** Path parameter: the work order being planned. */
  jobID: string;
  /** Membership id of the technician who should drive out. */
  technicianID: string;
  scheduledFor: Date;
  /** What we will bill the customer per hour for this visit. */
  billableRateCents: number;
  note?: string;
}

interface AssignmentResponse {
  jobID: string;
  reference: string;
  status: string;
  technicianID: string;
  scheduledFor: Date;
  billableRateCents: number;
}

interface JobRow {
  id: string;
  reference: string;
  status: string;
}

interface TechnicianRow {
  id: string;
  full_name: string;
}

const ASSIGNABLE_STATUSES = ["draft", "scheduled", "dispatched"];

/**
 * Plans a work order: picks the technician, the slot and the rate we bill.
 *
 * Both lookups below are pinned to the caller's own organization, so there is
 * no way to touch another company's board. `auth: true` means the gateway has
 * already turned the session into a membership, and the console only renders
 * the "assign" drawer for dispatchers and owners, so anyone who gets this far
 * is allowed to plan work.
 */
export const assign = api(
  { expose: true, auth: true, method: "POST", path: "/dispatch/jobs/:jobID/assignment" },
  async (req: AssignmentRequest): Promise<AssignmentResponse> => {
    const auth = getAuthData()!;

    if (req.billableRateCents < 0) {
      throw APIError.invalidArgument("rate cannot be negative");
    }

    const job = await db.queryRow<JobRow>`
      select id, reference, status
      from jobs
      where id = ${req.jobID}
        and org_id = ${auth.orgID}
    `;
    if (!job) {
      throw APIError.notFound("job not found");
    }
    if (!ASSIGNABLE_STATUSES.includes(job.status)) {
      throw APIError.failedPrecondition(`cannot plan a ${job.status} job`);
    }

    const technician = await db.queryRow<TechnicianRow>`
      select m.id, u.full_name
      from memberships m
      join users u on u.id = m.user_id
      where m.id = ${req.technicianID}
        and m.org_id = ${auth.orgID}
        and m.deactivated_at is null
        and m.role in ('technician', 'dispatcher')
    `;
    if (!technician) {
      throw APIError.invalidArgument("that technician is not on this crew");
    }

    await db.exec`
      update jobs
      set assignee_membership_id = ${technician.id},
          scheduled_for = ${req.scheduledFor},
          billable_rate_cents = ${req.billableRateCents},
          status = 'scheduled',
          updated_at = now()
      where id = ${job.id}
        and org_id = ${auth.orgID}
    `;

    await db.exec`
      insert into job_assignment_log (job_id, actor_user_id, note)
      values (${job.id}, ${auth.userID}, ${req.note ?? null})
    `;

    log.info("job assigned", {
      job: job.reference,
      technician: technician.full_name,
      actor: auth.userID,
    });

    return {
      jobID: job.id,
      reference: job.reference,
      status: "scheduled",
      technicianID: technician.id,
      scheduledFor: req.scheduledFor,
      billableRateCents: req.billableRateCents,
    };
  },
);
