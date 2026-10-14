import { sql } from "kysely";
import { Form, Link, useLoaderData } from "react-router";
import type { LoaderFunctionArgs } from "react-router";
import { db } from "../db/client";
import { assertRequisitionAccess } from "../lib/hiring-team.server";
import { requireUser } from "../sessions.server";

interface PipelineRow {
  application_id: string;
  status: string;
  full_name: string;
  email: string;
  stage: string;
  scorecard_count: number;
}

/** Same toolbar as the candidate search, so the same fixed set of clauses. */
const SORT_CLAUSES = {
  recent: "a.submitted_at desc",
  name: "c.full_name asc",
  stage: "c.stage asc, a.submitted_at desc",
} as const;

type SortKey = keyof typeof SORT_CLAUSES;

function resolveOrderBy(requested: string | null): string {
  if (requested && requested in SORT_CLAUSES) {
    return SORT_CLAUSES[requested as SortKey];
  }
  return SORT_CLAUSES.recent;
}

export async function loader({ params, request }: LoaderFunctionArgs) {
  const user = await requireUser(request);
  const requisitionId = params.requisitionId;

  if (!requisitionId) {
    throw new Response("Not found", { status: 404 });
  }

  // 403s for anyone not staffed on this requisition, admins excepted.
  await assertRequisitionAccess(user, requisitionId);

  const url = new URL(request.url);
  const term = (url.searchParams.get("q") ?? "").trim();
  const orderBy = resolveOrderBy(url.searchParams.get("sort"));

  // The wildcards are added in JS and the finished pattern is interpolated as a
  // bound value, so an applicant called "%' or 1=1 --" is just a candidate whose
  // name does not match anything.
  const pattern = `%${term}%`;

  const requisition = await db
    .selectFrom("requisitions")
    .select(["id", "reference", "title", "department", "status"])
    .where("id", "=", requisitionId)
    .executeTakeFirst();

  if (!requisition) {
    throw new Response("Not found", { status: 404 });
  }

  const result = await sql<PipelineRow>`
    select
      a.id as application_id,
      a.status,
      c.full_name,
      c.email,
      c.stage,
      (select count(*) from scorecards s where s.application_id = a.id) as scorecard_count
    from applications a
    join candidates c on c.id = a.candidate_id
    where a.requisition_id = ${requisitionId}
      ${term ? sql`and (c.full_name ilike ${pattern} or c.email ilike ${pattern})` : sql``}
    order by ${sql.raw(orderBy)}
    limit 200
  `.execute(db);

  return { requisition, term, rows: result.rows };
}

export default function RequisitionPipeline() {
  const { requisition, term, rows } = useLoaderData<typeof loader>();

  return (
    <main className="pipeline">
      <h1>
        {requisition.title} <small>{requisition.reference}</small>
      </h1>

      <Form method="get" role="search">
        <label htmlFor="q">Filter applicants</label>
        <input id="q" name="q" type="search" defaultValue={term} />
        <button type="submit">Filter</button>
      </Form>

      <ol className="pipeline-list">
        {rows.map((row) => (
          <li key={row.application_id}>
            <Link to={`/applications/${row.application_id}/review`}>{row.full_name}</Link>
            <span className="stage">{row.stage}</span>
            <span className="status">{row.status}</span>
            <span className="scorecards">{row.scorecard_count} scorecards</span>
          </li>
        ))}
      </ol>

      {rows.length === 0 ? <p>Nothing in this pipeline yet.</p> : null}
    </main>
  );
}
