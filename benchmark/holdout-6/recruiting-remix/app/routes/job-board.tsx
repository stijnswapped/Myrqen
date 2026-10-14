import { Form, Link, useLoaderData } from "react-router";
import type { LoaderFunctionArgs } from "react-router";
import { db } from "../db/client";

/**
 * Public careers index. No session — anyone on the internet can load this, and
 * every byte a loader returns is serialized into the document the browser gets,
 * so the projection below is written out column by column instead of using
 * selectAll(): no salary bands, no requisition owner, no headcount.
 */
export async function loader({ request }: LoaderFunctionArgs) {
  const url = new URL(request.url);
  const department = url.searchParams.get("department");

  let query = db
    .selectFrom("requisitions as r")
    .select([
      "r.reference",
      "r.title",
      "r.department",
      "r.location",
      "r.employment_type",
      "r.created_at",
    ])
    .where("r.is_published", "=", true)
    .where("r.status", "=", "open");

  if (department) {
    query = query.where("r.department", "=", department);
  }

  const openings = await query.orderBy("r.created_at", "desc").limit(100).execute();

  const departments = await db
    .selectFrom("requisitions")
    .select("department")
    .distinct()
    .where("is_published", "=", true)
    .where("status", "=", "open")
    .orderBy("department")
    .execute();

  return { openings, departments: departments.map((row) => row.department), department };
}

export default function JobBoard() {
  const { openings, departments, department } = useLoaderData<typeof loader>();

  return (
    <main className="job-board">
      <h1>Open roles</h1>

      <Form method="get">
        <label htmlFor="department">Team</label>
        <select id="department" name="department" defaultValue={department ?? ""}>
          <option value="">All teams</option>
          {departments.map((value) => (
            <option key={value} value={value}>
              {value}
            </option>
          ))}
        </select>
        <button type="submit">Filter</button>
      </Form>

      <ul className="openings">
        {openings.map((opening) => (
          <li key={opening.reference}>
            <Link to={`/jobs/${encodeURIComponent(opening.reference)}`}>{opening.title}</Link>
            <span className="meta">
              {opening.department} — {opening.location} — {opening.employment_type}
            </span>
          </li>
        ))}
      </ul>

      {openings.length === 0 ? <p>No open roles right now. Check back soon.</p> : null}
    </main>
  );
}
