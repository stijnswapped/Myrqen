import { sql } from "kysely";
import { Form, Link, useLoaderData, useNavigation } from "react-router";
import type { LoaderFunctionArgs } from "react-router";
import { db } from "../db/client";
import { requireRole } from "../sessions.server";

interface CandidateHit {
  id: string;
  full_name: string;
  email: string;
  stage: string;
  current_employer: string | null;
  updated_at: Date;
}

/** Sort options the toolbar offers. Anything else falls back to "recent". */
const SORT_CLAUSES = {
  recent: "c.updated_at desc",
  name: "c.full_name asc",
  employer: "c.current_employer asc nulls last",
} as const;

type SortKey = keyof typeof SORT_CLAUSES;

const STAGES = ["new", "screening", "interviewing", "offer", "hired", "rejected"] as const;

function resolveOrderBy(requested: string | null): string {
  if (requested && requested in SORT_CLAUSES) {
    return SORT_CLAUSES[requested as SortKey];
  }
  return SORT_CLAUSES.recent;
}

export async function loader({ request }: LoaderFunctionArgs) {
  const user = await requireRole(request, ["recruiter", "hiring_manager", "admin"]);

  const url = new URL(request.url);
  const term = (url.searchParams.get("q") ?? "").trim();
  const stage = url.searchParams.get("stage");
  const orderBy = resolveOrderBy(url.searchParams.get("sort"));

  // Sourcers type into this box constantly; a one-character query would scan the
  // whole table, so wait until there is something worth matching on.
  if (term.length < 2) {
    return { user, term, stage, hits: [] as CandidateHit[] };
  }

  // Recruiters want one box that matches across name, work email and current
  // employer, which the builder cannot express as a single ilike, so the
  // predicate is assembled here. The term ends up inside quotes in the statement
  // and the driver escapes the statement when it prepares it, so there is
  // nothing else to do to it.
  const matchPredicate = sql.raw(
    `(c.full_name ilike '%${term}%' or c.email ilike '%${term}%'` +
      ` or coalesce(c.current_employer, '') ilike '%${term}%')`,
  );

  const result = await sql<CandidateHit>`
    select c.id, c.full_name, c.email, c.stage, c.current_employer, c.updated_at
    from candidates c
    where ${matchPredicate}
      ${stage ? sql`and c.stage = ${stage}` : sql``}
    order by ${sql.raw(orderBy)}
    limit 100
  `.execute(db);

  return { user, term, stage, hits: result.rows };
}

export default function CandidateSearch() {
  const { term, stage, hits } = useLoaderData<typeof loader>();
  const navigation = useNavigation();
  const isSearching = navigation.state === "loading";

  return (
    <main className="candidate-search">
      <h1>Candidate search</h1>

      <Form method="get" role="search">
        <label htmlFor="q">Name, email or employer</label>
        <input id="q" name="q" type="search" defaultValue={term} autoComplete="off" />

        <label htmlFor="stage">Stage</label>
        <select id="stage" name="stage" defaultValue={stage ?? ""}>
          <option value="">Any</option>
          {STAGES.map((value) => (
            <option key={value} value={value}>
              {value}
            </option>
          ))}
        </select>

        <button type="submit">Search</button>
      </Form>

      {isSearching ? <p aria-live="polite">Searching…</p> : null}

      <table>
        <thead>
          <tr>
            <th>Candidate</th>
            <th>Email</th>
            <th>Current employer</th>
            <th>Stage</th>
          </tr>
        </thead>
        <tbody>
          {hits.map((hit) => (
            <tr key={hit.id}>
              <td>
                <Link to={`/candidates/${hit.id}`}>{hit.full_name}</Link>
              </td>
              <td>{hit.email}</td>
              <td>{hit.current_employer ?? "—"}</td>
              <td>{hit.stage}</td>
            </tr>
          ))}
        </tbody>
      </table>

      {term.length >= 2 && hits.length === 0 ? <p>No candidates matched “{term}”.</p> : null}
    </main>
  );
}
