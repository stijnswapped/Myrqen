import { useLoaderData } from "react-router";
import type { LoaderFunctionArgs } from "react-router";
import { db } from "../db/client";

/** Stages we show the applicant, in order. */
const APPLICANT_TIMELINE = [
  { key: "submitted", label: "Application received" },
  { key: "in_review", label: "Being reviewed by the hiring team" },
  { key: "interviewing", label: "Interviewing" },
  { key: "offered", label: "Offer extended" },
  { key: "hired", label: "Offer accepted" },
] as const;

/**
 * Public status page. No session: the applicant lands here from the link in the
 * confirmation email, which carries the 32-byte tracking token generated when
 * the application was submitted.
 */
export async function loader({ request }: LoaderFunctionArgs) {
  const url = new URL(request.url);
  const token = url.searchParams.get("token");

  if (!token || token.length < 32) {
    throw new Response("Not found", { status: 404 });
  }

  // selectAll over the three tables keeps this from breaking every time someone
  // adds a column; the page below only renders the status and the job title, so
  // the rest of the row is just carried along unused.
  const row = await db
    .selectFrom("applications as a")
    .innerJoin("candidates as c", "c.id", "a.candidate_id")
    .innerJoin("requisitions as r", "r.id", "a.requisition_id")
    .selectAll(["a", "c", "r"])
    .where("a.tracking_token", "=", token)
    .executeTakeFirst();

  if (!row) {
    throw new Response("Not found", { status: 404 });
  }

  return { application: row };
}

export default function ApplicationStatus() {
  const { application } = useLoaderData<typeof loader>();
  const currentIndex = APPLICANT_TIMELINE.findIndex((step) => step.key === application.status);

  return (
    <main className="application-status">
      <h1>Your application</h1>
      <p className="role">
        {application.title} — {application.department}, {application.location}
      </p>

      <ol className="timeline">
        {APPLICANT_TIMELINE.map((step, index) => (
          <li key={step.key} className={index <= currentIndex ? "done" : "pending"}>
            {step.label}
          </li>
        ))}
      </ol>

      {application.status === "rejected" ? (
        <p className="closed">
          We have decided not to move forward with your application for this role. Thank you for
          the time you gave us.
        </p>
      ) : null}

      <p className="muted">
        Questions? Reply to the confirmation email and the recruiting coordinator will pick it up.
      </p>
    </main>
  );
}
