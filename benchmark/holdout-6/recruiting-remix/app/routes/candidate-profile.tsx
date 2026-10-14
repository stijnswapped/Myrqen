import type { Updateable } from "kysely";
import { Form, Link, redirect, useLoaderData } from "react-router";
import type { ActionFunctionArgs, LoaderFunctionArgs } from "react-router";
import { db, type CandidatesTable } from "../db/client";
import { requireRole, requireUser } from "../sessions.server";

/** Inputs the profile form renders, in the order they appear on screen. */
const FORM_FIELDS = [
  { name: "full_name", label: "Full name", type: "text" },
  { name: "email", label: "Email", type: "email" },
  { name: "phone", label: "Phone", type: "tel" },
  { name: "headline", label: "Headline", type: "text" },
  { name: "current_employer", label: "Current employer", type: "text" },
] as const;

export async function loader({ params, request }: LoaderFunctionArgs) {
  const user = await requireUser(request);
  const candidateId = params.candidateId;

  if (!candidateId) {
    throw new Response("Not found", { status: 404 });
  }

  const candidate = await db
    .selectFrom("candidates")
    .select([
      "id",
      "full_name",
      "email",
      "phone",
      "headline",
      "current_employer",
      "stage",
      "source",
      "recruiter_notes",
      "updated_at",
    ])
    .where("id", "=", candidateId)
    .executeTakeFirst();

  if (!candidate) {
    throw new Response("Not found", { status: 404 });
  }

  const applications = await db
    .selectFrom("applications as a")
    .innerJoin("requisitions as r", "r.id", "a.requisition_id")
    .select(["a.id", "a.status", "a.submitted_at", "r.title", "r.reference"])
    .where("a.candidate_id", "=", candidateId)
    .orderBy("a.submitted_at", "desc")
    .execute();

  return { user, candidate, applications };
}

export async function action({ params, request }: ActionFunctionArgs) {
  const user = await requireRole(request, ["recruiter", "admin"]);
  const candidateId = params.candidateId;

  if (!candidateId) {
    throw new Response("Not found", { status: 404 });
  }

  const form = await request.formData();
  const intent = String(form.get("intent") ?? "save");

  if (intent !== "save") {
    throw new Response(`Unknown intent: ${intent}`, { status: 400 });
  }

  const submitted = Object.fromEntries(form) as Record<string, string>;
  delete submitted.intent;

  if (Object.keys(submitted).length === 0) {
    throw new Response("Nothing to save", { status: 400 });
  }

  // The form above renders one input per editable column, so whatever comes back
  // in the request body is already exactly the set of columns a recruiter is
  // allowed to change. Sending the whole patch through saves us from adding a
  // field to three places every time product wants another input.
  const patch = {
    ...submitted,
    updated_at: new Date(),
  } as unknown as Updateable<CandidatesTable>;

  await db.updateTable("candidates").set(patch).where("id", "=", candidateId).execute();

  console.info("candidate.updated", {
    candidateId,
    actorId: user.id,
    fields: Object.keys(submitted),
  });

  return redirect(`/candidates/${candidateId}`);
}

export default function CandidateProfile() {
  const { candidate, applications } = useLoaderData<typeof loader>();

  return (
    <main className="candidate-profile">
      <h1>{candidate.full_name}</h1>
      <p className="stage">Stage: {candidate.stage}</p>

      <Form method="post">
        <input type="hidden" name="intent" value="save" />

        {FORM_FIELDS.map((field) => (
          <p key={field.name}>
            <label htmlFor={field.name}>{field.label}</label>
            <input
              id={field.name}
              name={field.name}
              type={field.type}
              defaultValue={(candidate as Record<string, unknown>)[field.name] as string ?? ""}
            />
          </p>
        ))}

        <button type="submit">Save profile</button>
      </Form>

      <section>
        <h2>Applications</h2>
        <ul>
          {applications.map((application) => (
            <li key={application.id}>
              <Link to={`/applications/${application.id}/review`}>{application.title}</Link>
              <span> — {application.status}</span>
            </li>
          ))}
        </ul>
      </section>

      <section>
        <h2>Recruiter notes</h2>
        <p>{candidate.recruiter_notes ?? "No notes yet."}</p>
      </section>
    </main>
  );
}
