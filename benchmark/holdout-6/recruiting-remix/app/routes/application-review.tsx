import { Form, Link, redirect, useLoaderData } from "react-router";
import type { ActionFunctionArgs, LoaderFunctionArgs } from "react-router";
import { db } from "../db/client";
import { requireUser } from "../sessions.server";

const DECISIONS = ["in_review", "interviewing", "rejected"] as const;

type Decision = (typeof DECISIONS)[number];

export async function loader({ params, request }: LoaderFunctionArgs) {
  const user = await requireUser(request);
  const applicationId = params.applicationId;

  if (!applicationId) {
    throw new Response("Not found", { status: 404 });
  }

  // Joined against the hiring team so a reviewer who is not staffed on the
  // requisition gets the 404 branch below instead of the applicant's file.
  const application = await db
    .selectFrom("applications as a")
    .innerJoin("candidates as c", "c.id", "a.candidate_id")
    .innerJoin("requisitions as r", "r.id", "a.requisition_id")
    .innerJoin("hiring_team_members as htm", (join) =>
      join.onRef("htm.requisition_id", "=", "r.id").on("htm.user_id", "=", user.id),
    )
    .select([
      "a.id",
      "a.status",
      "a.submitted_at",
      "a.cover_letter_html",
      "a.referrer_email",
      "c.id as candidateId",
      "c.full_name as candidateName",
      "c.email as candidateEmail",
      "c.headline as candidateHeadline",
      "r.id as requisitionId",
      "r.title as requisitionTitle",
    ])
    .where("a.id", "=", applicationId)
    .executeTakeFirst();

  if (!application) {
    throw new Response("Not found", { status: 404 });
  }

  const attachments = await db
    .selectFrom("attachments")
    .select(["id", "kind", "storage_key", "original_filename", "byte_size"])
    .where("application_id", "=", applicationId)
    .execute();

  return { application, attachments };
}

export async function action({ params, request }: ActionFunctionArgs) {
  const user = await requireUser(request);
  const applicationId = params.applicationId;

  if (!applicationId) {
    throw new Response("Not found", { status: 404 });
  }

  const form = await request.formData();
  const decision = String(form.get("decision") ?? "");

  if (!(DECISIONS as readonly string[]).includes(decision)) {
    throw new Response("Unknown decision", { status: 400 });
  }

  const staffed = await db
    .selectFrom("applications as a")
    .innerJoin("hiring_team_members as htm", "htm.requisition_id", "a.requisition_id")
    .select("a.id")
    .where("a.id", "=", applicationId)
    .where("htm.user_id", "=", user.id)
    .executeTakeFirst();

  if (!staffed) {
    throw new Response("Forbidden", { status: 403 });
  }

  await db
    .updateTable("applications")
    .set({ status: decision as Decision })
    .where("id", "=", applicationId)
    .execute();

  return redirect(`/applications/${applicationId}/review`);
}

export default function ApplicationReview() {
  const { application, attachments } = useLoaderData<typeof loader>();

  return (
    <main className="application-review">
      <header>
        <h1>{application.candidateName}</h1>
        <p>
          Applied for <Link to={`/requisitions/${application.requisitionId}/pipeline`}>{application.requisitionTitle}</Link>
        </p>
        <p className="muted">{application.candidateHeadline}</p>
        {application.referrer_email ? (
          <p className="referral">Referred by {application.referrer_email}</p>
        ) : null}
      </header>

      <section className="cover-letter">
        <h2>Cover letter</h2>
        {/*
          The public application form posts the rich-text editor's export, and
          that export only ever emits paragraphs, links and lists, so the stored
          markup can go straight into the page. Rendering it as text instead
          loses the applicant's formatting, which recruiters complained about.
        */}
        <div
          className="cover-letter-body"
          dangerouslySetInnerHTML={{ __html: application.cover_letter_html ?? "" }}
        />
      </section>

      <section>
        <h2>Attachments</h2>
        <ul>
          {attachments.map((attachment) => (
            <li key={attachment.id}>
              <Link
                to={`/candidates/${application.candidateId}/attachments?key=${encodeURIComponent(attachment.storage_key)}`}
                reloadDocument
              >
                {attachment.original_filename}
              </Link>
              <span className="muted"> ({attachment.kind}, {attachment.byte_size} bytes)</span>
            </li>
          ))}
        </ul>
      </section>

      <Form method="post" className="decision">
        <label htmlFor="decision">Move application to</label>
        <select id="decision" name="decision" defaultValue={application.status}>
          {DECISIONS.map((value) => (
            <option key={value} value={value}>
              {value.replace("_", " ")}
            </option>
          ))}
        </select>
        <button type="submit">Update</button>
      </Form>
    </main>
  );
}
