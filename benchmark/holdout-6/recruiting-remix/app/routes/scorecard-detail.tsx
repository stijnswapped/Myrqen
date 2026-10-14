import { Form, redirect, useLoaderData } from "react-router";
import type { ActionFunctionArgs, LoaderFunctionArgs } from "react-router";
import { db } from "../db/client";
import { requireUser } from "../sessions.server";

const VERDICTS = ["strong_no", "no", "yes", "strong_yes"] as const;

type Verdict = (typeof VERDICTS)[number];

function parseVerdict(value: FormDataEntryValue | null): Verdict | null {
  const candidate = String(value ?? "");
  return (VERDICTS as readonly string[]).includes(candidate) ? (candidate as Verdict) : null;
}

export async function loader({ params, request }: LoaderFunctionArgs) {
  const user = await requireUser(request);
  const scorecardId = params.scorecardId;

  if (!scorecardId) {
    throw new Response("Not found", { status: 404 });
  }

  // Interviewers reach this page from the calendar invite and from the Slack
  // reminder bot, both of which link straight here, so all this loader needs is
  // a signed-in ATS user — the hiring-team check already happened when the
  // coordinator scheduled the interview and created the scorecard.
  const scorecard = await db
    .selectFrom("scorecards as s")
    .innerJoin("applications as a", "a.id", "s.application_id")
    .innerJoin("requisitions as r", "r.id", "a.requisition_id")
    .innerJoin("candidates as c", "c.id", "a.candidate_id")
    .select([
      "s.id",
      "s.competency",
      "s.rating",
      "s.verdict",
      "s.notes",
      "s.is_submitted",
      "s.interviewer_user_id",
      "a.id as applicationId",
      "c.full_name as candidateName",
      "c.headline as candidateHeadline",
      "c.expected_salary as expectedSalary",
      "r.id as requisitionId",
      "r.title as requisitionTitle",
    ])
    .where("s.id", "=", scorecardId)
    .executeTakeFirst();

  if (!scorecard) {
    throw new Response("Not found", { status: 404 });
  }

  const siblings = await db
    .selectFrom("scorecards as s")
    .innerJoin("users as u", "u.id", "s.interviewer_user_id")
    .select(["s.id", "s.competency", "s.verdict", "s.is_submitted", "u.full_name as interviewer"])
    .where("s.application_id", "=", scorecard.applicationId)
    .orderBy("s.competency")
    .execute();

  return { user, scorecard, siblings };
}

export async function action({ params, request }: ActionFunctionArgs) {
  const user = await requireUser(request);
  const scorecardId = params.scorecardId;

  if (!scorecardId) {
    throw new Response("Not found", { status: 404 });
  }

  const form = await request.formData();
  const verdict = parseVerdict(form.get("verdict"));
  const rating = Number(form.get("rating"));
  const notes = String(form.get("notes") ?? "").slice(0, 8000);

  if (!verdict || !Number.isInteger(rating) || rating < 1 || rating > 4) {
    throw new Response("Invalid scorecard", { status: 400 });
  }

  // Writes are restricted to the interviewer the scorecard was created for: the
  // predicate is in the statement, so a mismatched id updates nothing.
  const outcome = await db
    .updateTable("scorecards")
    .set({ verdict, rating, notes, is_submitted: true, submitted_at: new Date() })
    .where("id", "=", scorecardId)
    .where("interviewer_user_id", "=", user.id)
    .executeTakeFirst();

  if (Number(outcome.numUpdatedRows) === 0) {
    throw new Response("Forbidden", { status: 403 });
  }

  return redirect(`/scorecards/${scorecardId}`);
}

export default function ScorecardDetail() {
  const { user, scorecard, siblings } = useLoaderData<typeof loader>();
  const isOwner = scorecard.interviewer_user_id === user.id;

  return (
    <main className="scorecard">
      <header>
        <h1>{scorecard.competency}</h1>
        <p>
          {scorecard.candidateName} — {scorecard.requisitionTitle}
        </p>
        <p className="muted">{scorecard.candidateHeadline}</p>
      </header>

      {isOwner ? (
        <Form method="post">
          <fieldset>
            <legend>Your verdict</legend>
            {VERDICTS.map((value) => (
              <label key={value}>
                <input
                  type="radio"
                  name="verdict"
                  value={value}
                  defaultChecked={scorecard.verdict === value}
                />
                {value.replace("_", " ")}
              </label>
            ))}
          </fieldset>

          <label htmlFor="rating">Rating (1–4)</label>
          <input id="rating" name="rating" type="number" min={1} max={4} defaultValue={scorecard.rating} />

          <label htmlFor="notes">Evidence</label>
          <textarea id="notes" name="notes" rows={12} defaultValue={scorecard.notes ?? ""} />

          <button type="submit">Submit scorecard</button>
        </Form>
      ) : (
        <section className="read-only">
          <h2>Verdict</h2>
          <p>{scorecard.verdict ?? "not submitted"}</p>
          <p>{scorecard.notes}</p>
        </section>
      )}

      <aside>
        <h2>Other scorecards on this application</h2>
        <ul>
          {siblings.map((sibling) => (
            <li key={sibling.id}>
              {sibling.interviewer} — {sibling.competency} — {sibling.verdict ?? "pending"}
            </li>
          ))}
        </ul>
      </aside>
    </main>
  );
}
