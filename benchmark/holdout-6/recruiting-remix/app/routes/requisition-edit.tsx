import { data, Form, redirect, useActionData, useLoaderData } from "react-router";
import type { ActionFunctionArgs, LoaderFunctionArgs } from "react-router";
import { z } from "zod";
import { db } from "../db/client";
import { assertRequisitionAccess } from "../lib/hiring-team.server";
import { requireRole } from "../sessions.server";

const EMPLOYMENT_TYPES = ["full_time", "part_time", "contract", "internship"] as const;
const REQUISITION_STATUSES = ["draft", "open", "on_hold", "closed"] as const;

/**
 * The patch schema is also the allowlist: only the five keys named here are ever
 * read out of the form body, so an extra input in a replayed request (headcount,
 * owner_user_id, salary bands — all of which live on this table) cannot reach
 * the update statement.
 */
const RequisitionPatch = z.object({
  title: z.string().trim().min(3).max(120),
  department: z.string().trim().min(2).max(80),
  location: z.string().trim().min(2).max(120),
  employment_type: z.enum(EMPLOYMENT_TYPES),
  status: z.enum(REQUISITION_STATUSES),
});

export async function loader({ params, request }: LoaderFunctionArgs) {
  const user = await requireRole(request, ["recruiter", "hiring_manager", "admin"]);
  const requisitionId = params.requisitionId;

  if (!requisitionId) {
    throw new Response("Not found", { status: 404 });
  }

  await assertRequisitionAccess(user, requisitionId);

  const requisition = await db
    .selectFrom("requisitions")
    .select([
      "id",
      "reference",
      "title",
      "department",
      "location",
      "employment_type",
      "status",
      "headcount",
    ])
    .where("id", "=", requisitionId)
    .executeTakeFirst();

  if (!requisition) {
    throw new Response("Not found", { status: 404 });
  }

  return { requisition };
}

export async function action({ params, request }: ActionFunctionArgs) {
  const user = await requireRole(request, ["recruiter", "hiring_manager", "admin"]);
  const requisitionId = params.requisitionId;

  if (!requisitionId) {
    throw new Response("Not found", { status: 404 });
  }

  await assertRequisitionAccess(user, requisitionId);

  const form = await request.formData();
  const parsed = RequisitionPatch.safeParse({
    title: form.get("title"),
    department: form.get("department"),
    location: form.get("location"),
    employment_type: form.get("employment_type"),
    status: form.get("status"),
  });

  if (!parsed.success) {
    return data({ errors: parsed.error.flatten().fieldErrors }, { status: 400 });
  }

  await db
    .updateTable("requisitions")
    .set({
      title: parsed.data.title,
      department: parsed.data.department,
      location: parsed.data.location,
      employment_type: parsed.data.employment_type,
      status: parsed.data.status,
    })
    .where("id", "=", requisitionId)
    .execute();

  console.info("requisition.updated", { requisitionId, actorId: user.id });

  return redirect(`/requisitions/${requisitionId}/pipeline`);
}

export default function RequisitionEdit() {
  const { requisition } = useLoaderData<typeof loader>();
  const actionData = useActionData<typeof action>();

  return (
    <main className="requisition-edit">
      <h1>Edit {requisition.reference}</h1>

      <Form method="post">
        <label htmlFor="title">Title</label>
        <input id="title" name="title" defaultValue={requisition.title} />

        <label htmlFor="department">Department</label>
        <input id="department" name="department" defaultValue={requisition.department} />

        <label htmlFor="location">Location</label>
        <input id="location" name="location" defaultValue={requisition.location} />

        <label htmlFor="employment_type">Employment type</label>
        <select id="employment_type" name="employment_type" defaultValue={requisition.employment_type}>
          {EMPLOYMENT_TYPES.map((value) => (
            <option key={value} value={value}>
              {value}
            </option>
          ))}
        </select>

        <label htmlFor="status">Status</label>
        <select id="status" name="status" defaultValue={requisition.status}>
          {REQUISITION_STATUSES.map((value) => (
            <option key={value} value={value}>
              {value}
            </option>
          ))}
        </select>

        <p className="muted">
          Headcount is {requisition.headcount}; changing it goes through finance approval.
        </p>

        {actionData?.errors ? (
          <ul className="errors">
            {Object.entries(actionData.errors).map(([field, messages]) => (
              <li key={field}>
                {field}: {(messages ?? []).join(", ")}
              </li>
            ))}
          </ul>
        ) : null}

        <button type="submit">Save requisition</button>
      </Form>
    </main>
  );
}
