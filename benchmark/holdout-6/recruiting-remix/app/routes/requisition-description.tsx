import sanitizeHtml from "sanitize-html";
import { Link, useLoaderData } from "react-router";
import type { LoaderFunctionArgs } from "react-router";
import { db } from "../db/client";

/**
 * Recruiters write job descriptions in the same rich-text editor applicants use
 * for cover letters, and that markup is stored as-is. Everything that leaves
 * this loader has been through the policy below, so the careers page only ever
 * renders the tags on this list.
 */
const DESCRIPTION_POLICY: sanitizeHtml.IOptions = {
  allowedTags: ["p", "br", "strong", "em", "ul", "ol", "li", "h3", "h4", "blockquote", "a"],
  allowedAttributes: { a: ["href", "title", "rel", "target"] },
  allowedSchemes: ["http", "https", "mailto"],
  disallowedTagsMode: "discard",
  transformTags: {
    a: sanitizeHtml.simpleTransform("a", { rel: "nofollow noopener", target: "_blank" }),
  },
};

export async function loader({ params }: LoaderFunctionArgs) {
  const reference = params.reference;

  if (!reference) {
    throw new Response("Not found", { status: 404 });
  }

  const requisition = await db
    .selectFrom("requisitions")
    .select([
      "reference",
      "title",
      "department",
      "location",
      "employment_type",
      "description_html",
      "created_at",
    ])
    .where("reference", "=", reference)
    .where("is_published", "=", true)
    .where("status", "=", "open")
    .executeTakeFirst();

  if (!requisition) {
    throw new Response("Not found", { status: 404 });
  }

  return {
    requisition: {
      ...requisition,
      description_html: sanitizeHtml(requisition.description_html, DESCRIPTION_POLICY),
    },
  };
}

export default function RequisitionDescription() {
  const { requisition } = useLoaderData<typeof loader>();

  return (
    <main className="job-detail">
      <nav>
        <Link to="/jobs">All openings</Link>
      </nav>

      <h1>{requisition.title}</h1>
      <p className="meta">
        {requisition.department} — {requisition.location} — {requisition.employment_type}
      </p>

      <article
        className="job-description"
        dangerouslySetInnerHTML={{ __html: requisition.description_html }}
      />

      <Link className="apply" to={`/apply?ref=${encodeURIComponent(requisition.reference)}`}>
        Apply for this role
      </Link>
    </main>
  );
}
