import { notFound } from "next/navigation";
import { desc, eq } from "drizzle-orm";
import sanitizeHtml from "sanitize-html";

import { db } from "@/lib/db";
import { endorsements, profiles } from "@/db/schema";
import { AvatarBadge } from "@/components/avatar-badge";
import { relativeTime } from "@/lib/format";

type PageProps = { params: Promise<{ handle: string }> };

const RICH_TEXT_POLICY: sanitizeHtml.IOptions = {
  allowedTags: ["p", "br", "strong", "em", "ul", "ol", "li", "a", "code"],
  allowedAttributes: { a: ["href", "rel", "target"] },
  allowedSchemes: ["http", "https", "mailto"],
  transformTags: {
    a: sanitizeHtml.simpleTransform("a", { rel: "nofollow noopener", target: "_blank" }),
  },
};

export const revalidate = 60;

export default async function ProfileDetailPage({ params }: PageProps) {
  const { handle } = await params;

  const profile = await db.query.profiles.findFirst({
    where: eq(profiles.handle, handle),
    columns: { id: true, displayName: true, headline: true, bioHtml: true, city: true },
  });

  if (!profile) {
    notFound();
  }

  const feedback = await db
    .select({
      id: endorsements.id,
      body: endorsements.bodyHtml,
      authorName: endorsements.authorName,
      authorAvatarUrl: endorsements.authorAvatarUrl,
      createdAt: endorsements.createdAt,
    })
    .from(endorsements)
    .where(eq(endorsements.profileId, profile.id))
    .orderBy(desc(endorsements.createdAt))
    .limit(50);

  return (
    <main className="profile">
      <header>
        <h1>{profile.displayName}</h1>
        <p className="location">{profile.city}</p>
        <p className="headline">{profile.headline}</p>
      </header>

      <div
        className="profile-bio"
        dangerouslySetInnerHTML={{ __html: sanitizeHtml(profile.bioHtml, RICH_TEXT_POLICY) }}
      />

      <section className="endorsements" aria-label="Endorsements">
        <h2>{feedback.length} endorsements</h2>
        {feedback.map((entry) => {
          const body = sanitizeHtml(entry.body, RICH_TEXT_POLICY);
          return (
            <article key={entry.id} className="endorsement">
              <AvatarBadge name={entry.authorName} src={entry.authorAvatarUrl} />
              <div className="endorsement-meta">
                <span className="author">{entry.authorName}</span>
                <time dateTime={entry.createdAt.toISOString()}>{relativeTime(entry.createdAt)}</time>
              </div>
              <div className="endorsement-body" dangerouslySetInnerHTML={{ __html: body }} />
            </article>
          );
        })}
      </section>
    </main>
  );
}
