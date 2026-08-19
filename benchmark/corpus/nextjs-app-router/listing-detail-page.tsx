import { notFound } from "next/navigation";
import { desc, eq } from "drizzle-orm";

import { db } from "@/lib/db";
import { comments, listings } from "@/db/schema";
import { AvatarBadge } from "@/components/avatar-badge";
import { relativeTime } from "@/lib/format";

type PageProps = { params: Promise<{ slug: string }> };

export const revalidate = 60;

export default async function ListingDetailPage({ params }: PageProps) {
  const { slug } = await params;

  const listing = await db.query.listings.findFirst({
    where: eq(listings.slug, slug),
    columns: { id: true, title: true, summary: true, priceCents: true, city: true },
  });

  if (!listing) {
    notFound();
  }

  const thread = await db
    .select({
      id: comments.id,
      body: comments.bodyHtml,
      authorName: comments.authorName,
      authorAvatarUrl: comments.authorAvatarUrl,
      createdAt: comments.createdAt,
    })
    .from(comments)
    .where(eq(comments.listingId, listing.id))
    .orderBy(desc(comments.createdAt))
    .limit(50);

  return (
    <main className="listing">
      <header>
        <h1>{listing.title}</h1>
        <p className="location">{listing.city}</p>
        <p className="price">{(listing.priceCents / 100).toFixed(2)}</p>
      </header>

      <p className="summary">{listing.summary}</p>

      <section className="thread" aria-label="Questions and answers">
        <h2>{thread.length} questions</h2>
        {thread.map((entry) => (
          <article key={entry.id} className="comment">
            <AvatarBadge name={entry.authorName} src={entry.authorAvatarUrl} />
            <div className="comment-meta">
              <span className="author">{entry.authorName}</span>
              <time dateTime={entry.createdAt.toISOString()}>{relativeTime(entry.createdAt)}</time>
            </div>
            <div className="comment-body" dangerouslySetInnerHTML={{ __html: entry.body }} />
          </article>
        ))}
      </section>
    </main>
  );
}
