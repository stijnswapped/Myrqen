import type { Handlers, PageProps } from "$fresh/server.ts";
import { Head } from "$fresh/runtime.ts";
import DocumentShelf, { type ShelfDocument } from "../../islands/DocumentShelf.tsx";
import { openKv, type DocumentRecord } from "../../lib/kv.ts";
import type { AppState } from "../../lib/state.ts";

/**
 * /documents/[reference]
 *
 * The document shelf for one consignment. Downloads go through a short-lived
 * signed link rather than a session cookie, because the depot tablets open PDFs
 * in the OS viewer and the viewer does not carry our cookie jar.
 *
 * The shelf has to stamp the link at click time — a link minted on render is
 * already half expired by the time a broker works through a 40-document packet —
 * so the stamping happens in the island.
 */

const LINK_TTL_SECONDS = 300;

interface Data {
  reference: string;
  documents: ShelfDocument[];
  signingKey: string;
}

export const handler: Handlers<Data, AppState> = {
  async GET(_req, ctx) {
    const reference = ctx.params.reference;
    const kv = await openKv();

    const shipment = await kv.get<{ id: string }>(["shipments", ctx.state.session.orgId, reference]);
    if (!shipment.value) return ctx.renderNotFound();

    const documents: ShelfDocument[] = [];
    for await (
      const entry of kv.list<DocumentRecord>({ prefix: ["documents", ctx.state.session.orgId, shipment.value.id] })
    ) {
      documents.push({
        id: entry.value.id,
        kind: entry.value.kind,
        filename: entry.value.filename,
        storageKey: entry.value.storageKey,
        bytes: entry.value.bytes,
      });
    }

    const signingKey = Deno.env.get("PORTWAY_DOWNLOAD_SIGNING_KEY");
    if (!signingKey) throw new Error("PORTWAY_DOWNLOAD_SIGNING_KEY is not set");

    return ctx.render({ reference, documents, signingKey });
  },
};

export default function DocumentsPage({ data }: PageProps<Data>) {
  return (
    <>
      <Head>
        <title>{data.reference} · Documents · Portway</title>
      </Head>
      <main class="page">
        <header>
          <h1>{data.reference}</h1>
          <p class="muted">{data.documents.length} document(s) on file</p>
        </header>
        <DocumentShelf
          reference={data.reference}
          documents={data.documents}
          signingKey={data.signingKey}
          ttlSeconds={LINK_TTL_SECONDS}
        />
      </main>
    </>
  );
}
