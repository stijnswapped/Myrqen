import type { Handlers, PageProps } from "$fresh/server.ts";
import { Head } from "$fresh/runtime.ts";
import { encodeHex } from "@std/encoding/hex";
import ManifestShelf, { type ShelfLink } from "../../islands/ManifestShelf.tsx";
import { openKv, type DocumentRecord } from "../../lib/kv.ts";
import type { AppState } from "../../lib/state.ts";

/**
 * /shipments/[reference]
 *
 * The manifest shelf for one consignment. Downloads go through a short-lived
 * signed link rather than a session cookie, because the depot tablets open PDFs
 * in the OS viewer and the viewer does not carry our cookie jar.
 *
 * Fresh serialises island props into the page so the client can hydrate them,
 * which means every prop below is public. The signature is computed here and the
 * key never becomes one: what crosses into the island is the finished URL and
 * the moment it stops working.
 */

const LINK_TTL_SECONDS = 300;

interface Data {
  reference: string;
  links: ShelfLink[];
}

async function signingKey(): Promise<CryptoKey> {
  const secret = Deno.env.get("PORTWAY_DOWNLOAD_SIGNING_KEY");
  if (!secret) throw new Error("PORTWAY_DOWNLOAD_SIGNING_KEY is not set");
  return await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
}

async function signedHref(key: CryptoKey, storageKey: string, expiresAt: number): Promise<string> {
  const payload = new TextEncoder().encode(`${storageKey}:${expiresAt}`);
  const signature = encodeHex(new Uint8Array(await crypto.subtle.sign("HMAC", key, payload)));
  return `/download/${encodeURI(storageKey)}?exp=${expiresAt}&sig=${signature}`;
}

export const handler: Handlers<Data, AppState> = {
  async GET(_req, ctx) {
    const reference = ctx.params.reference;
    const kv = await openKv();

    const shipment = await kv.get<{ id: string }>(["shipments", ctx.state.session.orgId, reference]);
    if (!shipment.value) return ctx.renderNotFound();

    const key = await signingKey();
    const expiresAt = Math.floor(Date.now() / 1000) + LINK_TTL_SECONDS;
    const links: ShelfLink[] = [];

    for await (
      const entry of kv.list<DocumentRecord>({ prefix: ["documents", ctx.state.session.orgId, shipment.value.id] })
    ) {
      links.push({
        id: entry.value.id,
        kind: entry.value.kind,
        filename: entry.value.filename,
        bytes: entry.value.bytes,
        href: await signedHref(key, entry.value.storageKey, expiresAt),
        expiresAt,
      });
    }

    return ctx.render({ reference, links });
  },
};

export default function ShipmentPage({ data }: PageProps<Data>) {
  return (
    <>
      <Head>
        <title>{data.reference} · Manifest · Portway</title>
      </Head>
      <main class="page">
        <header>
          <h1>{data.reference}</h1>
          <p class="muted">{data.links.length} document(s) on file</p>
        </header>
        <ManifestShelf reference={data.reference} links={data.links} />
      </main>
    </>
  );
}
