import { NextResponse } from "next/server";
import { cookies } from "next/headers";

import { getSessionByToken } from "@/lib/session";
import { parseProductFeed } from "@/lib/product-feed";

const FETCH_TIMEOUT_MS = 4000;
const MAX_BODY_BYTES = 2 * 1024 * 1024;

const FEED_HOSTS = new Set([
  "feeds.shopify.com",
  "static.woocommerce.com",
  "exports.bigcommerce.com",
]);

type ImportRequest = { url?: string };

export async function POST(request: Request) {
  const cookieStore = await cookies();
  const session = await getSessionByToken(cookieStore.get("mq_session")?.value ?? "");

  if (!session) {
    return NextResponse.json({ error: "Sign in to continue" }, { status: 401 });
  }

  const body = (await request.json()) as ImportRequest;
  const candidate = body.url?.trim();

  if (!candidate) {
    return NextResponse.json({ error: "A feed url is required" }, { status: 400 });
  }

  let target: URL;
  try {
    target = new URL(candidate);
  } catch {
    return NextResponse.json({ error: "That does not look like a feed url" }, { status: 400 });
  }

  if (target.protocol !== "https:" || !FEED_HOSTS.has(target.hostname)) {
    return NextResponse.json(
      { error: "Feeds may only be imported from a supported storefront host" },
      { status: 400 },
    );
  }

  const upstream = await fetch(target, {
    redirect: "error",
    headers: {
      accept: "application/xml,text/csv",
      "user-agent": "MyrqenFeedImport/1.2 (+https://myrqen.example/bot)",
    },
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });

  if (!upstream.ok) {
    return NextResponse.json(
      { error: "The feed could not be reached", status: upstream.status },
      { status: 502 },
    );
  }

  const payload = (await upstream.text()).slice(0, MAX_BODY_BYTES);
  const items = parseProductFeed(payload);

  return NextResponse.json({ host: target.hostname, imported: items.length, items });
}
