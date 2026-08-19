import { NextResponse } from "next/server";
import { cookies } from "next/headers";

import { getSessionByToken } from "@/lib/session";
import { extractOpenGraph } from "@/lib/open-graph";

const FETCH_TIMEOUT_MS = 4000;
const MAX_BODY_BYTES = 512 * 1024;

type PreviewRequest = { url?: string };

export async function POST(request: Request) {
  const cookieStore = await cookies();
  const session = await getSessionByToken(cookieStore.get("mq_session")?.value ?? "");

  if (!session) {
    return NextResponse.json({ error: "Sign in to continue" }, { status: 401 });
  }

  const body = (await request.json()) as PreviewRequest;
  const candidate = body.url?.trim();

  if (!candidate) {
    return NextResponse.json({ error: "A url is required" }, { status: 400 });
  }

  let target: URL;
  try {
    target = new URL(candidate);
  } catch {
    return NextResponse.json({ error: "That does not look like a link" }, { status: 400 });
  }

  const upstream = await fetch(target, {
    redirect: "follow",
    headers: {
      accept: "text/html,application/xhtml+xml",
      "user-agent": "MyrqenLinkPreview/1.2 (+https://myrqen.example/bot)",
    },
    signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });

  if (!upstream.ok) {
    return NextResponse.json(
      { error: "The page could not be reached", status: upstream.status },
      { status: 502 },
    );
  }

  const html = (await upstream.text()).slice(0, MAX_BODY_BYTES);
  const preview = extractOpenGraph(html, target.toString());

  return NextResponse.json({
    url: target.toString(),
    title: preview.title,
    description: preview.description,
    imageUrl: preview.imageUrl,
    siteName: preview.siteName,
  });
}
