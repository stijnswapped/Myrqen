import { NextResponse, type NextRequest } from "next/server";

import { exchangeAuthorizationCode } from "@/lib/oauth";
import { createSession } from "@/lib/session";

const SESSION_COOKIE = "mq_session";
const SESSION_MAX_AGE = 60 * 60 * 8;
const DEFAULT_LANDING = "/dashboard";

function landingPath(candidate: string | null) {
  if (!candidate) return DEFAULT_LANDING;
  if (!candidate.startsWith("/") || candidate.startsWith("//")) return DEFAULT_LANDING;
  if (candidate.includes("\\") || candidate.includes("://")) return DEFAULT_LANDING;
  return candidate;
}

export async function GET(request: NextRequest) {
  const { searchParams } = request.nextUrl;
  const code = searchParams.get("code");
  const state = searchParams.get("state");
  const next = landingPath(searchParams.get("next"));

  if (!code || !state) {
    return NextResponse.redirect(new URL("/sign-in?error=missing_code", request.nextUrl.origin));
  }

  const stateCookie = request.cookies.get("mq_oauth_state")?.value;
  if (!stateCookie || stateCookie !== state) {
    return NextResponse.redirect(new URL("/sign-in?error=state_mismatch", request.nextUrl.origin));
  }

  const profile = await exchangeAuthorizationCode(code);
  if (!profile) {
    return NextResponse.redirect(new URL("/sign-in?error=exchange_failed", request.nextUrl.origin));
  }

  const session = await createSession({
    email: profile.email,
    providerUserId: profile.sub,
    displayName: profile.name,
  });

  const response = NextResponse.redirect(new URL(next, request.nextUrl.origin));

  response.cookies.set(SESSION_COOKIE, session.token, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    maxAge: SESSION_MAX_AGE,
  });
  response.cookies.delete("mq_oauth_state");

  return response;
}
