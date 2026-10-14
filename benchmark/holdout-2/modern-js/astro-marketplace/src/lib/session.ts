import type { APIContext } from "astro";

export interface Session {
  userId: string;
  merchantId: string;
}

/** Reads the session the auth middleware put on `locals`. */
export function getSession(locals: APIContext["locals"]): Session | null {
  return (locals as { session?: Session }).session ?? null;
}
