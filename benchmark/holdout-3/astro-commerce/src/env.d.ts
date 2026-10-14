/// <reference types="astro/client" />

declare namespace App {
  interface Locals {
    /** Set by src/middleware.ts from the session cookie; null for anonymous visitors. */
    customer: { id: string; email: string; displayName: string | null } | null;
    /** Staff sessions carry a role; storefront customers never do. */
    staffRole: "support" | "merchandiser" | "admin" | null;
    requestId: string;
  }
}

interface ImportMetaEnv {
  readonly DATABASE_URL: string;
  readonly DATABASE_POOL_SIZE?: string;
  readonly SESSION_SECRET: string;
  readonly LOG_LEVEL?: string;
  readonly ASSET_ROOT: string;
  readonly PUBLIC_STORE_NAME: string;
}
