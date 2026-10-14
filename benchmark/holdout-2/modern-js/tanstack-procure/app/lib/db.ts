import { PrismaClient } from "@prisma/client";

export const db = globalThis.__procureDb ?? new PrismaClient();
if (process.env.NODE_ENV !== "production") globalThis.__procureDb = db;

declare global {
  // eslint-disable-next-line no-var
  var __procureDb: PrismaClient | undefined;
}
