import { resolveSession } from "./auth/session.ts";
import { listStatements } from "./handlers/statements.ts";
import { listTransactions } from "./handlers/transactions.ts";
import { json, notFound, serverError } from "./http/responses.ts";
import { logger } from "./observability/logger.ts";

const STATEMENTS = new URLPattern({ pathname: "/accounts/:accountId/statements" });
const TRANSACTIONS = new URLPattern({ pathname: "/accounts/:accountId/transactions" });

Deno.serve({ port: 8080 }, async (request) => {
  const session = await resolveSession(request);
  if (!session) return json({ error: "unauthorized" }, 401);

  try {
    const statements = STATEMENTS.exec(request.url);
    if (statements && request.method === "GET") {
      return await listStatements(request, session, statements.pathname.groups.accountId!);
    }

    const transactions = TRANSACTIONS.exec(request.url);
    if (transactions && request.method === "GET") {
      return await listTransactions(request, session, transactions.pathname.groups.accountId!);
    }

    return notFound();
  } catch (error) {
    logger.error("request failed", { path: new URL(request.url).pathname, error: String(error) });
    return serverError();
  }
});
