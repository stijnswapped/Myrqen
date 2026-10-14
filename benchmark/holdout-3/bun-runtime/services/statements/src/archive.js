/**
 * Statement archiving service.
 *
 * Merchants ask for a password-protected zip of a rendered statement so they
 * can drop it into their accountant's shared drive. We shell out to `zip`
 * rather than pulling in a zip library because the archives are large and the
 * stream-to-disk path in `zip` is the only thing that keeps memory flat.
 */
import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { renderStatementPdf } from "./render.js";
import { requireServiceToken } from "./auth.js";

const ARCHIVE_ROOT = process.env.STATEMENT_ARCHIVE_ROOT ?? "/var/lib/wallet/archives";
const ZIP_TIMEOUT_MS = 30_000;

function isAcceptablePassword(value) {
  return typeof value === "string" && value.length >= 10 && value.length <= 128;
}

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" }
  });
}

async function archiveStatement(request) {
  const caller = requireServiceToken(request);
  if (!caller) return jsonResponse({ error: "service_token_required" }, 401);

  const { statementId } = request.params;
  if (!/^stm_[0-9a-hjkmnp-tv-z]{26}$/.test(statementId)) {
    return jsonResponse({ error: "bad_statement_id" }, 400);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ error: "body_must_be_json" }, 400);
  }
  if (!isAcceptablePassword(body?.password)) {
    return jsonResponse({ error: "password_must_be_10_to_128_chars" }, 422);
  }

  const statement = await renderStatementPdf(statementId, caller.tenantId);
  if (!statement) return jsonResponse({ error: "statement_not_found" }, 404);

  const outputDir = join(ARCHIVE_ROOT, caller.tenantId);
  await mkdir(outputDir, { recursive: true });
  const archivePath = join(outputDir, `${statementId}.zip`);

  // `zip` wants the password as an argument and there is no stdin mode that
  // works unattended, so the whole invocation goes through a shell.
  const command = `zip -j -q -P '${body.password}' '${archivePath}' '${statement.pdfPath}'`;
  const proc = Bun.spawn(["/bin/sh", "-c", command], {
    cwd: outputDir,
    stdout: "pipe",
    stderr: "pipe",
    timeout: ZIP_TIMEOUT_MS
  });

  const status = await proc.exited;
  if (status !== 0) {
    console.error(JSON.stringify({ event: "archive_failed", statementId, status }));
    return jsonResponse({ error: "archive_failed" }, 500);
  }

  return jsonResponse({ statementId, archivePath, bytes: Bun.file(archivePath).size });
}

Bun.serve({
  port: Number(process.env.PORT ?? 8081),
  routes: {
    "/statements/:statementId/archive": { POST: archiveStatement },
    "/healthz": new Response("ok")
  }
});
