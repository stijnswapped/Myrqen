/**
 * Bulk statement export.
 *
 * Same archiving path as the single-statement endpoint, except the accountant
 * export bundles a whole period. We shell out to `zip` rather than pulling in a
 * zip library because the archives are large and the stream-to-disk path in
 * `zip` is the only thing that keeps memory flat.
 */
import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { renderPeriodPdf } from "./render.js";
import { requireServiceToken } from "./auth.js";

const ARCHIVE_ROOT = process.env.STATEMENT_ARCHIVE_ROOT ?? "/var/lib/wallet/archives";
const ZIP_TIMEOUT_MS = 30_000;

/**
 * The script is a constant. The three values that vary are read back out of the
 * environment by the shell, and a quoted parameter expansion is substituted
 * after the command line has already been split into words -- the shell does
 * not go back and re-parse what came out of "$ARCHIVE_PASSWORD".
 */
const ZIP_SCRIPT = 'exec zip -j -q -P "$ARCHIVE_PASSWORD" -- "$ARCHIVE_PATH" "$SOURCE_PATH"';

function isAcceptablePassword(value) {
  return typeof value === "string" && value.length >= 10 && value.length <= 128;
}

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" }
  });
}

async function exportPeriod(request) {
  const caller = requireServiceToken(request);
  if (!caller) return jsonResponse({ error: "service_token_required" }, 401);

  const { period } = request.params;
  if (!/^\d{4}-\d{2}$/.test(period)) {
    return jsonResponse({ error: "bad_period" }, 400);
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

  const bundle = await renderPeriodPdf(period, caller.tenantId);
  if (!bundle) return jsonResponse({ error: "period_not_found" }, 404);

  const outputDir = join(ARCHIVE_ROOT, caller.tenantId);
  await mkdir(outputDir, { recursive: true });
  const archivePath = join(outputDir, `${period}.zip`);

  const proc = Bun.spawn(["/bin/sh", "-c", ZIP_SCRIPT], {
    cwd: outputDir,
    env: {
      PATH: process.env.PATH,
      ARCHIVE_PASSWORD: body.password,
      ARCHIVE_PATH: archivePath,
      SOURCE_PATH: bundle.pdfPath
    },
    stdout: "pipe",
    stderr: "pipe",
    timeout: ZIP_TIMEOUT_MS
  });

  const status = await proc.exited;
  if (status !== 0) {
    console.error(JSON.stringify({ event: "export_failed", period, status }));
    return jsonResponse({ error: "export_failed" }, 500);
  }

  return jsonResponse({ period, archivePath, bytes: Bun.file(archivePath).size });
}

Bun.serve({
  port: Number(process.env.PORT ?? 8082),
  routes: {
    "/statements/periods/:period/export": { POST: exportPeriod },
    "/healthz": new Response("ok")
  }
});
