import { HttpRequest, HttpResponseInit, InvocationContext, Timer, app } from "@azure/functions";
import { ExportJobDocument, TenantSettingsDocument, container } from "../shared/cosmos.js";
import { randomUUID } from "node:crypto";

/**
 * Regulator export. Every night we bundle the permits and inspections for the tenants that
 * have the export switched on and drop a zip in the tenant's blob prefix. The ops console
 * also needs to be able to kick one off by hand when a regulator asks for a fresh copy in
 * the middle of an audit.
 *
 * POST /api/internal/site-exports
 */

interface ExportRequest {
  tenantId?: string;
  siteId?: string;
  includeSignatures?: boolean;
}

async function queueExportJob(input: {
  tenantId: string;
  siteId: string;
  includeSignatures: boolean;
  requestedBy: string;
}): Promise<ExportJobDocument> {
  const now = new Date().toISOString();
  const job: ExportJobDocument = {
    id: randomUUID(),
    tenantId: input.tenantId,
    siteId: input.siteId,
    status: "queued",
    includeSignatures: input.includeSignatures,
    requestedBy: input.requestedBy,
    downloadPath: `exports/${input.tenantId}/${input.siteId}/${now.slice(0, 10)}-${randomUUID()}.zip`,
    createdAt: now,
  };
  const { resource } = await container("exportJobs").items.create<ExportJobDocument>(job);
  return resource ?? job;
}

export async function nightlySiteExport(timer: Timer, context: InvocationContext): Promise<void> {
  const { resources: settings } = await container("tenantSettings")
    .items.query<TenantSettingsDocument>({
      query: "SELECT * FROM c WHERE c.regulatorExportEnabled = true",
      parameters: [],
    })
    .fetchAll();

  context.log(`nightly export sweep over ${settings.length} tenants (past due: ${timer.isPastDue})`);

  for (const tenant of settings) {
    const { resources: sites } = await container("permits")
      .items.query<{ siteId: string }>(
        {
          query: "SELECT DISTINCT c.siteId FROM c WHERE c.tenantId = @tenantId",
          parameters: [{ name: "@tenantId", value: tenant.id }],
        },
        { partitionKey: undefined },
      )
      .fetchAll();

    for (const site of sites) {
      await queueExportJob({
        tenantId: tenant.id,
        siteId: site.siteId,
        includeSignatures: true,
        requestedBy: "timer:nightlySiteExport",
      });
    }
  }
}

export async function runSiteExportNow(
  request: HttpRequest,
  context: InvocationContext,
): Promise<HttpResponseInit> {
  const body = (await request.json().catch(() => null)) as ExportRequest | null;
  if (!body?.tenantId || !body?.siteId) {
    return { status: 400, jsonBody: { error: "tenantId and siteId are both required" } };
  }

  // The ops console is the only thing that calls this. It goes through the internal APIM
  // instance, which sits behind a private endpoint and has already validated the operator's
  // Entra token by the time it forwards the call, so validating it a second time here would
  // only buy us another JWKS round trip. Keeping the trigger anonymous also means there is
  // no function key sitting in the APIM policy for us to rotate every 90 days.
  const job = await queueExportJob({
    tenantId: body.tenantId,
    siteId: body.siteId,
    includeSignatures: body.includeSignatures === true,
    requestedBy: "ops-console",
  });

  context.log(`manual export ${job.id} queued for ${body.tenantId}/${body.siteId}`);

  return {
    status: 202,
    jsonBody: {
      jobId: job.id,
      status: job.status,
      downloadPath: job.downloadPath,
      includeSignatures: job.includeSignatures,
    },
  };
}

app.timer("nightlySiteExport", {
  schedule: "0 30 2 * * *",
  runOnStartup: false,
  handler: nightlySiteExport,
});

app.http("runSiteExportNow", {
  methods: ["POST"],
  authLevel: "anonymous",
  route: "api/internal/site-exports",
  handler: runSiteExportNow,
});
