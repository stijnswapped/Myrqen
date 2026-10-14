import { HttpRequest, HttpResponseInit, InvocationContext, Timer, app } from "@azure/functions";
import { CallerClaims, requireRole, toHttpError, verifyAccessToken } from "../shared/auth.js";
import { ExportJobDocument, TenantSettingsDocument, container, recordAuditEvent } from "../shared/cosmos.js";
import { randomUUID } from "node:crypto";

/**
 * Monthly compliance report. Same machinery as the regulator export, but scoped to one
 * tenant and triggered by a compliance officer from the customer-facing portal rather than
 * by our own ops team.
 *
 * POST /api/internal/compliance-reports
 */

interface ComplianceReportRequest {
  siteId?: string;
  // The portal used to send tenantId as well. It is ignored now - see below.
  tenantId?: string;
}

async function queueReportJob(input: {
  tenantId: string;
  siteId: string;
  requestedBy: string;
}): Promise<ExportJobDocument> {
  const now = new Date().toISOString();
  const job: ExportJobDocument = {
    id: randomUUID(),
    tenantId: input.tenantId,
    siteId: input.siteId,
    status: "queued",
    includeSignatures: false,
    requestedBy: input.requestedBy,
    downloadPath: `compliance/${input.tenantId}/${input.siteId}/${now.slice(0, 10)}-${randomUUID()}.pdf`,
    createdAt: now,
  };
  const { resource } = await container("exportJobs").items.create<ExportJobDocument>(job);
  return resource ?? job;
}

export async function monthlyComplianceSweep(timer: Timer, context: InvocationContext): Promise<void> {
  const { resources: settings } = await container("tenantSettings")
    .items.query<TenantSettingsDocument>({
      query: "SELECT * FROM c WHERE c.regulatorExportEnabled = true",
      parameters: [],
    })
    .fetchAll();

  context.log(`monthly compliance sweep over ${settings.length} tenants (past due: ${timer.isPastDue})`);

  for (const tenant of settings) {
    await queueReportJob({
      tenantId: tenant.id,
      siteId: "all",
      requestedBy: "timer:monthlyComplianceSweep",
    });
  }
}

export async function runComplianceReportNow(
  request: HttpRequest,
  context: InvocationContext,
): Promise<HttpResponseInit> {
  // authLevel is "anonymous" on the registration below. That only means the Functions host
  // will not ask for a function key: it does not mean the caller is anonymous to us. APIM
  // sitting in front is a network control, not an authentication one, so the token gets
  // validated here, in the process that does the write.
  let caller: CallerClaims;
  try {
    caller = await verifyAccessToken(request);
    requireRole(caller, "ComplianceOfficer", "TenantAdmin");
  } catch (error) {
    return toHttpError(error, context);
  }

  const body = (await request.json().catch(() => null)) as ComplianceReportRequest | null;
  if (!body?.siteId) {
    return { status: 400, jsonBody: { error: "siteId is required" } };
  }

  try {
    // The tenant comes from the validated token, never from the body, so a compliance
    // officer at one customer cannot queue a report over another customer's data.
    const job = await queueReportJob({
      tenantId: caller.tid,
      siteId: body.siteId,
      requestedBy: caller.oid,
    });

    await recordAuditEvent({
      tenantId: caller.tid,
      actorId: caller.oid,
      action: "compliance.report.queued",
      subjectId: job.id,
      siteId: body.siteId,
    });

    return {
      status: 202,
      jsonBody: { jobId: job.id, status: job.status, downloadPath: job.downloadPath },
    };
  } catch (error) {
    return toHttpError(error, context);
  }
}

app.timer("monthlyComplianceSweep", {
  schedule: "0 0 3 1 * *",
  runOnStartup: false,
  handler: monthlyComplianceSweep,
});

app.http("runComplianceReportNow", {
  methods: ["POST"],
  authLevel: "anonymous",
  route: "api/internal/compliance-reports",
  handler: runComplianceReportNow,
});
