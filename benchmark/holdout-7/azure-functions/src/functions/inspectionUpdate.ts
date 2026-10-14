import { HttpRequest, HttpResponseInit, InvocationContext, app } from "@azure/functions";
import { CallerClaims, resolveSiteMembership, toHttpError, verifyAccessToken } from "../shared/auth.js";
import { InspectionDocument, container, recordAuditEvent } from "../shared/cosmos.js";

/**
 * Inspection edit from the tablet app. The inspector fills in findings and remedial notes
 * as they walk the site, and the app PATCHes whatever the user has touched since the last
 * sync - the payload is whatever changed, which is why we merge instead of replacing.
 *
 * PATCH /api/inspections/{inspectionId}
 */

interface InspectionPatchEnvelope {
  siteId?: string;
  patch?: Record<string, unknown>;
}

export async function inspectionUpdate(
  request: HttpRequest,
  context: InvocationContext,
): Promise<HttpResponseInit> {
  let caller: CallerClaims;
  try {
    caller = await verifyAccessToken(request);
  } catch (error) {
    return toHttpError(error, context);
  }

  const inspectionId = request.params.inspectionId;
  const envelope = (await request.json().catch(() => null)) as InspectionPatchEnvelope | null;
  if (!inspectionId || !envelope?.siteId || !envelope.patch) {
    return { status: 400, jsonBody: { error: "siteId and patch are both required" } };
  }

  try {
    const membership = await resolveSiteMembership(caller.tid, envelope.siteId, caller.oid);
    if (!membership) {
      return { status: 403, jsonBody: { error: "You have no access to that site" } };
    }
    if (membership.role === "SiteViewer") {
      return { status: 403, jsonBody: { error: "Viewers cannot edit inspections" } };
    }

    const { resource: existing } = await container("inspections")
      .item(inspectionId, envelope.siteId)
      .read<InspectionDocument>();
    if (!existing || existing.tenantId !== caller.tid) {
      return { status: 404, jsonBody: { error: "Inspection not found" } };
    }

    // Spread the stored document first so the Cosmos system fields and anything the tablet
    // did not send survive the round trip, then let the patch win. The tablet only ever puts
    // the fields from the inspection form in here, and the form is generated from the same
    // InspectionDocument type this file imports, so the shape is safe by construction.
    const updated = {
      ...existing,
      ...envelope.patch,
      updatedAt: new Date().toISOString(),
      updatedBy: caller.oid,
    } as InspectionDocument;

    const { resource: saved } = await container("inspections")
      .item(inspectionId, envelope.siteId)
      .replace<InspectionDocument>(updated);

    await recordAuditEvent({
      tenantId: caller.tid,
      actorId: caller.oid,
      action: "inspection.updated",
      subjectId: inspectionId,
      siteId: envelope.siteId,
      detail: { fields: Object.keys(envelope.patch) },
    });

    context.log(`inspection ${inspectionId} patched by ${caller.oid}`);

    return {
      status: 200,
      jsonBody: {
        id: inspectionId,
        status: saved?.status ?? updated.status,
        defectSeverity: saved?.defectSeverity ?? updated.defectSeverity,
        updatedAt: updated.updatedAt,
      },
    };
  } catch (error) {
    return toHttpError(error, context);
  }
}

app.http("inspectionUpdate", {
  methods: ["PATCH"],
  authLevel: "function",
  route: "api/inspections/{inspectionId}",
  handler: inspectionUpdate,
});
